/* sw.js — the decrypting service worker.
 *
 * This is what lets the 30 generator pages stay BYTE-IDENTICAL while being
 * stored as ciphertext.
 *
 * The alternative designs all required editing the pages: inlining every
 * ../../../vendor/ reference so the tree could run from a blob URL, or
 * dismantling each page into an injectable fragment. Both mean touching 30
 * near-identical files that draw a statutory document on a canvas, which
 * CLAUDE.md is emphatic about for good reason — a label 0.4 mm out with nobody
 * able to say why is a worse outcome than any amount of service worker
 * plumbing.
 *
 * So nothing is edited. The worker sits between the browser and the network,
 * and when the page asks for ../../../vendor/i18n.js it receives exactly the
 * bytes that are in docs/vendor/i18n.js. The relative paths work because they
 * are never rewritten. The canvas code is the same code. The PDF test suite
 * drives the same controls.
 *
 *
 * WHERE THE KEY LIVES, AND THE HONEST TRADE-OFF IN THAT
 * ------------------------------------------------------
 * A service worker is killed and restarted by the browser whenever it feels
 * like it, and anything held in a variable dies with it. But the decrypted
 * pages cannot re-supply the key on wake-up, because they contain no code of
 * ours to do it — that is the price of leaving them untouched.
 *
 * So the session key is kept in IndexedDB, which survives a worker restart.
 * Be clear about what that costs: the content key is on disk for the duration
 * of a session. Someone with the unlocked, logged-in machine can dig it out.
 *
 * That is an acceptable trade here because it is not the threat being
 * defended against — anyone at an unlocked logged-in terminal can simply use
 * the application, which is strictly easier than extracting a key from
 * IndexedDB. The defence is against someone who downloads the public
 * repository, and they get ciphertext and nothing else.
 *
 * It is mitigated rather than ignored: sessions carry a hard expiry, logout
 * wipes the store, and an expired session is erased on the next request
 * rather than being allowed to linger.
 */

'use strict';

importScripts('./auth/argon2.umd.min.js', './auth/crypt.js');

const DB_NAME    = 'sky-session';
const STORE      = 'session';
const SESSION_MS = 10 * 60 * 60 * 1000;   // one shift, plus slack

/* The decrypted application lives under this prefix.
 *
 * It needs one because the login page occupies index.html at the root and the
 * generator portal is also called index.html. Rather than rename a file in
 * docs/ — which would mean editing the tree this design exists to leave alone
 * — the whole decrypted tree is mounted one level down:
 *
 *     /app/                        docs/index.html      (the portal)
 *     /app/af1/sgs/device/         docs/af1/sgs/device/index.html
 *
 * The pages' own ../../../vendor/ references resolve inside that prefix and
 * keep working untouched, because every path in the tree is relative to its
 * own position and nothing about their relative positions has changed.
 */
const APP_PREFIX = 'app/';

/* Served in the clear, because they are needed before anyone has a key.
 * Everything else in scope is ciphertext and goes through serveEncrypted(). */
const PLAINTEXT = new Set([
  '', 'index.html', 'sw.js', 'config.json', 'keyslots.json',
  'auth/crypt.js', 'auth/argon2.umd.min.js', 'auth/login.js', 'auth/shell.css',
  'auth/session.js', 'auth/guard.js',
  'auth/ui.css', 'auth/fonts/Geist-Variable.woff2', 'auth/fonts/GeistMono-Variable.woff2',
  'auth/fonts/Geist-OFL.txt',
  '.nojekyll', 'favicon.ico'
]);

/* --------------------------------------------------------------- IndexedDB */

function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => { open.result.close(); resolve(req && req.result); };
      tx.onerror = () => { open.result.close(); reject(tx.error); };
    };
  });
}

const putSession   = (s) => idb('readwrite', (st) => st.put(s, 'current'));
const readSession  = ()  => idb('readonly',  (st) => st.get('current'));
const clearSession = ()  => idb('readwrite', (st) => st.delete('current'));

/* ------------------------------------------------------------ session state
 * Cached in memory so the common case costs nothing, but IndexedDB remains
 * the source of truth so a restarted worker recovers rather than locking the
 * operator out mid-shift. */

let session = null;

/* path -> which tier decrypted it last time. See serveEncrypted(). */
const tierMemo = new Map();

async function getSession() {
  if (session) {
    if (Date.now() > session.expires) { await logout(); return null; }
    return session;
  }
  const stored = await readSession();
  if (!stored) return null;

  if (Date.now() > stored.expires) {
    // Do not merely refuse it — remove it. An expired key sitting on disk is
    // a liability with no remaining purpose.
    await clearSession();
    return null;
  }

  session = {
    role:     stored.role,
    username: stored.username,
    expires:  stored.expires,
    /* Carried so the page can ask the published account file whether this
       account is still there. Neither is secret: an opaque id and the
       ciphertext already published beside it. */
    slotId:   stored.slotId || null,
    slotC:    stored.slotC || null,
    keyViewer: await SkyCrypt.importContentKey(SkyCrypt.unb64(stored.ckViewer), ['decrypt']),
    keyAdmin:  stored.ckAdmin
      ? await SkyCrypt.importContentKey(SkyCrypt.unb64(stored.ckAdmin), ['decrypt'])
      : null,
    saltViewer: stored.saltViewer,
    saltAdmin:  stored.saltAdmin || null
  };
  return session;
}

async function logout() {
  session = null;
  tierMemo.clear();   // the next session may resolve the same paths differently
  await clearSession();
}

/* ------------------------------------------------------------------ paths */

function scopePath() {
  return new URL(self.registration.scope).pathname;   // e.g. '/labels/'
}

/* ---------------------------------------------------------------- the CSP */

/* A fresh value per response. Predicting it is the only way an injected
   <script> could claim the nonce, so it must not be derived from anything. */
function newNonce() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode.apply(null, b)).replace(/=+$/, '');
}

/* WHY A HEADER AND NOT A <meta> TAG
 *
 * The sign-in shell carries its policy in a meta tag because GitHub Pages
 * serves it and cannot be told to set a header. The generator pages are
 * different: they are assembled here, so they can have a real header - and
 * frame-ancestors, which is what stops this being framed by someone else's
 * page, is IGNORED in a meta tag. The shell logs a console warning saying so.
 *
 * script-src names a nonce and does not include 'unsafe-inline'. That is only
 * possible because the three inline onclick="download(...)" attributes were
 * replaced with data-dl attributes wired up inside the page's own script: a
 * nonce covers a block, and nothing covers a handler attribute.
 *
 * style-src still allows inline. The pages carry a <style> block and a dozen
 * style attributes, and injected CSS cannot run code - it is a far smaller
 * concern than script, and the shell already makes the same trade.
 *
 * data: appears in img-src and font-src because the label's JioType faces are
 * embedded as data: URIs and the canvas is read back with toDataURL. blob: is
 * there because every download here is made with URL.createObjectURL.
 */
/* THE VALIDATOR GETS A DIFFERENT POLICY, AND THIS IS WHY.
 *
 * The strict policy below broke it. The validator carries its text reader
 * (Tesseract) inline, and starts it by creating a <script> element at run time
 * and setting its text - a runtime inline script with no nonce, which is
 * precisely what a nonce policy exists to refuse. So Tesseract never loaded,
 * nothing on the label was read as text, and a PDF that the standalone
 * validator reads in full came back as "the text reader could not be loaded".
 *
 * The standalone validator - the version that works, and the one this is meant
 * to be merged as-is - ran with no CSP at all. Its code is not changed to suit
 * this wrapper. Instead it gets only the directives that cannot touch what its
 * scripts do:
 *
 *   frame-ancestors 'none'   nobody else's page may frame it (clickjacking)
 *   object-src 'none'        no plugins
 *   base-uri 'none'          no <base> tag can redirect its relative URLs
 *
 * With no default-src and no script-src, scripts, workers, WebAssembly, blob:
 * and data: all behave exactly as they did standalone. Tightening this further
 * means changing the validator's own code first, which is not to be done
 * without being asked. */
function isValidator(rel) {
  return /^validator\//.test(String(rel || ''));
}

function validatorCsp() {
  return ["frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"].join('; ');
}

function csp(nonce) {
  return [
    "default-src 'self'",
    /* 'wasm-unsafe-eval' is here for the Validator, which decodes with a
       WebAssembly build and will not compile without it. It permits
       WebAssembly compilation only - it does NOT bring back eval() or
       new Function() on JavaScript strings, which is why it is not simply
       'unsafe-eval'. The sign-in shell allows the same thing for argon2. */
    "script-src 'self' 'wasm-unsafe-eval' 'nonce-" + nonce + "'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ].join('; ');
}

/* Path relative to the worker's scope, with directory requests resolved to
 * their index.html so that /af1/sgs/device/ finds the file it means. */
function relativePath(url) {
  const base = scopePath();
  let p = url.pathname;
  if (!p.startsWith(base)) return null;
  p = p.slice(base.length);
  if (p === '' || p.endsWith('/')) p += 'index.html';
  return p;
}

const TYPES = {
  html: 'text/html; charset=utf-8',
  js:   'text/javascript; charset=utf-8',
  css:  'text/css; charset=utf-8',
  json: 'application/json; charset=utf-8',
  svg:  'image/svg+xml',
  png:  'image/png',
  jpg:  'image/jpeg',
  jpeg: 'image/jpeg',
  gif:  'image/gif',
  ico:  'image/x-icon',
  woff: 'font/woff',
  woff2:'font/woff2',
  ttf:  'font/ttf',
  pdf:  'application/pdf',
  txt:  'text/plain; charset=utf-8'
};

function contentType(p) {
  const ext = p.split('.').pop().toLowerCase();
  return TYPES[ext] || 'application/octet-stream';
}

/* ---------------------------------------------------------------- serving */

async function serveEncrypted(rel, sess) {
  /* ADMIN TIER FIRST, when this session holds that key.
   *
   * The order is load-bearing, not arbitrary. A few files are built twice —
   * vendor/vectorpdf.js is built restricted for viewers and unrestricted for
   * administrators — and both copies answer to the SAME path. Whichever tier
   * is tried first is the one an administrator gets, so trying the viewer
   * tier first would quietly hand administrators the restricted build and the
   * distinction this whole mechanism exists for would evaporate.
   *
   * A viewer cannot even compute the admin blob's filename — the salt is
   * derived from the admin content key they do not have — so an admin-only
   * path is not "forbidden" to them, it is absent.
   */
  const attempts = [];
  if (sess.keyAdmin && sess.saltAdmin) {
    attempts.push({ tier: 'a', key: sess.keyAdmin, salt: sess.saltAdmin });
  }
  attempts.push({ tier: 'v', key: sess.keyViewer, salt: sess.saltViewer });

  /* Most files exist in one tier only, so an administrator would otherwise
   * spend a wasted 404 on every viewer-tier request. Remember which tier
   * answered for a path and go straight there next time. Memory only: it dies
   * with the worker, which is correct — it is a cache, not state. */
  const remembered = tierMemo.get(rel);
  if (remembered) {
    const first = attempts.findIndex(a => a.tier === remembered);
    if (first > 0) attempts.unshift(attempts.splice(first, 1)[0]);
  }

  for (const attempt of attempts) {
    const id = await SkyCrypt.pathId(rel, attempt.salt);
    /* 'no-cache', not 'no-store'. These are CIPHERTEXT - the same bytes anyone
       can download from the public repository - so letting the browser keep
       them exposes nothing; the decrypted response is still marked no-store
       below and never reaches a cache. 'no-cache' revalidates every time, so a
       deploy is seen at once (a 304 when nothing changed, the new file when
       something did). With 'no-store' every page opened downloaded its whole
       blob again: 10.6 MB for the validator, on every visit. */
    const res = await fetch(scopePath() + 'e/' + id + '.enc', { cache: 'no-cache' });
    if (!res.ok) continue;

    const envelope = new Uint8Array(await res.arrayBuffer());
    if (envelope[0] !== 1) continue;                 // unknown envelope version

    const nonce = envelope.slice(1, 13);
    const ct    = envelope.slice(13);

    try {
      let plain = await SkyCrypt.decrypt(attempt.key, nonce, ct);
      tierMemo.set(rel, attempt.tier);

      /* Give every decrypted PAGE a session script.
       *
       * The generator pages are byte-identical to the files in docs/ and must
       * stay that way - it is why the canvas drawing a statutory label is the
       * same canvas it always was. So none of them carries a tag for this, and
       * it is added here instead: what the browser receives changes, what is
       * on disk does not.
       *
       * Only HTML documents, and only the one tag. Nothing else about the
       * document is touched. */
      const type = contentType(rel);
      const headers = {
        'Content-Type': type,
        // Decrypted bytes must never reach the HTTP cache — the whole point
        // is that they exist only for the length of a session.
        'Cache-Control': 'no-store, private',
        'X-Content-Type-Options': 'nosniff'
      };

      if (type.startsWith('text/html')) {
        const nonce = newNonce();
        /* guard.js beside it: the brand on the page, sealed against editing
           in the browser. Injected for the same reason session.js is - no
           page carries a tag for it, so none of them changes. */
        const tag = '<script nonce="' + nonce + '" src="' + scopePath() +
                    'auth/session.js" defer></' + 'script>' +
                    '<script nonce="' + nonce + '" src="' + scopePath() +
                    'auth/guard.js" defer></' + 'script>';
        let html = new TextDecoder().decode(plain);
        html = html.includes('<head')
          ? html.replace(/<head([^>]*)>/i, (m) => m + tag)
          : tag + html;

        /* Every inline <script> on the page gets this response's nonce. The
           tag added just above already carries it and has a src, so the
           negative lookahead leaves it alone rather than giving it a second.
           A generator page has exactly one inline block; the assertion is not
           made here because a page with none must still be served. */
        html = html.replace(/<script(?![^>]*\ssrc=)([^>]*)>/gi,
                            (m, attrs) => '<script nonce="' + nonce + '"' + attrs + '>');

        plain = new TextEncoder().encode(html);
        headers['Content-Security-Policy'] = isValidator(rel) ? validatorCsp() : csp(nonce);
      }

      return new Response(plain, { status: 200, headers });
    } catch {
      // Wrong key for this blob. Fall through and try the next tier.
    }
  }
  return null;
}

function redirectToLogin(rel) {
  const target = scopePath() + 'index.html?next=' + encodeURIComponent(rel || '');
  return Response.redirect(target, 302);
}

async function handle(request) {
  const url = new URL(request.url);

  // Anything off-origin or outside scope is none of this worker's business.
  if (url.origin !== self.location.origin) return fetch(request);
  const rel = relativePath(url);
  if (rel === null) return fetch(request);

  // The plaintext shell and the raw ciphertext blobs both go straight to the
  // network. Serving the blobs untouched is safe and necessary: they are what
  // this worker fetches and decrypts, and they are useless without a key.
  if (PLAINTEXT.has(rel) || rel.startsWith('e/')) return fetch(request);

  // Everything the application consists of sits under app/.
  if (!rel.startsWith(APP_PREFIX)) {
    return new Response('not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  const docsRel = rel.slice(APP_PREFIX.length);

  const sess = await getSession();
  if (!sess) {
    if (request.mode === 'navigate') return redirectToLogin(rel);
    return new Response('locked', { status: 401, headers: { 'Cache-Control': 'no-store' } });
  }

  const res = await serveEncrypted(docsRel, sess);
  if (res) return res;

  /* Reaching here means the session is valid but the file did not decrypt
   * under any key this session holds. Two different situations, deliberately
   * given the same answer:
   *
   *   - the file genuinely does not exist
   *   - it exists, but in the admin tier, and this is a viewer
   *
   * A viewer cannot distinguish them, which is the intended behaviour. They
   * cannot confirm the admin console exists by probing for it.
   */
  if (request.mode === 'navigate') {
    return new Response(
      '<!DOCTYPE html><meta charset="utf-8"><title>Not found</title>' +
      '<body style="font:15px system-ui;padding:40px;color:#334155">' +
      '<h1 style="font-size:17px">Not found</h1>' +
      '<p>This page does not exist, or your account does not have it.</p>' +
      '<p><a href="' + scopePath() + APP_PREFIX + '">Back to the generators</a></p>',
      { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }
    );
  }
  return new Response('not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
}

/* ---------------------------------------------------------------- wiring */

self.addEventListener('install', (e) => e.waitUntil(self.skipWaiting()));

self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (e) => {
  // GET only. Nothing in this application posts anywhere.
  if (e.request.method !== 'GET') return;
  e.respondWith(handle(e.request));
});

self.addEventListener('message', (e) => {
  const msg = e.data || {};
  const reply = (payload) => e.ports[0] && e.ports[0].postMessage(payload);

  if (msg.type === 'unlock') {
    e.waitUntil((async () => {
      const stored = {
        username:   msg.username,
        role:       msg.role,
        ckViewer:   msg.ckViewer,
        ckAdmin:    msg.ckAdmin || null,
        slotId:     msg.slotId || null,
        slotC:      msg.slotC || null,
        saltViewer: msg.saltViewer,
        saltAdmin:  msg.saltAdmin || null,
        expires:    Date.now() + SESSION_MS
      };
      session = null;                 // force a clean rebuild from the store
      await putSession(stored);
      await getSession();
      reply({ ok: true });
    })());
    return;
  }

  if (msg.type === 'logout') {
    e.waitUntil((async () => { await logout(); reply({ ok: true }); })());
    return;
  }

  /* The admin console needs the content keys in order to wrap new keyslots
   * for the users it creates. Handing them back to the page is safe because
   * the only pages that can be running at all are ones this session's keys
   * already decrypted: a viewer asking gets the viewer key, which their own
   * page was decrypted with, and nothing more. The admin key is returned only
   * to a session that already holds it. */
  if (msg.type === 'keys') {
    e.waitUntil((async () => {
      const s = await getSession();
      if (!s) return reply({ ok: false });
      const stored = await readSession();
      reply({
        ok: true,
        role: s.role,
        username: s.username,
        ckViewer: stored.ckViewer,
        ckAdmin: stored.ckAdmin || null
      });
    })());
    return;
  }

  if (msg.type === 'whoami') {
    e.waitUntil((async () => {
      const s = await getSession();
      reply(s ? { ok: true, username: s.username, role: s.role, expires: s.expires,
                  slotId: s.slotId, slotC: s.slotC }
              : { ok: false });
    })());
  }
});
