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
    const res = await fetch(scopePath() + 'e/' + id + '.enc', { cache: 'no-store' });
    if (!res.ok) continue;

    const envelope = new Uint8Array(await res.arrayBuffer());
    if (envelope[0] !== 1) continue;                 // unknown envelope version

    const nonce = envelope.slice(1, 13);
    const ct    = envelope.slice(13);

    try {
      const plain = await SkyCrypt.decrypt(attempt.key, nonce, ct);
      tierMemo.set(rel, attempt.tier);
      return new Response(plain, {
        status: 200,
        headers: {
          'Content-Type': contentType(rel),
          // Decrypted bytes must never reach the HTTP cache — the whole point
          // is that they exist only for the length of a session.
          'Cache-Control': 'no-store, private',
          'X-Content-Type-Options': 'nosniff'
        }
      });
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
      reply(s ? { ok: true, username: s.username, role: s.role, expires: s.expires }
              : { ok: false });
    })());
  }
});
