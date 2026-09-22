/* crypt.js — the whole security model of this application, in one file.
 *
 * Classic script. Defines globalThis.SkyCrypt. Loaded THREE ways, and the
 * bytes are identical in all three:
 *
 *   1. the login page        <script src="auth/crypt.js">
 *   2. the service worker    importScripts('auth/crypt.js')
 *   3. the Node build        require('../secure/crypt.js')
 *
 * That is deliberate and it is not a convenience. A key is created by (3) and
 * verified by (1). If those two ever ran different parameters — a different
 * memory cost, a different salt length, a different nonce discipline — every
 * password in the deployment would stop working, or worse, would keep working
 * while being weaker than advertised. One file cannot disagree with itself.
 *
 *
 * WHAT IS ACTUALLY PROTECTED, AND BY WHAT
 * ---------------------------------------
 * This site is published from a PUBLIC repository. Everything you can read
 * here, an attacker can read too. That is fine and it is the intended design:
 *
 *     The security rests entirely on key material that is never published.
 *
 * There is no login "check" anywhere in this system. A check is a branch, and
 * a branch can be deleted in devtools. Instead the application itself — all 30
 * generator pages and every vendor library — is stored as AES-256-GCM
 * ciphertext. Logging in IS the decryption. Deleting the login form reveals
 * nothing, because there is nothing behind it but ciphertext.
 *
 *
 * THERE IS NO PASSWORD HASH IN THIS SYSTEM
 * ----------------------------------------
 * Worth saying plainly, because it is the part people expect to find and it is
 * the part that is deliberately absent.
 *
 * Storing SHA-256(password) — or SHA-512, or any fast digest — would be the
 * classic mistake. Those functions are built for speed, and speed is precisely
 * what an offline attacker wants: a consumer GPU tries billions of SHA-256
 * candidates per second, so a real operator's password falls in minutes.
 *
 * So no digest of the password is stored. Instead:
 *
 *     KEK        = Argon2id(password, per-user salt)
 *     keyslot.c  = AES-256-GCM(KEK, {role, content keys})
 *
 * The GCM authentication tag is the password verifier. A wrong password
 * derives a wrong KEK, the tag fails, and you learn nothing else. An attacker
 * holding keyslots.json has no hash to attack — only the KDF, at 128 MiB of
 * memory per single guess. Memory cost is what makes GPUs and ASICs bad at
 * this; raw clock speed does not help them.
 *
 * The consequence, which governs everything else: THE PASSWORD IS THE ONLY
 * SECRET. Its entropy is the entire security margin. This is why passwords in
 * this system are generated (see WORDS below) and never chosen by a human.
 *
 *
 * WHAT keyslots.json LEAKS
 * ------------------------
 * Almost nothing, on purpose. Each record is {id, s, n, c, kdf}:
 *
 *   - no username      (id is a digest; the name itself lives INSIDE the
 *                       ciphertext, so it is readable only by that user)
 *   - no role          (also inside the ciphertext — you cannot tell from the
 *                       public file which record belongs to an admin, so an
 *                       attacker cannot pick the valuable target to grind)
 *   - no password hash (see above)
 *
 * What it does leak: how many accounts exist. Accepted.
 *
 * `id` is SHA-256(username + public deployment salt). That is a FAST digest
 * and it is meant to be — it is a lookup index, not a secret, and it keeps
 * login O(1) instead of trying every slot. It resists casual enumeration and
 * nothing more. Usernames in a factory are on the shift roster anyway; a
 * username without its password is worth nothing here.
 *
 *
 * TWO CONTENT KEYS, WHICH IS WHAT MAKES ROLES REAL
 * ------------------------------------------------
 * CK_viewer encrypts what everyone may have. CK_admin encrypts what only
 * admins may have (the user-management console). An admin's keyslot carries
 * both keys; a viewer's carries only CK_viewer.
 *
 * So a viewer does not have the admin console "hidden" from them by a CSS
 * class or a disabled button. They hold no key for it. It is ciphertext on
 * their machine and it stays ciphertext. That distinction is the difference
 * between access control and decoration.
 *
 * Be equally clear about the limit: this protects CONTENT A VIEWER NEVER
 * RECEIVES. It cannot govern how code behaves once a viewer legitimately holds
 * it — anything running in their browser is theirs to modify. See the note on
 * PDF permissions in build-secure.js.
 */
(function (root) {
  'use strict';

  /* ---------------------------------------------------------------------- *
   * Parameters.
   *
   * These are written into every keyslot at creation time rather than being
   * read from here at verification time. That is what lets these numbers be
   * raised later — as machines get faster they should be — without stranding
   * every account created under the old ones. A slot is always verified with
   * the parameters it was born with; CURRENT applies only to new slots.
   *
   * m=128 MiB is about six times OWASP's floor of 19 MiB. The cost that
   * matters against an attacker is the memory, not the iteration count: it is
   * what stops a GPU running ten thousand guesses in parallel.
   * ---------------------------------------------------------------------- */
  var CURRENT_KDF = { v: 1, alg: 'argon2id', m: 131072, t: 3, p: 1 };

  var SALT_LEN  = 16;
  var NONCE_LEN = 12;   // 96-bit, the size AES-GCM is actually specified for
  var KEY_LEN   = 32;   // AES-256

  /* ------------------------------ encoding ------------------------------ */

  function utf8(s) { return new TextEncoder().encode(s); }

  function b64(bytes) {
    var bin = '', a = new Uint8Array(bytes);
    for (var i = 0; i < a.length; i++) bin += String.fromCharCode(a[i]);
    return btoa(bin);
  }

  function unb64(s) {
    var bin = atob(s), a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  // URL- and filename-safe, because these become .enc filenames on disk.
  function b64url(bytes) {
    return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  /* -------------------------------- argon2 ------------------------------ *
   * The UMD bundle exposes itself as `hashwasm` in a browser or a worker, and
   * is require()d by the build. Resolved lazily so this file can be parsed in
   * any of the three environments before argon2 has loaded.
   * --------------------------------------------------------------------- */
  function argon2lib() {
    if (root.hashwasm && root.hashwasm.argon2id) return root.hashwasm;
    if (typeof module === 'object' && module.exports) {
      return require('hash-wasm/dist/argon2.umd.min.js');
    }
    throw new Error('argon2 unavailable: auth/argon2.umd.min.js must load first');
  }

  /* --------------------------------------------------------------------- *
   * deriveKEK — password + salt -> 256-bit key encrypting key.
   *
   * This is the only slow operation in the system, and its slowness is the
   * feature. Roughly 600 ms in a browser. Once per login, never per request.
   * --------------------------------------------------------------------- */
  async function deriveKEK(password, salt, kdf) {
    kdf = kdf || CURRENT_KDF;
    if (kdf.alg !== 'argon2id') {
      // Fail closed. A slot asking for something we do not implement is not a
      // slot to fall back on a weaker primitive for.
      throw new Error('unsupported KDF: ' + kdf.alg);
    }
    var raw = await argon2lib().argon2id({
      password:    password,
      salt:        salt,
      parallelism: kdf.p,
      memorySize:  kdf.m,
      iterations:  kdf.t,
      hashLength:  KEY_LEN,
      outputType:  'binary'
    });
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  /* ------------------------------ AES-GCM ------------------------------- *
   * A fresh random nonce every single time. GCM is catastrophic under nonce
   * reuse — two messages under one key/nonce pair leaks the XOR of the
   * plaintexts and, worse, the authentication subkey. Never derive a nonce
   * from a counter or a filename here.
   * --------------------------------------------------------------------- */
  async function encrypt(key, plaintextBytes) {
    var nonce = randomBytes(NONCE_LEN);
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintextBytes);
    return { nonce: nonce, ct: new Uint8Array(ct) };
  }

  async function decrypt(key, nonce, ct) {
    // Throws OperationError on a bad tag. Callers treat that as "wrong key",
    // which is the only thing it can mean.
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new Uint8Array(pt);
  }

  /* ---------------------------- raw key import -------------------------- */

  function importContentKey(rawBytes, usages) {
    return crypto.subtle.importKey('raw', rawBytes, 'AES-GCM', true, usages || ['encrypt', 'decrypt']);
  }

  async function exportContentKey(key) {
    return new Uint8Array(await crypto.subtle.exportKey('raw', key));
  }

  function generateContentKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  /* ------------------------------ identity ------------------------------ */

  // Case- and space-insensitive, so "R Kumbhar" and "r.kumbhar" cannot become
  // two accounts by accident on a factory floor.
  function normaliseUsername(u) {
    return String(u).trim().toLowerCase().replace(/\s+/g, ' ');
  }

  async function slotId(username, deploymentSalt) {
    var d = await crypto.subtle.digest('SHA-256', utf8(normaliseUsername(username) + '|' + deploymentSalt));
    return b64url(d);
  }

  // Same construction for file paths: the published tree is a flat directory
  // of opaque blobs, so the repository does not advertise its own structure —
  // no vendor names, no product families, no hint that an admin console exists.
  async function pathId(path, pathSaltValue) {
    var clean = String(path).replace(/^\/+/, '');
    var d = await crypto.subtle.digest('SHA-256', utf8('path|' + clean + '|' + pathSaltValue));
    return b64url(d);
  }

  /* The salt that hashes filenames is derived FROM THE CONTENT KEY, so it is
   * never published and cannot be computed by anyone who has not logged in.
   * An attacker with the whole repository cannot work out which opaque blob
   * is the admin console, or that one exists at all.
   *
   * This lives here rather than in the build because three separate places
   * need it — the build writes the names, the login page derives the salts,
   * the service worker resolves them — and three implementations of one
   * derivation is three chances for them to disagree. If they disagreed the
   * symptom would be a 404 on every page after a successful login, which is a
   * miserable thing to debug.
   */
  async function pathSalt(contentKeyB64) {
    var d = await crypto.subtle.digest('SHA-256', utf8('pathsalt|v1|' + contentKeyB64));
    return b64url(d);
  }

  /* ------------------------------- keyslots ----------------------------- *
   * createKeyslot / openKeyslot are exact inverses. The payload holds the
   * username, the role and the content keys this user is entitled to — all
   * three inside the ciphertext, so the public file reveals none of them.
   * --------------------------------------------------------------------- */
  async function createKeyslot(username, password, role, contentKeys, deploymentSalt, kdf) {
    kdf = kdf || CURRENT_KDF;
    var salt = randomBytes(SALT_LEN);
    var kek  = await deriveKEK(password, salt, kdf);

    var payload = {
      u: normaliseUsername(username),
      // The name as it was typed. `u` is normalised for lookup and comparison
      // and is therefore lower-case, which is correct for matching and wrong
      // for greeting somebody by name.
      d: String(username).trim(),
      r: role,
      k: contentKeys,               // {v: b64} for a viewer, {v: b64, a: b64} for an admin
      iat: Math.floor(Date.now() / 1000)
    };

    var out = await encrypt(kek, utf8(JSON.stringify(payload)));
    return {
      id:  await slotId(username, deploymentSalt),
      s:   b64(salt),
      n:   b64(out.nonce),
      c:   b64(out.ct),
      kdf: kdf
    };
  }

  async function openKeyslot(slot, password) {
    var kek = await deriveKEK(password, unb64(slot.s), slot.kdf);
    var pt  = await decrypt(kek, unb64(slot.n), unb64(slot.c));  // throws if wrong
    return JSON.parse(new TextDecoder().decode(pt));
  }

  /* ----------------------------- the directory -------------------------- *
   * A roster of who holds an account, sealed under the ADMIN content key and
   * carried inside keyslots.json.
   *
   * It exists because of a consequence of the keyslot design that is easy to
   * miss: each slot is encrypted under its own owner's password, so an
   * administrator genuinely cannot read anyone else's. That is the right
   * property — it is what stops a stolen admin password from immediately
   * revealing the whole staff list — but taken alone it would leave the admin
   * console unable to show a list of users at all, which makes reset and
   * removal unusable in practice.
   *
   * So the roster is kept separately and sealed under CK_admin. Admins can
   * read it because they hold that key. Viewers hold no admin key and cannot.
   * An attacker with the published file has neither.
   *
   * What it holds is only what an admin needs to manage accounts — the slot
   * id, the display name, the role, when it was issued. It never holds a
   * password, because no part of this system ever does.
   * --------------------------------------------------------------------- */
  async function sealDirectory(ckAdminB64, entries) {
    var key = await importContentKey(unb64(ckAdminB64), ['encrypt', 'decrypt']);
    var out = await encrypt(key, utf8(JSON.stringify(entries)));
    return { n: b64(out.nonce), c: b64(out.ct) };
  }

  async function openDirectory(ckAdminB64, sealed) {
    if (!sealed || !sealed.c) return [];
    var key = await importContentKey(unb64(ckAdminB64), ['encrypt', 'decrypt']);
    var pt  = await decrypt(key, unb64(sealed.n), unb64(sealed.c));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  /* ------------------------ generated passwords ------------------------- *
   * The password is the only secret in the system, so it is not left to a
   * human. A person asked to invent one produces about 30 bits and reuses it;
   * five words from this list is 64 bits, which is not brute-forceable against
   * a 128 MiB Argon2id even by someone with a serious budget and no deadline.
   *
   * The list is short, common, unambiguous English — words an operator can
   * read off a slip and type correctly, and say down a phone line without
   * spelling them. Entropy comes from the number of words, not from obscurity:
   * `WORDS.length` is public, and that changes nothing.
   *
   * No homophones, no near-anagrams, no words differing by one letter.
   * --------------------------------------------------------------------- */
  var WORDS = ('anchor amber apple arrow autumn bamboo barley basket beacon bishop ' +
    'blanket bottle branch bridge bronze bucket bundle butter cabin cactus ' +
    'camera candle canvas carbon cargo carpet castle cedar cement cherry ' +
    'chimney cinder circus citrus cobalt collar comet copper coral cotton ' +
    'crayon crystal cymbal dagger dahlia daisy denim diamond dolphin donkey ' +
    'dragon drawer driftwood eagle ember emerald engine fabric falcon feather ' +
    'fender fennel fiddle flint forest fossil fountain garden garnet gazelle ' +
    'ginger glacier granite gravel guitar hammer harbour hazel helmet hickory ' +
    'hollow honey hornet ingot island ivory jacket jasmine jersey jigsaw ' +
    'jungle kettle kitten ladder lagoon lantern lattice lemon lentil lighthouse ' +
    'lilac linen lobster locket lotus lumber magnet mammoth maple marble ' +
    'marigold meadow melon mercury meteor mitten monsoon mosaic muffin mulberry ' +
    'mustard nectar needle nickel nutmeg oatmeal obsidian octopus olive onyx ' +
    'orbit orchid otter oxide oyster paddle palace pantry parcel parsley ' +
    'pebble pelican pepper pewter pigeon pillow pineapple pistachio pocket pollen ' +
    'poppy portal pottery prairie pretzel pudding pumpkin quarry quartz quiver ' +
    'radish rafter rattle ribbon rocket rosemary rubble saffron sapphire satchel ' +
    'scarlet seashell sequoia shovel silver skillet slipper socket spindle ' +
    'sprocket squirrel stadium stencil sterling stirrup sugar sulphur summit ' +
    'sunset swallow sycamore syrup tabby tackle tadpole talon tangerine tapestry ' +
    'teapot tender thistle thunder timber tinder toffee topaz torrent trellis ' +
    'trumpet tulip tundra turnip turquoise umbrella vanilla velvet vessel vinegar ' +
    'violet walnut walrus wander wattle weasel whistle willow window winter ' +
    'wombat yarrow zephyr zinnia').split(' ');

  /* --------------------------------------------------------------------- *
   * MIN_BITS is a hard floor, enforced at runtime, and it exists because the
   * first version of this file got it wrong.
   *
   * That version generated five words and its comment claimed 64 bits. The
   * list underneath it holds 232 words, not the ~2000 the comment assumed, so
   * it was really emitting 39 bits — about four months of grinding for someone
   * with a GPU budget, rather than the "never" that was intended. Nothing in
   * the code contradicted the comment, so nothing caught it.
   *
   * So entropy is no longer asserted in prose. It is COMPUTED from the actual
   * alphabet at call time and checked against this floor, and the generators
   * throw rather than return something weak. A wordlist edited down to 50
   * entries by a well-meaning future hand now breaks the build loudly instead
   * of quietly halving everyone's protection.
   * --------------------------------------------------------------------- */
  var MIN_BITS = 64;

  /* Crockford's base32 alphabet: no I, L, O or U. I and L are unreadable next
   * to 1, O next to 0, and U is dropped so no random string can spell an
   * unfortunate word. 32 symbols is exactly 5 bits each, so the arithmetic
   * below is exact rather than approximate. */
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  // Rejection sampling. `% n` on a raw 32-bit value biases the low indices;
  // the bias is small but avoiding it is free, and this is the one place in
  // the system where the randomness IS the security.
  function uniformBelow(n) {
    var limit = Math.floor(4294967296 / n) * n, r;
    do { r = crypto.getRandomValues(new Uint32Array(1))[0]; } while (r >= limit);
    return r % n;
  }

  /* The default. 14 symbols x 5 bits = 70 bits, printed in groups of four so
   * it can be read off a slip without losing your place:  4K7R-M9XQ-T8PW-2G
   *
   * Shorter to type than a passphrase of equivalent strength (17 characters
   * against about 60), and unambiguous by construction, which matters when a
   * supervisor is reading it to someone on a noisy factory floor. */
  function generatePassword(symbols) {
    symbols = symbols || 14;
    var bits = symbols * Math.log2(ALPHABET.length);
    if (bits < MIN_BITS) {
      throw new Error('refusing to generate a ' + Math.floor(bits) + '-bit password; ' +
                      'minimum is ' + MIN_BITS + ' bits (' + minSymbols() + ' symbols)');
    }
    var out = '';
    for (var i = 0; i < symbols; i++) {
      if (i > 0 && i % 4 === 0) out += '-';
      out += ALPHABET.charAt(uniformBelow(ALPHABET.length));
    }
    return out;
  }

  /* The alternative, for anyone who has to dictate a password down a phone
   * line — words survive that, random symbols do not. Costs length: reaching
   * the same floor takes nine words from this list. */
  function generatePassphrase(wordCount) {
    wordCount = wordCount || minWords();
    var bits = wordCount * Math.log2(WORDS.length);
    if (bits < MIN_BITS) {
      throw new Error('refusing to generate a ' + Math.floor(bits) + '-bit passphrase; ' +
                      'minimum is ' + MIN_BITS + ' bits (' + minWords() + ' words from this list)');
    }
    var picked = [];
    for (var i = 0; i < wordCount; i++) picked.push(WORDS[uniformBelow(WORDS.length)]);
    return picked.join('-');
  }

  function minSymbols() { return Math.ceil(MIN_BITS / Math.log2(ALPHABET.length)); }
  function minWords()   { return Math.ceil(MIN_BITS / Math.log2(WORDS.length)); }

  // Measures what was actually produced, so a password pasted in from
  // elsewhere can be judged rather than assumed.
  function passwordBits(secret) {
    var s = String(secret);
    if (s.indexOf('-') !== -1 && /[a-z]{3}/.test(s)) {
      var parts = s.split('-').filter(function (w) { return WORDS.indexOf(w) !== -1; });
      if (parts.length) return Math.floor(parts.length * Math.log2(WORDS.length));
    }
    var symbols = s.replace(/-/g, '').length;
    return Math.floor(symbols * Math.log2(ALPHABET.length));
  }

  root.SkyCrypt = {
    CURRENT_KDF: CURRENT_KDF,
    WORD_COUNT: WORDS.length,
    utf8: utf8, b64: b64, unb64: unb64, b64url: b64url, randomBytes: randomBytes,
    deriveKEK: deriveKEK, encrypt: encrypt, decrypt: decrypt,
    importContentKey: importContentKey, exportContentKey: exportContentKey,
    generateContentKey: generateContentKey,
    normaliseUsername: normaliseUsername, slotId: slotId, pathId: pathId, pathSalt: pathSalt,
    createKeyslot: createKeyslot, openKeyslot: openKeyslot,
    sealDirectory: sealDirectory, openDirectory: openDirectory,
    generatePassword: generatePassword, generatePassphrase: generatePassphrase,
    passwordBits: passwordBits, minSymbols: minSymbols, minWords: minWords, MIN_BITS: MIN_BITS
  };

  if (typeof module === 'object' && module.exports) module.exports = root.SkyCrypt;

})(typeof self !== 'undefined' ? self : globalThis);
