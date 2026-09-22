/* login.js — the gate.
 *
 * What happens when the button is pressed, in order:
 *
 *   1. find this username's keyslot            (a fast digest lookup)
 *   2. Argon2id(password, that slot's salt)    (~600 ms, the expensive part)
 *   3. AES-GCM-unwrap the slot with the result (succeeds or throws; that IS
 *                                               the password check)
 *   4. hand the content keys to the service worker
 *   5. navigate into the application
 *
 * Step 3 is the whole authentication mechanism. There is no comparison against
 * a stored hash anywhere, because no stored hash exists — see the header of
 * crypt.js. A wrong password produces a wrong key, the GCM authentication tag
 * fails, and the unwrap throws. Nothing else distinguishes a good password
 * from a bad one, so there is nothing else to attack or to accidentally
 * bypass.
 *
 *
 * ON THE ERROR MESSAGES
 * ---------------------
 * Every failure below says what happened and what to do about it, EXCEPT one:
 * a wrong username and a wrong password give the identical message, in the
 * identical time. That is not vagueness, it is the point. Distinguishing them
 * would tell an attacker which usernames exist, which is a free half of the
 * problem. See signIn().
 *
 * Everything else — no network, no accounts yet, an insecure origin, a browser
 * that cannot do this — is a fault in the setup rather than a secret, so it is
 * named plainly. An operator staring at "something went wrong" at the start of
 * a shift is a support call; an operator reading "this page must be opened
 * over https" fixes it themselves.
 */

'use strict';

(function () {

  var form     = document.getElementById('loginForm');
  var card     = form;
  var userEl   = document.getElementById('username');
  var passEl   = document.getElementById('password');
  var btn      = document.getElementById('submitBtn');
  var statusEl = document.getElementById('status');
  var peekBtn  = document.getElementById('peek');

  var config = null;
  var keyslots = null;
  var ready = false;
  var busy = false;

  /* Throttle after repeated failures.
   *
   * Be honest about what this is: a UX nicety and a speed bump for somebody
   * typing at the keyboard. It is NOT a security control and could not be —
   * it lives in the page, so anyone attacking this system properly ignores the
   * page, downloads keyslots.json and grinds it offline.
   *
   * The real defence against that is Argon2id at 128 MiB combined with a
   * 70-bit generated password. This only stops idle guessing at a terminal. */
  var failures = 0;
  var lockedUntil = 0;
  var countdownTimer = null;

  /* -------------------------------------------------------------- status */

  function setStatus(html, kind) {
    statusEl.innerHTML = html || '';
    statusEl.className = 'status' + (kind ? ' ' + kind : '');
  }

  function fail(html, opts) {
    opts = opts || {};
    setStatus(html, opts.kind || 'error');
    if (opts.shake !== false) {
      card.classList.remove('nope');
      void card.offsetWidth;            // restart the animation
      card.classList.add('nope');
    }
    if (opts.mark) {
      (opts.mark === 'user' ? userEl : passEl).classList.add('wrong');
    }
    if (opts.focus) {
      (opts.focus === 'user' ? userEl : passEl).focus();
    }
  }

  function clearMarks() {
    userEl.classList.remove('wrong');
    passEl.classList.remove('wrong');
  }

  function setBusy(on, msg) {
    busy = on;
    btn.disabled = on || !ready;
    btn.classList.toggle('busy', on);
    btn.querySelector('.label').textContent = on ? (msg || 'Checking…') : 'Sign in';
  }

  function lockOut(seconds) {
    lockedUntil = Date.now() + seconds * 1000;
    tickCountdown();
  }

  function tickCountdown() {
    clearTimeout(countdownTimer);
    var left = Math.ceil((lockedUntil - Date.now()) / 1000);
    if (left <= 0) {
      lockedUntil = 0;
      setStatus('');
      setBusy(false);
      return;
    }
    setStatus('Too many attempts. Try again in <b>' + left + ' second' +
              (left === 1 ? '' : 's') + '</b>.' +
              '<span class="hint">If you have mislaid your password, an ' +
              'administrator can issue a new one. It cannot be recovered.</span>', 'warn');
    btn.disabled = true;
    countdownTimer = setTimeout(tickCountdown, 1000);
  }

  /* ----------------------------------------------------------- bootstrap *
   * Everything that can be wrong before a key is even pressed, checked here
   * so the operator is told at the moment they arrive rather than after they
   * have typed a password and waited for it. */

  function bootstrap() {
    /* Chrome exposes crypto.subtle only in a secure context, so on file:// or
       plain http it is simply undefined and every later call dies with an
       unhelpful TypeError. Catching it here turns a mystery into an
       instruction. */
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      return fail(
        'This page must be opened over <b>https</b>.' +
        '<span class="hint">Browsers only allow the cryptography this ' +
        'application needs on a secure connection. Opening the file directly ' +
        'from disk, or over plain http, will not work. Use the published ' +
        'https address, or http://localhost for testing.</span>',
        { shake: false });
    }

    if (typeof SkyCrypt === 'undefined') {
      return fail(
        'The application did not load correctly.' +
        '<span class="hint">auth/crypt.js is missing or was blocked. ' +
        'Reload the page; if it persists the deployment is incomplete.</span>',
        { shake: false });
    }

    if (typeof hashwasm === 'undefined' || !hashwasm.argon2id) {
      return fail(
        'The password module did not load.' +
        '<span class="hint">auth/argon2.umd.min.js is missing or was blocked. ' +
        'Reload the page; if it persists the deployment is incomplete.</span>',
        { shake: false });
    }

    if (!('serviceWorker' in navigator)) {
      return fail(
        'This browser cannot run the application.' +
        '<span class="hint">It needs service worker support. Chrome, Edge, ' +
        'Firefox and Safari all have it; private or restricted modes ' +
        'sometimes switch it off.</span>',
        { shake: false });
    }

    Promise.all([loadJson('config.json'), loadJson('keyslots.json')])
      .then(function (r) {
        config = r[0];
        keyslots = r[1];

        if (!config || !config.usernameSalt) {
          throw tagged('config.json is present but incomplete. The deployment needs rebuilding.');
        }
        if (!keyslots || !Array.isArray(keyslots.slots)) {
          throw tagged('keyslots.json is present but malformed. The account file may have been edited or truncated.');
        }
        if (keyslots.slots.length === 0) {
          return fail(
            'No accounts have been set up yet.' +
            '<span class="hint">Create the first administrator with the build ' +
            'tool, then publish the account file:<br>' +
            '<code>node build-secure.js --add-user "Your Name" --role admin</code></span>',
            { shake: false });
        }

        ready = true;
        setStatus('');
        setBusy(false);
        userEl.focus();
      })
      .catch(function (e) {
        fail(
          (e && e.friendly ? e.friendly : 'Could not load sign-in data.') +
          '<span class="hint">' +
          (navigator.onLine === false
            ? 'This device appears to be offline. Reconnect and reload.'
            : 'Reload the page. If it keeps happening, the site may be ' +
              'mid-deployment &mdash; wait a minute and try again.') +
          '</span>',
          { shake: false });
      });
  }

  function tagged(msg) { var e = new Error(msg); e.friendly = msg; return e; }

  function loadJson(url) {
    return fetch(url, { cache: 'no-store' }).then(function (r) {
      if (r.status === 404) throw tagged(url + ' is missing from the deployment.');
      if (!r.ok) throw tagged('The server returned ' + r.status + ' for ' + url + '.');
      return r.json().catch(function () {
        throw tagged(url + ' is not valid JSON. It may have been edited by hand.');
      });
    });
  }

  /* ------------------------------------------------------------------ UI */

  peekBtn.addEventListener('click', function () {
    var shown = passEl.type === 'text';
    passEl.type = shown ? 'password' : 'text';
    peekBtn.setAttribute('aria-pressed', String(!shown));
    peekBtn.setAttribute('aria-label', shown ? 'Show password' : 'Hide password');
    passEl.focus();
  });

  [userEl, passEl].forEach(function (el) {
    el.addEventListener('input', function () {
      el.classList.remove('wrong');
      if (statusEl.classList.contains('error') && !lockedUntil) setStatus('');
    });
  });

  /* --------------------------------------------------------------- login */

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (busy || !ready) return;

    if (lockedUntil && Date.now() < lockedUntil) { tickCountdown(); return; }

    var username = userEl.value.trim();
    var password = passEl.value;

    clearMarks();

    if (!username && !password) {
      return fail('Enter your username and password.', { mark: 'user', focus: 'user' });
    }
    if (!username) {
      return fail('Enter your username.', { mark: 'user', focus: 'user' });
    }
    if (!password) {
      return fail('Enter your password.', { mark: 'pass', focus: 'pass' });
    }

    setBusy(true, 'Unlocking…');
    setStatus('Deriving your key… this takes a moment by design.', 'info');

    signIn(username, password)
      .then(function (session) {
        failures = 0;
        setStatus('Signed in. Opening the generators…', 'info');
        return start(session);
      })
      .catch(function (err) {
        setBusy(false);

        if (err && err.fatal) {
          return fail(err.friendly || err.message, { shake: false });
        }

        failures++;
        passEl.value = '';

        /* The one deliberately unhelpful message in the file. A wrong username
           and a wrong password are indistinguishable here, and take the same
           time, so this page cannot be used to discover which accounts
           exist. */
        if (failures >= 5) {
          failures = 0;
          lockOut(30);
          return;
        }

        var left = 5 - failures;
        fail('Username or password is incorrect.' +
             '<span class="hint">Passwords are case-sensitive and include the ' +
             'dashes. ' + left + ' attempt' + (left === 1 ? '' : 's') +
             ' before a short pause.</span>',
             { mark: 'pass', focus: 'pass' });
      });
  });

  async function signIn(username, password) {
    var id;
    try {
      id = await SkyCrypt.slotId(username, config.usernameSalt);
    } catch (e) {
      throw fatal('Could not process the username. Reload the page and try again.');
    }

    var slot = null;
    for (var i = 0; i < keyslots.slots.length; i++) {
      if (keyslots.slots[i].id === id) { slot = keyslots.slots[i]; break; }
    }

    if (!slot) {
      /* No such user — but do the work anyway before failing.
       *
       * Returning immediately would make an unknown username answer in a
       * millisecond while a real one takes the better part of a second. That
       * gap is trivially measurable and would turn this page into a username
       * enumeration oracle. So an unknown username burns the same Argon2id
       * derivation a real one would, against a throwaway salt. */
      try {
        await SkyCrypt.deriveKEK(password, SkyCrypt.randomBytes(16), SkyCrypt.CURRENT_KDF);
      } catch (e) { /* the result is discarded either way */ }
      throw new Error('no such account');
    }

    if (!slot.kdf || slot.kdf.alg !== 'argon2id') {
      throw fatal('This account was created by a newer version of the ' +
                  'application than this page. Redeploy the site.');
    }

    var payload;
    try {
      payload = await SkyCrypt.openKeyslot(slot, password);   // throws on wrong password
    } catch (e) {
      if (e && e.name === 'OperationError') throw new Error('wrong password');
      if (e && /memory|allocat/i.test(e.message || '')) {
        throw fatal('This device ran out of memory while checking the password.' +
                    '<span class="hint">Close some other tabs or applications ' +
                    'and try again.</span>');
      }
      throw new Error('unreadable keyslot');
    }

    if (!payload || !payload.k || !payload.k.v) {
      throw fatal('This account is damaged and cannot be opened. ' +
                  'Ask an administrator to reset your password.');
    }

    return {
      type: 'unlock',
      username: payload.d || payload.u,
      role: payload.r,
      ckViewer: payload.k.v,
      ckAdmin: payload.k.a || null,
      saltViewer: await SkyCrypt.pathSalt(payload.k.v),
      saltAdmin: payload.k.a ? await SkyCrypt.pathSalt(payload.k.a) : null
    };
  }

  function fatal(friendly) {
    var e = new Error(friendly.replace(/<[^>]+>/g, ''));
    e.fatal = true; e.friendly = friendly;
    return e;
  }

  /* ------------------------------------------- hand off to the worker */

  async function start(session) {
    var reg;
    try {
      reg = await navigator.serviceWorker.register('sw.js', { scope: './' });
    } catch (e) {
      throw fatal('The application could not start.' +
                  '<span class="hint">Registering its service worker failed: ' +
                  escapeHtml(e.message) + '. This usually means private ' +
                  'browsing, or a browser setting blocking site data.</span>');
    }

    try {
      await navigator.serviceWorker.ready;
    } catch (e) {
      throw fatal('The application did not finish starting. Reload and try again.');
    }

    /* The worker that will answer fetches is the ACTIVE one. A waiting worker
       takes over only after a navigation, by which point the key would have
       gone to the wrong instance and every page would 401. */
    var target = reg.active || navigator.serviceWorker.controller;
    if (!target) {
      throw fatal('The application did not finish starting. Reload the page and sign in again.');
    }

    try {
      await postToWorker(target, session);
    } catch (e) {
      throw fatal(e.friendly || 'The application did not accept the session. Reload and try again.');
    }

    var next = new URLSearchParams(location.search).get('next');
    /* Only ever navigate inside the application. An attacker-supplied ?next=
       must not be able to bounce a freshly signed-in operator off-site. */
    var dest = (next && /^app\/[A-Za-z0-9._\/-]*$/.test(next) && next.indexOf('..') === -1)
      ? next : 'app/';

    location.replace(dest);
  }

  function postToWorker(worker, message) {
    return new Promise(function (resolve, reject) {
      var channel = new MessageChannel();
      var timer = setTimeout(function () {
        var e = new Error('timeout');
        e.friendly = 'The application stopped responding while signing in.' +
                     '<span class="hint">Reload the page and try again.</span>';
        reject(e);
      }, 15000);

      channel.port1.onmessage = function (ev) {
        clearTimeout(timer);
        if (ev.data && ev.data.ok) resolve();
        else {
          var e = new Error('rejected');
          e.friendly = 'The application rejected the session. Reload and try again.';
          reject(e);
        }
      };

      try {
        worker.postMessage(message, [channel.port2]);
      } catch (e) {
        clearTimeout(timer);
        reject(e);
      }
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  /* --------------------------------------------------------------- start */

  btn.disabled = true;
  window.addEventListener('offline', function () {
    if (!busy) setStatus('This device is offline. Signing in needs a connection ' +
                         'the first time on each device.', 'warn');
  });

  bootstrap();

})();
