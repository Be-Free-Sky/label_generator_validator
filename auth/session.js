/* session.js — sign out, idle lock, and revocation, for the generator pages.
 *
 * INJECTED, NOT INCLUDED.
 *
 * The 30 generator pages are stored encrypted and are byte-identical to the
 * files in docs/ - that is deliberate, and it is why the canvas that draws a
 * statutory label is the same canvas it has always been. So none of them
 * carries a <script> tag for this. The service worker adds one to each HTML
 * document as it decrypts it, which changes what the browser receives without
 * changing anything on disk or in the repository.
 *
 * Everything this file adds lives in a shadow root, so no page's own CSS can
 * reach it and, more importantly, nothing here can reach a page's own layout.
 * A stray rule from this file landing on a label canvas would be exactly the
 * class of accident the byte-identical rule exists to prevent.
 *
 *
 * WHAT IT DOES
 * ------------
 *   1. a Sign out control, which the application otherwise had no way to offer
 *   2. an idle lock at 20 minutes, with a warning first
 *   3. a revocation check: if the account is removed - or its password reset -
 *      on the published site, this tab signs itself out within the minute
 *
 * (3) is the one worth explaining. Removing somebody in Access Control and
 * publishing takes their password out of the account file, so they cannot sign
 * in AGAIN - but a browser they were already signed into holds the content key
 * and would carry on working until the session expired. This closes that: the
 * page asks the published file whether its own account is still there, and
 * signs out if it is not.
 *
 * It is a courtesy, not a containment boundary. Somebody who has decided to
 * keep working can disable JavaScript or hold the decrypted page. Real
 * revocation is --rekey, which changes the content keys and makes every copy
 * they hold worthless. This handles the ordinary case: a person leaves, and
 * the tab they left open stops working.
 */

'use strict';

(function () {

  var IDLE_MS    = 20 * 60 * 1000;
  var WARN_MS    = 2 * 60 * 1000;     // warn this long before locking
  var CHECK_MS   = 60 * 1000;         // how often to ask if we still exist
  var TICK_MS    = 15 * 1000;

  var root  = location.pathname.replace(/app\/.*$/, '');
  var me    = null;                   // {username, role, slotId, slotC}
  var last  = Date.now();
  var ended = false;

  /* ------------------------------------------------------- talk to the SW */

  function ask(type) {
    if (!navigator.serviceWorker || !navigator.serviceWorker.controller) {
      return Promise.reject(new Error('no controller'));
    }
    return new Promise(function (resolve, reject) {
      var ch = new MessageChannel();
      var t = setTimeout(function () { reject(new Error('timeout')); }, 6000);
      ch.port1.onmessage = function (e) { clearTimeout(t); resolve(e.data); };
      navigator.serviceWorker.controller.postMessage({ type: type }, [ch.port2]);
    });
  }

  function signOut(reason) {
    if (ended) return;
    ended = true;
    ask('logout').catch(function () {}).then(function () {
      location.replace(root + 'index.html' + (reason ? '?signedout=' + reason : ''));
    });
  }

  /* ------------------------------------------------------------- the pill */

  var host, shadow, label, warnEl;

  function mount() {
    host = document.createElement('div');
    host.id = '__sky_session';
    host.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483000';
    /* Closed shadow root: the generator pages cannot style into it and it
       cannot style out. */
    shadow = host.attachShadow({ mode: 'closed' });

    var css = document.createElement('style');
    css.textContent = [
      ':host{all:initial}',
      '*{box-sizing:border-box;font-family:Aptos,"Segoe UI",system-ui,sans-serif}',
      '.bar{display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.96);',
      'border:1px solid #d7e3f2;border-radius:99px;padding:7px 8px 7px 15px;',
      'box-shadow:0 4px 18px rgba(11,27,58,.16);backdrop-filter:blur(10px)}',
      '.who{font-size:13px;color:#3d5a76;white-space:nowrap;max-width:46vw;',
      'overflow:hidden;text-overflow:ellipsis}',
      '.who b{color:#08203a;font-weight:700}',
      'button{font:inherit;font-size:12.5px;font-weight:700;cursor:pointer;',
      'border-radius:99px;padding:8px 15px;border:0;color:#fff;',
      'background:linear-gradient(135deg,#155e87,#0a2c4d);',
      'box-shadow:0 2px 8px rgba(10,44,77,.28)}',
      'button:hover{filter:brightness(1.12)}',
      '.warn{display:none;align-items:center;gap:10px;margin-bottom:9px;',
      'background:#fffbeb;border:1px solid #fde68a;border-radius:99px;',
      'padding:9px 10px 9px 16px;font-size:12.5px;color:#8a5209;',
      'box-shadow:0 4px 18px rgba(11,27,58,.14)}',
      '.warn.on{display:flex}',
      '.warn button{background:#fff;color:#8a5209;border:1px solid #fde68a;',
      'box-shadow:none;font-weight:700}'
    ].join('');

    var wrap = document.createElement('div');

    warnEl = document.createElement('div');
    warnEl.className = 'warn';
    var wtxt = document.createElement('span');
    wtxt.textContent = 'Signing out shortly through inactivity.';
    var stay = document.createElement('button');
    stay.type = 'button';
    stay.textContent = 'Stay signed in';
    stay.onclick = function () { last = Date.now(); warnEl.classList.remove('on'); };
    warnEl.appendChild(wtxt); warnEl.appendChild(stay);

    var bar = document.createElement('div');
    bar.className = 'bar';
    label = document.createElement('span');
    label.className = 'who';
    var out = document.createElement('button');
    out.type = 'button';
    out.textContent = 'Sign out';
    out.onclick = function () { signOut('manual'); };
    bar.appendChild(label); bar.appendChild(out);

    wrap.appendChild(warnEl); wrap.appendChild(bar);
    shadow.appendChild(css); shadow.appendChild(wrap);
    document.body.appendChild(host);
  }

  /* ------------------------------------------------------------ the checks */

  /* Has this account been removed, or its password reset, on the published
   * site? Compared by ciphertext rather than by id: a reset keeps the username
   * and therefore the slot id, and only the encrypted blob changes. */
  async function stillValid() {
    if (!me || !me.slotId) return true;
    var res;
    try {
      res = await fetch(root + 'keyslots.json?t=' + Date.now(), { cache: 'no-store' });
    } catch (e) {
      return true;              // offline is not revoked; say nothing
    }
    if (!res.ok) return true;
    var v;
    try { v = await res.json(); } catch (e) { return true; }
    if (!v || !Array.isArray(v.slots)) return true;

    for (var i = 0; i < v.slots.length; i++) {
      if (v.slots[i].id === me.slotId) {
        return !me.slotC || v.slots[i].c === me.slotC;
      }
    }
    return false;               // gone from the published file
  }

  function bump() { last = Date.now(); if (warnEl) warnEl.classList.remove('on'); }

  /* ------------------------------------------------------------------ boot */

  async function boot() {
    try {
      var who = await ask('whoami');
      if (!who || !who.ok) return;        // not signed in; the SW will redirect
      me = who;
    } catch (e) {
      return;                              // no controller yet; nothing to show
    }

    mount();
    label.innerHTML = '';
    label.appendChild(document.createTextNode('Signed in as '));
    var b = document.createElement('b');
    b.textContent = me.username || 'operator';
    label.appendChild(b);
    if (me.role) {
      label.appendChild(document.createTextNode(' · ' + me.role));
    }

    ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function (ev) {
      window.addEventListener(ev, bump, { passive: true });
    });

    var lastCheck = 0;
    setInterval(async function () {
      if (ended) return;

      var idle = Date.now() - last;
      if (idle > IDLE_MS) return signOut('idle');
      warnEl.classList.toggle('on', idle > IDLE_MS - WARN_MS);

      if (Date.now() - lastCheck >= CHECK_MS) {
        lastCheck = Date.now();
        var ok = await stillValid();
        if (!ok) return signOut('revoked');
      }
    }, TICK_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
