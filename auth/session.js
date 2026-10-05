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

    /* On the shared design system (ui.css): custom properties cross into a
       shadow root even past `all:initial`, so the bar takes the page's tokens
       - with the values written out as fallbacks for a page without them. */
    var css = document.createElement('style');
    css.textContent = [
      ':host{all:initial}',
      '*{box-sizing:border-box;font-family:var(--ui-font,"Segoe UI",system-ui,sans-serif);',
      '-webkit-font-smoothing:antialiased}',
      /* Glass, like every floating surface in the product: frosted, with a
         light inner edge and a hairline outside it. */
      '.bar{display:flex;align-items:center;gap:8px;min-width:0;',
      'background:var(--ui-glass-bg,rgba(255,255,255,.9));',
      '-webkit-backdrop-filter:var(--ui-glass-blur,blur(20px));backdrop-filter:var(--ui-glass-blur,blur(20px));',
      'border-radius:999px;padding:6px 6px 6px 16px;',
      'box-shadow:var(--ui-glass-edge,0 0 0 1px rgba(11,29,48,.08)),',
      'var(--ui-shadow-3,0 16px 40px -16px rgba(10,44,77,.3))}',
      '.who{font-size:13px;color:var(--ui-ink-3,#42586e);white-space:nowrap;min-width:0;',
      'max-width:46vw;overflow:hidden;text-overflow:ellipsis}',
      '.who b{color:var(--ui-ink,#0b1d30);font-weight:600}',
      /* A press gives (scale .97, 140ms); hover only where a pointer hovers.
         Buttons never shrink or wrap - on a phone the NAME gives way instead,
         where "Sign out" used to break onto two lines. */
      'button{font:inherit;font-size:13px;font-weight:600;cursor:pointer;flex:none;',
      'white-space:nowrap;border-radius:999px;padding:8px 15px;border:0;color:#fff;',
      'background:var(--ui-gradient,linear-gradient(118deg,#001B48,#02457A 55%,#018ABE 130%));',
      'box-shadow:inset 0 1px 0 rgba(255,255,255,.18),',
      'var(--ui-shadow-press,0 6px 16px -6px rgba(19,80,127,.5));',
      'transition:transform 140ms cubic-bezier(.23,1,.32,1),filter 180ms ease,',
      'background-color 180ms ease}',
      'button:active{transform:scale(.97)}',
      '@media (hover:hover) and (pointer:fine){button:hover{filter:brightness(1.08)}',
      '.home:hover{background:var(--ui-accent-tint,#eef5fb);filter:none}}',
      '.warn{display:none;align-items:center;gap:10px;margin-bottom:9px;',
      'background:var(--ui-warn-tint,#fff8eb);border:1px solid var(--ui-warn-line,#f3d9a4);',
      'border-radius:999px;padding:7px 7px 7px 16px;font-size:13px;color:var(--ui-warn,#8a5206);',
      'box-shadow:var(--ui-shadow-2,0 10px 28px -14px rgba(10,44,77,.2))}',
      '.warn.on{display:flex}',
      '.warn button{background:#fff;color:var(--ui-warn,#8a5206);',
      'border:1px solid var(--ui-warn-line,#f3d9a4);box-shadow:none}',
      /* Home is secondary: white with navy ink, so it can never be mistaken for
         Sign out, which ends the session and is the one that must stand out. */
      '.home{background:rgba(255,255,255,.85);color:var(--ui-navy,#001B48);',
      'border:1px solid var(--ui-line-2,rgba(11,29,48,.16));box-shadow:none;',
      'display:inline-flex;align-items:center;gap:6px;padding:7px 13px 7px 11px}',
      '.home svg{width:15px;height:15px}',
      /* A phone: Home keeps its icon and drops its word, the name truncates. */
      '@media (max-width:520px){.home span{display:none}.home{padding:7px 9px}',
      '.bar{padding-left:13px}.who{max-width:38vw}}',
      '@media (prefers-reduced-motion:reduce){button:active{transform:none}}'
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

    /* HOME - back to the landing page, where the generator and the validator
       are chosen. It lives in this bar because the bar is on EVERY page: the
       thirty generators, the portal and the validator alike. Putting it in each
       page's own header would have meant editing the validator's code, which is
       merged as-is, and the statutory generator pages, which are kept
       byte-identical. Hidden on the landing page itself, where it would lead
       nowhere. */
    var onHome = /\/app\/home\/?(index\.html)?$/.test(location.pathname);
    if (!onHome) {
      var home = document.createElement('button');
      home.type = 'button';
      home.className = 'home';
      home.setAttribute('aria-label', 'Home - choose the generator or the validator');
      home.title = 'Home - switch between the generator and the validator';
      home.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M3 11.5 12 4l9 7.5"></path><path d="M5.5 10v9.5h13V10"></path></svg>' +
        '<span>Home</span>';
      home.onclick = function () { location.href = root + 'app/home/'; };
      bar.appendChild(home);
    }

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

  /* ------------------------------------------------ the room the bar takes
   *
   * The bar is fixed to the bottom-right corner, so on a page scrolled to its
   * end it sits over the last lines of that page's footer. Footers used to
   * guess how much room to leave with a fixed number - and the bar is 64px
   * tall on a desktop but 80px on a phone, where it wraps onto two rows. The
   * guesses were wrong: measured, the portal hid a footer line under the bar at
   * every desktop width, and release notes hid five lines on a phone.
   *
   * So the bar says how much room it takes, as --sky-bar-space on <html>: the
   * distance from the bottom of the window to its top edge, plus a small gap.
   * A footer reserves exactly that with padding-bottom: var(--sky-bar-space).
   *
   * A variable changes nothing on its own - only a page that asks for it is
   * affected - which keeps this file out of the pages' layout, as the note at
   * the top of the file requires. It stays current as the bar changes size:
   * when it wraps on a narrow window, and when the inactivity warning opens
   * above it. */
  function publishSpace() {
    if (!host) return;
    var r = host.getBoundingClientRect();
    if (!r.height) return;
    var space = Math.ceil(window.innerHeight - r.top) + 10;
    document.documentElement.style.setProperty('--sky-bar-space', space + 'px');
  }

  /* ------------------------------------------- the height of the page header
   *
   * The same idea, for the top of the page. A generator's header is sticky,
   * and its label preview column is sticky BENEATH it - at a fixed 98px, set
   * when the header was one row. The header has since grown a second row (the
   * label tabs), so the column slid under it by 30px and more, and by more
   * again in Chinese, where the title and sub-line run longer.
   *
   * So the header's real height is published as --sky-header-h, and the
   * column sits at that plus a gap. Like --sky-bar-space it changes nothing
   * by itself; palette.css asks for it, with a fallback for the pages opened
   * from disk, where this file does not run. */
  var pageHeader = null;
  function publishHeader() {
    if (!pageHeader) return;
    var h = Math.ceil(pageHeader.getBoundingClientRect().height);
    if (h) document.documentElement.style.setProperty('--sky-header-h', h + 'px');
  }

  /* ----------------------------------------------------------- integrity
   *
   * A TRIPWIRE, NOT A WALL. Anyone can change what runs in their own browser;
   * no page can prevent that. What this catches is the obvious route to an
   * unapproved label: opening the console and replacing the function that
   * checks the approval before a file is made.
   *
   * The functions that matter are captured the moment this script runs, and
   * compared by IDENTITY - the same function object, not the same text:
   *   download()        the generator's own gate, called by every Download
   *                     button, and a plain global, so it CAN be replaced
   *   Approval          frozen and non-writable already; watched anyway, so a
   *                     future change that loosened it would still be caught
   * If either is no longer the original, the session ends.
   *
   * It is checked on EVERY click, in the capture phase at window level, so it
   * runs before any button's own handler - replace the gate and then press
   * Download, and the press never arrives. And every two seconds regardless,
   * so a replacement is caught even if nothing is pressed.
   *
   * Only what exists is watched. The validator, the portal and the landing page
   * have neither function, so on those pages this does nothing at all - and
   * cannot sign anyone out by mistake. No page reassigns download() itself
   * (checked across all thirty), so an honest session never trips it.
   *
   * What it does NOT stop, stated plainly: someone who writes fresh code that
   * never touches these functions, or who blocks this script from loading.
   * The real control is the signed approval, which an edited page cannot
   * forge. This raises the cost of the easy attempt; it is not a guarantee. */
  var watched = null;

  function snapshot() {
    var w = {};
    if (typeof window.download === 'function') w.download = window.download;
    var A = window.Approval;
    if (A) { w.Approval = A; w.ok = A.ok; w.gate = A.gate; }
    return Object.keys(w).length ? w : null;
  }

  function tampered() {
    if (!watched) return '';
    if (watched.download && window.download !== watched.download) return 'download';
    if (watched.Approval) {
      var A = window.Approval;
      if (A !== watched.Approval || !A || A.ok !== watched.ok || A.gate !== watched.gate) {
        return 'approval';
      }
    }
    return '';
  }

  function guard(ev) {
    if (ended || !tampered()) return;
    if (ev) { ev.preventDefault(); ev.stopImmediatePropagation(); }
    signOut('tampered');
  }

  /* ------------------------------------------------------------------ boot */

  async function boot() {
    /* Before anything is awaited, so the window in which the page could be
       changed before its originals are recorded is as small as it can be. */
    watched = snapshot();

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

    /* The label has its text now, so the bar has its real size. */
    publishSpace();
    window.addEventListener('resize', publishSpace);
    if (typeof ResizeObserver === 'function') new ResizeObserver(publishSpace).observe(host);

    pageHeader = document.querySelector('body > header:not(.hero)');
    if (pageHeader) {
      publishHeader();
      if (typeof ResizeObserver === 'function') new ResizeObserver(publishHeader).observe(pageHeader);
    }

    ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function (ev) {
      window.addEventListener(ev, bump, { passive: true });
    });

    if (watched) {
      window.addEventListener('click', guard, true);   // capture: before any button
      setInterval(guard, 2000);
    }

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
