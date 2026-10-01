/* guard.js — the brand, sealed. The SKYWORTH wordmark, the product name and
 * the credits cannot be changed, hidden or covered in the browser.
 *
 * LOADED WITHOUT CHANGING ANY PAGE. The sign-in page names it in a <script>
 * tag. Every page the service worker decrypts has it added beside session.js,
 * by the same route and for the same reason: the thirty generator pages stay
 * byte-identical to their files.
 *
 *
 * WHAT IT WATCHES
 * ---------------
 * The parts of a page that say whose it is:
 *   - the SKYWORTH 创维 wordmark, wherever it is drawn
 *   - the product name: each page's heading and header title
 *   - the credits in the footer, on every page that has them
 *   - the title in the browser tab
 *
 *
 * HOW
 * ---
 *   1. CHANGED. Once the page has settled, those parts are recorded - every
 *      tag, attribute and character - and a MutationObserver compares them
 *      again whenever anything touches them. Retyping the heading in the
 *      Elements panel, deleting the footer, editing the logo: the page locks
 *      at once.
 *   2. HIDDEN. A rule added in the Styles panel changes no markup, so the
 *      screen is checked too, every 1.5 s: the wordmark, the name and the
 *      credits must be displayed, full-size, in a colour that can be seen,
 *      with nothing added before or after them and nothing over them but the
 *      page's own headers, dialogs and toasts and the sign-out bar. A fault
 *      must be seen three checks running, so a toast passing over the footer,
 *      or an animation, cannot trip it.
 *
 * THE LANGUAGE SWITCH IS NOT TAMPERING. Choosing 中文 rewrites the product
 * name in several of these parts, and version.js rewrites more in reply.
 * Every one of those writes arrives together with a change to <html lang>,
 * which no DevTools edit does - one edit is one change. So a change that
 * comes with a new language, or follows one within moments, becomes the new
 * record. And what must never change in EITHER language - the wordmark reads
 * SKYWORTH 创维, the credits name Rahul Kumbhar and Skyworth Group - is
 * checked against fixed text, whatever the record says.
 *
 *
 * WHAT HAPPENS
 * ------------
 * The page is replaced by a notice saying what was found, and the session is
 * ended: carrying on means signing in again, to the page as published.
 *
 * A TRIPWIRE, NOT A WALL - as session.js says of its own check. Code typed
 * into the console can do anything this file can, including stop it. What
 * this ends is the easy way: right-click, Inspect, retype.
 */

'use strict';

(function () {

  var PRODUCT = 'Skyworth Label Generator & Validator';
  var EVERY_MS = 1500;
  var SETTLE_MS = 1500;     // after load, before the record is taken
  var GRACE_MS = 400;       // after a language switch, its echoes are still its
  var STRIKES = 3;          // checks running before something hidden counts

  /* The parts that say whose page this is. Each page has some of them. */
  var PARTS = [
    'svg[aria-label^="SKYWORTH"]',     // the wordmark, wherever it is drawn
    'header .h-lock',                  // a generator: wordmark, build, label
    '.topbar .brand', '.hero-title',   // the validator
    '.top .brand', '.hero h1',         // the portal; the release notes
    'main.wrap > h1',                  // the landing page
    '.intro h1', '.brandfoot',         // the sign-in page
    'body > footer'                    // the credits
  ].join(', ');

  var MARKS = 'svg[aria-label^="SKYWORTH"]';
  var NAMES = '.h-title, .brand-name, .hero-title, .hero h1, main.wrap > h1, .intro h1';
  var CREDITS = 'body > footer:not(.brandfoot)';

  /* What may legitimately pass over them. The page's own sticky headers, as
     the page scrolls under them, are taken as they stand when the record is
     made; the rest can appear at any time. */
  var HEADERS = 'header, .top, .topbar';
  var OVERLAYS = '#__sky_session, dialog, [role="dialog"], [aria-modal="true"], .lb, #toast, .skip-link';

  var WHY = {
    brand:  'The SKYWORTH logo, the product name or the credits were changed.',
    title:  'The title in the browser tab was changed.',
    hidden: 'The SKYWORTH logo, the product name or the credits were hidden, shrunk or covered.'
  };

  var path = location.pathname;
  var root = path.indexOf('/app/') >= 0 ? path.replace(/app\/.*$/, '') : path.replace(/[^/]*$/, '');
  var signedIn = path.indexOf('/app/') >= 0;

  var rec = null;           // {shot, title, looks, headers, hiders}
  var locked = false, pending = false, sawLang = false;
  var langAt = 0, resizedAt = 0, strikes = 0, printing = false;
  var mo = null, timer = 0;

  /* ------------------------------------------------------------ the record */

  /* A part as text: every tag, every attribute in a fixed order, every
     character. Two parts are the same exactly when their records are. */
  function canon(n, out) {
    if (n.nodeType === 3) { out.push(JSON.stringify(n.nodeValue)); return out; }
    if (n.nodeType !== 1) return out;
    var a = [];
    for (var i = 0; i < n.attributes.length; i++) {
      a.push(n.attributes[i].name + '=' + JSON.stringify(n.attributes[i].value));
    }
    out.push('<' + n.tagName + (a.length ? ' ' + a.sort().join(' ') : '') + '>');
    for (var c = n.firstChild; c; c = c.nextSibling) canon(c, out);
    out.push('</' + n.tagName + '>');
    return out;
  }

  function shot() {
    var s = [], list = document.querySelectorAll(PARTS);
    for (var i = 0; i < list.length; i++) s.push(canon(list[i], []).join(''));
    return s.join('\n');
  }

  /* Every element inside the parts, with what is drawn before and after it.
     A rule like `h1::after { content: "..." }` adds words without adding
     markup, so it is caught here rather than by the record above. */
  function looks() {
    var out = [], list = document.querySelectorAll(PARTS);
    for (var i = 0; i < list.length; i++) {
      var els = [list[i]].concat(Array.prototype.slice.call(list[i].querySelectorAll('*')));
      for (var j = 0; j < els.length; j++) {
        out.push(getComputedStyle(els[j], '::before').content + '|' +
                 getComputedStyle(els[j], '::after').content);
      }
    }
    return out.join('\n');
  }

  /* The page's own rules that take something off the screen, with the media
     queries they sit in, as they stand before anyone has had a chance to edit
     them. See `undrawn` below for why. Taken once, at the start, and never
     again: a language switch must not be a way to have a new rule adopted. */
  function hidingRules() {
    var out = [];
    /* A style rule is checked BEFORE looking for rules inside it: with CSS
       nesting, every style rule carries a cssRules list of its own, so asking
       "is this a group?" first would pass over every rule there is. */
    var walk = function (rules, media) {
      for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        if (r.selectorText && r.style && r.style.display === 'none') {
          out.push({ rule: r, text: r.cssText, media: media });
        }
        var inner = r.styleSheet ? r.styleSheet.cssRules : r.cssRules;   // @import, or a group
        if (inner && inner.length) walk(inner, r.media && r.media.mediaText ? media.concat(r.media.mediaText) : media);
      }
    };
    for (var s = 0; s < document.styleSheets.length; s++) {
      try { walk(document.styleSheets[s].cssRules, []); } catch (e) { /* not readable */ }
    }
    return out;
  }

  function take() {
    rec = { shot: shot(), title: document.title, looks: looks(),
            headers: Array.prototype.slice.call(document.querySelectorAll(HEADERS)),
            hiders: rec ? rec.hiders : hidingRules() };
  }

  /* True in either language, whatever the record says. */
  function fixedFault() {
    var marks = document.querySelectorAll(MARKS);
    for (var i = 0; i < marks.length; i++) {
      var words = Array.prototype.map.call(marks[i].querySelectorAll('text'), function (t) { return t.textContent; });
      if (words.join('').replace(/\s+/g, '') !== 'SKYWORTH创维') return 'brand';
    }
    var feet = document.querySelectorAll(CREDITS);
    for (var j = 0; j < feet.length; j++) {
      var t = feet[j].textContent.replace(/\s+/g, ' ');
      if (t.indexOf('Rahul Kumbhar') < 0 || t.indexOf('trademarks of Skyworth Group') < 0) return 'brand';
    }
    return '';
  }

  function changedFault() {
    if (shot() !== rec.shot) return 'brand';
    if (document.title !== rec.title) return 'title';
    return fixedFault();
  }

  /* ------------------------------------------------------- on the screen */

  /* Every check below answers with WHAT it found, or '' for nothing: the
     notice carries it in data-detail, so a lock can be explained after the
     event rather than guessed at. */

  function name(e) {
    if (!e || e.nodeType !== 1) return String(e);
    var c = (e.getAttribute('class') || '').trim().split(/\s+/)[0];
    return e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (c ? '.' + c : '');
  }

  function alpha(c) {
    if (!c || c === 'transparent' || c === 'none') return 0;
    var m = /rgba?\(([^)]*)\)/.exec(c);
    if (!m) return 1;                       // a named colour, or a paint server
    var v = m[1].split(/[\s,/]+/).filter(Boolean);
    if (v.length < 4) return 1;
    var a = parseFloat(v[3]);
    return /%/.test(v[3]) ? a / 100 : a;
  }

  function filterHides(f) {
    if (!f || f === 'none') return false;
    if (/url\(/.test(f)) return true;
    var m, re = /(opacity|blur|brightness|contrast|invert)\(([^)]*)\)/g;
    while ((m = re.exec(f))) {
      var v = parseFloat(m[2]);
      if (/%/.test(m[2])) v /= 100;
      if (m[1] === 'opacity' && v < 0.5) return true;
      if (m[1] === 'blur' && v > 1.5) return true;
      if (m[1] === 'brightness' && (v < 0.4 || v > 2.5)) return true;
      if (m[1] === 'contrast' && v < 0.4) return true;
      if (m[1] === 'invert' && v > 0.3) return true;
    }
    return false;
  }

  /* Faded, filtered, clipped or skipped - by the element or anything above it. */
  function chainHides(el) {
    var op = 1;
    for (var e = el; e && e.nodeType === 1; e = e.parentElement) {
      var s = getComputedStyle(e);
      op *= parseFloat(s.opacity);
      if (filterHides(s.filter)) return 'filter ' + s.filter + ' on ' + name(e);
      if (s.clipPath !== 'none') return 'clip-path on ' + name(e);
      if (s.mixBlendMode !== 'normal') return 'blend mode on ' + name(e);
      if (s.contentVisibility === 'hidden') return 'content-visibility on ' + name(e);
    }
    if (op < 0.5) return 'opacity ' + op.toFixed(2);
    return getComputedStyle(el).visibility !== 'visible' ? 'visibility' : '';
  }

  /* Gradient lettering paints its text transparent and lets a background,
     clipped to the letters, show through. That is the house style for the
     headings, so a transparent fill is only a fault where nothing paints it. */
  function painted(el, upTo) {
    for (var e = el; e && e.nodeType === 1; e = e.parentElement) {
      var s = getComputedStyle(e);
      if ((s.backgroundClip === 'text' || s.webkitBackgroundClip === 'text') &&
          s.backgroundImage !== 'none') return true;
      if (e === upTo) break;
    }
    return false;
  }

  function rectOf(n) {
    var r = document.createRange();
    r.selectNodeContents(n);
    return r.getBoundingClientRect();
  }

  /* Everything an element says must be drawn: in a readable size, in a
     colour that shows, with a box to be drawn in. */
  function textHides(el) {
    var w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT), n, seen = 0;
    while ((n = w.nextNode())) {
      if (!n.nodeValue.trim()) continue;
      var p = n.parentElement, s = getComputedStyle(p);
      if (parseFloat(s.fontSize) < 9) return 'font-size ' + s.fontSize;
      if (s.visibility !== 'visible') return 'visibility ' + s.visibility;
      if (alpha(s.webkitTextFillColor || s.color) < 0.5 && !painted(p, el)) {
        return 'colour ' + (s.webkitTextFillColor || s.color);
      }
      var r = rectOf(n);
      if (r.width < 2 || r.height < 6) return 'text box ' + Math.round(r.width) + 'x' + Math.round(r.height);
      seen++;
    }
    return seen ? chainHides(el) : 'no text';
  }

  /* The wordmark: a full-size logo with both of its words drawn inside it. */
  function markHides(svg) {
    var r = svg.getBoundingClientRect();
    if (r.width < 48 || r.height < 7) return 'size ' + Math.round(r.width) + 'x' + Math.round(r.height);
    var texts = svg.querySelectorAll('text');
    if (texts.length !== 2) return texts.length + ' words';
    for (var i = 0; i < texts.length; i++) {
      var s = getComputedStyle(texts[i]), t = texts[i].getBoundingClientRect();
      if (s.display === 'none' || s.visibility !== 'visible') return 'word ' + (i + 1) + ' not shown';
      if (alpha(s.fill) < 0.5) return 'word ' + (i + 1) + ' fill ' + s.fill;
      if (t.width < r.width * 0.12 || t.height < r.height * 0.3) return 'word ' + (i + 1) + ' shrunk';
      if (t.left < r.left - 4 || t.right > r.right + 4 || t.top < r.top - 4 || t.bottom > r.bottom + 4) {
        return 'word ' + (i + 1) + ' moved';
      }
    }
    return chainHides(svg);
  }

  /* Is anything drawn over this point that is not the page's own? */
  function coveredAt(x, y, el) {
    if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return '';   // off screen
    var hit = document.elementFromPoint(x, y);
    if (!hit || el.contains(hit) || hit.contains(el)) return '';
    var part = el.closest(PARTS);
    if (part && part.contains(hit)) return '';
    if (hit.closest(OVERLAYS)) return '';
    for (var i = 0; i < rec.headers.length; i++) if (rec.headers[i].contains(hit)) return '';
    return 'covered by ' + name(hit);
  }

  function coveredText(el) {
    var w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT), n;
    while ((n = w.nextNode())) {
      if (!n.nodeValue.trim()) continue;
      var r = rectOf(n);
      return coveredAt(r.left + Math.min(r.width / 2, 24), r.top + r.height / 2, el);
    }
    return '';
  }

  function creditLines() {
    var out = [], feet = document.querySelectorAll(CREDITS);
    for (var i = 0; i < feet.length; i++) {
      var w = document.createTreeWalker(feet[i], NodeFilter.SHOW_TEXT), n;
      while ((n = w.nextNode())) {
        if (n.nodeValue.trim() && out.indexOf(n.parentElement) < 0) out.push(n.parentElement);
      }
    }
    return out;
  }

  /* Everything that has to stay on screen. */
  function keys() {
    return Array.prototype.slice.call(document.querySelectorAll(MARKS))
      .concat(Array.prototype.slice.call(document.querySelectorAll(NAMES)), creditLines());
  }

  /* An element with no box at all - display:none on it or above it. The page
     does this itself, on purpose: a generator drops the wordmark below 560px
     so the label's name keeps its line, and the validator takes its big
     heading away once results are on screen. Both are rules in the page's own
     stylesheets. So an element that has gone is the page's doing when one of
     the rules recorded at the start - unedited, its media query in force -
     hides it now. A rule added in the Styles panel is not on that list, and
     an existing rule edited to hide something no longer reads as recorded. */
  function pageHid(a) {
    for (var i = 0; i < rec.hiders.length; i++) {
      var h = rec.hiders[i];
      if (h.rule.cssText !== h.text) continue;
      if (!h.media.every(function (m) { return matchMedia(m).matches; })) continue;
      try { if (a.matches(h.rule.selectorText)) return true; } catch (e) { /* a selector this browser cannot test */ }
    }
    return false;
  }

  /* '' if it has a box; 'gone' if the page took it away; otherwise a fault. */
  function undrawn(e) {
    if (e.getClientRects().length) return '';
    for (var a = e; a && a.nodeType === 1; a = a.parentElement) {
      if (getComputedStyle(a).display === 'none') return pageHid(a) ? 'gone' : 'display:none on ' + name(a);
    }
    return 'no box';
  }

  function hiddenFault() {
    if (looks() !== rec.looks) return 'something drawn before or after it';
    var k = keys();
    for (var i = 0; i < k.length; i++) {
      var u = undrawn(k[i]), f;
      if (u === 'gone') continue;
      if (u) return name(k[i]) + ': ' + u;
      if (k[i].tagName.toLowerCase() === 'svg') {
        var r = k[i].getBoundingClientRect();
        f = markHides(k[i]) || coveredAt(r.left + r.width / 2, r.top + r.height / 2, k[i]);
      } else {
        f = textHides(k[i]) || coveredText(k[i]);
      }
      if (f) return name(k[i]) + ': ' + f;
    }
    return '';
  }

  /* ------------------------------------------------------------- watching */

  function touches(r) {
    if (r.type === 'attributes' && r.target === document.documentElement && r.attributeName === 'lang') {
      sawLang = true;
      langAt = Date.now();
      return true;
    }
    var t = r.target.nodeType === 1 ? r.target : r.target.parentElement;
    if (t && (t.closest(PARTS) || t.closest('title'))) return true;
    var moved = function (n) {
      return n.nodeType === 1 && (n.matches(PARTS) || n.matches('title') || !!n.querySelector(PARTS));
    };
    return Array.prototype.some.call(r.addedNodes, moved) ||
           Array.prototype.some.call(r.removedNodes, moved);
  }

  function settled() {
    pending = false;
    if (locked) return;
    if (sawLang || Date.now() - langAt < GRACE_MS) {
      sawLang = false;
      var f = fixedFault();          // a new language may change the name, never these
      if (f) return lock(f);
      take();
      strikes = 0;
      return;
    }
    var why = changedFault();
    if (why) lock(why);
  }

  function check() {
    if (locked || pending) return;
    var why = changedFault();
    if (why) {
      if (Date.now() - langAt < GRACE_MS && !fixedFault()) { take(); return; }
      return lock(why);
    }
    /* The screen is only judged while it is a screen: not printing (print
       styles hide headers on purpose), not in a background tab, not in the
       moment a resize is still laying out. */
    if (document.hidden || printing || document.fullscreenElement ||
        Date.now() - resizedAt < 1000) { strikes = 0; return; }
    var seen = hiddenFault();
    if (seen) {
      if (++strikes >= STRIKES) lock('hidden', seen);
    } else {
      strikes = 0;
    }
  }

  function start() {
    if (locked) return;
    take();
    var f = fixedFault();
    if (f) return lock(f);

    mo = new MutationObserver(function (recs) {
      var any = false;
      for (var i = 0; i < recs.length; i++) if (touches(recs[i])) any = true;
      if (!any || pending) return;
      pending = true;
      setTimeout(settled, 0);        // after the page's own replies have run
    });
    mo.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });

    timer = setInterval(check, EVERY_MS);
    window.addEventListener('resize', function () { resizedAt = Date.now(); strikes = 0; });
    window.addEventListener('beforeprint', function () { printing = true; });
    window.addEventListener('afterprint', function () { printing = false; strikes = 0; });

    console.log('%c' + PRODUCT + '%c\nThis page is sealed. Changing, hiding or covering the SKYWORTH name, ' +
      'the logo, the product name or the credits locks it and ends the session.\n' +
      'Copyright © Rahul Kumbhar. SKYWORTH, 创维 and the SKYWORTH logo are trademarks of Skyworth Group.',
      'font:800 15px system-ui,sans-serif;color:#155e87', 'font:13px system-ui,sans-serif;color:#123a5c');
  }

  /* ------------------------------------------------------------- the lock */

  function endSession() {
    try {
      var c = navigator.serviceWorker && navigator.serviceWorker.controller;
      if (c) c.postMessage({ type: 'logout' }, [new MessageChannel().port2]);
    } catch (e) { /* nothing to end */ }
  }

  function el(tag, css, text) {
    var e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (text) e.textContent = text;
    return e;
  }

  /* The page is replaced by a notice. Its styles are inline: the page's own
     stylesheets are what may have been tampered with, so they go. A new
     <body>, not a cleared one, so nothing still observing the old one - the
     language switcher, for one - can reach in and rewrite the notice. */
  function lock(why, detail) {
    if (locked) return;
    locked = true;
    if (mo) mo.disconnect();
    clearInterval(timer);
    if (signedIn) endSession();

    document.querySelectorAll('style, link[rel~="stylesheet"]').forEach(function (n) { n.remove(); });

    var font = "font-family:Aptos,'Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;";
    var body = el('body', 'margin:0;padding:0 16px;background:#f3f7fd;' + font);
    var card = el('div', 'box-sizing:border-box;max-width:660px;margin:12vh auto;padding:28px 30px;' +
      'border:1px solid #cbd9ea;border-radius:18px;background:#fff;color:#08203a;font-size:15.5px;' +
      'line-height:1.6;box-shadow:0 20px 50px -24px rgba(10,44,77,.35)');
    card.id = 'sky-lock';
    card.setAttribute('role', 'alert');

    card.appendChild(el('div', 'font-weight:800;font-size:13px;letter-spacing:.16em;color:#155e87', 'SKYWORTH 创维'));
    card.appendChild(el('h1', 'margin:10px 0;font-size:23px;line-height:1.3',
      'This copy of ' + PRODUCT + ' has been altered'));
    card.appendChild(el('p', 'margin:0 0 12px',
      'It only runs as published. The SKYWORTH name and logo, the product name and the credits are part ' +
      'of every page, and they cannot be changed, hidden or covered in the browser.'));

    var found = el('p', 'margin:0 0 12px;color:#123a5c');
    found.appendChild(el('b', 'color:#08203a', 'Found: '));
    var reason = el('span', '', WHY[why] || why);
    reason.id = 'sky-lock-why';
    reason.setAttribute('data-why', why);
    if (detail) reason.setAttribute('data-detail', detail);
    found.appendChild(reason);
    card.appendChild(found);

    card.appendChild(el('p', 'margin:0 0 18px', signedIn
      ? 'You have been signed out. Sign in again to carry on, with the page as it was published.'
      : 'Reload the sign-in page to carry on, as it was published.'));

    var go = el('a', 'display:inline-block;padding:11px 20px;border-radius:10px;color:#fff;font-weight:700;' +
      'text-decoration:none;background:linear-gradient(135deg,#155e87,#0a2c4d)',
      signedIn ? 'Sign in again' : 'Reload the sign-in page');
    go.href = root + 'index.html' + (signedIn ? '?signedout=tampered' : '');
    card.appendChild(go);

    card.appendChild(el('p', 'margin:22px 0 0;padding-top:14px;border-top:1px solid #e3ebf6;' +
      'font-size:13px;color:#3d5a76',
      'Copyright © 2026 Rahul Kumbhar. All rights reserved. Skyworth Label Generator and ' +
      'Validator™ by Rahul Kumbhar. SKYWORTH, 创维 and the SKYWORTH logo are trademarks of ' +
      'Skyworth Group.'));

    body.appendChild(card);
    document.documentElement.replaceChild(body, document.body);
    document.title = 'Altered copy · ' + PRODUCT;
  }

  /* --------------------------------------------------------------- start */

  /* After the page has loaded and settled: the language it was left in has
     been applied, the version stamped, the validator's own start-up done. */
  function whenSettled() { setTimeout(start, SETTLE_MS); }
  if (document.readyState === 'complete') whenSettled();
  else window.addEventListener('load', whenSettled, { once: true });

})();
