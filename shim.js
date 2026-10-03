/*
 * SwiftProxy — client runtime shim.
 * Injected as the FIRST script of every proxied HTML page (inlined by PHP).
 * Static HTML is rewritten on the server; this file handles everything that
 * JavaScript on the page creates at runtime: fetch / XHR, lazy-loaded images,
 * innerHTML templates, window.open, history.pushState and document.cookie.
 * Expects window.__SP = { base: "<real page URL>", entry: "/path/proxy.php" }.
 */
(function () {
  'use strict';
  var SP = window.__SP;
  if (!SP || window.__spInstalled) return;
  window.__spInstalled = true;

  var ENTRY = SP.entry;
  var ORIGIN = location.origin;
  var base = SP.base;

  /* ---------- helpers ---------- */
  function b64(s) {
    return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return decodeURIComponent(escape(atob(s)));
  }
  function isProxied(u) {
    if (typeof u !== 'string') return false;
    var p = ENTRY + '?u=';
    return u.indexOf(p) === 0 || u.indexOf(ORIGIN + p) === 0 || u.indexOf('proxy.php?u=') === 0;
  }
  function prox(u) {
    if (u === null || u === undefined) return u;
    u = String(u);
    if (!u || /^\s*(#|data:|javascript:|mailto:|tel:|about:|blob:|sms:)/i.test(u) || isProxied(u)) return u;
    var a;
    try { a = new URL(u, base).href; } catch (e) { return u; }
    if (!/^https?:/i.test(a)) return u;
    // If the URL points at OUR proxy host but isn't a proxied URL, the
    // browser resolved a site-relative URL against the proxy page URL
    // (e.g. new Request("/media/x") -> https://proxyhost/media/x, or a
    // script reading el.src / location.origin + path).
    // - Our own UI files (proxy.php bare, index.html, ...) are left alone:
    //   they genuinely live on our host (proxifying them would SSRF-block).
    // - Anything else is re-resolved against the REAL site origin, or it
    //   would hit our own server and get SSRF-blocked (this broke media
    //   players that pre-resolve URLs).
    try {
      var uu = new URL(a);
      if (uu.origin === ORIGIN && !isProxied(a)) {
        if (/^\/(proxy\.php|index\.html?|style\.css|app\.js|shim\.js)(\?|#|$)/.test(uu.pathname)) return u;
        var rb = new URL(base);
        a = rb.origin + uu.pathname + uu.search + uu.hash;
      }
    } catch (e) {}
    var h = '', i = a.indexOf('#');
    if (i > -1) { h = a.slice(i); a = a.slice(0, i); }
    return ENTRY + '?u=' + b64(a) + h;
  }
  function unprox(u) {
    try {
      if (isProxied(u)) {
        var m = /[?&]u=([A-Za-z0-9_-]+)/.exec(u);
        if (m) return unb64(m[1]);
      }
    } catch (e) {}
    return u;
  }
  function proxSrcset(v) {
    return String(v).split(',').map(function (part) {
      var t = part.trim();
      if (!t) return t;
      var seg = t.split(/\s+/);
      seg[0] = prox(seg[0]);
      return seg.join(' ');
    }).join(', ');
  }
  function proxCss(css) {
    if (typeof css !== 'string' || css.indexOf('url(') < 0) return css;
    return css.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, function (m, q, u) {
      return 'url(' + q + prox(u) + q + ')';
    });
  }
  function decEnt(s) {
    return s.replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }
  function encEnt(s) {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  }
  var HTML_ATTR = /(\s)((?:data-[\w-]*)?(?:src|href|action|poster|data|formaction|background|original|thumb[\w-]*)|srcset|data-[\w-]*srcset)(\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi;
  function proxHtml(h) {
    if (typeof h !== 'string' || h.indexOf('<') < 0) return h;
    return h.replace(HTML_ATTR, function (m, sp, name, eq, dq, sq) {
      var v = dq !== undefined ? dq : sq;
      var q = dq !== undefined ? '"' : "'";
      var n = name.toLowerCase();
      var nv = /srcset$/.test(n) ? proxSrcset(decEnt(v)) : prox(decEnt(v));
      return sp + name + eq + q + encEnt(nv) + q;
    });
  }

  /* ---------- fetch / XHR ---------- */
  if (window.fetch) {
    var oFetch = window.fetch;
    window.fetch = function (input, init) {
      try {
        if (typeof input === 'string' || (window.URL && input instanceof URL)) input = prox(String(input));
        else if (input && input.url) input = new Request(prox(input.url), input);
      } catch (e) {}
      return oFetch.call(this, input, init);
    };
  }
  if (window.XMLHttpRequest) {
    var oOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var a = Array.prototype.slice.call(arguments);
      try { a[1] = prox(url); } catch (e) {}
      return oOpen.apply(this, a);
    };
  }
  if (window.Worker) {
    var OW = window.Worker;
    window.Worker = function (url, opts) { return new OW(prox(url), opts); };
    window.Worker.prototype = OW.prototype;
  }

  /* ---------- attributes set from script ---------- */
  var URL_ATTRS = { src: 1, href: 1, action: 1, poster: 1, data: 1, formaction: 1, background: 1 };
  var oSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      var n = String(name).toLowerCase();
      if (this.id !== 'pxform' && this.id !== 'pxbar') {
        if (URL_ATTRS[n]) value = prox(value);
        else if (/srcset$/.test(n)) value = proxSrcset(value);
        else if (n === 'style') value = proxCss(String(value));
      }
    } catch (e) {}
    return oSetAttr.call(this, name, value);
  };

  function patchProp(proto, prop, kind) {
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || !d.get) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: function () {
          var v = d.get.call(this);
          return kind === 'srcset' ? v : unprox(v);
        },
        set: function (v) {
          if (this.id === 'pxform') return d.set.call(this, v);
          d.set.call(this, kind === 'srcset' ? proxSrcset(v) : prox(v));
        }
      });
    } catch (e) {}
  }
  [
    ['HTMLImageElement', 'src'], ['HTMLScriptElement', 'src'], ['HTMLIFrameElement', 'src'],
    ['HTMLSourceElement', 'src'], ['HTMLMediaElement', 'src'], ['HTMLEmbedElement', 'src'],
    ['HTMLTrackElement', 'src'], ['HTMLInputElement', 'src'], ['HTMLAnchorElement', 'href'],
    ['HTMLAreaElement', 'href'], ['HTMLLinkElement', 'href'], ['HTMLFormElement', 'action'],
    ['HTMLObjectElement', 'data'], ['HTMLVideoElement', 'poster']
  ].forEach(function (p) { if (window[p[0]]) patchProp(window[p[0]].prototype, p[1]); });
  ['HTMLImageElement', 'HTMLSourceElement'].forEach(function (n) {
    if (window[n]) patchProp(window[n].prototype, 'srcset', 'srcset');
  });

  /* ---------- HTML strings inserted from script ---------- */
  function patchHtmlSetter(proto, prop) {
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function (v) { d.set.call(this, proxHtml(v)); }
      });
    } catch (e) {}
  }
  patchHtmlSetter(Element.prototype, 'innerHTML');
  patchHtmlSetter(Element.prototype, 'outerHTML');
  if (Element.prototype.insertAdjacentHTML) {
    var oIAH = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, html) { return oIAH.call(this, pos, proxHtml(html)); };
  }
  ['write', 'writeln'].forEach(function (k) {
    var o = document[k];
    if (!o) return;
    document[k] = function () {
      var a = Array.prototype.slice.call(arguments).map(proxHtml);
      return o.apply(document, a);
    };
  });

  /* ---------- inline styles ---------- */
  if (window.CSSStyleDeclaration) {
    var CP = CSSStyleDeclaration.prototype;
    var oSP = CP.setProperty;
    CP.setProperty = function (name, value, prio) { return oSP.call(this, name, proxCss(String(value)), prio); };
    ['backgroundImage', 'background', 'cssText', 'listStyleImage', 'content', 'borderImage'].forEach(function (prop) {
      try {
        var d = Object.getOwnPropertyDescriptor(CP, prop);
        if (!d || !d.set) return;
        Object.defineProperty(CP, prop, {
          configurable: true, enumerable: d.enumerable, get: d.get,
          set: function (v) { d.set.call(this, proxCss(String(v))); }
        });
      } catch (e) {}
    });
  }

  /* ---------- navigation helpers ----------
   * Sites often bounce the top window to a canonical URL
   * (location.href = "...", location.assign/replace(...)). Without this,
   * that navigation escapes the proxy and lands on the real site.
   * Location.prototype's href/assign/replace are configurable in practice,
   * so we wrap them to stay inside the proxy. */
  try {
    var LP = window.Location && Location.prototype;
    if (LP) {
      var hrefDesc = Object.getOwnPropertyDescriptor(LP, 'href');
      if (hrefDesc && hrefDesc.configurable && typeof hrefDesc.set === 'function') {
        Object.defineProperty(LP, 'href', {
          configurable: true,
          enumerable: hrefDesc.enumerable,
          get: hrefDesc.get,
          set: function (v) { hrefDesc.set.call(this, prox(v)); }
        });
      }
      ['assign', 'replace'].forEach(function (m) {
        try {
          var orig = LP[m];
          if (typeof orig === 'function') {
            LP[m] = function (u) { return orig.call(this, prox(u)); };
          }
        } catch (e) {}
      });
    }
  } catch (e) {}
  var oOpenWin = window.open;
  window.open = function (url) {
    var a = Array.prototype.slice.call(arguments);
    if (a[0]) a[0] = prox(a[0]);
    return oOpenWin.apply(window, a);
  };
  ['pushState', 'replaceState'].forEach(function (k) {
    var o = history[k];
    if (!o) return;
    history[k] = function (state, title, url) {
      if (url !== undefined && url !== null && url !== '') {
        try { base = new URL(String(url), base).href; } catch (e) {}
        url = prox(url);
      }
      return o.call(history, state, title, url);
    };
  });

  /* ---------- cookies ----------
   * Upstream cookies live in the browser under the name  __sp~<domain>~<name>
   * so every proxied site gets its own jar. document.cookie is mapped to that
   * namespace so scripts see (and set) the cookies of the REAL site.
   */
  try {
    var cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cd && cd.get && cd.set) {
      var hostOf = function () { try { return new URL(base).hostname.toLowerCase(); } catch (e) { return ''; } };
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        get: function () {
          var raw = cd.get.call(this), host = hostOf(), out = [];
          raw.split(/;\s*/).forEach(function (p) {
            var m = /^__sp~([^~]*)~([^=]*)=(.*)$/.exec(p);
            if (!m) return;
            var d = m[1];
            if (host === d || host.slice(-d.length - 1) === '.' + d) out.push(m[2] + '=' + m[3]);
          });
          return out.join('; ');
        },
        set: function (v) {
          var parts = String(v).split(';');
          var nv = parts.shift();
          var eq = nv.indexOf('=');
          var name = eq < 0 ? '' : nv.slice(0, eq).trim();
          var val = eq < 0 ? nv : nv.slice(eq + 1);
          var host = hostOf(), dom = host, exp = '', max = '';
          parts.forEach(function (a) {
            var i = a.indexOf('='), k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase(), x = i < 0 ? '' : a.slice(i + 1).trim();
            if (k === 'domain') {
              x = x.replace(/^\./, '').toLowerCase();
              if (x && (host === x || host.slice(-x.length - 1) === '.' + x)) dom = x;
            } else if (k === 'expires') exp = x;
            else if (k === 'max-age') max = x;
          });
          var c = '__sp~' + dom + '~' + name + '=' + val + '; path=/; SameSite=Lax';
          if (max !== '') c += '; max-age=' + max; else if (exp) c += '; expires=' + exp;
          if (location.protocol === 'https:') c += '; Secure';
          cd.set.call(this, c);
        }
      });
    }
  } catch (e) {}
})();
