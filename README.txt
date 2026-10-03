SwiftProxy — free web-proxy tool (HTML + CSS + pure JS + PHP)
============================================================

WHAT IT IS
  A tiny website that lets visitors open sites blocked in their country.
  The visitor enters a URL, your server fetches the page on their behalf
  (so the block doesn't apply), rewrites every link/image/form to stay
  inside the proxy, and shows the result with a small toolbar on top.

  Your server IS the free HTTPS proxy — nothing else to buy or subscribe to.

REQUIREMENTS
  - Any PHP hosting (PHP 7.2 or newer) with the cURL extension enabled.
    (cURL is enabled by default on virtually all shared hosts.)
  - No database, no Composer, no build step.

INSTALL (2 minutes)
  1. Upload ALL files in this folder to your hosting, e.g. into
     public_html/ or public_html/proxy/.
  2. Open https://your-domain.com/index.html — done.
  3. (Optional) Open config.php to tweak timeouts, block extra hosts,
     or add upstream proxies.

HOW IT WORKS
  index.html          Landing page: URL box, quick links, how-it-works, FAQ.
  proxy.php           Entry point. POSTing a URL 302-redirects to a clean
                      shareable link like proxy.php?u=<token>, exactly like
                      the big proxy sites do. The landing page submits with
                      target="_blank", so the proxied site opens in a new tab.
  proxy_lib.php       The engine: fetching (cURL), cookie jar, SSRF guard,
                      and rewriting of HTML/CSS links.
  config.php          Timeouts, size limits, optional upstream proxies.

WHAT IT HANDLES (v3)
  - Every kind of site: blogs, forums, docs, news, shops, video tubes,
    adult sites, etc. — the proxy is content-agnostic.
  - Full URL rewriting: links, images, srcset, scripts, stylesheets,
    iframes, forms, video/audio/track, CSS url() and @import, inline
    styles, meta refresh.
  - Lazy-loaded images: data-src, data-srcset and friends are rewritten
    (the #1 reason images "don't load" on modern sites) — including custom
    attributes tube sites use (data-src-avif, data-pvv, data-sfwthumb...).
  - JavaScript-built URLs: a runtime shim (shim.js) is injected as the
    first script of every page and rewrites URLs the page's own JS builds
    at runtime — fetch/XHR, setAttribute, innerHTML templates, window.open,
    history.pushState — plus a document.cookie bridge so JS-set cookies
    work through the proxy. URLs the browser pre-resolved against the
    proxy host (e.g. new Request("/media/x")) are mapped back to the real
    site instead of hitting our own server.
  - No escape: location.href / location.assign / location.replace are
    wrapped so a site's canonical-URL or www-redirect bounces stay inside
    the proxy instead of jumping to the real site. Server-side redirects
    are followed and served under the proxy; the toolbar always shows the
    final URL.
  - Escaped navigation: JS that sets location.href to a bare path is
    caught by .htaccess + proxy.php's stray handler, which resolves it
    against the page you came from (via the Referer) and forwards it.
  - No request queueing: the server keeps zero per-visitor state (no PHP
    sessions), so a page's 50 images/videos load in parallel instead of
    one-by-one.
  - Hotlink-protected media: the proxy sends the embedding page as the
    HTTP Referer, just like a browser — unblocks many images/videos.
  - Video: byte-range requests forwarded (206 Partial Content) so
    seeking works; HLS (.m3u8) playlists and DASH (.mpd) manifests
    are rewritten so streams keep playing through the proxy. Streams are
    never cut by the page timeout; a low-speed guard kills only stalled
    transfers.
  - Large files stream straight through (no memory blow-ups), and the
    compressed Content-Length mismatch that broke gzipped JS/CSS is fixed.
  - Cookies: upstream cookies are stored in the VISITOR'S browser under
    __sp~domain~name (one jar per site), so logins/age-gates persist with
    zero server state.
  - Geo-block detection: when a site serves its region wall (e.g. PH from
    a blocked server country), visitors get a plain-English explanation
    page (HTTP 451) pointing at proxy.php?diag=1 — not a confusing blank.
  - Free-proxy resilience: failed proxies are retried automatically with
    a different proxy (up to 3 attempts per request).
  - Content-Security-Policy meta tags stripped so pages render fully.
  - Visitor's Accept / Accept-Language / Range / XHR headers forwarded
    for correct content negotiation (e.g. WebP images).

SECURITY NOTES
  - Localhost / private-network IPs are blocked (anti-SSRF) so the proxy
    can't be abused to scan internal systems. Keep $CFG_ALLOW_PRIVATE=false
    on any public server.
  - Upstream sites are fetched with TLS certificate verification on.
  - Upstream cookies live in each visitor's own browser (__sp~domain~name),
    namespaced per site — the server stores nothing about visitors.
  - The landing page stores NOTHING about visited sites: no "recently
    visited" list, no localStorage history, no tracking cookies. (Older
    versions kept a recent list; it is removed and old data is wiped on
    next visit.)
  - As with any open proxy, add rate limiting / a CAPTCHA on index.html
    if you get abused. Don't use it for illegal activity.

LIMITS (honest)
  - Very JS-heavy single-page apps may partly break: content loaded via
    JavaScript fetch/XHR/WebSockets can't be rewritten. Most classic
    websites, articles, docs, forums, tubes and media pages work fine.
  - Sites behind Cloudflare / bot challenges may show a challenge page;
    those can't be solved server-side by any PHP proxy.
  - Don't enter banking or highly sensitive credentials through ANY proxy.

GEO-BLOCKED SITES (e.g. Pornhub shows a block/verification page)
  We researched this deeply (Oct 2026), including how competitors like
  fastproxy.win do it. The truth is simple:

  * Pornhub's block is PURE IP GEOLOCATION of your SERVER. It checks the
    country of the connecting IP and nothing else — no browser
    fingerprinting, no datacenter-IP ban, no Cloudflare challenge.
    Blocked regions include 25+ US states (TX, FL, AZ, UT, VA...), the UK
    (new users), and France. If your server is in one of them, Pornhub
    serves an age-verification notice INSTEAD of the site. The proxy is
    working correctly — the site itself refuses that server location.
  * Competitors work because their SERVERS sit in allowed countries
    (e.g. Netherlands). It is server location, not clever code.
  * Images need no special trick: Pornhub thumbnails (ei.phncdn.com) load
    with no referer and no cookies (verified). SwiftProxy already proxies
    every image through itself, so once the page loads, images load.

  DIAGNOSE FIRST: open proxy.php?diag=1 in your browser. It shows your
  server's IP + country, what pornhub.com serves it directly (real page
  vs block page), and whether the free-proxy pool currently holds a
  working proxy — with ranked fixes.

  Fixes, ranked by reliability (all in config.php):
  1) MOVE HOSTING to an allowed country (Netherlands, Germany, Canada…).
     Then everything works with ZERO proxy config — this is what the big
     proxy sites do.
  2) YOUR OWN PROXY/VPS (~$5/mo in NL) as upstream for just that site:
      $CFG_HOST_UPSTREAM = [
        'pornhub.com' => 'http://user:pass@your-nl-proxy:3128',
        'phncdn.com'  => 'http://user:pass@your-nl-proxy:3128', // its CDN
      ];
     Subdomains (www.pornhub.com etc.) match automatically; every other
     site keeps going direct.
  3) AUTOMATIC FREE-PROXY POOL (default, zero setup): every 30 minutes
     SwiftProxy downloads fresh lists (ProxyScrape v4 + v2 free APIs and
     several GitHub http/socks lists — the old per-country ProxyScrape
     feeds return empty lists, so they were dropped), health-tests up to
     30 candidates IN PARALLEL against a real page URL per host
     (configurable via $CFG_PROXY_TEST_URL — e.g. pornhub.com itself only
     answers 301, and *.phncdn.com answers 403 at its root, so the pool
     tests www.pornhub.com instead and follows redirects), and keeps only
     proxies returning HTTP 200 WITHOUT block-page markers. One working
     proxy is picked at random per request for the hosts in
     $CFG_PROXY_FOR_HOSTS (default: pornhub.com + phncdn.com). Results are
     cached on disk so visitors never wait for the test.
     Honest caveat: free proxies are ~99% dead at any moment (measured),
     the live ones are slow, and they CAN SEE the traffic. If a proxy dies
     mid-request, SwiftProxy automatically retries with a different one
     (up to 3 attempts). Fine for casual browsing; never log in to
     anything important through them.
  Priority per request: your per-host upstream -> free-proxy pool ->
  global upstream list -> direct. The proxy cannot fake its own country;
  one of these hops is the only real fix.

FILES
  index.html, style.css, app.js, proxy.php, proxy_lib.php, config.php,
  shim.js (runtime URL shim injected into every proxied page),
  .htaccess (catches navigation that escaped the rewriter)
