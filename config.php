<?php
/*
 * SwiftProxy — configuration
 * Upload this whole folder to any PHP hosting (PHP 7.2+ with cURL enabled)
 * and open index.html. No database needed.
 */

// Max time (seconds) to wait for the target site to respond.
$CFG_TIMEOUT = 25;

// Max page/resource size (megabytes) the proxy will download.
$CFG_MAX_MB = 15;

/*
 * OPTIONAL upstream HTTPS proxies.
 * Leave empty [] (recommended): YOUR server fetches sites directly and acts
 * as the free proxy itself — simplest and most reliable.
 * To add an extra hop, list free proxy URLs here, e.g.:
 *   $CFG_UPSTREAM = [
 *     'http://203.0.113.10:8080',
 *     'http://user:pass@198.51.100.20:3128',
 *   ];
 * One is picked at random per request. Free public lists change fast, so
 * verify any list you paste still works.
 */
$CFG_UPSTREAM = [];

/*
 * PER-SITE upstream routing (for geo-blocked sites).
 * Some sites (e.g. Pornhub) decide what to show based on the SERVER's
 * country: a server in Texas gets an age-verification block page instead
 * of the site. Route just those hosts through a proxy/VPS in a permissive
 * country (e.g. Netherlands) while everything else stays direct:
 *   $CFG_HOST_UPSTREAM = [
 *     'pornhub.com'  => 'http://user:pass@your-nl-proxy:3128',
 *     'phncdn.com'   => 'http://user:pass@your-nl-proxy:3128', // its CDN too
 *   ];
 * Subdomains match automatically (www.pornhub.com etc.).
 */
$CFG_HOST_UPSTREAM = [];

// Extra hostnames to block (in addition to the automatic private-IP block).
$CFG_BLOCK_HOSTS = [];

// Set to true ONLY for local testing if you need to proxy intranet/test hosts.
// NEVER true on a public server (it would allow SSRF attacks).
$CFG_ALLOW_PRIVATE = false;

/*
 * ------------------------------------------------------------------
 * AUTOMATIC FREE-PROXY POOL (fresh lists fetched from GitHub etc.)
 * ------------------------------------------------------------------
 * SwiftProxy can fetch fresh free-proxy lists automatically and use a
 * tested-working proxy for chosen sites (e.g. pornhub.com). How it works:
 *   1. Every $CFG_PROXY_REFRESH seconds it downloads the lists below,
 *      parses "ip:port" lines and health-tests up to $CFG_PROXY_MAX_TEST
 *      of them IN PARALLEL against each target site.
 *   2. Only proxies returning HTTP 200 WITHOUT block-page markers
 *      (age-verification walls, "Access Denied", bot checks) are kept.
 *   3. One is picked at random per request; results are cached on disk
 *      so visitors don't wait for the test.
 *
 * Honest notes: free proxies are flaky by nature (most list entries are
 * dead; the live ones are slow and CAN SEE your traffic). This pool is
 * meant for casual browsing of the listed hosts only — never log in to
 * anything important through it. For reliability, a small VPS/proxy you
 * control (see $CFG_HOST_UPSTREAM above) beats any free list.
 *
 * When a proxy fails mid-request, the next request automatically retries
 * with a different one (up to 3 attempts).
 */
$CFG_PROXY_SOURCES = [
  // ProxyScrape free API (no key, rate-limited) — plain "ip:port" lines.
  'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text&timeout=20000',
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&ssl=all&anonymity=all',
  // GitHub mirrors (http + socks; curl speaks all of these):
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
  // NOTE: ProxyScrape's per-country v2 feeds (country=NL/DE/...) currently
  // return empty lists, so they were dropped. If they come back, add e.g.
  // 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=NL&ssl=all&anonymity=all'
  // — proxies in Pornhub-allowed countries have a far better hit rate.
];

// Target hosts that should use the automatic free-proxy pool.
// Domain + subdomains match ('pornhub.com' covers www.pornhub.com).
// Everything else ignores the pool completely.
$CFG_PROXY_FOR_HOSTS = ['pornhub.com', 'phncdn.com'];

// Which URL proves a proxy really works for a host? Some hosts don't serve a
// usable page at their own root, so the pool health-test uses these instead:
//   - "pornhub.com" alone answers 301 (redirect to www.pornhub.com);
//     the tester follows redirects, but testing www. directly is cheaper.
//   - "*.phncdn.com" answers 403 at its root — a dead-end for testing.
// Suffix match against the pool host; unmatched hosts use https://<host>/ .
$CFG_PROXY_TEST_URL = [
  'pornhub.com' => 'https://www.pornhub.com/',
  'phncdn.com'  => 'https://www.pornhub.com/',
];

$CFG_PROXY_REFRESH      = 1800; // seconds between list re-fetch + re-test
$CFG_PROXY_MAX_TEST     = 30;   // candidates health-tested per refresh/host
$CFG_PROXY_TEST_TIMEOUT = 10;   // seconds allowed per health check

// If a proxied response contains any of these, the proxy is rejected
// (it hit a block wall / captcha instead of the real site).
$CFG_PROXY_BLOCK_MARKERS = [
  'elected officials in',   // Pornhub Texas age-verification wall
  'age-verification',
  'Access Denied',
  'are you a robot',
  'Attention Required',
];
