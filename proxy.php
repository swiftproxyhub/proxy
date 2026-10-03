<?php
/*
 * SwiftProxy — proxy.php
 * Entry point. Usage:
 *   POST  proxy.php            with field "url"      -> 302 to the GET form below
 *   GET   proxy.php?u=<token>                        -> proxied page (shareable link)
 *   GET   proxy.php?diag=1                           -> owner diagnostics page
 *   any   <stray path>         (via .htaccess)        -> resolved with the Referer
 * The token is just the base64url-encoded target URL.
 *
 * NOTE: no session_start() anywhere on purpose. A PHP session locks the whole
 * request, which made pages with many images load one-by-one (or stall).
 * Cookies live in the visitor's browser (__sp~domain~name) and the Referer is
 * mapped back from the proxy URL, so the server keeps zero per-visitor state.
 */
require __DIR__ . '/config.php';
require __DIR__ . '/proxy_lib.php';

$method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET');

function sp_fail($msg, $code = 400, $detail = '') {
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: text/html; charset=UTF-8');
    }
    $home = sp_dir() . '/index.html';
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>SwiftProxy — Error</title>'
        . '<style>body{background:#0d1117;color:#e6edf3;font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}'
        . '.box{max-width:560px;padding:32px;background:#141a26;border:1px solid #2b3548;border-radius:12px;text-align:center}'
        . 'small{color:#8b98ad;word-break:break-all}a{color:#7dd3fc}</style></head><body><div class="box">'
        . '<h2>&#9888;&#65039; Could not open that page</h2><p>'
        . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8')
        . '</p>' . ($detail !== '' ? '<p><small>' . htmlspecialchars($detail, ENT_QUOTES, 'UTF-8') . '</small></p>' : '')
        . '<p><a href="' . htmlspecialchars($home, ENT_QUOTES, 'UTF-8') . '">&larr; Back to SwiftProxy home</a></p></div></body></html>';
    exit;
}

// The target site served its geo-block / age-verification wall instead of the
// real page. This is decided purely by THIS SERVER's IP country — the
// visitor's own location is irrelevant. Explain it plainly and point at diag.
function sp_blocked_page($host) {
    if (!headers_sent()) {
        http_response_code(451);
        header('Content-Type: text/html; charset=UTF-8');
    }
    $diag = htmlspecialchars(sp_entry() . '?diag=1', ENT_QUOTES, 'UTF-8');
    $home = htmlspecialchars(sp_dir() . '/index.html', ENT_QUOTES, 'UTF-8');
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>SwiftProxy — Blocked by region</title>'
        . '<style>body{background:#0d1117;color:#e6edf3;font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}'
        . '.box{max-width:600px;padding:32px;background:#141a26;border:1px solid #2b3548;border-radius:12px}'
        . 'a{color:#7dd3fc}li{margin:.4em 0}</style></head><body><div class="box">'
        . '<h2>&#128274; This site blocks your proxy server’s country</h2>'
        . '<p><b>' . htmlspecialchars($host, ENT_QUOTES, 'UTF-8') . '</b> decides what to show based on the '
        . '<b>server’s</b> IP address — not yours. From this server’s country it only serves an '
        . 'age-verification / region wall, so there is no real page to proxy. No code change can fix that; '
        . 'the request has to leave from an allowed country.</p>'
        . '<p><b>What you can do (owner):</b></p><ol>'
        . '<li>Open the <a href="' . $diag . '">diagnostics page</a> — it shows this server’s country, '
        . 'what the site serves it, and whether the free-proxy pool has a working proxy right now.</li>'
        . '<li>Most reliable: host SwiftProxy in an allowed country (NL/DE/CA…), or add one cheap VPS '
        . 'there as <code>$CFG_HOST_UPSTREAM</code> in <code>config.php</code>.</li>'
        . '</ol><p><a href="' . $home . '">&larr; Back to SwiftProxy home</a></p></div></body></html>';
    exit;
}

// 0) Owner diagnostics: proxy.php?diag=1 explains WHY a geo-blocked site fails
//    (server country, direct-fetch result, pool status) with ranked fixes.
if (isset($_GET['diag'])) {
    sp_diag_page();
    exit;
}

// 0b) Strays: requests that reached this server as plain paths (the rewriter
//     or shim couldn't see them — e.g. JS doing location.href = "/watch/1").
//     The Referer tells us which proxied page they came from.
if (isset($_GET['sp_stray'])) {
    $ref = isset($_SERVER['HTTP_REFERER']) ? sp_real_from_proxy_url($_SERVER['HTTP_REFERER']) : null;
    if ($ref === null) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Not found');
    }
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
    // Strip our own sub-directory prefix (/proxy/watch/1 -> /watch/1).
    $dir = sp_dir();
    if ($dir !== '') {
        if ($uri === $dir || strpos($uri, $dir . '?') === 0) $uri = substr($uri, strlen($dir));
        elseif (strpos($uri, $dir . '/') === 0) $uri = substr($uri, strlen($dir));
    }
    if ($uri === '' || $uri[0] !== '/') $uri = '/' . $uri;
    // Drop our own marker param; keep the site's real query string.
    if (($qp = strpos($uri, '?')) !== false) {
        parse_str(substr($uri, $qp + 1), $qa);
        unset($qa['sp_stray']);
        $uri = substr($uri, 0, $qp) . ($qa ? '?' . http_build_query($qa) : '');
    }
    $abs = sp_resolve_url($ref, $uri);
    if (!sp_url_allowed($abs)) sp_fail('That URL is invalid or blocked.', 403);
    header('Location: ' . sp_entry() . '?u=' . sp_b64e($abs), true, 307); // 307 keeps method + body
    exit;
}

// 1) Address bar: POST field "url" (home page / toolbar) or GET ?url=
//    (only when this isn't already a proxied request carrying a token).
$bar = null;
if ($method === 'POST' && empty($_GET['u']) && isset($_POST['url'])) $bar = $_POST['url'];
elseif ($method === 'GET' && empty($_GET['u']) && isset($_GET['url'])) $bar = $_GET['url'];
if ($bar !== null) {
    $t = sp_normalize_url($bar);
    if ($t === null || !sp_url_allowed($t)) sp_fail('That URL looks invalid or is not allowed.');
    header('Location: ' . sp_entry() . '?u=' . sp_b64e($t), true, 302);
    header('Cache-Control: no-store');
    exit;
}

// 2) Proxied request. The target comes from the token.
$target = !empty($_GET['u']) ? sp_b64d((string)$_GET['u']) : null;
if ($target === null) { header('Location: ' . sp_dir() . '/index.html', true, 302); exit; }
$target = sp_normalize_url($target);
if ($target === null || !sp_url_allowed($target)) sp_fail('That URL is invalid or blocked.', 403);

// 3) A GET form on the proxied page sends its fields as extra query parameters.
if ($method === 'GET') {
    $extra = $_GET;
    unset($extra['u'], $extra['sp_stray'], $extra['diag']);
    if (!empty($extra)) {
        $frag = '';
        if (($h = strpos($target, '#')) !== false) { $frag = substr($target, $h); $target = substr($target, 0, $h); }
        $target .= (strpos($target, '?') === false ? '?' : '&') . http_build_query($extra) . $frag;
    }
}

$host = strtolower((string)parse_url($target, PHP_URL_HOST));
$is_pool_host = false;
foreach ((array)$CFG_PROXY_FOR_HOSTS as $t) {
    if (sp_host_matches($host, $t)) { $is_pool_host = true; break; }
}

// 4) Fetch + serve. Free proxies are flaky: on a transport failure (or a
//    proxy that serves a block wall from the wrong country) retry with a
//    different proxy before giving up.
$exclude = array();
$attempt = 0;
$max_attempts = 3;
do {
    $attempt++;
    list($body, $err, $info, $headers, $streamed, $used_proxy) = sp_fetch($target, $exclude);
    if ($body === false && !$streamed) {
        if ($used_proxy !== null && $attempt < $max_attempts) { $exclude[] = $used_proxy; continue; }
        $hint = '';
        if (stripos($err, 'SSL certificate problem') !== false || stripos($err, 'certificate') !== false) {
            $hint = 'TLS certificate problem. The host’s CA bundle may be outdated.';
        } elseif (stripos($err, 'timed out') !== false || stripos($err, 'timeout') !== false) {
            $hint = 'The site took too long to answer (blocked or very slow from this server).';
        } elseif (stripos($err, 'could not resolve') !== false) {
            $hint = 'DNS lookup failed for that host.';
        }
        sp_fail('The site did not respond' . ($err !== '' ? ': ' . $err : '.'), 502, $hint);
    }
    if ($streamed) exit; // bytes (with correct status/headers) were already sent
    if ($is_pool_host && sp_has_block_markers((string)$body)) {
        if ($used_proxy !== null && $attempt < $max_attempts) { $exclude[] = $used_proxy; continue; }
        sp_blocked_page($host); // direct fetch hit the site's region wall
    }
    break;
} while (true);

$effective = (isset($info['url']) && $info['url'] !== '') ? $info['url'] : $target;
$eff_host = strtolower((string)parse_url($effective, PHP_URL_HOST));
if ($eff_host === '') $eff_host = $host;
$status = (int)(isset($info['http_code']) ? $info['http_code'] : 0);

sp_emit_cookies_from_headers($headers, $eff_host);
header('X-SP-Upstream-Status: ' . $status);
header('X-SP-Target: ' . preg_replace('/[^\x20-\x7e]/', '', $target));
if ($status > 0) http_response_code($status);

$ctype = sp_last_content_type($headers);
$mime  = strtolower(trim(strtok($ctype, ';')));
$path  = (string)parse_url($effective, PHP_URL_PATH);
$body  = (string)$body;

// 5) Rewrite + serve according to content type.
if ($body === '') {
    // Empty body (204 / 304 / HEAD / empty 200): headers above are the answer.
    if ($ctype !== '') header('Content-Type: ' . $ctype);
    exit;
}
$is_m3u8 = (stripos($mime, 'mpegurl') !== false) || preg_match('/\.m3u8($|\?)/i', $path);
if ($is_m3u8) {
    header('Content-Type: application/vnd.apple.mpegurl');
    echo sp_rewrite_m3u8((string)$body, $effective);
    exit;
}
$is_mpd = preg_match('/\.mpd($|\?)/i', $path) || stripos((string)$body, '<MPD') !== false;
if ($is_mpd) {
    header('Content-Type: application/dash+xml');
    echo sp_rewrite_mpd((string)$body, $effective);
    exit;
}
if (strpos($mime, 'text/html') !== false || strpos($mime, 'application/xhtml') !== false) {
    header('Content-Type: text/html; charset=UTF-8');
    echo sp_rewrite_html((string)$body, $effective, $ctype);
    exit;
}
if (strpos($mime, 'text/css') !== false) {
    header('Content-Type: text/css; charset=UTF-8');
    echo sp_rewrite_css_urls((string)$body, $effective);
    exit;
}
// Anything left: pass through.
if ($ctype !== '') header('Content-Type: ' . $ctype);
foreach ($headers as $h) {
    if (stripos($h, 'Content-Disposition:') === 0) { header(trim($h)); break; }
}
echo $body;
