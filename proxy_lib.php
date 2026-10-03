<?php
/*
 * SwiftProxy — proxy engine (library, no side effects on include).
 * Fetches a target URL server-side with cURL and rewrites the response so
 * every link, image, form, stylesheet and script keeps working through the
 * proxy. Included by proxy.php.
 */

/* ---------------- base64url helpers ---------------- */

function sp_b64e($s) {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function sp_b64d($s) {
    $s = strtr($s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    $r = base64_decode($s, true);
    return $r === false ? null : $r;
}

/* ---------------- environment helpers ---------------- */

function sp_is_https() {
    if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') return true;
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && stripos($_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') !== false) return true;
    return isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443;
}

// Root-relative path of proxy.php, e.g. "/proxy.php" or "/tools/proxy.php".
function sp_entry() {
    static $e = null;
    if ($e === null) {
        $s = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/proxy.php';
        $dir = rtrim(str_replace('\\', '/', dirname($s)), '/');
        $e = $dir . '/proxy.php';
    }
    return $e;
}

function sp_dir() {
    return rtrim(str_replace('\\', '/', dirname(sp_entry())), '/');
}

// Reverse of sp_proxify_url: "https://me/proxy.php?u=TOKEN" -> real URL (or null).
function sp_real_from_proxy_url($url) {
    $q = parse_url((string)$url, PHP_URL_QUERY);
    if (!$q) return null;
    parse_str($q, $arr);
    if (empty($arr['u'])) return null;
    $real = sp_b64d((string)$arr['u']);
    if ($real === null || !preg_match('#^https?://#i', $real)) return null;
    return $real;
}

/* ---------------- URL helpers ---------------- */

function sp_self_host() {
    return strtolower(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
}

// Add https:// when the user typed a bare domain. Returns null if invalid.
function sp_normalize_url($u) {
    $u = trim((string)$u);
    if ($u === '') return null;
    if (!preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $u)) $u = 'https://' . $u;
    $p = parse_url($u);
    if (!$p || empty($p['host'])) return null;
    if (!in_array(strtolower($p['scheme']), array('http', 'https'), true)) return null;
    // Host must be a valid IP or a sane hostname (rejects "not a url" etc).
    $host = $p['host'];
    if (!filter_var($host, FILTER_VALIDATE_IP)
        && !preg_match('/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i', $host)) return null;
    return $u;
}

// SSRF guard: block our own host, localhost, and private/reserved IPs.
function sp_host_allowed($host) {
    $host = strtolower(trim($host));
    if ($host === '') return false;
    $self = sp_self_host();
    if ($self !== '' && ($host === $self || substr($host, -strlen('.' . $self)) === '.' . $self)) return false;
    if ($host === 'localhost') return false;
    foreach ($GLOBALS['CFG_BLOCK_HOSTS'] as $b) {
        $b = strtolower(trim($b));
        if ($b !== '' && ($host === $b || substr($host, -strlen('.' . $b)) === '.' . $b)) return false;
    }
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ip = $host;
    } else {
        $ip = @gethostbyname($host);
        if ($ip === $host) return false; // DNS lookup failed
    }
    if (empty($GLOBALS['CFG_ALLOW_PRIVATE'])) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
    }
    return true;
}

function sp_url_allowed($url) {
    $p = parse_url($url);
    if (!$p || empty($p['host'])) return false;
    if (!in_array(strtolower(isset($p['scheme']) ? $p['scheme'] : ''), array('http', 'https'), true)) return false;
    return sp_host_allowed($p['host']);
}

// Resolve a possibly-relative URL against a base URL (RFC 3986 style).
function sp_resolve_url($base, $rel) {
    $rel = trim((string)$rel);
    if ($rel === '') return $base;
    if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*:#', $rel)) return $rel; // absolute URI
    $b = parse_url($base);
    $scheme = isset($b['scheme']) ? $b['scheme'] : 'https';
    $host   = isset($b['host']) ? $b['host'] : '';
    $port   = isset($b['port']) ? ':' . $b['port'] : '';
    if ($host === '') return $rel;
    if (substr($rel, 0, 2) === '//') return $scheme . ':' . $rel;
    if ($rel[0] === '/') {
        $path = $rel;
    } else {
        $bpath = isset($b['path']) ? $b['path'] : '/';
        if (substr($bpath, -1) !== '/') $bpath = preg_replace('#/[^/]*$#', '/', $bpath);
        $path = $bpath . $rel;
    }
    $path = preg_replace('#\?.*$#', '', $path);
    $query = '';
    $qm = strpos($rel, '?');
    if ($rel[0] === '/') {
        $q2 = strpos($rel, '?');
        if ($q2 !== false) $query = substr($rel, $q2);
    } elseif ($qm !== false) {
        $query = substr($rel, $qm);
    }
    // dot-segment removal (keep a trailing slash if the merged path had one)
    $trailing = (substr($path, -1) === '/');
    $segs = explode('/', $path);
    $out = array();
    foreach ($segs as $seg) {
        if ($seg === '' || $seg === '.') continue;
        if ($seg === '..') { array_pop($out); continue; }
        $out[] = $seg;
    }
    $path = '/' . implode('/', $out);
    if ($trailing && substr($path, -1) !== '/') $path .= '/';
    return $scheme . '://' . $host . $port . $path . $query;
}

// Turn any page URL into a proxy.php link. Leaves data:/javascript:/etc alone.
function sp_proxify_url($url, $base) {
    $url = trim(html_entity_decode((string)$url, ENT_QUOTES, 'UTF-8'));
    $frag = '';
    $hp = strpos($url, '#');
    if ($hp !== false) { $frag = substr($url, $hp); $url = substr($url, 0, $hp); }
    if ($url === '') return $frag === '' ? '' : $frag;
    if (strpos($url, sp_entry() . '?u=') === 0) return $url . $frag; // already ours
    $low = strtolower($url);
    foreach (array('data:', 'javascript:', 'mailto:', 'tel:', 'about:', 'blob:') as $pfx) {
        if (strpos($low, $pfx) === 0) return $url . $frag;
    }
    $abs = sp_resolve_url($base, $url);
    // Never double-proxy our own links.
    if (stripos($abs, 'proxy.php?u=') !== false && stripos($abs, sp_self_host()) !== false) {
        return $abs . $frag;
    }
    return sp_entry() . '?u=' . sp_b64e($abs) . $frag;
}

// Rewrite every URL inside a srcset attribute.
function sp_rewrite_srcset($srcset, $base) {
    $parts = explode(',', (string)$srcset);
    foreach ($parts as &$p) {
        $p = trim($p);
        if ($p === '') continue;
        $seg = preg_split('/\s+/', $p, 2);
        $seg[0] = sp_proxify_url($seg[0], $base);
        $p = implode(' ', $seg);
    }
    unset($p);
    return implode(', ', $parts);
}

// Rewrite url(...) and @import "..." inside CSS text.
function sp_rewrite_css_urls($css, $base) {
    $css = preg_replace_callback('#url\(\s*(["\']?)(.*?)\1\s*\)#i', function ($m) use ($base) {
        return 'url(' . $m[1] . sp_proxify_url($m[2], $base) . $m[1] . ')';
    }, (string)$css);
    $css = preg_replace_callback('#@import\s+(["\'])(.*?)\1#i', function ($m) use ($base) {
        return '@import ' . $m[1] . sp_proxify_url($m[2], $base) . $m[1];
    }, $css);
    return $css;
}

/* ---------------- HLS playlist / DASH manifest rewriting ---------------- */

// Rewrite every segment/key URI inside an HLS (.m3u8) playlist so video
// chunks keep flowing through the proxy.
function sp_rewrite_m3u8($body, $base) {
    $lines = preg_split('/\r\n|\r|\n/', (string)$body);
    foreach ($lines as &$ln) {
        $t = trim($ln);
        if ($t === '') continue;
        if ($t[0] === '#') {
            // Key / map URIs: #EXT-X-KEY:METHOD=AES-128,URI="key.key" ...
            $ln = preg_replace_callback('#URI="([^"]+)"#', function ($m) use ($base) {
                return 'URI="' . sp_proxify_url($m[1], $base) . '"';
            }, $ln);
            continue;
        }
        $ln = sp_proxify_url($t, $base);
    }
    unset($ln);
    return implode("\n", $lines);
}

// Light-touch DASH (.mpd) rewrite: BaseURL elements only.
function sp_rewrite_mpd($body, $base) {
    return preg_replace_callback('#<BaseURL>(.*?)</BaseURL>#s', function ($m) use ($base) {
        return '<BaseURL>' . sp_proxify_url(trim($m[1]), $base) . '</BaseURL>';
    }, (string)$body);
}

/* ---------------- cookie jar ----------------
 * Upstream cookies are stored IN THE VISITOR'S BROWSER with the name
 *     __sp~<domain>~<cookie-name>
 * so each proxied site has its own jar, expiry/deletion is handled by the
 * browser, JavaScript (shim.js) can read/write them, and the server keeps no
 * state at all (=> no session lock: 50 image requests run in parallel).
 */

function sp_outgoing_cookies($host) {
    $raw = isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '';
    $host = strtolower($host);
    $jar = array();
    foreach (explode(';', $raw) as $p) {
        $p = ltrim($p);
        if (strncmp($p, '__sp~', 5) !== 0) continue;
        if (!preg_match('/^__sp~([^~]*)~([^=]*)=(.*)$/s', $p, $m)) continue;
        $d = $m[1];
        if ($d === '') continue;
        if ($host === $d || substr($host, -strlen($d) - 1) === '.' . $d) $jar[$m[2]] = $m[3];
    }
    $out = array();
    foreach ($jar as $n => $v) $out[] = $n . '=' . $v;
    return implode('; ', $out);
}

function sp_emit_cookies($cookies, $host) {
    $host = strtolower($host);
    foreach ((array)$cookies as $c) {
        $parts = explode(';', $c);
        $nv = array_shift($parts);
        $eq = strpos($nv, '=');
        if ($eq === false) continue;
        $name = trim(substr($nv, 0, $eq));
        $val  = trim(substr($nv, $eq + 1));
        if ($name === '' || strpos($name, '~') !== false) continue;
        $dom = $host; $exp = null; $max = null; $http = false;
        foreach ($parts as $a) {
            $a = trim($a);
            $i = strpos($a, '=');
            $k = strtolower(trim($i === false ? $a : substr($a, 0, $i)));
            $v = trim($i === false ? '' : substr($a, $i + 1));
            if ($k === 'domain') {
                $d = strtolower(ltrim($v, '.'));
                if ($d !== '' && ($host === $d || substr($host, -strlen($d) - 1) === '.' . $d)) $dom = $d;
            } elseif ($k === 'expires') { $exp = $v; }
            elseif ($k === 'max-age') { $max = (int)$v; }
            elseif ($k === 'httponly') { $http = true; }
        }
        $line = '__sp~' . $dom . '~' . $name . '=' . $val . '; Path=/; SameSite=Lax';
        if ($max !== null) $line .= '; Max-Age=' . $max;
        elseif ($exp !== null && $exp !== '') $line .= '; Expires=' . $exp;
        if ($http) $line .= '; HttpOnly';
        if (sp_is_https()) $line .= '; Secure';
        header('Set-Cookie: ' . $line, false);
    }
}

// Adapter: emit cookies from raw upstream response header lines.
function sp_emit_cookies_from_headers($headers, $host) {
    $cookies = array();
    foreach ((array)$headers as $h) {
        if (stripos($h, 'Set-Cookie:') === 0) $cookies[] = trim(substr($h, 11));
    }
    if ($cookies) sp_emit_cookies($cookies, $host);
}

/* ---------------- request building ---------------- */

function sp_request_headers($target, $method, $hostCookies) {
    $p = parse_url($target);
    $origin = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    $h = array();
    $h[] = 'Accept: ' . (!empty($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '*/*');
    $h[] = 'Accept-Language: ' . (!empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : 'en-US,en;q=0.9');

    // Referer: map "our" page URL back to the real page URL, else the site root.
    $ref = '';
    if (!empty($_SERVER['HTTP_REFERER'])) {
        $real = sp_real_from_proxy_url($_SERVER['HTTP_REFERER']);
        if ($real !== null) $ref = $real;
    }
    $h[] = 'Referer: ' . ($ref !== '' ? $ref : $origin . '/');
    if (($method !== 'GET' && $method !== 'HEAD') || !empty($_SERVER['HTTP_ORIGIN'])) $h[] = 'Origin: ' . $origin;

    // Selected end-user headers that sites' own JavaScript relies on.
    $pass = array('HTTP_X_REQUESTED_WITH', 'HTTP_IF_NONE_MATCH', 'HTTP_IF_MODIFIED_SINCE', 'HTTP_RANGE', 'HTTP_CACHE_CONTROL', 'HTTP_PRAGMA');
    foreach ($_SERVER as $k => $v) {
        if (strpos($k, 'HTTP_X_') === 0 && !preg_match('/^HTTP_X_(FORWARDED|REAL_IP|CLIENT|LSCACHE|LITESPEED|HOSTINGER|PROXY|ORIGINAL|REWRITE|SP_)/', $k)) $pass[] = $k;
    }
    foreach (array_unique($pass) as $k) {
        if (!isset($_SERVER[$k]) || $_SERVER[$k] === '') continue;
        $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
        $h[] = $name . ': ' . $_SERVER[$k];
    }
    if ($hostCookies !== '') $h[] = 'Cookie: ' . $hostCookies;
    return $h;
}

/* ---------------- client runtime shim ---------------- */

// Inlines shim.js as the first script of every proxied page. It catches the
// URLs that JavaScript builds at runtime (fetch/XHR, setAttribute, innerHTML
// templates, window.open, history.pushState) and maps document.cookie to the
// __sp~ namespaced jar, so JS-heavy sites keep working through the proxy.
function sp_shim_html($base) {
    static $js = null;
    if ($js === null) {
        $f = __DIR__ . '/shim.js';
        $js = is_file($f) ? file_get_contents($f) : '';
        $js = str_ireplace('</script', '<\/script', $js);
    }
    if ($js === '') return '';
    $cfg = json_encode(array('base' => $base, 'entry' => sp_entry()), JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES);
    return '<script>window.__SP=' . $cfg . ';</script><script>' . $js . '</script>';
}

/* ---------------- upstream proxy selection ---------------- */

// Domain match: exact host or any subdomain (case-insensitive).
function sp_host_matches($host, $domain) {
    $host = strtolower(trim((string)$host));
    $domain = strtolower(trim(trim((string)$domain), '.'));
    return $domain !== '' && ($host === $domain || substr($host, -strlen('.' . $domain)) === '.' . $domain);
}

// Pick an upstream proxy for a target host:
//   1. manual per-host rule ($CFG_HOST_UPSTREAM) — the operator's own proxy
//      always wins: it is the reliable one,
//   2. automatic free-proxy pool (for $CFG_PROXY_FOR_HOSTS),
//   3. global list ($CFG_UPSTREAM),
//   4. direct (null).
// $exclude lists proxies that just failed, so a retry picks a different one.
function sp_pick_upstream($host, $exclude = array()) {
    $host = strtolower(trim((string)$host));
    $ex = array_flip((array)$exclude);
    $usable = function ($px) use ($ex) { return $px !== null && $px !== '' && !isset($ex[$px]); };
    foreach ((array)$GLOBALS['CFG_HOST_UPSTREAM'] as $domain => $px) {
        if (sp_host_matches($host, $domain) && $usable($px)) return $px;
    }
    $pool = sp_pool_proxy_for($host, $exclude);
    if ($pool) return $pool;
    if (!empty($GLOBALS['CFG_UPSTREAM'])) {
        $cands = array_values(array_filter((array)$GLOBALS['CFG_UPSTREAM'], $usable));
        if ($cands) return $cands[array_rand($cands)];
    }
    return null;
}

/* ---------------- automatic free-proxy pool ---------------- */

// Download the configured proxy lists and parse them into proxy URLs.
// Accepts "ip:port" lines and full URLs (http/https/socks4/socks5).
function sp_fetch_proxy_sources() {
    $out = array();
    foreach ((array)$GLOBALS['CFG_PROXY_SOURCES'] as $url) {
        $url = trim((string)$url);
        if (!preg_match('#^https?://#i', $url)) continue;
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'SwiftProxy/1.0',
        ));
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (!is_string($body) || $code !== 200 || strlen($body) > 2000000) continue;
        foreach (preg_split('/\R/', $body) as $line) {
            $line = trim(preg_replace('/\s+#.*$/', '', trim($line)));
            if ($line === '' || $line[0] === '#') continue;
            if (preg_match('#^(https?|socks4|socks5)://(\S+)$#i', $line, $m)) {
                $scheme = strtolower($m[1]);
                $addr = $m[2];
            } elseif (preg_match('#^(\S+):(\d{1,5})$#', $line, $m) && strpos($m[1], '/') === false) {
                $scheme = 'http';
                $addr = $m[1] . ':' . $m[2];
            } else {
                continue;
            }
            if (strpos($addr, '0.0.0.0') === 0) continue; // junk entries some lists include
            $port = (int)substr(strrchr($addr, ':'), 1);
            if ($port < 1 || $port > 65535) continue;
            $out[$scheme . '://' . $addr] = true;
        }
    }
    $list = array_keys($out);
    shuffle($list);
    return $list;
}

// Health-test proxies IN PARALLEL against a real page URL.
// Keeps only proxies returning HTTP 200 without block-page markers.
// Redirects are followed: https://pornhub.com/ answers 301 to www.
function sp_test_proxies($proxies, $test_url) {
    if (!$proxies) return array();
    $url = (string)$test_url;
    if ($url === '') return array();
    $timeout = max(3, (int)$GLOBALS['CFG_PROXY_TEST_TIMEOUT']);
    $markers = (array)$GLOBALS['CFG_PROXY_BLOCK_MARKERS'];
    $mh = curl_multi_init();
    $handles = array();
    foreach ($proxies as $px) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_PROXY => $px,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(6, $timeout),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
            CURLOPT_HTTPHEADER => array('Accept: text/html'),
        ));
        curl_multi_add_handle($mh, $ch);
        $handles[] = array($ch, $px);
    }
    $active = null;
    do {
        $mrc = curl_multi_exec($mh, $active);
        if ($active) curl_multi_select($mh, 1);
    } while ($active && $mrc === CURLM_OK);
    $good = array();
    foreach ($handles as $h) {
        list($ch, $px) = $h;
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $body = curl_multi_getcontent($ch);
        $ok = ($code === 200 && is_string($body) && strlen($body) > 500);
        if ($ok) {
            foreach ($markers as $mk) {
                if ($mk !== '' && stripos($body, (string)$mk) !== false) { $ok = false; break; }
            }
        }
        if ($ok) $good[] = $px;
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $good;
}

function sp_proxy_cache_file() {
    return rtrim(sys_get_temp_dir(), '/\\') . '/swiftproxy_pool.json';
}

// Return a working free proxy for $host, or null. Uses a disk cache so the
// expensive fetch+test only runs every $CFG_PROXY_REFRESH seconds.
// $exclude lists proxies that just failed this request: they are never
// returned, so a retry picks a different one.
function sp_pool_proxy_for($host, $exclude = array()) {
    $host = strtolower(trim((string)$host));
    $matched = null;
    foreach ((array)$GLOBALS['CFG_PROXY_FOR_HOSTS'] as $t) {
        if (sp_host_matches($host, $t)) { $matched = strtolower(trim(trim((string)$t), '.')); break; }
    }
    if ($matched === null || empty($GLOBALS['CFG_PROXY_SOURCES'])) return null;

    // Which page proves a proxy really works for this host? Some hosts don't
    // serve a usable page at their own root (pornhub.com 301s to www;
    // *.phncdn.com answers 403), so the config can map them to a real page.
    $test_url = 'https://' . $host . '/';
    foreach ((array)$GLOBALS['CFG_PROXY_TEST_URL'] as $domain => $u) {
        if (sp_host_matches($matched, $domain) || sp_host_matches($host, $domain)) { $test_url = (string)$u; break; }
    }

    $ex = array_flip((array)$exclude);
    $pick = function ($list) use ($ex) {
        $cands = array();
        foreach ((array)$list as $p) { if (!isset($ex[$p])) $cands[] = $p; }
        return $cands ? $cands[array_rand($cands)] : null;
    };

    $file = sp_proxy_cache_file();
    $ttl = max(300, (int)$GLOBALS['CFG_PROXY_REFRESH']);
    $now = time();
    $cache = array('fetched_at' => 0, 'good' => array());
    if (is_readable($file)) {
        $fp = @fopen($file, 'r');
        if ($fp) {
            if (flock($fp, LOCK_SH)) { $raw = stream_get_contents($fp); flock($fp, LOCK_UN); }
            fclose($fp);
            $j = json_decode(isset($raw) ? (string)$raw : '', true);
            if (is_array($j)) $cache = $j + $cache;
        }
    }
    $old = (isset($cache['good'][$matched]) && is_array($cache['good'][$matched]))
        ? array_values($cache['good'][$matched]) : array();
    if ($old && ($now - (int)$cache['fetched_at']) < $ttl) {
        $p = $pick($old);
        if ($p !== null) return $p; // fresh cache: serve instantly
    }

    // Stale/empty: refresh under a non-blocking exclusive lock so concurrent
    // visitors don't all hammer the lists at once.
    $fp = @fopen($file, 'c+');
    if (!$fp || !flock($fp, LOCK_EX | LOCK_NB)) {
        if ($fp) fclose($fp);
        return $pick($old); // someone else is refreshing: serve stale, else null
    }
    $raw = stream_get_contents($fp);
    $j = json_decode((string)$raw, true);
    if (is_array($j)) $cache = $j + $cache;
    $old = (isset($cache['good'][$matched]) && is_array($cache['good'][$matched]))
        ? array_values($cache['good'][$matched]) : array();
    if ($old && ($now - (int)$cache['fetched_at']) < $ttl) {
        flock($fp, LOCK_UN); fclose($fp);
        return $pick($old); // refreshed by someone else meanwhile
    }

    $all = sp_fetch_proxy_sources();
    $max = max(5, (int)$GLOBALS['CFG_PROXY_MAX_TEST']);
    $batch = array_slice($all, 0, $max);
    $fresh = sp_test_proxies($batch, $test_url); // test against a real page URL
    $tested = array_flip($batch);
    $kept = array();
    foreach ($old as $p) { if (!isset($tested[$p])) $kept[] = $p; } // not re-tested: keep
    $merged = array_values(array_unique(array_merge($fresh, $kept)));
    $merged = array_slice($merged, 0, 60);
    $cache['fetched_at'] = $now;
    $cache['good'][$matched] = $merged;
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($cache)); fflush($fp);
    flock($fp, LOCK_UN); fclose($fp);
    $p = $pick($merged);
    if ($p !== null) return $p;
    return $pick($old); // last resort: stale, else direct
}

/* ---------------- fetching ---------------- */

/* ---------------- diagnostics ----------------
 * proxy.php?diag=1 shows the site owner WHY a geo-blocked site fails:
 * this server's country, what pornhub.com serves it directly, and whether
 * the free-proxy pool currently holds a working proxy. Read-only: it never
 * changes config or cache. (The visitor's own location is irrelevant —
 * only the SERVER's IP country matters.)
 */
function sp_server_geo() {
    $file = rtrim(sys_get_temp_dir(), '/\\') . '/swiftproxy_geo.json';
    if (is_readable($file) && filemtime($file) > time() - 3600) {
        $j = json_decode((string)@file_get_contents($file), true);
        if (is_array($j) && !empty($j['country'])) return $j;
    }
    $d = array('country' => 'unknown', 'code' => '', 'ip' => '');
    $ch = curl_init('http://ip-api.com/json/?fields=status,country,countryCode,query');
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_USERAGENT => 'SwiftProxy/1.0',
    ));
    $body = curl_exec($ch);
    curl_close($ch);
    $j = json_decode((string)$body, true);
    if (is_array($j) && ($j['status'] ?? '') === 'success') {
        $d = array(
            'country' => (string)$j['country'],
            'code' => (string)$j['countryCode'],
            'ip' => (string)$j['query'],
        );
        @file_put_contents($file, json_encode($d));
    }
    return $d;
}

function sp_diag_report() {
    $geo = sp_server_geo();
    // What does pornhub.com serve THIS server directly?
    $direct = array('ok' => false, 'code' => 0, 'size' => 0, 'blocked' => false, 'error' => '');
    $ch = curl_init('https://www.pornhub.com/');
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
        CURLOPT_HTTPHEADER => array('Accept: text/html'),
    ));
    $body = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (is_string($body) && $code === 200 && strlen($body) > 500) {
        $direct['ok'] = true;
        $direct['code'] = $code;
        $direct['size'] = strlen($body);
        foreach ((array)$GLOBALS['CFG_PROXY_BLOCK_MARKERS'] as $mk) {
            if ($mk !== '' && stripos($body, (string)$mk) !== false) { $direct['blocked'] = true; break; }
        }
    } else {
        $direct['error'] = $err !== '' ? $err : ('HTTP ' . $code);
        $direct['code'] = $code;
    }
    // What does the free-proxy pool currently hold for pornhub.com?
    $pool = array('proxy' => null, 'fresh' => false, 'age' => null);
    $cf = sp_proxy_cache_file();
    if (is_readable($cf)) {
        $c = json_decode((string)@file_get_contents($cf), true);
        if (is_array($c) && !empty($c['good']['pornhub.com']) && is_array($c['good']['pornhub.com'])) {
            $pool['proxy'] = (string)$c['good']['pornhub.com'][0];
            $pool['age'] = time() - (int)($c['fetched_at'] ?? 0);
            $pool['fresh'] = $pool['age'] < max(300, (int)$GLOBALS['CFG_PROXY_REFRESH']);
        }
    }
    return array('geo' => $geo, 'direct' => $direct, 'pool' => $pool, 'time' => date('c'));
}

function sp_diag_page() {
    $r = sp_diag_report();
    $h = function ($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
    $geo = $r['geo'];
    $direct = $r['direct'];
    $pool = $r['pool'];
    $d = $direct;
    if ($d['ok'] && !$d['blocked']) {
        $verdict = '<p class="good"><b>Your server reaches the real Pornhub directly.</b> No proxy is needed for the page itself — if visitors still see problems, it is a rewriting issue, not a block.</p>';
    } elseif ($d['ok'] && $d['blocked']) {
        $verdict = '<p class="bad"><b>Your server is served the age-verification block page.</b> Pornhub decides purely by this server\'s IP country'
            . ($geo['country'] !== 'unknown' ? ' (' . $h($geo['country']) . ')' : '')
            . '. No code can change that — the request must exit from an allowed country.</p>';
    } else {
        $verdict = '<p class="warn"><b>Direct fetch failed:</b> ' . $h($d['error']) . '. Check that this server can make outbound HTTPS requests (curl).</p>';
    }
    $poolHtml = $pool['proxy']
        ? '<p class="good"><b>Pool has a working proxy:</b> <code>' . $h($pool['proxy']) . '</code> (' . ($pool['fresh'] ? 'fresh' : 'stale') . ', tested ' . (int)$pool['age'] . 's ago). Requests to pornhub.com will use it.</p>'
        : '<p class="warn"><b>Pool has no working proxy right now.</b> Free lists are ~99% dead proxies; the pool keeps retrying every refresh. For reliability use your own upstream (see below).</p>';
    $fix = '';
    if (($d['ok'] && $d['blocked']) || !$pool['proxy']) {
        $fix = '<h2>How to fix it (ranked)</h2><ol>'
            . '<li><b>Move this site\'s hosting to an allowed country</b> (Netherlands, Germany, Canada…). Then everything works with zero proxy config — this is what the big proxy sites do.</li>'
            . '<li><b>Keep hosting, add one reliable upstream</b> — a cheap VPS (~$5/mo) in the Netherlands running Squid/tinyproxy, then in <code>config.php</code>:<br><code>$CFG_HOST_UPSTREAM = [\'pornhub.com\' =&gt; \'http://user:pass@your-nl-vps:3128\', \'phncdn.com\' =&gt; \'http://user:pass@your-nl-vps:3128\'];</code></li>'
            . '<li><b>Free-proxy pool</b> (already built in) — zero cost, but unreliable by nature. Never log in to anything sensitive through it.</li>'
            . '</ol>';
    }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>SwiftProxy diagnostics</title><style>'
        . 'body{font-family:system-ui,sans-serif;max-width:760px;margin:2em auto;padding:0 1em;color:#1c1c1e;background:#fff;line-height:1.55}'
        . 'code{background:#f2f2f7;padding:.15em .4em;border-radius:6px;font-size:.92em;word-break:break-all}'
        . '.good{background:#e8f7ee;border:1px solid #b7e4c7;border-radius:10px;padding:.8em 1em}'
        . '.bad{background:#fdecea;border:1px solid #f5c6cb;border-radius:10px;padding:.8em 1em}'
        . '.warn{background:#fff8e1;border:1px solid #ffe082;border-radius:10px;padding:.8em 1em}'
        . 'table{border-collapse:collapse;margin:1em 0}td,th{border:1px solid #ddd;padding:.45em .8em;text-align:left}th{background:#f6f6f8}'
        . '</style></head><body>'
        . '<h1>SwiftProxy diagnostics</h1>'
        . '<table><tr><th>Server IP</th><td><code>' . $h($geo['ip'] !== '' ? $geo['ip'] : 'unknown') . '</code></td></tr>'
        . '<tr><th>Server country</th><td>' . $h($geo['country']) . ($geo['code'] !== '' ? ' (' . $h($geo['code']) . ')' : '') . '</td></tr>'
        . '<tr><th>Direct pornhub.com fetch</th><td>' . ($d['ok'] ? 'HTTP ' . (int)$d['code'] . ', ' . number_format((int)$d['size']) . ' bytes' . ($d['blocked'] ? ' — <b>block page</b>' : ' — <b>real page</b>') : $h($d['error'])) . '</td></tr>'
        . '<tr><th>Checked at</th><td>' . $h($r['time']) . '</td></tr></table>'
        . $verdict . $poolHtml . $fix
        . '<p><a href="./">← back to SwiftProxy</a></p></body></html>';
}

// Flatten nested PHP form arrays into curl's "a[b]" field names.
function sp_flatten_post($arr, $prefix = '') {
    $out = array();
    foreach ((array)$arr as $k => $v) {
        $key = $prefix === '' ? (string)$k : $prefix . '[' . $k . ']';
        if (is_array($v)) $out = array_merge($out, sp_flatten_post($v, $key));
        else $out[$key] = $v;
    }
    return $out;
}

// Fetch $url server-side. Returns array($body, $err, $info, $headers,
// $streamed, $used_proxy). $body is false on transport failure, null when the
// response was already streamed to the visitor. $exclude lists proxies that
// just failed, so the retry picks a different one.
function sp_fetch($url, $exclude = array()) {
    @set_time_limit(0);
    @ignore_user_abort(false);
    @ini_set('zlib.output_compression', '0');
    @ini_set('display_errors', '0');

    $p = parse_url($url);
    $host = strtolower(isset($p['host']) ? $p['host'] : '');
    $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET');

    $reqHeaders = sp_request_headers($url, $method, sp_outgoing_cookies($host));
    $max_buf = (int)$GLOBALS['CFG_MAX_MB'] * 1024 * 1024;
    $deadline = (int)$GLOBALS['CFG_TIMEOUT'];
    $start = microtime(true);
    $ua = !empty($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT']
        : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

    // Request body.
    $reqBody = null; $isMultipart = false;
    if ($method !== 'GET' && $method !== 'HEAD') {
        $cin = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
        if (stripos($cin, 'multipart/form-data') === 0) {
            $isMultipart = true;
            $reqBody = sp_flatten_post($_POST);
            foreach ($_FILES as $k => $f) {
                if (!is_array($f) || !isset($f['tmp_name']) || is_array($f['tmp_name'])) continue;
                if ($f['error'] === UPLOAD_ERR_OK && is_uploaded_file($f['tmp_name'])) {
                    $reqBody[$k] = curl_file_create($f['tmp_name'], $f['type'], $f['name']);
                }
            }
        } else {
            $reqBody = file_get_contents('php://input');
            if ($cin !== '') $reqHeaders[] = 'Content-Type: ' . $cin;
        }
    }
    $hasRange = !empty($_SERVER['HTTP_RANGE']);

    $used_proxy = null;
    if (!empty($GLOBALS['CFG_UPSTREAM']) || !empty($GLOBALS['CFG_HOST_UPSTREAM']) || !empty($GLOBALS['CFG_PROXY_FOR_HOSTS'])) {
        $used_proxy = sp_pick_upstream($host, $exclude);
    }

    $ch = curl_init($url);
    $headers = array();
    $body = '';
    $stream_mode = false;    // true once we decide to pipe bytes straight through
    $stream_decided = false;
    $aborted_big = false;    // true when the buffered body exceeded CFG_MAX_MB

    $emit_stream_head = function () use ($ch, &$headers, $host) {
        while (ob_get_level()) @ob_end_clean();
        http_response_code((int)curl_getinfo($ch, CURLINFO_HTTP_CODE));
        sp_emit_cookies_from_headers($headers, $host);
        // If curl decoded a Content-Encoding, the stored Content-Length
        // describes the ENCODED bytes — forwarding it would corrupt or
        // truncate the stream (this broke gzipped JS/CSS on some sites).
        $decoded = false;
        foreach (array_reverse($headers) as $h) {
            if (stripos($h, 'Content-Encoding:') === 0) {
                $v = strtolower(trim(substr($h, 17)));
                if ($v !== '' && $v !== 'identity') $decoded = true;
                break;
            }
        }
        foreach (array('Content-Type', 'Content-Length', 'Content-Range', 'Accept-Ranges',
                        'Content-Disposition', 'ETag', 'Last-Modified') as $hn) {
            if ($hn === 'Content-Length' && $decoded) continue;
            foreach (array_reverse($headers) as $h) {
                if (stripos($h, $hn . ':') === 0) { header(trim($h)); break; }
            }
        }
    };

    $opts = array(
        CURLOPT_FOLLOWLOCATION   => true,
        CURLOPT_MAXREDIRS        => 5,
        CURLOPT_CONNECTTIMEOUT   => 10,
        CURLOPT_TIMEOUT          => 0,   // streams must NOT be cut mid-download;
        CURLOPT_LOW_SPEED_LIMIT  => 1,   // stalled transfers still die via the
        CURLOPT_LOW_SPEED_TIME   => 30,  // low-speed guard below
        CURLOPT_NOPROGRESS       => false,
        CURLOPT_PROGRESSFUNCTION => function ($ch, $dlt, $dl) use (&$stream_decided, $start, $deadline) {
            // Pages (HTML/CSS) that take longer than $CFG_TIMEOUT are aborted;
            // streams are exempt and rely on the low-speed guard instead.
            if (!$stream_decided && (microtime(true) - $start) > $deadline) return 1;
            return 0;
        },
        CURLOPT_ENCODING         => $hasRange ? 'identity' : '', // curl decodes gzip/deflate
        CURLOPT_SSL_VERIFYPEER   => true,
        CURLOPT_SSL_VERIFYHOST   => 2,
        CURLOPT_USERAGENT        => $ua,
        CURLOPT_HTTPHEADER       => $reqHeaders,
        CURLOPT_HEADERFUNCTION   => function ($ch, $h) use (&$headers) { $headers[] = $h; return strlen($h); },
        CURLOPT_WRITEFUNCTION    => function ($ch, $data) use (&$headers, &$body, &$stream_mode, &$stream_decided, &$aborted_big, $max_buf, $emit_stream_head) {
            if (!$stream_decided) {
                // First body chunk: HTML/CSS/m3u8 get buffered for rewriting,
                // everything else streams straight to the visitor.
                $ctype = sp_last_content_type($headers);
                $mime = strtolower(trim(strtok($ctype, ';')));
                $needs_rewrite = (strpos($mime, 'text/html') !== false)
                    || (strpos($mime, 'application/xhtml') !== false)
                    || (strpos($mime, 'text/css') !== false)
                    || (stripos($mime, 'mpegurl') !== false);
                if (!$needs_rewrite) {
                    $stream_mode = true;
                    $emit_stream_head();
                }
                $stream_decided = true;
            }
            if ($stream_mode) {
                echo $data;
                flush();
                if (connection_aborted()) return 0;
                return strlen($data);
            }
            if (strlen($body) + strlen($data) > $max_buf) { $aborted_big = true; return 0; } // abort: too big
            $body .= $data;
            return strlen($data);
        },
    );
    if ($used_proxy !== null) $opts[CURLOPT_PROXY] = $used_proxy;

    if ($method === 'HEAD') { $opts[CURLOPT_NOBODY] = true; }
    elseif ($method === 'POST') { $opts[CURLOPT_POST] = true; $opts[CURLOPT_POSTFIELDS] = $reqBody === null ? '' : $reqBody; }
    elseif ($method !== 'GET') {
        $opts[CURLOPT_CUSTOMREQUEST] = $method;
        if ($reqBody !== null && $reqBody !== '') $opts[CURLOPT_POSTFIELDS] = $reqBody;
    }
    if ($isMultipart) {
        // let cURL build the multipart boundary itself
        $opts[CURLOPT_HTTPHEADER] = array_values(array_filter($reqHeaders, function ($x) { return stripos($x, 'Content-Type:') !== 0; }));
    }
    curl_setopt_array($ch, $opts);
    $ok   = curl_exec($ch);
    $err  = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    if (!$ok) {
        if ($aborted_big) $err = 'Response exceeded the ' . (int)$GLOBALS['CFG_MAX_MB'] . ' MB safety limit';
        // If the stream had already started, headers + partial bytes went out:
        // just stop; appending an error page would corrupt the download.
        return array(false, $err, $info, $headers, $stream_mode, $used_proxy);
    }
    return array($stream_mode ? null : $body, $err, $info, $headers, $stream_mode, $used_proxy);
}

function sp_last_content_type($headers) {
    foreach (array_reverse((array)$headers) as $h) {
        if (stripos($h, 'Content-Type:') === 0) return trim(substr($h, 13));
    }
    return '';
}

// True when an HTML body looks like a geo-block / age-verification wall
// instead of the real site (used for pool hosts fetched without a proxy).
function sp_has_block_markers($html) {
    if (!is_string($html) || $html === '') return false;
    foreach ((array)$GLOBALS['CFG_PROXY_BLOCK_MARKERS'] as $mk) {
        if ($mk !== '' && stripos($html, (string)$mk) !== false) return true;
    }
    return false;
}

/* ---------------- HTML rewriting ---------------- */

function sp_rewrite_html($body, $base, $ctype) {
    $charset = 'UTF-8';
    if (preg_match('#charset=([a-z0-9_-]+)#i', (string)$ctype, $m)) $charset = strtoupper($m[1]);
    if ($charset !== 'UTF-8' && function_exists('mb_convert_encoding')) {
        $conv = @mb_convert_encoding($body, 'UTF-8', $charset);
        if ($conv !== false && $conv !== '') $body = $conv;
    }

    $doc = new DOMDocument();
    libxml_use_internal_errors(true);
    if (function_exists('mb_convert_encoding')) {
        $doc->loadHTML(mb_convert_encoding($body, 'HTML-ENTITIES', 'UTF-8'));
    } else {
        // No mbstring on this host: tell libxml the encoding explicitly.
        $doc->loadHTML('<?xml encoding="UTF-8">' . $body);
    }
    libxml_clear_errors();

    // Drop <base>: we resolve every URL ourselves against the real page URL.
    foreach (iterator_to_array($doc->getElementsByTagName('base')) as $b) {
        if ($b->parentNode) $b->parentNode->removeChild($b);
    }

    // Strip Content-Security-Policy meta tags: they would otherwise block our
    // toolbar and forbid loading the rewritten resources from our domain.
    foreach (iterator_to_array($doc->getElementsByTagName('meta')) as $m) {
        $he = strtolower(trim($m->getAttribute('http-equiv')));
        if ($he === 'content-security-policy' || $he === 'content-security-policy-report-only') {
            if ($m->parentNode) $m->parentNode->removeChild($m);
        }
    }

    $map = array(
        'a' => 'href', 'area' => 'href', 'link' => 'href',
        'form' => 'action', 'button' => 'formaction',
        'img' => 'src', 'script' => 'src', 'iframe' => 'src', 'frame' => 'src',
        'embed' => 'src', 'source' => 'src', 'video' => 'src', 'audio' => 'src',
        'track' => 'src', 'input' => 'src', 'object' => 'data',
        'blockquote' => 'cite', 'q' => 'cite', 'del' => 'cite', 'ins' => 'cite',
    );
    foreach ($map as $tag => $attr) {
        foreach ($doc->getElementsByTagName($tag) as $el) {
            if ($el->hasAttribute($attr)) {
                $el->setAttribute($attr, sp_proxify_url($el->getAttribute($attr), $base));
            }
        }
    }

    foreach (array('img', 'source') as $tag) {
        foreach ($doc->getElementsByTagName($tag) as $el) {
            if ($el->hasAttribute('srcset')) {
                $el->setAttribute('srcset', sp_rewrite_srcset($el->getAttribute('srcset'), $base));
            }
        }
    }

    // <video poster="...">
    foreach ($doc->getElementsByTagName('video') as $v) {
        if ($v->hasAttribute('poster')) {
            $v->setAttribute('poster', sp_proxify_url($v->getAttribute('poster'), $base));
        }
    }

    // Lazy-loading attributes (data-src etc.): the reason many images
    // "don't load" on modern sites — the real URL isn't in src at all.
    $lazy_attrs = array('data-src', 'data-original', 'data-lazy-src', 'data-poster',
                        'data-thumb', 'data-image', 'data-bg', 'data-background',
                        'data-background-image', 'data-href');
    $conds = array();
    foreach (array_merge($lazy_attrs, array('data-srcset')) as $a) $conds[] = '@' . $a;
    $xp_lazy = new DOMXPath($doc);
    foreach ($xp_lazy->query('//*[' . implode(' or ', $conds) . ']') as $el) {
        foreach ($lazy_attrs as $a) {
            if ($el->hasAttribute($a)) {
                $el->setAttribute($a, sp_proxify_url($el->getAttribute($a), $base));
            }
        }
        if ($el->hasAttribute('data-srcset')) {
            $el->setAttribute('data-srcset', sp_rewrite_srcset($el->getAttribute('data-srcset'), $base));
        }
    }
    // Generic data-* URL rewriting: tube/gallery sites stash real media URLs
    // in custom attributes (data-src-avif, data-sfwthumb, data-pvv, data-mzl,
    // ...). Any data-* attribute holding absolute URL(s) gets proxified.
    // (The allowlist above additionally covers relative URLs on known attrs.)
    $xp_data = new DOMXPath($doc);
    foreach ($xp_data->query('//*') as $el) {
        if (!$el->hasAttributes()) continue;
        foreach ($el->attributes as $attr) {
            $aname = $attr->nodeName;
            $lname = strtolower($aname);
            if (strpos($lname, 'data-') !== 0) continue;
            if (in_array($lname, $lazy_attrs, true) || $lname === 'data-srcset') continue; // already done
            $val = $attr->nodeValue;
            if ($val === '' || $val === null) continue;
            if (substr($lname, -6) === 'srcset') {
                $el->setAttribute($aname, sp_rewrite_srcset($val, $base));
            } elseif (preg_match('#^\s*(https?:)?//#i', $val)) {
                $el->setAttribute($aname, sp_proxify_url($val, $base));
            } elseif (strpos($val, '://') !== false) {
                // JSON blobs or compound values with embedded absolute URLs
                $el->setAttribute($aname, preg_replace_callback(
                    '#https?://[^\s"\'<>\\\\]+#i',
                    function ($mm) use ($base) { return sp_proxify_url($mm[0], $base); },
                    $val
                ));
            }
        }
    }

    foreach ($doc->getElementsByTagName('meta') as $m) {
        if (strtolower($m->getAttribute('http-equiv')) === 'refresh' && $m->hasAttribute('content')) {
            $m->setAttribute('content', preg_replace_callback('#url\s*=\s*(.*)#i', function ($mm) use ($base) {
                return 'url=' . sp_proxify_url(trim($mm[1], " '\""), $base);
            }, $m->getAttribute('content')));
        }
    }

    $xp = new DOMXPath($doc);
    foreach ($xp->query('//*[@style]') as $el) {
        $el->setAttribute('style', sp_rewrite_css_urls($el->getAttribute('style'), $base));
    }
    foreach ($doc->getElementsByTagName('style') as $st) {
        $css = '';
        foreach (iterator_to_array($st->childNodes) as $cn) {
            if ($cn->nodeType === XML_TEXT_NODE || $cn->nodeType === XML_CDATA_SECTION_NODE) $css .= $cn->data;
        }
        $new = sp_rewrite_css_urls($css, $base);
        while ($st->firstChild) $st->removeChild($st->firstChild);
        $st->appendChild($doc->createTextNode($new));
    }

    $html = $doc->saveHTML();
    if ($html === false || $html === '') $html = $body;
    // Client runtime shim FIRST inside <head>: it rewrites URLs that the
    // page's own JavaScript builds at runtime (fetch/XHR, lazy images,
    // innerHTML templates, window.open, history.pushState, document.cookie).
    $shim = sp_shim_html($base);
    if ($shim !== '') {
        if (preg_match('#<head[^>]*>#i', $html, $hm)) {
            $html = str_replace($hm[0], $hm[0] . $shim, $html);
        } else {
            $html = $shim . $html;
        }
    }
    return sp_inject_toolbar($html, $base);
}

/* ---------------- toolbar injection ---------------- */

function sp_toolbar_css() {
    return 'html body{padding-top:48px!important}'
        . '#pxbar{position:fixed;top:0;left:0;right:0;height:48px;background:#141a26;border-bottom:1px solid #2b3548;display:flex;align-items:center;gap:8px;padding:0 10px;z-index:2147483647;font-family:Arial,Helvetica,sans-serif;box-sizing:border-box}'
        . '#pxbar *{box-sizing:border-box}'
        . '#pxhome{color:#7dd3fc!important;text-decoration:none!important;font-weight:bold;font-size:14px;white-space:nowrap;background:none!important;border:0!important;padding:0!important;margin:0!important}'
        . '#pxform{flex:1;display:flex;gap:6px;margin:0!important;padding:0!important;background:none!important;border:0!important}'
        . '#pxurl{flex:1;height:32px;border:1px solid #2b3548;border-radius:6px;background:#0b0f16;color:#e6edf3;padding:0 10px;font-size:13px;min-width:0}'
        . '#pxgo{height:32px;border:0;border-radius:6px;background:#2563eb;color:#fff;padding:0 16px;font-size:13px;cursor:pointer;white-space:nowrap}'
        . '#pxhide{height:32px;width:32px;border:0;border-radius:6px;background:#1f2937;color:#9ca3af;font-size:14px;cursor:pointer}'
        . '#pxshow{position:fixed;top:10px;left:10px;z-index:2147483647;display:none}'
        . '#pxopen{height:36px;width:36px;border:0;border-radius:50%;background:#2563eb;color:#fff;font-size:16px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.4)}';
}

function sp_toolbar_html($current) {
    $cu = htmlspecialchars($current, ENT_QUOTES, 'UTF-8');
    return '<div id="pxbar">'
        . '<a id="pxhome" href="index.html" target="_top" title="Back to SwiftProxy home">&#9889; Home</a>'
        . '<form id="pxform" method="post" action="proxy.php" target="_top">'
        . '<input id="pxurl" type="text" name="url" value="' . $cu . '" autocomplete="off" spellcheck="false" />'
        . '<button id="pxgo" type="submit">Go</button>'
        . '</form>'
        . '<button id="pxhide" type="button" title="Hide toolbar">&#10005;</button>'
        . '</div>'
        . '<div id="pxshow"><button id="pxopen" type="button" title="Show toolbar">&#9889;</button></div>'
        . '<script>(function(){'
        . 'var bar=document.getElementById("pxbar"),show=document.getElementById("pxshow");'
        . 'document.getElementById("pxhide").onclick=function(){bar.style.display="none";show.style.display="block";document.body.style.paddingTop="0";};'
        . 'document.getElementById("pxopen").onclick=function(){show.style.display="none";bar.style.display="flex";document.body.style.paddingTop="48px";};'
        . '})();</script>';
}

function sp_inject_toolbar($html, $current) {
    $style_tag = '<style>' . sp_toolbar_css() . '</style>';
    if (stripos($html, '</head>') !== false) {
        $html = preg_replace('#</head>#i', $style_tag . '</head>', $html, 1);
    } else {
        $html = $style_tag . $html;
    }
    $bar = sp_toolbar_html($current);
    if (stripos($html, '</body>') !== false) {
        $html = preg_replace('#</body>#i', $bar . '</body>', $html, 1);
    } else {
        $html .= $bar;
    }
    return $html;
}
