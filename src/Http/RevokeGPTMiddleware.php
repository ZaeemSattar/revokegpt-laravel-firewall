<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Http;

use Closure;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use RevokeGPT\Firewall\Core\Decide;
use RevokeGPT\Firewall\Core\Headers;
use RevokeGPT\Firewall\Core\Host;
use RevokeGPT\Firewall\Core\Limits;
use RevokeGPT\Firewall\Core\Normalize;
use RevokeGPT\Firewall\Core\Session;
use RevokeGPT\Firewall\Firewall;

/**
 * The RevokeGPT firewall as a global Laravel middleware. It strips every x-rg-* request header
 * (and the HTTP_X_RG_* server variables they become), serves the reserved /__rg/ routes, decides,
 * and either answers (block, redirect, challenge) or passes the request on with the decision's
 * headers set.
 *
 * The raw target is the server's REQUEST_URI (what {@see Request::getRequestUri()} returns for an
 * origin-form request), never the decoded path of the router.
 */
final class RevokeGPTMiddleware
{
    public function __construct(
        private readonly Firewall $fw,
        private readonly ?LoggerInterface $log = null,
    ) {
    }

    // ---- request access ------------------------------------------------------------------------

    private static function server(Request $r, string $header): string
    {
        $v = $r->server->get('HTTP_' . strtoupper(str_replace('-', '_', $header)));
        return is_string($v) ? $v : '';
    }

    private static function rawTarget(Request $r): string
    {
        $uri = $r->server->get('REQUEST_URI');
        return is_string($uri) && $uri !== '' ? $uri : $r->getRequestUri();
    }

    private static function acceptsHtml(Request $r): bool
    {
        foreach (explode(',', self::server($r, 'Accept')) as $part) {
            $semi = strpos($part, ';');
            $mt = trim($semi === false ? $part : substr($part, 0, $semi));
            if (strcasecmp($mt, 'text/html') === 0) {
                return true;
            }
        }
        return false;
    }

    /** The first cookie of that name in the Cookie header; null when absent or malformed. */
    public static function cookie(Request $r, string $name): ?string
    {
        foreach (explode(';', self::server($r, 'Cookie')) as $pair) {
            $p = trim($pair);
            $eq = strpos($p, '=');
            if ($eq === false || $eq === 0 || substr($p, 0, $eq) !== $name) {
                continue;
            }
            $v = substr($p, $eq + 1);
            if (strlen($v) >= 2 && $v[0] === '"' && str_ends_with($v, '"')) {
                $v = substr($v, 1, -1);
            }
            if (preg_match('/\A[\x20-\x7e]*\z/D', $v) !== 1 || strpbrk($v, "\";\\") !== false) {
                return null;
            }
            return $v;
        }
        return null;
    }

    /** Removes every x-rg-* header, and every HTTP_X_RG_* server variable, from the request and the globals. */
    private static function stripRgHeaders(Request $r): void
    {
        foreach ($r->headers->keys() as $name) {
            if (Headers::isRgHeader((string) $name)) {
                $r->headers->remove((string) $name);
            }
        }
        foreach (array_keys($r->server->all()) as $k) {
            if (preg_match('/\A(?:REDIRECT_)*HTTP_X_RG_/iD', (string) $k) === 1) {
                $r->server->remove((string) $k);
            }
        }
        foreach (array_keys($_SERVER) as $k) {
            if (preg_match('/\A(?:REDIRECT_)*HTTP_X_RG_/iD', (string) $k) === 1) {
                unset($_SERVER[$k]);
            }
        }
    }

    private static function setHeader(Request $r, string $name, string $value): void
    {
        $r->headers->set($name, $value);
        $var = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        $r->server->set($var, $value);
        $_SERVER[$var] = $value;
    }

    // ---- responses -----------------------------------------------------------------------------

    private const STATUS_TEXT = [
        303 => 'See Other', 400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed',
        413 => 'Payload Too Large', 415 => 'Unsupported Media Type', 429 => 'Too Many Requests',
        503 => 'Service Unavailable',
    ];

    /**
     * Answers with Cache-Control: no-store; extra headers never override it.
     *
     * @param array<string,string> $extra
     * @param list<RawCookie> $cookies
     */
    private function respond(int $status, array $extra = [], bool $vary = false, array $cookies = []): Response
    {
        $noBody = $status === 204 || ($status >= 300 && $status < 400);
        $res = new Response($noBody ? '' : (self::STATUS_TEXT[$status] ?? (string) $status) . "\n", $status);
        $res->headers->set('Cache-Control', 'no-store');
        $res->headers->set('Content-Type', 'text/plain; charset=utf-8');
        $res->headers->set('X-Content-Type-Options', 'nosniff');
        if ($vary) {
            $res->headers->set('Vary', 'Cookie', false);
        }
        foreach ($extra as $k => $v) {
            if (strcasecmp($k, 'Cache-Control') === 0) {
                continue;
            }
            $res->headers->set($k, $v);
        }
        foreach ($cookies as $c) {
            $res->headers->setCookie($c);
        }
        return $res;
    }

    private static function cookieHeader(string $name, string $value, int $maxAge): RawCookie
    {
        return RawCookie::make($name, $value, $maxAge, Limits::COOKIE_ATTRIBUTES);
    }

    /** The value uses only RFC 6265 cookie-octets. */
    private static function cookieSafe(string $v): bool
    {
        return preg_match('/\A[\x21-\x7e]*\z/D', $v) === 1 && strpbrk($v, "\",;\\") === false;
    }

    private function logDecision(string $id, ?int $rule, string $action): void
    {
        $this->log?->info('rg decision', ['id' => $id, 'rule' => $rule ?? -1, 'action' => $action]);
    }

    // ---- the middleware ------------------------------------------------------------------------

    public function handle(Request $request, Closure $next): Response
    {
        $id = bin2hex(random_bytes(8));
        // Read what travels in x-rg-* headers first: they are all stripped below.
        $actionToken = self::server($request, 'X-RG-Token');
        $sessionInit = self::server($request, 'X-RG-Session-Init');
        self::stripRgHeaders($request);

        $raw = self::rawTarget($request);
        $hostHeader = self::server($request, 'Host');
        $method = (string) $request->server->get('REQUEST_METHOD', $request->getMethod());
        $dreq = [
            'host' => $hostHeader,
            'method' => $method,
            'rawTarget' => $raw,
            'fetchMode' => strcasecmp(self::server($request, 'Sec-Fetch-Mode'), 'navigate') === 0 ? 'navigate' : 'other',
            'acceptsHtml' => self::acceptsHtml($request),
        ];

        $b = $this->fw->currentBundle();
        if ($b === null) {
            if ($this->fw->failOpen() || $this->fw->noPolicies()) {
                $this->logDecision($id, null, 'allow-no-bundle');
                self::setHeader($request, 'X-RG-Verdict', 'none');
                return $next($request);
            }
            $this->logDecision($id, null, 'block-no-bundle');
            return $this->respond(503, ['Retry-After' => '30']);
        }
        if (($b['disabled'] ?? false) === true) {
            // Kill switch: no rules, cookies, challenge, X-RG-Sig or verify call, whatever failMode says.
            return $next($request);
        }
        $now = $this->fw->nowSeconds();
        $vary = $b['usesCookies'];

        $n = Normalize::normalize($raw);
        if ($n['ok'] && $now <= $b['expiresAt'] + Limits::STALE_GRACE_SECONDS) {
            if ($n['path'] === Limits::PATH_RETURN) {
                return $this->serveReturn($request, $b, $id, $now, $method, $hostHeader);
            }
            if ($n['path'] === Limits::PATH_SESSION) {
                return $this->serveSession($b, $id, $now, $method, $hostHeader, $sessionInit);
            }
            // The rest of the /__rg/ namespace belongs to the integration and never reaches the origin.
            if (self::inReserved($n['path']) || self::inReserved($n['collapsed'])) {
                $this->logDecision($id, null, 'reserved-namespace');
                return $this->respond(404);
            }
        }

        $host = Host::requestHost($hostHeader);
        $sess = ['kind' => 'none', 'lvl' => 0, 'sc' => 0];
        if ($host !== null) {
            $sess = $this->sessionFromCookies($request, $b, $host, $now);
        }
        $d = Decide::decide($b, $dreq, $sess, null, $now);
        if ($d['kind'] === 'needs-verify') {
            $out = $actionToken === ''
                ? ['kind' => 'absent', 'score' => 0.0]
                : $this->fw->siteverify($actionToken, $host ?? '', $d['verify']['expectedAction']);
            $d = Decide::decide($b, $dreq, $sess, $out, $now);
        }
        $this->logDecision($id, $d['ruleIndex'], $d['kind']);

        switch ($d['kind']) {
            case 'allow':
                $set = $this->fw->signHeaders($d['setHeaders'], $host ?? '', $method, $raw, ($b['sigHeader'] ?? false) === true);
                foreach ($set as $k => $v) {
                    self::setHeader($request, (string) $k, $v);
                }
                $response = $next($request);
                if ($vary) {
                    $response->headers->set('Vary', 'Cookie', false);
                }
                return $response;
            case 'block':
                return $this->respond($d['status'], [], $vary);
            case 'redirect':
                return $this->respond($d['status'], ['Location' => $d['location']], $vary);
            case 'challenge':
                // setHeader values are origin-bound only: nothing but the action marker reaches the client.
                $extra = [];
                $cookies = [];
                if (isset($d['setHeaders']['X-RG-Action'])) {
                    $extra['X-RG-Action'] = $d['setHeaders']['X-RG-Action'];
                }
                if ($d['status'] === 303) {
                    $extra['Location'] = $d['location'];
                    $rp = self::returnPathFor($raw);
                    if ($rp !== '') {
                        $cookies[] = self::cookieHeader(Limits::COOKIE_RETURN_PATH, $rp, 600);
                    }
                }
                return $this->respond($d['status'], $extra, $vary, $cookies);
            default: // needs-verify cannot survive the second decision; fail closed
                return $this->respond(403, [], $vary);
        }
    }

    /** Runs after the response is sent: refreshes the bundle when it is due. */
    public function terminate(Request $request, Response $response): void
    {
        $this->fw->refreshIfDue();
    }

    private static function inReserved(string $p): bool
    {
        return $p === '/__rg' || str_starts_with($p, '/__rg/');
    }

    /** The normalised path plus the raw query of a challenged GET, if it is a safe, cookie-safe path of at most 2 KiB. */
    public static function returnPathFor(string $raw): string
    {
        $n = Normalize::normalize($raw);
        if (!$n['ok']) {
            return '';
        }
        $cand = $n['path'];
        $q = strpos($raw, '?');
        if ($q !== false) {
            $qs = substr($raw, $q);
            $h = strpos($qs, '#');
            if ($h !== false) {
                $qs = substr($qs, 0, $h);
            }
            $cand .= $qs;
        }
        if (strlen($cand) > Limits::MAX_RETURN_PATH_LENGTH || !Headers::isSafeReturnPath($cand) || !self::cookieSafe($cand)) {
            return '';
        }
        return $cand;
    }

    /**
     * A valid clearance or session cookie wins (the higher level); a present but invalid one gives
     * "invalid"; none gives "none".
     *
     * @return array{kind:string,lvl:int,sc:int}
     */
    private function sessionFromCookies(Request $r, array $b, string $host, int $now): array
    {
        $best = ['kind' => 'none', 'lvl' => 0, 'sc' => 0];
        foreach ([Limits::COOKIE_CLEARANCE, Limits::COOKIE_SESSION] as $name) {
            $v = self::cookie($r, $name);
            if ($v === null || $v === '') {
                continue;
            }
            if (strlen($name) + 1 + strlen($v) > Limits::MAX_COOKIE_BYTES) {
                $st = ['kind' => 'invalid', 'lvl' => 0, 'sc' => 0];
            } else {
                $st = $this->verify($v, $b, $host, $now)['state'];
            }
            if ($st['kind'] === 'valid' && ($best['kind'] !== 'valid' || $st['lvl'] > $best['lvl'])) {
                $best = $st;
            } elseif ($st['kind'] === 'invalid' && $best['kind'] === 'none') {
                $best = $st;
            }
        }
        return $best;
    }

    private function verify(string $token, array $b, string $host, int $now): array
    {
        return Session::verifyClaims(
            $token,
            $b['tokenKeys'],
            ['siteId' => $b['siteId'], 'host' => $host],
            ['minIat' => $b['minIat'], 'revokedJti' => $b['revokedJti']],
            $now,
        );
    }

    private static function hostCovered(array $b, string $host): bool
    {
        foreach ($b['hosts'] as $p) {
            if (Host::hostnameMatches($host, $p)) {
                return true;
            }
        }
        return false;
    }

    /** POST /__rg/session: the session token comes in X-RG-Session-Init and leaves in __Host-rg_s. No body is read. */
    private function serveSession(array $b, string $id, int $now, string $method, string $hostHeader, string $init): Response
    {
        if ($method !== 'POST') {
            return $this->respond(405, ['Allow' => 'POST']);
        }
        $host = Host::requestHost($hostHeader);
        if ($host === null || !self::hostCovered($b, $host)) {
            return $this->respond(400);
        }
        $r = $this->verify($init, $b, $host, $now);
        if ($r['state']['kind'] !== 'valid' || $r['state']['lvl'] !== 0
            || strlen(Limits::COOKIE_SESSION) + 1 + strlen($init) > Limits::MAX_COOKIE_BYTES || !self::cookieSafe($init)) {
            $this->logDecision($id, null, 'session-refused');
            return $this->respond(403);
        }
        $this->logDecision($id, null, 'session-set');
        return $this->respond(204, [], false, [self::cookieHeader(Limits::COOKIE_SESSION, $init, $r['claims']['exp'] - $now)]);
    }

    /** The urlencoded body (at most 4 KiB), or null when it is larger. */
    private static function readBody(Request $r): ?string
    {
        $len = $r->server->get('CONTENT_LENGTH');
        if (is_numeric($len) && (int) $len > Limits::RETURN_BODY_LIMIT) {
            return null;
        }
        $stream = $r->getContent(true);
        $body = is_resource($stream) ? (string) stream_get_contents($stream, Limits::RETURN_BODY_LIMIT + 1) : '';
        return strlen($body) > Limits::RETURN_BODY_LIMIT ? null : $body;
    }

    /** The value of the only field, rg_clearance, in an urlencoded body (exactly one field, exactly once); else null. */
    public static function singleField(string $body): ?string
    {
        if (str_contains($body, ';') || preg_match('/%(?![0-9A-Fa-f]{2})/', $body) === 1) {
            return null;
        }
        $found = null;
        $fields = 0;
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            $k = urldecode($eq === false ? $pair : substr($pair, 0, $eq));
            $v = urldecode($eq === false ? '' : substr($pair, $eq + 1));
            $fields++;
            if ($k !== Limits::RETURN_FIELD || $found !== null) {
                return null;
            }
            $found = $v;
        }
        return $fields === 1 ? $found : null;
    }

    /** POST /__rg/return: the only route that reads a body (urlencoded, at most 4 KiB, field rg_clearance). */
    private function serveReturn(Request $request, array $b, string $id, int $now, string $method, string $hostHeader): Response
    {
        if ($method !== 'POST') {
            return $this->respond(405, ['Allow' => 'POST']);
        }
        $host = Host::requestHost($hostHeader);
        if ($host === null || !self::hostCovered($b, $host)) {
            return $this->respond(400);
        }
        $ct = (string) $request->server->get('CONTENT_TYPE', self::server($request, 'Content-Type'));
        $semi = strpos($ct, ';');
        $mt = strtolower(trim($semi === false ? $ct : substr($ct, 0, $semi)));
        if ($mt !== 'application/x-www-form-urlencoded') {
            return $this->respond(415);
        }
        $body = self::readBody($request);
        if ($body === null) {
            return $this->respond(413);
        }
        $tok = self::singleField($body);
        if ($tok === null) {
            return $this->respond(400);
        }
        $r = $this->verify($tok, $b, $host, $now);
        if ($r['state']['kind'] !== 'valid' || $r['state']['lvl'] < 1
            || strlen(Limits::COOKIE_CLEARANCE) + 1 + strlen($tok) > Limits::MAX_COOKIE_BYTES || !self::cookieSafe($tok)) {
            $this->logDecision($id, null, 'return-refused');
            return $this->respond(403);
        }
        $location = '/';
        $rp = self::cookie($request, Limits::COOKIE_RETURN_PATH);
        if ($rp !== null && Headers::isSafeReturnPath($rp)) {
            $location = $rp;
        }
        $this->logDecision($id, null, 'return');
        return $this->respond(303, ['Location' => $location], false, [
            self::cookieHeader(Limits::COOKIE_CLEARANCE, $tok, $r['claims']['exp'] - $now),
            self::cookieHeader(Limits::COOKIE_RETURN_PATH, '', 0),
        ]);
    }
}
