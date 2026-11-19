<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall;

use Closure;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use RevokeGPT\Firewall\Core\Bundle;
use RevokeGPT\Firewall\Core\Json;
use RevokeGPT\Firewall\Core\Limits;
use RevokeGPT\Firewall\Core\Schema;
use RevokeGPT\Firewall\Core\Normalize;
use RevokeGPT\Firewall\Core\Sig;
use RevokeGPT\Firewall\Http\CurlTransport;
use RevokeGPT\Firewall\Http\TransportException;

/**
 * The verified bundle, the siteverify client and their shared state. PHP serves each request in a
 * fresh process, so everything that must outlive one request lives in the Laravel Cache store
 * (APCu or file): the verified bundle, its ETag, the refresh schedule, the highest accepted bundle
 * version and the circuit breaker. A refresh runs under Cache::lock (single-flight).
 *
 * Config keys: siteKey (required), secretKey, apiBase, siteId, pinnedKeys, initialFailMode
 * ("open" default, or "closed"), refreshIntervalMs (an override has no jitter), sigSecret (string of
 * at least 16 characters; enables the opt-in X-RG-Sig header when the bundle asks for it).
 */
final class Firewall
{
    public const VERSION = '0.1.1';
    private const DEFAULT_API_BASE = 'https://api.revokegpt.com';
    private const SITEVERIFY_TIMEOUT = 2.0;
    private const BUNDLE_TIMEOUT = 5.0;
    private const MAX_SITEVERIFY_BODY = 65536;
    private const BREAKER_THRESHOLD = 5;
    private const BREAKER_OPEN_FOR = 30.0;
    private const REFRESH_BASE = 60.0;
    private const REFRESH_EXTRA = 20.0;
    private const COLD_RETRY_AFTER = 10.0; // protocol v1 section 18.5: no more often than every 10 s while no bundle is held

    private readonly string $siteKey;
    private readonly string $secret;
    private readonly string $apiBase;
    private readonly string $integration;
    /** @var list<array{kid:string,alg:string,pub:string,notAfter:int}> */
    private readonly array $pinned;
    private readonly bool $failOpen;
    private readonly bool $siteIdPinned;
    private readonly bool $canonicalSiteKey;
    private readonly float $refreshBase;
    private readonly float $refreshExtra;
    private readonly string $stateKey;
    private readonly string $breakerKey;
    private readonly string $lockName;
    private readonly string $pinFingerprint;
    private readonly Closure $transport;
    private readonly Closure $clock;
    private readonly ?string $sigSecret;
    private bool $sigWarned = false;
    private ?string $pinnedSiteId;
    private bool $refreshDue = false;
    private bool $authLogged = false;
    /** Config errors logged for a refused bundle fetch (tests). */
    public int $authErrors = 0;
    /** @var array<string,array<string,mixed>> sha1(served) => verified payload, for long-lived workers */
    private static array $memo = [];

    public function __construct(
        array $config,
        private readonly Repository $cache,
        ?Closure $transport = null,
        ?Closure $clock = null,
        private readonly ?LoggerInterface $log = null,
    ) {
        $siteKey = $config['siteKey'] ?? null;
        if (!is_string($siteKey) || preg_match('/\Argpk_[A-Za-z0-9_]+\z/D', $siteKey) !== 1 || strlen($siteKey) > 128) {
            throw new InvalidArgumentException('firewall: invalid siteKey');
        }
        $secret = $config['secretKey'] ?? '';
        if ($secret !== '' && $secret !== null && (!is_string($secret) || preg_match('/\Argsk_[A-Za-z0-9_-]+\z/D', $secret) !== 1 || strlen($secret) > 256)) {
            throw new InvalidArgumentException('firewall: invalid secretKey');
        }
        $base = $config['apiBase'] ?? '';
        $base = ($base === null || $base === '') ? self::DEFAULT_API_BASE : $base;
        $u = is_string($base) ? parse_url($base) : false;
        if ($u === false || !isset($u['scheme'], $u['host']) || isset($u['user']) || isset($u['pass']) || isset($u['query'])
            || isset($u['fragment']) || (isset($u['path']) && $u['path'] !== '' && $u['path'] !== '/')
            || str_ends_with((string) $base, '?') || str_ends_with((string) $base, '#')) {
            throw new InvalidArgumentException('firewall: invalid apiBase');
        }
        $host = strtolower($u['host']);
        $local = in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
        if ($u['scheme'] !== 'https' && !($u['scheme'] === 'http' && $local)) {
            throw new InvalidArgumentException('firewall: apiBase must be https');
        }
        $canonical = preg_match(Schema::RE_SITE_KEY, $siteKey) === 1;
        $pinned = $config['pinnedKeys'] ?? null;
        foreach ($pinned ?? [] as $k) {
            if (Sig::isTestKey($k) && ($canonical || !$local)) {
                throw new InvalidArgumentException(
                    'firewall: TEST keys are allowed only for a non-canonical site key with a loopback API base',
                );
            }
        }
        $siteId = $config['siteId'] ?? null;
        if ($siteId !== null && $siteId !== '' && (!is_string($siteId) || preg_match(Schema::RE_SITE_ID, $siteId) !== 1)) {
            throw new InvalidArgumentException('firewall: invalid siteId');
        }
        $ifm = $config['initialFailMode'] ?? null;
        if ($ifm !== null && $ifm !== '' && $ifm !== 'open' && $ifm !== 'closed') {
            throw new InvalidArgumentException('firewall: invalid initialFailMode');
        }
        $sigSecret = $config['sigSecret'] ?? null;
        if ($sigSecret === '') {
            $sigSecret = null;
        }
        if ($sigSecret !== null && (!is_string($sigSecret) || strlen($sigSecret) < 16)) {
            throw new InvalidArgumentException('firewall: invalid sigSecret');
        }
        $this->sigSecret = $sigSecret;
        $this->siteKey = $siteKey;
        $this->secret = (string) $secret;
        $this->apiBase = $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
        $this->integration = 'laravel/' . self::VERSION;
        $this->pinned = $pinned ?? Sig::pinnedPolicyKeys();
        $this->pinFingerprint = sha1((string) json_encode($this->pinned) . ($canonical ? 'c' : 'n'));
        $this->failOpen = $ifm !== 'closed';
        $this->canonicalSiteKey = $canonical;
        $this->pinnedSiteId = ($siteId === null || $siteId === '') ? null : $siteId;
        $this->siteIdPinned = $this->pinnedSiteId !== null;
        $ms = $config['refreshIntervalMs'] ?? null;
        if (is_int($ms) && $ms > 0) {
            $this->refreshBase = $ms / 1000;
            $this->refreshExtra = 0.0;
        } else {
            $this->refreshBase = self::REFRESH_BASE;
            $this->refreshExtra = self::REFRESH_EXTRA;
        }
        $this->transport = $transport ?? Closure::fromCallable(new CurlTransport());
        $this->clock = $clock ?? static fn (): float => microtime(true);
        $h = sha1($siteKey);
        $this->stateKey = 'rg:fw:state:' . $h;
        $this->breakerKey = 'rg:fw:breaker:' . $h;
        $this->lockName = 'rg:fw:refresh:' . $h;
    }

    public function nowSeconds(): int
    {
        return (int) floor(($this->clock)());
    }

    private function nowF(): float
    {
        return ($this->clock)();
    }

    /** True while no bundle has ever been verified and the initial fail mode is "open". */
    public function failOpen(): bool
    {
        return $this->failOpen;
    }

    // ---- shared state -------------------------------------------------------------------------

    /**
     * The shared state. 'served' is the signed envelope exactly as the API sent it (scalars only, so no
     * object ever goes through the cache serializer); it is re-verified when read.
     *
     * @return array{served:?string,etag:string,nextRefresh:float,siteId:?string,lastFail:float,notFound:bool}
     */
    private function state(): array
    {
        $s = $this->cache->get($this->stateKey);
        if (!is_array($s) || !array_key_exists('served', $s)) {
            return ['served' => null, 'etag' => '', 'nextRefresh' => 0.0, 'siteId' => $this->pinnedSiteId,
                'lastFail' => 0.0, 'notFound' => false];
        }
        return $s;
    }

    /**
     * The verified payload of the cached bundle, or null. The signature, site binding and key are
     * checked again on every read, so a tampered cache entry is never trusted.
     *
     * @return array<string,mixed>|null
     */
    private function cachedPayload(array $s): ?array
    {
        if ($s['served'] === null) {
            return null;
        }
        $h = sha1($s['served'] . '|' . $this->pinFingerprint . '|' . ($s['siteId'] ?? '') . '|' . $this->siteKey);
        if (isset(self::$memo[$h])) {
            return self::$memo[$h];
        }
        $expect = ['siteId' => $s['siteId'] ?? '', 'anySite' => ($s['siteId'] ?? null) === null, 'serving' => true];
        if ($this->siteIdPinned || $this->canonicalSiteKey) {
            $expect['siteKey'] = $this->siteKey;
        }
        $res = Bundle::verify($s['served'], $this->pinned, $this->nowSeconds(), 0, $expect);
        if (!$res['ok']) {
            return null;
        }
        self::$memo = [$h => $res['payload']];
        return $res['payload'];
    }

    private function saveState(array $s): void
    {
        $this->cache->forever($this->stateKey, $s);
    }

    /** True while the policies endpoint answers an authentic 404 (no published policies) and nothing is cached. */
    public function noPolicies(): bool
    {
        $s = $this->state();
        return $s['notFound'] && $s['served'] === null;
    }

    private function versionKey(string $siteId): string
    {
        return 'rg:fw:version:' . $siteId;
    }

    private function storedVersion(string $siteId): int
    {
        $v = $this->cache->get($this->versionKey($siteId));
        return is_int($v) ? $v : 0;
    }

    private function storeVersion(string $siteId, int $version): void
    {
        if ($version > $this->storedVersion($siteId)) {
            $this->cache->forever($this->versionKey($siteId), $version);
        }
    }

    private function refreshDelay(): float
    {
        return $this->refreshBase + ($this->refreshExtra > 0 ? (mt_rand() / mt_getrandmax()) * $this->refreshExtra : 0.0);
    }

    /**
     * Adds X-RG-Sig to the headers sent toward the origin when the bundle asks for it ($bundleWantsSig)
     * and a sigSecret is configured: "t=<unix seconds>,v1=<hex HMAC-SHA256>" over
     * t, host, method, normalized path, X-RG-Score, X-RG-Verdict and X-RG-Rule joined by "\n".
     *
     * @param array<string,string> $h
     * @return array<string,string>
     */
    public function signHeaders(array $h, string $host, string $method, string $rawTarget, bool $bundleWantsSig): array
    {
        if (!$bundleWantsSig) {
            return $h;
        }
        if ($this->sigSecret === null) {
            if (!$this->sigWarned) {
                $this->sigWarned = true;
                $this->warn('config-warning:sig-secret-missing');
            }
            return $h;
        }
        $t = $this->nowSeconds();
        $n = Normalize::normalize($rawTarget);
        $data = implode("\n", [
            (string) $t, $host, $method, $n['ok'] ? $n['path'] : '',
            $h['X-RG-Score'] ?? '', $h['X-RG-Verdict'] ?? '', $h['X-RG-Rule'] ?? '',
        ]);
        $h['X-RG-Sig'] = 't=' . $t . ',v1=' . hash_hmac('sha256', $data, $this->sigSecret);
        return $h;
    }

    private function warn(string $msg): void
    {
        $this->log?->warning($msg);
    }

    // ---- bundle -------------------------------------------------------------------------------

    private function request(string $method, string $path, float $timeout, int $maxBytes, ?string $body = null, array $extra = []): array
    {
        $headers = ['Accept' => 'application/json', 'X-RG-Integration' => $this->integration] + $extra;
        if ($this->secret !== '') {
            $headers['Authorization'] = 'Bearer ' . $this->secret;
        }
        return ($this->transport)($method, $this->apiBase . $path, $headers, $body, $timeout, $maxBytes);
    }

    /**
     * Fetches, verifies and installs a bundle; any failure keeps the last good bundle (a bad signature
     * is treated as no bundle). Call only while holding the refresh lock, or when no lock is available.
     */
    private function refresh(): void
    {
        $s = $this->state();
        $now = $this->nowF();
        $extra = $s['etag'] !== '' ? ['If-None-Match' => $s['etag']] : [];
        try {
            $resp = $this->request('GET', '/v1/policies/' . $this->siteKey, self::BUNDLE_TIMEOUT, Limits::MAX_SERVED_BYTES, null, $extra);
        } catch (TransportException) {
            $s['notFound'] = false;
            $this->noteFailure($s, $now, 'fetch-error');
            return;
        }
        $status = $resp['status'];
        $havePayload = $this->cachedPayload($s) !== null;
        $s['notFound'] = $status === 404 && !$havePayload;
        if ($status === 304 && $havePayload) {
            $s['nextRefresh'] = $now + $this->refreshDelay();
            $this->saveState($s);
            return;
        }
        if (($status === 401 || $status === 403) && !$this->authLogged) {
            // A private bundle needs the site secret as a Bearer: a configuration error, logged once
            // (never the secret) and handled as an outage like any other failure.
            $this->authLogged = true;
            $this->authErrors++;
            $this->log?->error('rg config error: bundle-unauthorized (status ' . $status . ')');
        }
        if ($status !== 200 || strlen($resp['body']) > Limits::MAX_SERVED_BYTES) {
            $this->noteFailure($s, $now, 'fetch-error');
            return;
        }
        $siteId = $s['siteId'];
        $minVersion = $siteId !== null ? $this->storedVersion($siteId) : 0;
        // The cached bundle's own version is a floor too: it survives a lost or evicted floor key.
        $cached = $this->cachedPayload($s);
        if ($cached !== null) {
            $minVersion = max($minVersion, (int) $cached['version']);
        }
        $expect = ['siteId' => $siteId ?? '', 'anySite' => $siteId === null];
        if ($this->siteIdPinned || $this->canonicalSiteKey) {
            $expect['siteKey'] = $this->siteKey; // a canonical production key always checks the bundle's siteKey
        }
        $res = Bundle::verify($resp['body'], $this->pinned, (int) floor($now), $minVersion, $expect);
        if (!$res['ok']) {
            $this->noteFailure($s, $now, 'bundle-' . $res['reason']);
            return;
        }
        $payload = $res['payload'];
        $this->saveState([
            'served' => $resp['body'],
            'etag' => $resp['headers']['etag'] ?? '',
            'nextRefresh' => $now + $this->refreshDelay(),
            // trust on first use: the pinned key signed the bundle
            'siteId' => $s['siteId'] ?? $payload['siteId'],
            'lastFail' => 0.0,
            'notFound' => false,
        ]);
        $this->storeVersion($payload['siteId'], $payload['version']);
    }

    private function noteFailure(array $s, float $now, string $why): void
    {
        $s['lastFail'] = $now;
        if ($s['served'] !== null) {
            $s['nextRefresh'] = $now + $this->refreshDelay();
        }
        $this->saveState($s);
        $this->warn('rg bundle refresh failed: ' . $why);
    }

    private function lock(int $seconds): ?object
    {
        $store = $this->cache->getStore();
        return $store instanceof LockProvider ? $store->lock($this->lockName, $seconds) : null;
    }

    /**
     * The last good verified bundle. With none cached it fetches one under the lock (single-flight, so
     * concurrent requests do not stampede the API); with one cached it serves it and flags a refresh
     * that {@see refreshIfDue()} runs after the response.
     *
     * @return array<string,mixed>|null
     */
    public function currentBundle(): ?array
    {
        $s = $this->state();
        $p = $this->cachedPayload($s);
        if ($p !== null) {
            $this->refreshDue = $this->nowF() >= $s['nextRefresh'];
            return $p;
        }
        if ($s['lastFail'] > 0 && $this->nowF() - $s['lastFail'] < self::COLD_RETRY_AFTER) {
            return null;
        }
        $lock = $this->lock(15);
        $held = false;
        if ($lock !== null) {
            try {
                $held = $lock->block(5);
            } catch (\Throwable) {
                $held = false;
            }
        }
        try {
            $s = $this->state();
            if ($this->cachedPayload($s) === null
                && !($s['lastFail'] > 0 && $this->nowF() - $s['lastFail'] < self::COLD_RETRY_AFTER)) {
                $this->refresh();
            }
        } finally {
            if ($held) {
                $lock->release();
            }
        }
        return $this->cachedPayload($this->state());
    }

    /** Refreshes the bundle when it is due. Run it after the response (the middleware's terminate step). */
    public function refreshIfDue(): void
    {
        if (!$this->refreshDue) {
            return;
        }
        $this->refreshDue = false;
        $lock = $this->lock(15);
        if ($lock !== null && !$lock->get()) {
            return; // another process is already refreshing
        }
        try {
            $s = $this->state();
            if ($this->cachedPayload($s) === null || $this->nowF() >= $s['nextRefresh']) {
                $this->refresh();
            }
        } finally {
            $lock?->release();
        }
    }

    // ---- siteverify ---------------------------------------------------------------------------

    /** Length 20 to 4096 and only base64url characters and ".". A token failing it is never sent anywhere. */
    public static function validActionToken(string $t): bool
    {
        return strlen($t) >= 20 && strlen($t) <= 4096 && preg_match('/\A[A-Za-z0-9_.-]+\z/D', $t) === 1;
    }

    /** @return array{fails:int,until:float} */
    private function breaker(): array
    {
        $b = $this->cache->get($this->breakerKey);
        return is_array($b) ? $b : ['fails' => 0, 'until' => 0.0];
    }

    private function breakerFailure(): void
    {
        $b = $this->breaker();
        $b['fails']++;
        if ($b['fails'] >= self::BREAKER_THRESHOLD) {
            $b['until'] = $this->nowF() + self::BREAKER_OPEN_FOR;
        }
        $this->cache->put($this->breakerKey, $b, 3600);
    }

    private function breakerSuccess(): void
    {
        $this->cache->forget($this->breakerKey);
    }

    /**
     * POST /v1/siteverify: 2 s timeout, one retry on a connection error only (never on a timeout), a
     * circuit breaker (5 consecutive failures open it for 30 s, with nothing sent meanwhile). The
     * outcome is "pass" only for success:true with this host and this action and a score in [0,1].
     *
     * @return array{kind:string,score:float,reason?:string}
     */
    public function siteverify(string $token, string $host, string $expectedAction): array
    {
        if (!self::validActionToken($token)) {
            return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'malformed-token'];
        }
        if ($this->secret === '') {
            return ['kind' => 'unreachable', 'score' => 0.0, 'reason' => 'no-secret'];
        }
        if ($this->nowF() < $this->breaker()['until']) {
            return ['kind' => 'unreachable', 'score' => 0.0, 'reason' => 'breaker-open'];
        }
        // The secret travels only as the Authorization Bearer (request()): the edge answers bad-request
        // when it is also in the body.
        $form = http_build_query(['response' => $token], '', '&', PHP_QUERY_RFC1738);
        // One 2 s budget for everything (connect, send, the full body, and the retry).
        $deadline = microtime(true) + self::SITEVERIFY_TIMEOUT;
        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $resp = $this->request('POST', '/v1/siteverify', max(0.05, $deadline - microtime(true)),
                    self::MAX_SITEVERIFY_BODY + 1, $form, ['Content-Type' => 'application/x-www-form-urlencoded']);
            } catch (TransportException $e) {
                // Retry once, only when the connection could not be established (nothing was sent) and
                // budget remains. A timeout, or any failure after the request may have been written, is final.
                if (!$e->connect || $e->timeout || microtime(true) >= $deadline) {
                    break;
                }
                continue;
            }
            // A 429 (the site over its siteverify rate limit, e.g. a junk-token flood) is an answer: fail
            // closed and never count it, so it cannot open the breaker into an onError allow bypass (E-1).
            if ($resp['status'] === 429) {
                $this->breakerSuccess();
                return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'rate-limited'];
            }
            if (strlen($resp['body']) > self::MAX_SITEVERIFY_BODY || $resp['status'] !== 200) {
                $this->breakerFailure();
                return ['kind' => 'unreachable', 'score' => 0.0, 'reason' => 'http-error'];
            }
            return $this->readSiteverify($resp['body'], $host, $expectedAction);
        }
        $this->breakerFailure();
        return ['kind' => 'unreachable', 'score' => 0.0, 'reason' => 'network-error'];
    }

    /** @return array{kind:string,score:float,reason?:string} */
    private function readSiteverify(string $body, string $host, string $expectedAction): array
    {
        [$ok, $m] = Json::parse($body);
        if (!$ok || !$m instanceof \stdClass) {
            $this->breakerFailure();
            return ['kind' => 'unreachable', 'score' => 0.0, 'reason' => 'bad-body'];
        }
        $this->breakerSuccess();
        if (Json::get($m, 'success') !== true) {
            return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'not-verified'];
        }
        if (Json::get($m, 'hostname') !== $host) {
            return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'hostname-mismatch'];
        }
        if (Json::get($m, 'action') !== $expectedAction) {
            return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'action-mismatch'];
        }
        $score = Json::asFloat(Json::get($m, 'score'));
        if ($score === null || $score < 0 || $score > 1) {
            return ['kind' => 'fail', 'score' => 0.0, 'reason' => 'score-invalid'];
        }
        return ['kind' => 'pass', 'score' => $score];
    }
}
