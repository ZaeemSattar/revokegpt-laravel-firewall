<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Tests;

use Closure;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\Repository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Http\Request;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;
use RevokeGPT\Firewall\Core\Sig;
use RevokeGPT\Firewall\Firewall;
use RevokeGPT\Firewall\Http\TransportException;
use RevokeGPT\Firewall\Http\RevokeGPTMiddleware;

/** A request that records whether anybody read its body. */
final class SpyRequest extends Request
{
    public bool $bodyRead = false;

    public function getContent(bool $asResource = false)
    {
        $this->bodyRead = true;
        return parent::getContent($asResource);
    }
}

/** The middleware against a fake API, using the signed bundle and the tokens of the shared vectors. */
final class MiddlewareTest extends TestCase
{
    private const NOW = 1790000000;
    private const SITE_ID = '3f1c2a9e-5b7d-4e2f-9a1b-0c8d7e6f5a4b';

    private array $vectors;
    private float $now = self::NOW;
    /** @var list<string> */
    private array $calls = [];
    private int $bundleFetches = 0;
    private int $bundleStatus = 200;
    private ?string $served = null;
    private ?string $verifyBody = null;
    private int $verifyStatus = 200;
    private ?string $transportError = null;
    private bool $transportConnect = true;
    private string $tmp;

    protected function setUp(): void
    {
        $this->vectors = json_decode((string) file_get_contents(VectorsTest::policyPath()), true);
        foreach ($this->vectors['bundle'] as $r) {
            if ($r['name'] === 'valid-current-key') {
                $this->served = $r['served'];
            }
        }
        $this->tmp = sys_get_temp_dir() . '/rg-php-test-' . bin2hex(random_bytes(4));
        mkdir($this->tmp);
        unset($_SERVER['HTTP_X_RG_SCORE'], $_SERVER['HTTP_X_RG_RULE']);
    }

    protected function tearDown(): void
    {
        (new Filesystem())->deleteDirectory($this->tmp);
    }

    private function token(string $row): string
    {
        foreach ($this->vectors['session'] as $r) {
            if ($r['name'] === $row) {
                return $r['token'];
            }
        }
        self::fail("no session row $row");
    }

    private function transport(): Closure
    {
        return function (string $method, string $url, array $headers, ?string $body, float $timeout, int $max): array {
            $path = (string) parse_url($url, PHP_URL_PATH);
            $this->calls[] = $method . ' ' . $path;
            if ($this->transportError !== null) {
                throw new TransportException($this->transportError, false, $this->transportConnect);
            }
            if (str_starts_with($path, '/v1/policies/')) {
                $this->bundleFetches++;
                return ['status' => $this->bundleStatus, 'headers' => ['etag' => '"v1"'],
                    'body' => $this->bundleStatus === 200 ? (string) $this->served : ''];
            }
            return ['status' => $this->verifyStatus, 'headers' => [], 'body' => (string) $this->verifyBody];
        };
    }

    private function repo(string $kind = 'array'): Repository
    {
        return $kind === 'file'
            ? new Repository(new FileStore(new Filesystem(), $this->tmp))
            : new Repository(new ArrayStore());
    }

    private function firewall(array $extra = [], ?Repository $repo = null): Firewall
    {
        $cfg = $extra + [
            'siteKey' => 'rgpk_conformance',
            'secretKey' => 'rgsk_conformance',
            'apiBase' => 'http://127.0.0.1:1',
            'pinnedKeys' => Sig::testPolicyKeys(),
        ];
        return new Firewall($cfg, $repo ?? $this->repo(), $this->transport(), fn (): float => $this->now);
    }

    /** @return array{0:Response|null,1:Request|null} [response from the middleware, request the origin saw] */
    private function send(Firewall $fw, string $method, string $target, array $headers = [], ?string $content = null, ?Request $req = null): array
    {
        $server = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $target, 'HTTP_HOST' => 'example.com'];
        foreach ($headers as $k => $v) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
        }
        if (isset($headers['Content-Type'])) {
            $server['CONTENT_TYPE'] = $headers['Content-Type'];
        }
        if ($content !== null) {
            $server['CONTENT_LENGTH'] = (string) strlen($content);
        }
        $request = $req ?? new Request([], [], [], [], [], $server, $content);
        if ($req !== null) {
            $request->server->add($server);
        }
        $seen = null;
        $mw = new RevokeGPTMiddleware($fw);
        $response = $mw->handle($request, function (Request $r) use (&$seen): Response {
            $seen = $r;
            return new Response('origin');
        });
        $reached = $seen !== null;
        return [$response, $reached ? $seen : null];
    }

    public function testAllowStripsClientRgHeadersAndSetsRule(): void
    {
        $fw = $this->firewall();
        $_SERVER['HTTP_X_RG_SCORE'] = '100';
        [$res, $seen] = $this->send($fw, 'GET', '/x/page', [
            'X-RG-Score' => '100', 'X_RG_Rule' => '9', 'X-RG-Verdict' => 'pass', 'X-Rgx' => 'kept',
        ]);
        self::assertNotNull($seen);
        self::assertNull($seen->headers->get('X-RG-Score'));
        self::assertNull($seen->server->get('HTTP_X_RG_SCORE'));
        self::assertNull($seen->server->get('HTTP_X_RG_RULE'));
        self::assertNull($seen->headers->get('X-RG-Verdict'));
        self::assertSame('kept', $seen->headers->get('X-Rgx'));
        self::assertArrayNotHasKey('HTTP_X_RG_SCORE', $_SERVER);
        foreach ($seen->headers->keys() as $name) {
            self::assertStringStartsNotWith('x-rg-', strtolower(str_replace('_', '-', (string) $name)));
        }
        self::assertSame(1, $this->bundleFetches);
    }

    public function testBlockCarriesNoStore(): void
    {
        [$res, $seen] = $this->send($this->firewall(), 'GET', '/admin/panel');
        self::assertNull($seen);
        self::assertSame(403, $res->getStatusCode());
        self::assertStringContainsString('no-store', (string) $res->headers->get('Cache-Control'));
    }

    public function testRawTargetPathDifferential(): void
    {
        $fw = $this->firewall();
        foreach (['//admin/x', '/Admin/../admin/x', '/admin/./x', '/./admin/x'] as $t) {
            [$res, $seen] = $this->send($fw, 'GET', $t);
            self::assertNull($seen, "$t reached the origin");
            self::assertSame(403, $res->getStatusCode(), $t);
        }
        foreach (['/admin%2Fsecret', '/%2e%2e/admin', '/admin;jsessionid=1', '/%C0%AF'] as $t) {
            [$res, $seen] = $this->send($fw, 'POST', $t);
            self::assertNull($seen, $t);
            self::assertSame(403, $res->getStatusCode(), $t);
            [, $seen] = $this->send($fw, 'GET', $t);
            self::assertNotNull($seen, $t);
            self::assertSame('non-canonical', $seen->headers->get('X-RG-Path'));
            self::assertSame('none', $seen->headers->get('X-RG-Verdict'));
        }
        self::assertSame(400, $this->send($fw, 'GET', '/a%zz')[0]->getStatusCode());
        self::assertSame(400, $this->send($fw, 'GET', '/a\\b')[0]->getStatusCode());
    }

    public function testRequireTokenFlow(): void
    {
        $fw = $this->firewall();
        self::assertSame(403, $this->send($fw, 'POST', '/login')[0]->getStatusCode());
        self::assertNotContains('POST /v1/siteverify', $this->calls);
        self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => 'short'])[0]->getStatusCode());
        self::assertNotContains('POST /v1/siteverify', $this->calls);

        $this->verifyBody = '{"success":true,"hostname":"example.com","action":"login","score":0.9}';
        [, $seen] = $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)]);
        self::assertNotNull($seen);
        self::assertSame('90', $seen->headers->get('X-RG-Score'));
        self::assertSame('pass', $seen->headers->get('X-RG-Verdict'));
        self::assertSame('1', $seen->headers->get('X-RG-Rule'));
        self::assertSame(1, count(array_keys($this->calls, 'POST /v1/siteverify', true)));

        $this->verifyBody = '{"success":true,"hostname":"example.com","action":"other","score":0.9}';
        self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)])[0]->getStatusCode());
        $this->verifyBody = '{"success":true,"hostname":"example.com","action":"login","score":0.5}';
        self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)])[0]->getStatusCode());
    }

    public function testA429IsAFailAndNeverOpensTheBreaker(): void
    {
        // red team E-1: a junk-token flood over the site's siteverify rate limit gets 429s
        $fw = $this->firewall();
        $this->send($fw, 'GET', '/x');
        $this->verifyStatus = 429;
        for ($i = 0; $i < 10; $i++) {
            self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)])[0]->getStatusCode());
        }
        self::assertSame(10, count(array_keys($this->calls, 'POST /v1/siteverify', true)), 'the breaker stayed closed');
    }

    public function testBreakerOpensAfterFiveFailuresAndConnectionErrorRetriesOnce(): void
    {
        $fw = $this->firewall();
        $this->send($fw, 'GET', '/x'); // load the bundle first
        $this->verifyStatus = 500;
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)])[0]->getStatusCode());
        }
        $sent = count(array_keys($this->calls, 'POST /v1/siteverify', true));
        self::assertSame(5, $sent);
        self::assertSame(403, $this->send($fw, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)])[0]->getStatusCode());
        self::assertSame($sent, count(array_keys($this->calls, 'POST /v1/siteverify', true)), 'the open breaker sends nothing');

        // a connection error is retried once, never more (fresh firewall, so the breaker is closed)
        $fw2 = $this->firewall(['siteKey' => 'rgpk_other'], $this->repo());
        $this->send($fw2, 'GET', '/x');
        $this->calls = [];
        $this->transportError = 'connection refused';
        $this->send($fw2, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)]);
        self::assertSame(2, count(array_keys($this->calls, 'POST /v1/siteverify', true)));

        // a failure that may have happened after the request was sent (connect = false) is never retried
        $this->transportError = null;
        $fw3 = $this->firewall(['siteKey' => 'rgpk_third'], $this->repo());
        $this->send($fw3, 'GET', '/x');
        $this->calls = [];
        $this->transportError = 'connection reset';
        $this->transportConnect = false;
        $this->send($fw3, 'POST', '/login', ['X-RG-Token' => str_repeat('A', 40)]);
        self::assertSame(1, count(array_keys($this->calls, 'POST /v1/siteverify', true)));
    }

    public function testBodyIsNeverReadOutsideReturnRoute(): void
    {
        $fw = $this->firewall();
        $req = new SpyRequest([], [], [], [], [], [], 'rg_clearance=abc');
        $this->send($fw, 'POST', '/x/y', ['Content-Type' => 'application/x-www-form-urlencoded'], 'rg_clearance=abc', $req);
        self::assertFalse($req->bodyRead);
        // the action token is never taken from a body
        $this->verifyBody = '{"success":true,"hostname":"example.com","action":"login","score":0.9}';
        $body = new SpyRequest([], [], [], [], [], [], 'response=' . str_repeat('A', 40));
        [$res] = $this->send($fw, 'POST', '/login', ['Content-Type' => 'application/x-www-form-urlencoded'], 'response=' . str_repeat('A', 40), $body);
        self::assertSame(403, $res->getStatusCode());
        self::assertFalse($body->bodyRead);
        self::assertNotContains('POST /v1/siteverify', $this->calls);
    }

    public function testReturnRoute(): void
    {
        $fw = $this->firewall();
        $clearance = $this->token('valid-pow-clearance');
        $form = ['Content-Type' => 'application/x-www-form-urlencoded'];
        [$res, $seen] = $this->send($fw, 'POST', '/__rg/return', $form + ['Cookie' => '__Host-rg_r=/shop/cart?x=1'], 'rg_clearance=' . $clearance);
        self::assertNull($seen);
        self::assertSame(303, $res->getStatusCode());
        self::assertSame('/shop/cart?x=1', $res->headers->get('Location'));
        self::assertStringContainsString('no-store', (string) $res->headers->get('Cache-Control'));
        $cookies = [];
        foreach ($res->headers->getCookies() as $c) {
            $cookies[$c->getName()] = $c;
        }
        self::assertSame($clearance, $cookies['__Host-rg_c']->getValue());
        self::assertTrue($cookies['__Host-rg_c']->isSecure());
        self::assertTrue($cookies['__Host-rg_c']->isHttpOnly());
        self::assertSame('lax', $cookies['__Host-rg_c']->getSameSite());
        self::assertSame('/', $cookies['__Host-rg_c']->getPath());
        self::assertNull($cookies['__Host-rg_c']->getDomain());
        self::assertGreaterThan(0, $cookies['__Host-rg_c']->getMaxAge());
        self::assertSame(0, $cookies['__Host-rg_r']->getMaxAge(), 'the return cookie is cleared');
        // the exact wire format of section 18.7
        self::assertMatchesRegularExpression('/\A__Host-rg_c=' . preg_quote($clearance, '/') . '; Max-Age=\d+; HttpOnly; Secure; SameSite=Lax; Path=\/\z/', (string) $cookies['__Host-rg_c']);
        self::assertSame('__Host-rg_r=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/', (string) $cookies['__Host-rg_r']);

        // an unsafe stored return path lands on "/"
        [$res] = $this->send($fw, 'POST', '/__rg/return', $form + ['Cookie' => '__Host-rg_r=//evil.com'], 'rg_clearance=' . $clearance);
        self::assertSame('/', $res->headers->get('Location'));

        // a level 0 session is not a clearance; GET is 405; wrong content type 415; extra field 400; big 413
        self::assertSame(403, $this->send($fw, 'POST', '/__rg/return', $form, 'rg_clearance=' . $this->token('valid-session'))[0]->getStatusCode());
        self::assertSame(405, $this->send($fw, 'GET', '/__rg/return')[0]->getStatusCode());
        self::assertSame(415, $this->send($fw, 'POST', '/__rg/return', ['Content-Type' => 'application/json'], '{}')[0]->getStatusCode());
        self::assertSame(400, $this->send($fw, 'POST', '/__rg/return', $form, 'rg_clearance=' . $clearance . '&a=b')[0]->getStatusCode());
        self::assertSame(413, $this->send($fw, 'POST', '/__rg/return', $form, 'rg_clearance=' . str_repeat('A', 5000))[0]->getStatusCode());
    }

    public function testSessionRoute(): void
    {
        $fw = $this->firewall();
        $tok = $this->token('valid-session');
        [$res, $seen] = $this->send($fw, 'POST', '/__rg/session', ['X-RG-Session-Init' => $tok]);
        self::assertNull($seen);
        self::assertSame(204, $res->getStatusCode());
        $c = $res->headers->getCookies()[0];
        self::assertSame('__Host-rg_s', $c->getName());
        self::assertSame($tok, $c->getValue());
        self::assertSame(1740, $c->getMaxAge());
        self::assertTrue($c->isSecure() && $c->isHttpOnly());
        self::assertSame('__Host-rg_s=' . $tok . '; Max-Age=1740; HttpOnly; Secure; SameSite=Lax; Path=/', (string) $c);
        self::assertSame(403, $this->send($fw, 'POST', '/__rg/session', ['X-RG-Session-Init' => $this->token('valid-pow-clearance')])[0]->getStatusCode());
        self::assertSame(403, $this->send($fw, 'POST', '/__rg/session')[0]->getStatusCode());
        self::assertSame(405, $this->send($fw, 'GET', '/__rg/session')[0]->getStatusCode());
    }

    public function testReservedNamespaceNeverReachesTheOrigin(): void
    {
        $fw = $this->firewall();
        [$res, $seen] = $this->send($fw, 'GET', '/__rg/other');
        self::assertNull($seen);
        self::assertSame(404, $res->getStatusCode());
        self::assertSame(404, $this->send($fw, 'GET', '//__rg/x')[0]->getStatusCode());
    }

    public function testColdStartFailModes(): void
    {
        $this->bundleStatus = 500;
        [, $seen] = $this->send($this->firewall(), 'GET', '/admin/x');
        self::assertNotNull($seen, 'initialFailMode open passes');
        self::assertSame('none', $seen->headers->get('X-RG-Verdict'));

        [$res] = $this->send($this->firewall(['initialFailMode' => 'closed']), 'GET', '/x');
        self::assertSame(503, $res->getStatusCode());
        self::assertSame('30', $res->headers->get('Retry-After'));

        $this->bundleStatus = 404; // an authentic 404 (no policies) passes even when closed
        [, $seen] = $this->send($this->firewall(['initialFailMode' => 'closed']), 'GET', '/admin/x');
        self::assertNotNull($seen);
    }

    /** @return array{0:string,1:array<string,mixed>} [served bundle signed by a fresh key, the key pinned for it] */
    private function signedBundle(array $extra): array
    {
        $env = json_decode((string) $this->served, true);
        $payloadJson = (string) base64_decode(strtr($env['payload'], '-_', '+/'));
        $payload = $extra + json_decode($payloadJson, true);
        $bytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $kp = sodium_crypto_sign_keypair();
        $pub = sodium_crypto_sign_publickey($kp);
        $kid = \RevokeGPT\Firewall\Core\Sig::kidOfPublicKey($pub);
        $b64 = static fn (string $b): string => sodium_bin2base64($b, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $sig = sodium_crypto_sign_detached("rg-policy-v1\0" . $bytes, sodium_crypto_sign_secretkey($kp));
        $served = (string) json_encode(['alg' => 'Ed25519', 'kid' => $kid, 'payload' => $b64($bytes), 'sig' => $b64($sig)]);
        return [$served, ['kid' => $kid, 'alg' => 'Ed25519', 'pub' => $b64($pub), 'notAfter' => 4102444800]];
    }

    public function testDisabledBundlePassesEverythingThroughUntouched(): void
    {
        [$served, $key] = $this->signedBundle(['disabled' => true, 'sigHeader' => true]);
        $this->served = $served;
        $fw = $this->firewall(['pinnedKeys' => [$key], 'sigSecret' => '0123456789abcdef-secret', 'initialFailMode' => 'closed']);
        [$res, $seen] = $this->send($fw, 'GET', '/admin/x');
        self::assertNotNull($seen, 'the kill switch lets the request reach the origin');
        self::assertSame('origin', $res->getContent());
        self::assertNull($seen->headers->get('X-RG-Rule'));
        self::assertNull($seen->headers->get('X-RG-Sig'));
        self::assertNull($seen->headers->get('X-RG-Verdict'));
        self::assertCount(0, $res->headers->getCookies());
    }

    public function testDisabledMustBeABoolean(): void
    {
        [$served, $key] = $this->signedBundle(['disabled' => 'yes']);
        $this->served = $served;
        $fw = $this->firewall(['pinnedKeys' => [$key], 'initialFailMode' => 'closed']);
        self::assertSame(503, $this->send($fw, 'GET', '/x')[0]->getStatusCode(), 'a non-boolean disabled is an invalid bundle');
        [$served, $key] = $this->signedBundle(['disabled' => false]);
        $this->served = $served;
        $fw = $this->firewall(['pinnedKeys' => [$key], 'initialFailMode' => 'closed']);
        self::assertSame(403, $this->send($fw, 'GET', '/admin/x')[0]->getStatusCode());
    }

    public function testBundleSurvivesAnOutageAndIsSharedThroughTheFileCache(): void
    {
        // APCu absent: the file cache store carries the verified bundle between "requests".
        $repo = $this->repo('file');
        $fw = $this->firewall(['refreshIntervalMs' => 50], $repo);
        self::assertSame(403, $this->send($fw, 'GET', '/admin/x')[0]->getStatusCode());
        self::assertSame(1, $this->bundleFetches);

        // a second "process" (a new Firewall on the same store) does not fetch again
        $fw2 = $this->firewall(['refreshIntervalMs' => 50], $this->repo('file'));
        self::assertSame(403, $this->send($fw2, 'GET', '/admin/x')[0]->getStatusCode());
        self::assertSame(1, $this->bundleFetches);

        // due: the refresh runs after the response (terminate), a failing API keeps the last good bundle
        $this->now += 1;
        $this->bundleStatus = 500;
        $mw = new RevokeGPTMiddleware($fw2);
        $mw->handle(new Request([], [], [], [], [], ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/x', 'HTTP_HOST' => 'example.com']), fn () => new Response('o'));
        $mw->terminate(new Request(), new Response());
        self::assertSame(2, $this->bundleFetches);
        self::assertSame(403, $this->send($fw2, 'GET', '/admin/x')[0]->getStatusCode(), 'last good bundle kept');
    }

    public function testATamperedCacheEntryIsNeverTrusted(): void
    {
        $repo = $this->repo('file');
        $fw = $this->firewall([], $repo);
        $this->send($fw, 'GET', '/x');
        $key = 'rg:fw:state:' . sha1('rgpk_conformance');
        $state = $repo->get($key);
        $state['served'] = str_replace('"alg"', '"alg "', $state['served']); // break the envelope
        $repo->forever($key, $state);
        $this->bundleStatus = 500;
        // no verified bundle any more: the initial fail mode applies (open: passes, marked none)
        [, $seen] = $this->send($this->firewall([], $repo), 'GET', '/admin/x');
        self::assertNotNull($seen);
        self::assertSame('none', $seen->headers->get('X-RG-Verdict'));
    }

    public function testPlaceholderKeysFailClosed(): void
    {
        $fw = new Firewall(['siteKey' => 'rgpk_7Hq2LmZ9xK4aBc8DeFgH', 'apiBase' => 'https://api.example.com', 'initialFailMode' => 'closed'],
            $this->repo(), $this->transport(), fn (): float => $this->now);
        [$res] = $this->send($fw, 'GET', '/x');
        self::assertSame(503, $res->getStatusCode(), 'the placeholder pinned keys refuse every bundle with "kid"');
    }

    public function testSetHeaderValuesReachTheOriginOnly(): void
    {
        [, $seen] = $this->send($this->firewall(), 'GET', '/plain');
        self::assertNotNull($seen);
        [$res] = $this->send($this->firewall(), 'GET', '/admin/x');
        self::assertNull($res->headers->get('X-RG-Rule'));
    }

    public function testConfigValidation(): void
    {
        $repo = $this->repo();
        foreach ([
            [[], 'siteKey'],
            [['siteKey' => 'rgpk_x', 'secretKey' => 'nope'], 'secretKey'],
            [['siteKey' => 'rgpk_x', 'apiBase' => 'http://example.com'], 'apiBase'],
            [['siteKey' => 'rgpk_x', 'apiBase' => 'https://u@example.com'], 'apiBase'],
            [['siteKey' => 'rgpk_x', 'initialFailMode' => 'maybe'], 'initialFailMode'],
        ] as [$cfg, $what]) {
            try {
                new Firewall($cfg, $repo);
                self::fail("accepted a bad $what");
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString($what, $e->getMessage());
            }
        }
    }

    public function testTestKeysOnlyForNonCanonicalKeyWithLoopbackApi(): void
    {
        $test = Sig::testPolicyKeys();
        $repo = $this->repo();
        $bad = [
            ['siteKey' => 'rgpk_7Hq2LmZ9xK4aBc8DeFgH', 'apiBase' => 'http://127.0.0.1:1', 'pinnedKeys' => $test],
            ['siteKey' => 'rgpk_conformance', 'apiBase' => 'https://api.example.com', 'pinnedKeys' => $test],
        ];
        foreach ($bad as $cfg) {
            try {
                new Firewall($cfg, $repo);
                self::fail('accepted TEST keys');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        foreach (['http://127.0.0.1:1', 'http://localhost:1', 'http://[::1]:1'] as $base) {
            self::assertInstanceOf(Firewall::class, new Firewall(['siteKey' => 'rgpk_conformance', 'apiBase' => $base, 'pinnedKeys' => $test], $repo));
        }
    }

    public function testSingleFieldParser(): void
    {
        self::assertSame('abc', RevokeGPTMiddleware::singleField('rg_clearance=abc'));
        self::assertNull(RevokeGPTMiddleware::singleField('rg_clearance=a&rg_clearance=b'));
        self::assertNull(RevokeGPTMiddleware::singleField('rg_clearance=a;b=c'));
        self::assertNull(RevokeGPTMiddleware::singleField('other=a'));
        self::assertNull(RevokeGPTMiddleware::singleField('rg_clearance=%zz'));
        self::assertNull(RevokeGPTMiddleware::singleField(''));
    }

    public function testSecretTravelsOnlyAsBearerNeverInTheBody(): void
    {
        $seen = [];
        $t = function (string $method, string $url, array $headers, ?string $body, float $timeout, int $max) use (&$seen): array {
            if (str_ends_with($url, '/v1/siteverify')) {
                $seen[] = [$headers, $body];
                return ['status' => 200, 'headers' => [], 'body' => '{"success":true,"hostname":"example.com","action":"login","score":0.9}'];
            }
            return ['status' => 500, 'headers' => [], 'body' => ''];
        };
        $fw = new Firewall(['siteKey' => 'rgpk_conformance', 'secretKey' => 'rgsk_conformance',
            'apiBase' => 'http://127.0.0.1:1', 'pinnedKeys' => Sig::testPolicyKeys()], $this->repo(), $t);
        self::assertSame('pass', $fw->siteverify(str_repeat('A', 40), 'example.com', 'login')['kind']);
        self::assertSame('Bearer rgsk_conformance', $seen[0][0]['Authorization']);
        self::assertSame('response=' . str_repeat('A', 40), $seen[0][1]);
        self::assertStringNotContainsString('secret', (string) $seen[0][1]);
    }

    public function testMissingBundleIsRetriedNoOftenerThanEvery10Seconds(): void
    {
        $this->bundleStatus = 500;
        $fw = $this->firewall();
        $fw->currentBundle();
        self::assertSame(1, $this->bundleFetches);
        $this->now += 9;
        $fw->currentBundle();
        self::assertSame(1, $this->bundleFetches);
        $this->now += 2;
        $fw->currentBundle();
        self::assertSame(2, $this->bundleFetches);
    }

    public function testBundleFetchSendsBearerAndA401IsLoggedOnceAsAConfigError(): void
    {
        $auth = [];
        $t = function (string $method, string $url, array $headers, ?string $body, float $timeout, int $max) use (&$auth): array {
            $auth[] = $headers['Authorization'] ?? null;
            return ['status' => 401, 'headers' => [], 'body' => ''];
        };
        $fw = new Firewall(['siteKey' => 'rgpk_conformance', 'secretKey' => 'rgsk_conformance',
            'apiBase' => 'http://127.0.0.1:1', 'pinnedKeys' => Sig::testPolicyKeys()], $this->repo(), $t, fn (): float => $this->now);
        for ($i = 0; $i < 3; $i++) {
            self::assertNull($fw->currentBundle());
            $this->now += 11;
        }
        self::assertSame(['Bearer rgsk_conformance', 'Bearer rgsk_conformance', 'Bearer rgsk_conformance'], $auth);
        self::assertSame(1, $fw->authErrors);
    }

    public function testBundleMayCarrySigHeaderAsABoolean(): void
    {
        $base = $this->vectors['fixtures']['bundles']['basic'];
        $parse = static fn (array $p): ?array => \RevokeGPT\Firewall\Core\Schema::parsePayload((string) json_encode($p));
        self::assertNotNull($parse($base));
        self::assertNotNull($parse($base + ['sigHeader' => true]));
        self::assertNull($parse($base + ['sigHeader' => 'yes']));
    }

    /** @return array{0:Firewall,1:object} a firewall serving a bundle with the given sigHeader, and its log lines */
    private function sigFirewall(?bool $sigHeader, ?string $secret): array
    {
        $kp = sodium_crypto_sign_keypair();
        $pub = sodium_crypto_sign_publickey($kp);
        $b64 = static fn (string $b): string => rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
        $p = $this->vectors['fixtures']['bundles']['basic'];
        if ($sigHeader !== null) {
            $p['sigHeader'] = $sigHeader;
        }
        $payload = (string) json_encode($p);
        $sig = sodium_crypto_sign_detached(\RevokeGPT\Firewall\Core\Limits::POLICY_SIGNATURE_DOMAIN . $payload, sodium_crypto_sign_secretkey($kp));
        $this->served = (string) json_encode(['alg' => 'Ed25519', 'kid' => Sig::kidOfPublicKey($pub),
            'payload' => $b64($payload), 'sig' => $b64($sig)]);
        $log = new class () extends \Psr\Log\AbstractLogger {
            /** @var list<string> */
            public array $lines = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->lines[] = (string) $message;
            }
        };
        $cfg = ['siteKey' => 'rgpk_conformance', 'apiBase' => 'http://127.0.0.1:1',
            'pinnedKeys' => [['kid' => Sig::kidOfPublicKey($pub), 'alg' => 'Ed25519', 'pub' => $b64($pub), 'notAfter' => 4102444800]]];
        if ($secret !== null) {
            $cfg['sigSecret'] = $secret;
        }
        return [new Firewall($cfg, $this->repo(), $this->transport(), fn (): float => $this->now, $log), $log];
    }

    public function testSigHeaderKnownAnswer(): void
    {
        [$fw] = $this->sigFirewall(true, 'sixteen-byte-secret!');
        [, $seen] = $this->send($fw, 'GET', '/x/page', ['X-RG-Sig' => 'forged']);
        self::assertNotNull($seen);
        // Independently computed: HMAC-SHA256 over "t\nhost\nmethod\npath\nscore\nverdict\nrule".
        $mac = $this->hmacHex('sixteen-byte-secret!', self::NOW . "\nexample.com\nGET\n/x/page\n" . $seen->headers->get('X-RG-Score') . "\n" . $seen->headers->get('X-RG-Verdict') . "\n" . $seen->headers->get('X-RG-Rule'));
        self::assertSame('t=' . self::NOW . ',v1=' . $mac, $seen->headers->get('X-RG-Sig'));
        // Fixed vector (computed with openssl): data "1790000000\nexample.com\nGET\n/x/page\n\n\n".
        self::assertSame(
            'b42be27e223fed65b85466910a839a0cd980cd1d6d6b0dea36f7d78777657f13',
            hash_hmac('sha256', "1790000000\nexample.com\nGET\n/x/page\n\n\n", 'sixteen-byte-secret!'),
        );
    }

    private function hmacHex(string $key, string $data): string
    {
        return bin2hex(hash_hmac('sha256', $data, $key, true));
    }

    public function testSigHeaderFalseOrAbsentIsUnsigned(): void
    {
        foreach ([false, null] as $flag) {
            [$fw] = $this->sigFirewall($flag, 'sixteen-byte-secret!');
            [, $seen] = $this->send($fw, 'GET', '/x/page', ['X-RG-Sig' => 'forged']);
            self::assertNotNull($seen);
            self::assertNull($seen->headers->get('X-RG-Sig'));
        }
    }

    public function testSigHeaderWithoutSecretWarnsOnce(): void
    {
        [$fw, $log] = $this->sigFirewall(true, null);
        $this->send($fw, 'GET', '/x/page');
        [, $seen] = $this->send($fw, 'GET', '/x/page', ['X-RG-Sig' => 'forged']);
        self::assertNotNull($seen);
        self::assertNull($seen->headers->get('X-RG-Sig'));
        self::assertSame(1, count(array_filter($log->lines, static fn (string $l): bool => $l === 'config-warning:sig-secret-missing')));
    }

    public function testShortSigSecretIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid sigSecret');
        new Firewall(['siteKey' => 'rgpk_x', 'sigSecret' => 'too-short'], $this->repo());
    }
}
