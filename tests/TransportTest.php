<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Tests;

use Closure;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\TestCase;
use RevokeGPT\Firewall\Core\Sig;
use RevokeGPT\Firewall\Firewall;
use RevokeGPT\Firewall\Http\CurlTransport;
use RevokeGPT\Firewall\Http\TransportException;

/** The real cURL transport and siteverify budget against sockets: connect-only retry within one 2 s budget. */
final class TransportTest extends TestCase
{
    private const TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    /** @var resource|null */
    private $proc = null;
    private array $pipes = [];

    protected function tearDown(): void
    {
        if (is_resource($this->proc)) {
            proc_terminate($this->proc);
            proc_close($this->proc);
        }
    }

    private function server(string $mode): int
    {
        $this->proc = proc_open([PHP_BINARY, __DIR__ . '/fixtures/server.php', $mode], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $this->pipes);
        return (int) trim((string) fgets($this->pipes[1]));
    }

    private function firewall(int $port, int &$attempts): Firewall
    {
        $curl = new CurlTransport();
        $t = function (...$a) use ($curl, &$attempts) {
            $attempts++;
            return $curl(...$a);
        };
        return new Firewall(
            ['siteKey' => 'rgpk_conformance', 'secretKey' => 'rgsk_conformance',
                'apiBase' => 'http://127.0.0.1:' . $port, 'pinnedKeys' => Sig::testPolicyKeys()],
            new Repository(new ArrayStore()),
            Closure::fromCallable($t),
        );
    }

    public function testConnectRefusedIsFlaggedAndRetriedOnce(): void
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr((string) stream_socket_get_name($s, false), ':'), 1);
        fclose($s);
        try {
            (new CurlTransport())('GET', "http://127.0.0.1:$port/", [], null, 1.0, 100);
            self::fail('connected');
        } catch (TransportException $e) {
            self::assertTrue($e->connect);
            self::assertFalse($e->timeout);
        }
        $attempts = 0;
        $r = $this->firewall($port, $attempts)->siteverify(self::TOKEN, 'example.com', 'login');
        self::assertSame('unreachable', $r['kind']);
        self::assertSame(2, $attempts);
    }

    public function testResetAfterSendIsNotRetried(): void
    {
        $port = $this->server('reset');
        $attempts = 0;
        $r = $this->firewall($port, $attempts)->siteverify(self::TOKEN, 'example.com', 'login');
        self::assertSame('unreachable', $r['kind']);
        self::assertSame(1, $attempts);
    }

    public function testSlowBodyIsCutAtTheBudget(): void
    {
        $port = $this->server('slow');
        $attempts = 0;
        $start = microtime(true);
        $r = $this->firewall($port, $attempts)->siteverify(self::TOKEN, 'example.com', 'login');
        $took = microtime(true) - $start;
        self::assertSame('unreachable', $r['kind']);
        self::assertSame(1, $attempts);
        self::assertLessThan(2.6, $took);
    }
}
