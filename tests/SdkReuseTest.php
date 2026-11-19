<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Tests;

use PHPUnit\Framework\TestCase;
use RevokeGPT\Firewall\Core\Host;
use RevokeGPT\Firewall\Core\Json;
use RevokeGPT\Firewall\Core\Punycode;
use RevokeGPT\Internal\Host as SdkHost;
use RevokeGPT\Internal\Json as SdkJson;
use RevokeGPT\Internal\Punycode as SdkPunycode;

/** The firewall's hostname, punycode and JSON primitives delegate to the SDK's, not copies. */
final class SdkReuseTest extends TestCase
{
    public function testHostDelegatesToTheSdk(): void
    {
        foreach (['Example.COM', 'xn--bcher-kva.example', '0x7f.1', 'a..b', "b\u{FC}cher.example", ''] as $h) {
            self::assertSame(SdkHost::canonicalize($h), Host::canonicalize($h));
            self::assertSame(SdkHost::requestHost($h . ':80'), Host::requestHost($h . ':80'));
        }
        self::assertTrue(Host::hostMatches('*.example.com', 'a.example.com:443'));
        self::assertSame(SdkHost::isValidHostnamePattern('*.com'), Host::isValidHostnamePattern('*.com'));
    }

    /** Same golden values as the Go port and the reference (canonicalizeHostname via requestHost). */
    public function testNonAsciiHostsMatchTheReference(): void
    {
        $golden = [
            "\u{DF}" => 'xn--zca', "\u{65E5}\u{672C}.example" => 'xn--wgv71a.example',
            "\u{C0}\u{C9}.example" => 'xn--0cas.example', "\u{142}\u{F3}d\u{17A}.example" => 'xn--d-uga0v4h.example',
            'XN--BCHER-KVA.example' => 'xn--bcher-kva.example', "b\u{FC}cher.example" => 'xn--bcher-kva.example',
            "B\u{DC}CHER.example" => 'xn--bcher-kva.example', '07.07' => '7.0.0.7', '0x7f.1' => '127.0.0.1',
        ];
        foreach ($golden as $in => $want) {
            self::assertSame($want, Host::requestHost((string) $in), (string) $in);
        }
        foreach (['xn--a.example', 'xn--bcher-kva-.example', 'xn--zca-.example', "\u{1C6}.example", "\u{130}.example",
            "\u{FF45}xample.com", "a\u{AD}.com", "\u{1E8D}.com", "\u{FB01}.com", 'a b.com', '[::1]'] as $in) {
            self::assertNull(Host::requestHost($in), $in);
        }
    }

    public function testPunycodeDelegatesToTheSdk(): void
    {
        self::assertSame(SdkPunycode::encode([0xFC]), Punycode::encode([0xFC]));
        self::assertSame(SdkPunycode::decode('bcher-kva'), Punycode::decode('bcher-kva'));
    }

    public function testJsonDelegatesToTheSdk(): void
    {
        foreach (['{"a":1}', '[1,', 'NaN', '{"a":1} x', '1e999'] as $t) {
            self::assertEquals(SdkJson::parse($t), Json::parse($t));
        }
    }

    public function testNoCopyOfTheSdkCodeRemains(): void
    {
        foreach (['Host', 'Punycode', 'Json'] as $f) {
            self::assertStringContainsString('RevokeGPT\\Internal\\', (string) file_get_contents(__DIR__ . "/../src/Core/$f.php"));
            self::assertLessThan(80, count(file(__DIR__ . "/../src/Core/$f.php") ?: []));
        }
    }
}
