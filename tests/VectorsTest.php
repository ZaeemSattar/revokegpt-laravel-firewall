<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RevokeGPT\Firewall\Core\Bundle;
use RevokeGPT\Firewall\Core\Decide;
use RevokeGPT\Firewall\Core\Glob;
use RevokeGPT\Firewall\Core\Headers;
use RevokeGPT\Firewall\Core\Host;
use RevokeGPT\Firewall\Core\Normalize;
use RevokeGPT\Firewall\Core\Schema;
use RevokeGPT\Firewall\Core\Session;
use RevokeGPT\Firewall\Core\Sig;

/** The arbiter: packages/protocol/test-vectors/policy.json. Every row of every section must pass. */
final class VectorsTest extends TestCase
{
    /** packages/protocol/test-vectors/policy.json in the monorepo, vectors/policy.json in the public mirror. */
    public static function policyPath(): string
    {
        foreach ([__DIR__ . '/../../../../packages/protocol/test-vectors', __DIR__ . '/../vectors'] as $dir) {
            if (is_file($dir . '/policy.json')) {
                return $dir . '/policy.json';
            }
        }
        throw new \RuntimeException('policy.json was not found');
    }

    /** @var array<string,mixed>|null */
    private static ?array $assoc = null;
    private static ?object $objects = null;

    /** @return array<string,mixed> */
    private static function v(): array
    {
        if (self::$assoc === null) {
            $raw = file_get_contents(self::policyPath());
            self::$assoc = json_decode((string) $raw, true, 512, JSON_THROW_ON_ERROR);
            self::$objects = json_decode((string) $raw, false, 512, JSON_THROW_ON_ERROR);
        }
        return self::$assoc;
    }

    /** @return array<string,array{0:array<string,mixed>}> */
    private static function rows(string $section): array
    {
        $out = [];
        foreach (self::v()[$section] as $row) {
            $out[$section . '/' . $row['name']] = [$row];
        }
        return $out;
    }

    public static function normalizeRows(): array
    {
        return self::rows('normalize');
    }

    public static function globRows(): array
    {
        return self::rows('glob');
    }

    public static function hostRows(): array
    {
        return self::rows('host');
    }

    public static function decideRows(): array
    {
        return self::rows('decide');
    }

    public static function bundleRows(): array
    {
        return self::rows('bundle');
    }

    public static function sessionRows(): array
    {
        return self::rows('session');
    }

    public static function headerRows(): array
    {
        return self::rows('headers');
    }

    public static function returnPathRows(): array
    {
        return self::rows('returnPath');
    }

    public function testHeader(): void
    {
        self::assertSame('policy', self::v()['suite']);
        self::assertSame(1, self::v()['protocolVersion']);
    }

    #[DataProvider('normalizeRows')]
    public function testNormalize(array $c): void
    {
        $got = Normalize::normalize($c['input']);
        $e = $c['expected'];
        self::assertSame($e['ok'], $got['ok'], json_encode($got));
        if ($got['ok']) {
            self::assertSame($e['path'], $got['path']);
            self::assertSame($e['collapsed'], $got['collapsed']);
        } else {
            self::assertSame($e['reason'], $got['reason']);
            self::assertSame($e['detail'], $got['detail']);
        }
    }

    #[DataProvider('globRows')]
    public function testGlob(array $c): void
    {
        $g = Glob::compile($c['pattern']);
        if (array_key_exists('compiles', $c) && $c['compiles'] === false) {
            self::assertNull($g, 'pattern compiled');
            return;
        }
        self::assertNotNull($g, 'pattern did not compile');
        $start = hrtime(true);
        $path = $c['path'] ?? null;
        if (($c['target'] ?? null) !== null) {
            $n = Normalize::normalize($c['target']);
            self::assertTrue($n['ok']);
            $path = $n['collapsed'];
        }
        self::assertSame($c['matches'], $g->matches($path));
        if (isset($c['budgetMs'])) {
            self::assertLessThanOrEqual($c['budgetMs'], (hrtime(true) - $start) / 1e6, 'over budget');
        }
    }

    public function testGlobHasBudgetRow(): void
    {
        $saw = false;
        foreach (self::v()['glob'] as $c) {
            $saw = $saw || (($c['budgetMs'] ?? null) === 5);
        }
        self::assertTrue($saw);
    }

    #[DataProvider('hostRows')]
    public function testHost(array $c): void
    {
        self::assertSame($c['matches'], Host::hostMatches($c['pattern'], $c['host']));
    }

    /** @return array<string,array<string,mixed>> */
    private static function bundles(): array
    {
        self::v();
        $out = [];
        foreach (['bundles', 'unvalidated'] as $set) {
            foreach (self::$objects->fixtures->{$set} as $name => $obj) {
                $p = Schema::parsePayloadValue($obj);
                self::assertNotNull($p, "fixture $name does not parse");
                $out[$name] = $p;
            }
        }
        return $out;
    }

    /** Deep equality where every JSON number compares by value and strings compare strictly. */
    public static function deepEq(mixed $a, mixed $b): bool
    {
        if ((is_int($a) || is_float($a)) && (is_int($b) || is_float($b))) {
            return (float) $a === (float) $b;
        }
        if (is_array($a) && is_array($b)) {
            if (count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $k => $x) {
                if (!array_key_exists($k, $b) || !self::deepEq($x, $b[$k])) {
                    return false;
                }
            }
            return true;
        }
        return $a === $b;
    }

    #[DataProvider('decideRows')]
    public function testDecide(array $c): void
    {
        static $bundles = null;
        $bundles ??= self::bundles();
        $p = $bundles[$c['bundle']] ?? null;
        self::assertNotNull($p, 'fixture missing');
        $s = $c['session'];
        $session = ['kind' => $s['kind'], 'lvl' => $s['lvl'] ?? 0, 'sc' => $s['sc'] ?? 0];
        $verify = null;
        if ($c['verify'] !== null) {
            $verify = ['kind' => $c['verify']['kind'], 'score' => (float) ($c['verify']['score'] ?? 0)];
        }
        $now = $c['now'] ?? self::v()['nowDefault'];
        $got = Decide::decide($p, $c['request'], $session, $verify, $now);
        $want = $c['expected'];
        self::assertTrue(self::deepEq($got, $want), 'got ' . json_encode($got) . "\nwant " . json_encode($want));
    }

    public function testEveryDecisionKindIsProduced(): void
    {
        $bundles = self::bundles();
        $kinds = [];
        foreach (self::v()['decide'] as $c) {
            $s = $c['session'];
            $verify = $c['verify'] === null ? null : ['kind' => $c['verify']['kind'], 'score' => (float) ($c['verify']['score'] ?? 0)];
            $d = Decide::decide($bundles[$c['bundle']], $c['request'],
                ['kind' => $s['kind'], 'lvl' => $s['lvl'] ?? 0, 'sc' => $s['sc'] ?? 0], $verify, $c['now'] ?? self::v()['nowDefault']);
            $kinds[$d['kind']] = true;
        }
        foreach (['allow', 'block', 'challenge', 'redirect', 'needs-verify'] as $k) {
            self::assertArrayHasKey($k, $kinds, "no decide row produced kind $k");
        }
    }

    #[DataProvider('bundleRows')]
    public function testBundle(array $c): void
    {
        $expect = ['siteId' => $c['expect']['siteId'] ?? '', 'siteKey' => $c['expect']['siteKey'] ?? ''];
        $r = Bundle::verify($c['served'], $c['pinned'], $c['now'], $c['minVersion'], $expect);
        $e = $c['expected'];
        self::assertSame($e['ok'], $r['ok'], 'reason ' . ($r['reason'] ?? ''));
        if ($r['ok']) {
            self::assertSame($e['version'], $r['payload']['version']);
        } else {
            self::assertSame($e['reason'], $r['reason']);
        }
    }

    public function testNonCanonicalSRowExists(): void
    {
        $names = array_column(self::v()['bundle'], 'name');
        self::assertContains('sig-non-canonical-s', $names);
    }

    #[DataProvider('sessionRows')]
    public function testSession(array $c): void
    {
        $got = Session::verify(
            $c['token'] ?? '',
            $c['keys'],
            ['siteId' => $c['expect']['siteId'], 'host' => $c['expect']['host']],
            ['minIat' => $c['b']['minIat'], 'revokedJti' => $c['b']['revokedJti']],
            $c['now'],
        );
        self::assertSame($c['expected']['kind'], $got['kind']);
        if ($got['kind'] === 'valid') {
            self::assertSame($c['expected']['lvl'], $got['lvl']);
            self::assertSame($c['expected']['sc'], $got['sc']);
        }
    }

    #[DataProvider('headerRows')]
    public function testHeaders(array $c): void
    {
        self::assertSame($c['expected'], Headers::stripRgHeaders($c['names']));
    }

    #[DataProvider('returnPathRows')]
    public function testReturnPath(array $c): void
    {
        self::assertSame($c['safe'], Headers::isSafeReturnPath($c['path']));
    }

    // ---- explicit Ed25519 canonical-S behaviour ------------------------------------------------

    public function testNonCanonicalSIsRejectedInPhpBeforeLibsodium(): void
    {
        $l = (string) hex2bin('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
        $sig = str_repeat("\0", 32) . strrev($l); // S = L exactly
        self::assertFalse(Sig::isCanonicalS($sig), 'S = L must be refused');
        $lMinus1 = str_repeat("\0", 32) . substr_replace(strrev($l), chr(ord(strrev($l)[0]) - 1), 0, 1);
        self::assertTrue(Sig::isCanonicalS($lMinus1), 'S = L - 1 is canonical');
        self::assertFalse(Sig::isCanonicalS(str_repeat("\0", 63) . "\xff" . str_repeat("\xff", 0)), 'wrong length');
        self::assertFalse(Sig::isCanonicalS(str_repeat("\0", 32) . str_repeat("\xff", 32)), 'S >= 2^255');

        // verifyDomain refuses it before sodium is asked: even a "valid" key never gets that far.
        $key = ['kid' => '3d75ce3772a93b6e', 'alg' => 'Ed25519', 'pub' => 'mkgsn6TedEnh1On988cT8ujJnUMDF1SaeTPCjRaasF0', 'notAfter' => 4102444800];
        self::assertFalse(Sig::verifyDomain($key, 'd', 'p', $sig));
    }

    public function testStrictBase64Url(): void
    {
        self::assertNull(Sig::fromBase64Url('AA=='), 'padding refused');
        self::assertNull(Sig::fromBase64Url('A'), 'length 1 mod 4 refused');
        self::assertNull(Sig::fromBase64Url('AB'), 'non-zero trailing bits refused');
        self::assertNull(Sig::fromBase64Url("AA\n"), 'trailing newline refused');
        self::assertNull(Sig::fromBase64Url('a+b/'), 'standard alphabet refused');
        self::assertSame("\0", Sig::fromBase64Url('AA'));
    }
}
