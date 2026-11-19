<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * The firewall decision for one request (protocol v1, section 18.4). Pure and total.
 *
 * Request: ['host' => string, 'method' => string, 'rawTarget' => string, 'fetchMode' => 'navigate'|'other',
 *           'acceptsHtml' => bool].
 * Session state: ['kind' => 'none'|'valid'|'invalid', 'lvl' => int, 'sc' => int].
 * Verify outcome (or null before siteverify has been called): ['kind' => 'absent'|'pass'|'fail'|'unreachable',
 *           'score' => float].
 * Decision: ['kind' => allow|block|challenge|redirect|needs-verify, 'ruleIndex' => ?int, 'status'? => int,
 *           'location'? => string, 'setHeaders' => array<string,string>, 'verify'? => [expectedAction, threshold]].
 */
final class Decide
{
    private const SC_FLOOR_HUNDREDTHS = [0, 25, 50, 75];
    private const KIND_RANK = ['allow' => 1, 'needs-verify' => 2, 'challenge' => 3, 'redirect' => 4, 'block' => 5];

    /** The session score bucket sc (0-3) for a siteverify score: quarters of the range, 1.0 in bucket 3. */
    public static function sessionScoreBucket(float $score): int
    {
        if (is_nan($score) || is_infinite($score) || $score <= 0) {
            return 0;
        }
        if ($score >= 0.75) {
            return 3;
        }
        if ($score >= 0.5) {
            return 2;
        }
        return $score >= 0.25 ? 1 : 0;
    }

    private static function methodMatches(array $methods, string $method): bool
    {
        if (in_array($method, $methods, true)) {
            return true;
        }
        if ($method === 'OPTIONS') {
            return false; // OPTIONS only matches a rule that lists it
        }
        if (in_array('*', $methods, true)) {
            return true;
        }
        return $method === 'HEAD' && in_array('GET', $methods, true);
    }

    private static function jsRound(float $x): float
    {
        return floor($x + 0.5);
    }

    private static function whenHolds(array $w, array $s): bool
    {
        if (!$w['present']) {
            return true;
        }
        $valid = $s['kind'] === 'valid';
        if ($w['noSession'] && $valid) {
            return false;
        }
        if ($w['sessionLevelBelow'] !== null) {
            $lvl = $valid ? $s['lvl'] : -1;
            if (!($lvl < $w['sessionLevelBelow'])) {
                return false;
            }
        }
        if ($w['scoreBelow'] !== null) {
            // No valid session: the score is unknown, which counts as below any threshold.
            if ($valid && !((float) self::SC_FLOOR_HUNDREDTHS[$s['sc']] < self::jsRound($w['scoreBelow'] * 100))) {
                return false;
            }
        }
        return true;
    }

    private static function stricter(array $a, array $b): array
    {
        $ra = self::KIND_RANK[$a['kind']];
        $rb = self::KIND_RANK[$b['kind']];
        if ($ra !== $rb) {
            return $ra > $rb ? $a : $b;
        }
        $ai = $a['ruleIndex'] ?? INF;
        $bi = $b['ruleIndex'] ?? INF;
        return $bi < $ai ? $b : $a;
    }

    private static function block(int $status, ?int $ruleIndex, array $h = []): array
    {
        return ['kind' => 'block', 'ruleIndex' => $ruleIndex, 'status' => $status, 'setHeaders' => $h];
    }

    private static function scoreHeaders(?array $v, array $s): array
    {
        if ($v !== null && $v['kind'] === 'pass') {
            return ['X-RG-Score' => Headers::scoreBucket((float) $v['score']), 'X-RG-Verdict' => 'pass'];
        }
        if ($s['kind'] === 'valid') {
            return [
                'X-RG-Score' => Headers::scoreBucket(self::SC_FLOOR_HUNDREDTHS[$s['sc']] / 100),
                'X-RG-Verdict' => 'pass',
            ];
        }
        return ['X-RG-Score' => '0', 'X-RG-Verdict' => 'none'];
    }

    private static function evaluate(array $b, string $host, string $method, string $path, array $r, array $s, ?array $v): array
    {
        $headers = [];
        $wantScore = false;
        $acc = static function () use (&$headers, &$wantScore, $v, $s): array {
            $h = $headers;
            if ($wantScore) {
                foreach (self::scoreHeaders($v, $s) as $k => $x) {
                    $h[$k] = $x;
                }
            }
            return $h;
        };
        $finishAllow = static function (?int $ruleIndex, array $extra = []) use ($acc): array {
            $h = $acc();
            foreach ($extra as $k => $x) {
                $h[$k] = $x;
            }
            if ($ruleIndex !== null) {
                $h['X-RG-Rule'] = (string) $ruleIndex;
            }
            return ['kind' => 'allow', 'ruleIndex' => $ruleIndex, 'setHeaders' => $h];
        };
        foreach ($b['policies'] as $i => $rule) {
            if (!$rule['enabled'] || !self::methodMatches($rule['methods'], $method)) {
                continue;
            }
            $hostOk = false;
            foreach ($rule['hosts'] as $p) {
                if (Host::hostnameMatches($host, $p)) {
                    $hostOk = true;
                    break;
                }
            }
            if (!$hostOk || !$rule['glob']->matches($path) || !self::whenHolds($rule['when'], $s)) {
                continue;
            }
            $terminal = null;
            foreach ($rule['actions'] as $a) {
                if ($a['type'] === 'setHeader') {
                    $headers[$a['name']] = $a['value'];
                } elseif ($a['type'] === 'scoreHeader') {
                    $wantScore = true;
                } elseif (Schema::isTerminalAction($a)) {
                    $terminal = $a;
                }
            }
            if ($terminal === null) {
                continue;
            }
            switch ($terminal['type']) {
                case 'allow':
                    return $finishAllow($i);
                case 'block':
                    return self::block($terminal['status'], $i, $acc());
                case 'redirect':
                    // Re-checked here as well as in the editor: a bundle is data, never trusted blindly.
                    if (!Schema::isSafeRedirectLocation($terminal['location'], $b['hosts'])) {
                        return self::block(403, $i, $acc());
                    }
                    return ['kind' => 'redirect', 'ruleIndex' => $i, 'status' => $terminal['status'],
                        'location' => $terminal['location'], 'setHeaders' => $acc()];
                case 'challengePage':
                    if ($s['kind'] === 'valid' && $s['lvl'] >= $terminal['minLevel']) {
                        return $finishAllow($i);
                    }
                    $nav = $method === 'GET' && $r['fetchMode'] === 'navigate' && $r['acceptsHtml'];
                    if ($nav) {
                        return ['kind' => 'challenge', 'ruleIndex' => $i, 'status' => 303,
                            'location' => $b['challengeBase'] . '/c/' . $b['siteKey'] . '?h=' . $host,
                            'setHeaders' => $acc()];
                    }
                    $h = $acc();
                    $h['X-RG-Action'] = 'challenge';
                    return ['kind' => 'challenge', 'ruleIndex' => $i, 'status' => 403, 'setHeaders' => $h];
                case 'requireToken':
                    if ($v === null) {
                        return ['kind' => 'needs-verify', 'ruleIndex' => $i, 'setHeaders' => $acc(),
                            'verify' => ['expectedAction' => $terminal['action'], 'threshold' => $terminal['threshold']]];
                    }
                    if ($v['kind'] === 'unreachable') {
                        if ($rule['onError'] === 'allow') {
                            return $finishAllow($i, ['X-RG-Verdict' => 'none']);
                        }
                        return self::block(403, $i, $acc());
                    }
                    if ($v['kind'] === 'pass') {
                        if (self::jsRound($v['score'] * 1e6) >= self::jsRound($terminal['threshold'] * 1e6)) {
                            $wantScore = true;
                            return $finishAllow($i);
                        }
                        return self::block(403, $i, $acc());
                    }
                    return self::block(403, $i, $acc()); // absent or fail
            }
        }
        return $finishAllow(null);
    }

    /**
     * Order: (1) a bundle past expiresAt + 6 h applies its fail mode (open: allow, closed: 503);
     * (2) a method that is not upper case, or a host that is not a canonical hostname, is a 400;
     * (3) a path that is not origin-form or holds a bad escape is a 400; a non-canonical path follows
     * onNonCanonical; (4) rules run top to bottom on both forms of the path; the stricter decision
     * wins. $v is null until the integration has called siteverify.
     *
     * @param array<string,mixed> $b a validated payload
     */
    public static function decide(array $b, array $r, array $s, ?array $v, int $now): array
    {
        if ($now > $b['expiresAt'] + Limits::STALE_GRACE_SECONDS) {
            if ($b['failMode'] === 'open') {
                return ['kind' => 'allow', 'ruleIndex' => null, 'setHeaders' => ['X-RG-Verdict' => 'none']];
            }
            return self::block(503, null);
        }
        // kill switch, on a non-stale bundle only (red team E-2: a stale bundle is not trusted, so its kill switch is not either (v1.md 18.5)): every request passes, no headers
        if (($b['disabled'] ?? false) === true) {
            return ['kind' => 'allow', 'ruleIndex' => null, 'setHeaders' => []];
        }
        if (preg_match(Schema::RE_METHOD, $r['method']) !== 1) {
            return self::block(400, null);
        }
        $host = Host::requestHost($r['host']);
        if ($host === null) {
            return self::block(400, null);
        }
        $n = Normalize::normalize($r['rawTarget']);
        if (!$n['ok']) {
            if ($n['reason'] === 'invalid') {
                return self::block(400, null);
            }
            $read = $r['method'] === 'GET' || $r['method'] === 'HEAD' || $r['method'] === 'OPTIONS';
            if ($b['onNonCanonical'] === 'block' || !$read) {
                return self::block(403, null);
            }
            return ['kind' => 'allow', 'ruleIndex' => null,
                'setHeaders' => ['X-RG-Verdict' => 'none', 'X-RG-Path' => 'non-canonical']];
        }
        $first = self::evaluate($b, $host, $r['method'], $n['path'], $r, $s, $v);
        if ($n['collapsed'] === $n['path']) {
            return $first;
        }
        return self::stricter($first, self::evaluate($b, $host, $r['method'], $n['collapsed'], $r, $s, $v));
    }
}
