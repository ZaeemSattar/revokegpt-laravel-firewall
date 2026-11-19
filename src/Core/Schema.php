<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

use stdClass;

/**
 * Bundle payload validation (strict: unknown fields are refused), as PolicyBundlePayloadSchema does.
 *
 * A validated payload is an array with the keys of the wire format plus 'usesCookies'; every
 * policy is an array whose 'glob' is a compiled Glob and whose 'when' holds the predicates; an
 * action is an array with 'type' and the fields of that type.
 */
final class Schema
{
    public const RE_BASE62_ID = '/\A[0-9A-Za-z]{8}\z/D';
    public const RE_KID = '/\A[0-9a-f]{16}\z/D';
    public const RE_JTI = '/\A[A-Za-z0-9_-]{16,32}\z/D';
    public const RE_METHOD = '/\A[A-Z][A-Z-]{0,31}\z/D';
    public const RE_HEADER_NAME = '/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/D';
    public const RE_SITE_ID = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/D';
    public const RE_SITE_KEY = '/\Argpk_[0-9A-Za-z]{20}\z/D';
    private const RE_ACTION = '/\A[A-Za-z0-9\/_]{1,100}\z/D';
    private const RE_KEY_PUB = '/\A[A-Za-z0-9_-]{43}\z/D';
    private const RE_CHALLENGE = '/\Ahttps:\/\/([a-z0-9.-]+)(?::[0-9]{1,5})?\z/D';
    private const RE_SET_VALUE = '/\A[\x20-\x7e]*\z/D';

    private const SET_HEADER_DENY = [
        'host', 'forwarded', 'content-length', 'transfer-encoding', 'set-cookie', 'cookie', 'authorization',
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te',
        'trailer', 'trailers', 'upgrade',
    ];

    private const PAYLOAD_KEYS = ['v', 'siteId', 'siteKey', 'challengeBase', 'version', 'issuedAt', 'notBefore',
        'expiresAt', 'failMode', 'onNonCanonical', 'minIat', 'sigHeader', 'disabled', 'revokedJti', 'session', 'hosts', 'tokenKeys', 'policies'];

    /** C0/C1 controls and bidirectional controls in a rule name. */
    private static function nameForbidden(string $s): bool
    {
        if (!Util::validUtf8($s)) {
            return false;
        }
        foreach (Util::codepoints($s) as $r) {
            if ($r <= 0x1f || ($r >= 0x7f && $r <= 0x9f)) {
                return true;
            }
            if ($r === 0x200e || $r === 0x200f || ($r >= 0x202a && $r <= 0x202e) || ($r >= 0x2066 && $r <= 0x2069)) {
                return true;
            }
        }
        return false;
    }

    public static function isSettableHeaderName(string $name): bool
    {
        if ($name === '' || strlen($name) > Limits::MAX_SET_HEADER_NAME || preg_match(self::RE_HEADER_NAME, $name) !== 1) {
            return false;
        }
        if (in_array($name, self::SET_HEADER_DENY, true)) {
            return false;
        }
        return !(str_starts_with($name, 'x-rg-') || str_starts_with($name, 'x-forwarded-') || $name === 'x-rg');
    }

    public static function isSettableHeaderValue(string $v): bool
    {
        return strlen($v) <= Limits::MAX_SET_HEADER_VALUE && preg_match(self::RE_SET_VALUE, $v) === 1;
    }

    /**
     * A path ("/x", not "//", no backslash, no control) or an https URL on a site host.
     *
     * @param list<string> $siteHosts
     */
    public static function isSafeRedirectLocation(string $loc, array $siteHosts): bool
    {
        if ($loc === '' || Util::utf16Len($loc) > 2048) {
            return false;
        }
        for ($i = 0, $n = strlen($loc); $i < $n; $i++) {
            $c = ord($loc[$i]);
            if ($c <= 0x20 || $c >= 0x7f || $c === 0x5c) {
                return false;
            }
        }
        if ($loc[0] === '/') {
            return !str_starts_with($loc, '//');
        }
        if (!str_starts_with($loc, 'https://')) {
            return false;
        }
        $rest = substr($loc, 8);
        $end = strcspn($rest, '/?#:@');
        $hostPart = substr($rest, 0, $end);
        $tail = substr($rest, $end);
        if ($hostPart === '') {
            return false;
        }
        if (str_starts_with($tail, ':')) {
            $i = 1;
            $tl = strlen($tail);
            while ($i < $tl && $tail[$i] >= '0' && $tail[$i] <= '9') {
                $i++;
            }
            if ($i === 1 || $i > 6) {
                return false;
            }
            $tail = substr($tail, $i);
        }
        if ($tail !== '' && strpos('/?#', $tail[0]) === false) {
            return false;
        }
        $host = Host::canonicalize($hostPart);
        if ($host === null) {
            return false;
        }
        foreach ($siteHosts as $p) {
            if (Host::isValidHostnamePattern($p) && self::patternCovers($p, $host)) {
                return true;
            }
        }
        return false;
    }

    private static function patternCovers(string $site, string $rule): bool
    {
        if ($site === $rule) {
            return true;
        }
        if (!str_starts_with($site, '*.')) {
            return false;
        }
        $base = substr($site, 2);
        $target = str_starts_with($rule, '*.') ? substr($rule, 2) : $rule;
        return $target !== $base && str_ends_with($target, '.' . $base);
    }

    private static function asThreshold(mixed $v): ?float
    {
        $f = Json::asFloat($v);
        if ($f === null || $f < 0.1 || $f > 1 || round($f * 10) / 10 !== $f) {
            return null;
        }
        return $f;
    }

    /** @return array{kid:string,alg:string,pub:string,notAfter:int}|null */
    private static function parseKey(mixed $v): ?array
    {
        $all = ['kid', 'alg', 'pub', 'notAfter'];
        $m = Json::strictObject($v, $all, $all);
        if ($m === null) {
            return null;
        }
        $kid = Json::get($m, 'kid');
        $alg = Json::get($m, 'alg');
        $pub = Json::get($m, 'pub');
        $na = Json::asInt(Json::get($m, 'notAfter'), 0, Limits::MAX_SAFE_INTEGER);
        if (!is_string($kid) || !is_string($alg) || !is_string($pub) || $na === null
            || preg_match(self::RE_KID, $kid) !== 1 || $alg !== 'Ed25519' || preg_match(self::RE_KEY_PUB, $pub) !== 1) {
            return null;
        }
        return ['kid' => $kid, 'alg' => $alg, 'pub' => $pub, 'notAfter' => $na];
    }

    private static function isTerminal(string $type): bool
    {
        return in_array($type, ['allow', 'block', 'requireToken', 'challengePage', 'redirect'], true);
    }

    /** @return array<string,mixed>|null */
    private static function parseAction(mixed $m): ?array
    {
        if (!$m instanceof stdClass) {
            return null;
        }
        $t = Json::get($m, 'type');
        if (!is_string($t)) {
            return null;
        }
        $a = ['type' => $t];
        switch ($t) {
            case 'allow':
            case 'scoreHeader':
                return Json::strictObject($m, ['type'], ['type']) !== null ? $a : null;
            case 'block':
                if (Json::strictObject($m, ['type', 'status'], ['type', 'status']) === null) {
                    return null;
                }
                $s = Json::asInt(Json::get($m, 'status'), 0, 1000);
                if ($s === null || !in_array($s, [403, 404, 429], true)) {
                    return null;
                }
                $a['status'] = $s;
                return $a;
            case 'requireToken':
                if (Json::strictObject($m, ['type', 'action', 'threshold'], ['type', 'action', 'threshold']) === null) {
                    return null;
                }
                $act = Json::get($m, 'action');
                $th = self::asThreshold(Json::get($m, 'threshold'));
                if (!is_string($act) || $th === null || preg_match(self::RE_ACTION, $act) !== 1) {
                    return null;
                }
                $a['action'] = $act;
                $a['threshold'] = $th;
                return $a;
            case 'challengePage':
                if (Json::strictObject($m, ['type', 'minLevel'], ['type', 'minLevel']) === null) {
                    return null;
                }
                $l = Json::asInt(Json::get($m, 'minLevel'), 0, 1000);
                if ($l === null || ($l !== 1 && $l !== 2)) {
                    return null;
                }
                $a['minLevel'] = $l;
                return $a;
            case 'redirect':
                if (Json::strictObject($m, ['type', 'location', 'status'], ['type', 'location', 'status']) === null) {
                    return null;
                }
                $loc = Json::get($m, 'location');
                $s = Json::asInt(Json::get($m, 'status'), 0, 1000);
                if (!is_string($loc) || $s === null || $loc === '' || Util::utf16Len($loc) > 2048
                    || !in_array($s, [302, 307, 308], true)) {
                    return null;
                }
                $a['location'] = $loc;
                $a['status'] = $s;
                return $a;
            case 'setHeader':
                if (Json::strictObject($m, ['type', 'name', 'value'], ['type', 'name', 'value']) === null) {
                    return null;
                }
                $name = Json::get($m, 'name');
                $val = Json::get($m, 'value');
                if (!is_string($name) || !is_string($val) || !self::isSettableHeaderName($name)
                    || !self::isSettableHeaderValue($val)) {
                    return null;
                }
                $a['name'] = $name;
                $a['value'] = $val;
                return $a;
        }
        return null;
    }

    /** @return array<string,mixed>|null */
    private static function parseRule(mixed $v): ?array
    {
        $m = Json::strictObject(
            $v,
            ['id', 'name', 'enabled', 'match', 'when', 'actions', 'onError'],
            ['id', 'name', 'enabled', 'match', 'actions', 'onError'],
        );
        if ($m === null) {
            return null;
        }
        $id = Json::get($m, 'id');
        if (!is_string($id) || preg_match(self::RE_BASE62_ID, $id) !== 1) {
            return null;
        }
        $name = Json::get($m, 'name');
        if (!is_string($name)) {
            return null;
        }
        $nlen = Util::utf16Len($name);
        if ($nlen < 1 || $nlen > Limits::MAX_RULE_NAME || self::nameForbidden($name)) {
            return null;
        }
        $enabled = Json::get($m, 'enabled');
        if (!is_bool($enabled)) {
            return null;
        }
        $match = Json::strictObject(Json::get($m, 'match'), ['hosts', 'path', 'methods'], ['hosts', 'path', 'methods']);
        if ($match === null) {
            return null;
        }
        $hosts = Json::asStringArray(Json::get($match, 'hosts'), 1, Limits::MAX_HOSTS_PER_RULE);
        if ($hosts === null) {
            return null;
        }
        foreach ($hosts as $h) {
            if (!Host::isValidHostnamePattern($h)) {
                return null;
            }
        }
        $path = Json::get($match, 'path');
        if (!is_string($path)) {
            return null;
        }
        $glob = Glob::compile($path);
        if ($glob === null) {
            return null;
        }
        $methods = Json::asStringArray(Json::get($match, 'methods'), 1, Limits::MAX_METHODS_PER_RULE);
        if ($methods === null) {
            return null;
        }
        $seen = [];
        foreach ($methods as $me) {
            if ($me !== '*' && preg_match(self::RE_METHOD, $me) !== 1) {
                return null;
            }
            if (isset($seen[$me])) {
                return null;
            }
            $seen[$me] = true;
        }
        if (isset($seen['*']) && count($methods) !== 1) {
            return null;
        }
        $when = ['present' => false, 'scoreBelow' => null, 'sessionLevelBelow' => null, 'noSession' => false];
        if (Json::has($m, 'when')) {
            $wm = Json::strictObject(Json::get($m, 'when'), ['scoreBelow', 'sessionLevelBelow', 'noSession'], []);
            if ($wm === null) {
                return null;
            }
            $when['present'] = true;
            if (Json::has($wm, 'scoreBelow')) {
                $f = self::asThreshold(Json::get($wm, 'scoreBelow'));
                if ($f === null) {
                    return null;
                }
                $when['scoreBelow'] = $f;
            }
            if (Json::has($wm, 'sessionLevelBelow')) {
                $l = Json::asInt(Json::get($wm, 'sessionLevelBelow'), 0, 1000);
                if ($l === null || $l > 2) {
                    return null;
                }
                $when['sessionLevelBelow'] = $l;
            }
            if (Json::has($wm, 'noSession')) {
                if (Json::get($wm, 'noSession') !== true) {
                    return null;
                }
                $when['noSession'] = true;
            }
        }
        $acts = Json::get($m, 'actions');
        if (!is_array($acts) || !array_is_list($acts) || count($acts) < 1 || count($acts) > Limits::MAX_ACTIONS_PER_RULE) {
            return null;
        }
        $actions = [];
        $terminals = 0;
        foreach ($acts as $x) {
            $a = self::parseAction($x);
            if ($a === null) {
                return null;
            }
            if (self::isTerminal($a['type'])) {
                $terminals++;
            }
            $actions[] = $a;
        }
        if ($terminals > 1) {
            return null;
        }
        $onError = Json::get($m, 'onError');
        if ($onError !== 'allow' && $onError !== 'block') {
            return null;
        }
        return [
            'id' => $id, 'name' => $name, 'enabled' => $enabled, 'hosts' => $hosts, 'path' => $path,
            'methods' => $methods, 'when' => $when, 'actions' => $actions, 'onError' => $onError, 'glob' => $glob,
        ];
    }

    public static function isTerminalAction(array $action): bool
    {
        return self::isTerminal($action['type']);
    }

    /**
     * Reads and validates a bundle payload from JSON text; null when it does not conform.
     *
     * @return array<string,mixed>|null
     */
    public static function parsePayload(string $text): ?array
    {
        [$ok, $v] = Json::parse($text);
        return $ok ? self::parsePayloadValue($v) : null;
    }

    /** @return array<string,mixed>|null */
    public static function parsePayloadValue(mixed $v): ?array
    {
        $required = array_values(array_filter(self::PAYLOAD_KEYS, static fn (string $k): bool => $k !== 'onNonCanonical' && $k !== 'sigHeader' && $k !== 'disabled'));
        $m = Json::strictObject($v, self::PAYLOAD_KEYS, $required);
        if ($m === null) {
            return null;
        }
        $p = [];
        if (Json::asInt(Json::get($m, 'v'), 1, 1) === null) {
            return null;
        }
        $p['v'] = 1;
        $siteId = Json::get($m, 'siteId');
        if (!is_string($siteId) || preg_match(self::RE_SITE_ID, $siteId) !== 1) {
            return null;
        }
        $p['siteId'] = $siteId;
        $siteKey = Json::get($m, 'siteKey');
        if (!is_string($siteKey) || preg_match(self::RE_SITE_KEY, $siteKey) !== 1) {
            return null;
        }
        $p['siteKey'] = $siteKey;
        $cb = Json::get($m, 'challengeBase');
        if (!is_string($cb) || Util::utf16Len($cb) > 300 || preg_match(self::RE_CHALLENGE, $cb, $cm) !== 1) {
            return null;
        }
        $ch = Host::canonicalize($cm[1]);
        if ($ch === null || $ch !== $cm[1]) {
            return null;
        }
        $p['challengeBase'] = $cb;
        foreach (['version' => 1, 'issuedAt' => 0, 'notBefore' => 0, 'expiresAt' => 0] as $k => $min) {
            $x = Json::asInt(Json::get($m, $k), $min, Limits::MAX_SAFE_INTEGER);
            if ($x === null) {
                return null;
            }
            $p[$k] = $x;
        }
        $fm = Json::get($m, 'failMode');
        if ($fm !== 'open' && $fm !== 'closed') {
            return null;
        }
        $p['failMode'] = $fm;
        $p['onNonCanonical'] = 'block-writes';
        if (Json::has($m, 'onNonCanonical')) {
            $s = Json::get($m, 'onNonCanonical');
            if ($s !== 'block-writes' && $s !== 'block') {
                return null;
            }
            $p['onNonCanonical'] = $s;
        }
        $minIat = Json::asInt(Json::get($m, 'minIat'), 0, Limits::MAX_SAFE_INTEGER);
        if ($minIat === null) {
            return null;
        }
        $p['minIat'] = $minIat;
        // Optional boolean: the bundle asks the integration to sign X-RG-Sig (needs a configured sigSecret).
        $sigHeader = Json::has($m, 'sigHeader') ? Json::get($m, 'sigHeader') : false;
        if (!is_bool($sigHeader)) {
            return null;
        }
        $p['sigHeader'] = $sigHeader;
        // Optional boolean kill switch (absent = false): true passes every request through untouched.
        $disabled = Json::has($m, 'disabled') ? Json::get($m, 'disabled') : false;
        if (!is_bool($disabled)) {
            return null;
        }
        $p['disabled'] = $disabled;
        $revoked = Json::asStringArray(Json::get($m, 'revokedJti'), 0, Limits::MAX_REVOKED_JTI);
        if ($revoked === null) {
            return null;
        }
        foreach ($revoked as $j) {
            if (preg_match(self::RE_JTI, $j) !== 1) {
                return null;
            }
        }
        $p['revokedJti'] = $revoked;
        $sm = Json::strictObject(Json::get($m, 'session'), ['ttl', 'max', 'clearanceTtl'], ['ttl', 'max', 'clearanceTtl']);
        if ($sm === null) {
            return null;
        }
        $ttl = Json::asInt(Json::get($sm, 'ttl'), 300, 86400);
        $max = Json::asInt(Json::get($sm, 'max'), 300, 86400);
        $cttl = Json::asInt(Json::get($sm, 'clearanceTtl'), 300, 86400);
        if ($ttl === null || $max === null || $cttl === null || $ttl > $max) {
            return null;
        }
        $p['session'] = ['ttl' => $ttl, 'max' => $max, 'clearanceTtl' => $cttl];
        $hosts = Json::asStringArray(Json::get($m, 'hosts'), 1, Limits::MAX_SITE_HOSTS);
        if ($hosts === null) {
            return null;
        }
        foreach ($hosts as $h) {
            if (!Host::isValidHostnamePattern($h)) {
                return null;
            }
        }
        $p['hosts'] = $hosts;
        $tk = Json::get($m, 'tokenKeys');
        if (!is_array($tk) || !array_is_list($tk) || count($tk) < 1 || count($tk) > 4) {
            return null;
        }
        $p['tokenKeys'] = [];
        foreach ($tk as $kx) {
            $k = self::parseKey($kx);
            if ($k === null) {
                return null;
            }
            $p['tokenKeys'][] = $k;
        }
        $pol = Json::get($m, 'policies');
        if (!is_array($pol) || !array_is_list($pol) || count($pol) > Limits::MAX_POLICIES) {
            return null;
        }
        $p['policies'] = [];
        $p['usesCookies'] = false;
        $ids = [];
        foreach ($pol as $rx) {
            $r = self::parseRule($rx);
            if ($r === null || isset($ids[$r['id']])) {
                return null;
            }
            $ids[$r['id']] = true;
            $p['policies'][] = $r;
            if ($r['when']['present']) {
                $p['usesCookies'] = true;
            }
            foreach ($r['actions'] as $a) {
                if ($a['type'] === 'challengePage') {
                    $p['usesCookies'] = true;
                }
            }
        }
        if (!($p['expiresAt'] > $p['notBefore'] && $p['expiresAt'] - $p['notBefore'] <= 86400)) {
            return null;
        }
        return $p;
    }
}
