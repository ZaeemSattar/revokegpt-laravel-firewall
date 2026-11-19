<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * Offline verification of a session or clearance token (protocol v1, section 18.6). Every failure
 * is "invalid"; an empty token is "none".
 */
final class Session
{
    private const CLAIM_KEYS = ['exp', 'host', 'iat', 'jti', 'lvl', 'max', 'sc', 'sid'];

    /** Strict UTF-8 payload text with one leading BOM dropped (as TextDecoder does); null when invalid. */
    public static function decodeUtf8(string $payload): ?string
    {
        if (str_starts_with($payload, "\xEF\xBB\xBF")) {
            $payload = substr($payload, 3);
        }
        return Util::validUtf8($payload) ? $payload : null;
    }

    /**
     * @param list<array{kid:string,alg:string,pub:string,notAfter:int}> $keys
     * @param array{siteId:string,host:string} $expect
     * @param array{minIat:int,revokedJti:list<string>} $b
     * @return array{state: array{kind:string,lvl:int,sc:int}, claims: ?array<string,mixed>}
     */
    public static function verifyClaims(string $token, array $keys, array $expect, array $b, int $now): array
    {
        $invalid = ['state' => ['kind' => 'invalid', 'lvl' => 0, 'sc' => 0], 'claims' => null];
        if ($token === '') {
            return ['state' => ['kind' => 'none', 'lvl' => 0, 'sc' => 0], 'claims' => null];
        }
        if (Util::utf16Len($token) > Limits::MAX_SESSION_TOKEN_LEN) {
            return $invalid;
        }
        $parts = explode('.', $token);
        if (count($parts) !== 4 || $parts[0] !== 'v1') {
            return $invalid;
        }
        [, $kid, $p, $s] = $parts;
        if (preg_match(Schema::RE_KID, $kid) !== 1) {
            return $invalid;
        }
        $key = null;
        foreach ($keys as $k) {
            if ($k['kid'] === $kid) {
                $key = $k;
                break;
            }
        }
        if ($key === null || !Sig::keyIsConsistent($key) || $now > $key['notAfter']) {
            return $invalid;
        }
        $payload = Sig::fromBase64Url($p);
        $sig = Sig::fromBase64Url($s);
        if ($payload === null || $sig === null) {
            return $invalid;
        }
        if (!Sig::verifyDomain($key, Limits::SESSION_SIGNATURE_DOMAIN, $payload, $sig)) {
            return $invalid;
        }
        $text = self::decodeUtf8($payload);
        if ($text === null) {
            return $invalid;
        }
        [$ok, $j] = Json::parse($text);
        $c = $ok ? Json::strictObject($j, self::CLAIM_KEYS, self::CLAIM_KEYS) : null;
        if ($c === null) {
            return $invalid;
        }
        $sid = Json::get($c, 'sid');
        $host = Json::get($c, 'host');
        $jti = Json::get($c, 'jti');
        if (!is_string($sid) || !is_string($host) || !is_string($jti)) {
            return $invalid;
        }
        $iat = Json::asInt(Json::get($c, 'iat'), 0, Limits::MAX_SAFE_INTEGER);
        $exp = Json::asInt(Json::get($c, 'exp'), 0, Limits::MAX_SAFE_INTEGER);
        $max = Json::asInt(Json::get($c, 'max'), 1, 86400);
        if ($iat === null || $exp === null || $max === null) {
            return $invalid;
        }
        $lvl = Json::asInt(Json::get($c, 'lvl'), 0, 2);
        $sc = Json::asInt(Json::get($c, 'sc'), 0, 3);
        if ($lvl === null || $sc === null || preg_match(Schema::RE_JTI, $jti) !== 1) {
            return $invalid;
        }
        $want = Host::requestHost($expect['host']);
        if ($sid !== $expect['siteId'] || $want === null || $host !== $want) {
            return $invalid;
        }
        if ($iat > $now + Limits::CLOCK_SKEW_SECONDS) {
            return $invalid;
        }
        if ($now >= $exp || $exp > $iat + $max || $now > $iat + $max) {
            return $invalid;
        }
        if ($iat < $b['minIat']) {
            return $invalid;
        }
        if (in_array($jti, $b['revokedJti'], true)) {
            return $invalid;
        }
        return [
            'state' => ['kind' => 'valid', 'lvl' => $lvl, 'sc' => $sc],
            'claims' => ['sid' => $sid, 'host' => $host, 'iat' => $iat, 'exp' => $exp, 'max' => $max,
                'lvl' => $lvl, 'sc' => $sc, 'jti' => $jti],
        ];
    }

    /**
     * @param list<array{kid:string,alg:string,pub:string,notAfter:int}> $keys
     * @return array{kind:string,lvl:int,sc:int}
     */
    public static function verify(string $token, array $keys, array $expect, array $b, int $now): array
    {
        return self::verifyClaims($token, $keys, $expect, $b, $now)['state'];
    }
}
