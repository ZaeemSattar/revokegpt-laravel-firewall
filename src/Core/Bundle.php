<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/** Signed policy bundle verification (protocol v1, section 18.5). */
final class Bundle
{
    /**
     * Verifies a served bundle. Checked in order: size, schema (envelope), kid, sig, schema (payload),
     * site, rollback, not-yet, expired. The signature covers the exact decoded payload bytes; nothing
     * is re-serialised, and a bad signature is never partially trusted.
     *
     * @param list<array{kid:string,alg:string,pub:string,notAfter:int}> $pinned
     * With $expect['serving'] the not-yet and expired checks are skipped: the integration re-verifies a
     * cached bundle on every request, and the stale-while-error window is enforced by Decide::decide().
     *
     * @param array{siteId:string,siteKey?:string,anySite?:bool,serving?:bool} $expect
     * @return array{ok:bool,payload?:array<string,mixed>,bytes?:string,reason?:string}
     */
    public static function verify(string $served, array $pinned, int $now, int $minVersion, array $expect): array
    {
        if (Util::utf16Len($served) > Limits::MAX_SERVED_BYTES) {
            return ['ok' => false, 'reason' => 'size'];
        }
        [$ok, $env] = Json::parse($served);
        $keys = ['alg', 'kid', 'payload', 'sig'];
        $e = $ok ? Json::strictObject($env, $keys, $keys) : null;
        if ($e === null || count(Json::keys($e)) !== 4) {
            return ['ok' => false, 'reason' => 'schema'];
        }
        $alg = Json::get($e, 'alg');
        $kid = Json::get($e, 'kid');
        $payloadB64 = Json::get($e, 'payload');
        $sigB64 = Json::get($e, 'sig');
        if (!is_string($alg) || !is_string($kid) || !is_string($payloadB64) || !is_string($sigB64) || $alg !== 'Ed25519') {
            return ['ok' => false, 'reason' => 'schema'];
        }
        $payload = Sig::fromBase64Url($payloadB64);
        $sig = Sig::fromBase64Url($sigB64);
        if ($payload === null || $sig === null) {
            return ['ok' => false, 'reason' => 'schema'];
        }
        if (strlen($payload) > Limits::MAX_BUNDLE_BYTES) {
            return ['ok' => false, 'reason' => 'size'];
        }
        $key = null;
        foreach ($pinned as $k) {
            if ($k['kid'] === $kid && $k['alg'] === $alg) {
                $key = $k;
                break;
            }
        }
        if ($key === null || !Sig::keyIsConsistent($key) || $now > $key['notAfter']) {
            return ['ok' => false, 'reason' => 'kid'];
        }
        if (!Sig::verifyDomain($key, Limits::POLICY_SIGNATURE_DOMAIN, $payload, $sig)) {
            return ['ok' => false, 'reason' => 'sig'];
        }
        $text = Session::decodeUtf8($payload);
        $p = $text === null ? null : Schema::parsePayload($text);
        if ($p === null) {
            return ['ok' => false, 'reason' => 'schema'];
        }
        if (!($expect['anySite'] ?? false) && $p['siteId'] !== ($expect['siteId'] ?? '')) {
            return ['ok' => false, 'reason' => 'site'];
        }
        if (($expect['siteKey'] ?? '') !== '' && $p['siteKey'] !== $expect['siteKey']) {
            return ['ok' => false, 'reason' => 'site'];
        }
        if ($p['version'] < $minVersion) {
            return ['ok' => false, 'reason' => 'rollback'];
        }
        if ($expect['serving'] ?? false) {
            return ['ok' => true, 'payload' => $p, 'bytes' => $payload];
        }
        if ($p['notBefore'] > $now + Limits::CLOCK_SKEW_SECONDS) {
            return ['ok' => false, 'reason' => 'not-yet'];
        }
        if ($now > $p['expiresAt'] + Limits::CLOCK_SKEW_SECONDS) {
            return ['ok' => false, 'reason' => 'expired'];
        }
        return ['ok' => true, 'payload' => $p, 'bytes' => $payload];
    }
}
