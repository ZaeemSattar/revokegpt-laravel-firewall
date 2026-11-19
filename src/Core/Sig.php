<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * Ed25519 verification (libsodium) with an explicit canonical-S check in PHP, strict base64url
 * and the key helpers. A key is an array ['kid' => string, 'alg' => string, 'pub' => string,
 * 'notAfter' => int].
 */
final class Sig
{
    /** The Ed25519 group order L as 32 big-endian bytes: 2^252 + 27742317777372353535851937790883648493. */
    private const GROUP_ORDER_L_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';

    /** Strict unpadded base64url: no padding, no characters outside the alphabet, no non-zero trailing bits, no length of 1 mod 4. */
    public static function fromBase64Url(string $s): ?string
    {
        $n = strlen($s);
        if ($n % 4 === 1 || preg_match('/\A[A-Za-z0-9_-]*\z/D', $s) !== 1) {
            return null;
        }
        $std = strtr($s, '-_', '+/') . str_repeat('=', (4 - $n % 4) % 4);
        $bin = base64_decode($std, true);
        if ($bin === false) {
            return null;
        }
        // A canonical encoding round-trips: this rejects non-zero trailing bits.
        if (rtrim(strtr(base64_encode($bin), '+/', '-_'), '=') !== $s) {
            return null;
        }
        return $bin;
    }

    /** The first 8 bytes of SHA-256(raw public key) as 16 lower-case hex characters. */
    public static function kidOfPublicKey(string $raw): string
    {
        return bin2hex(substr(hash('sha256', $raw, true), 0, 8));
    }

    /**
     * Whether the S half (little-endian, bytes 32..63) of a 64-byte signature is below the group
     * order L (RFC 8032). Checked here, before the libsodium call and independently of it, so a
     * malleated signature is never accepted.
     */
    public static function isCanonicalS(string $sig): bool
    {
        if (strlen($sig) !== 64) {
            return false;
        }
        $sBe = strrev(substr($sig, 32, 32));
        return strcmp($sBe, (string) hex2bin(self::GROUP_ORDER_L_HEX)) < 0;
    }

    /** Verifies domain || payload under a key: Ed25519, 64-byte signature with a canonical S. Never throws. */
    public static function verifyDomain(array $key, string $domain, string $payload, string $sig): bool
    {
        if ($key['alg'] !== 'Ed25519' || !self::isCanonicalS($sig)) {
            return false;
        }
        $pub = self::fromBase64Url($key['pub']);
        if ($pub === null || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $domain . $payload, $pub);
        } catch (\Throwable) {
            return false;
        }
    }

    /** The key's declared kid is the real kid of its public key (placeholders are not). */
    public static function keyIsConsistent(array $key): bool
    {
        $pub = self::fromBase64Url($key['pub']);
        return $pub !== null && strlen($pub) === 32 && self::kidOfPublicKey($pub) === $key['kid'];
    }

    /**
     * Production bundle keys, current and next (as packages/protocol/src/policy/pinned-keys.ts).
     *
     * @return list<array{kid:string,alg:string,pub:string,notAfter:int}>
     */
    public static function pinnedPolicyKeys(): array
    {
        return [
            ['kid' => 'dc43cba74b531a58', 'alg' => 'Ed25519', 'pub' => '9aawK32yAp7kIuAaLJYE7Y5W40w0TjJxuaoqSe2NNuA', 'notAfter' => 4102444800],
            ['kid' => '79105aac0b45dd0c', 'alg' => 'Ed25519', 'pub' => 'ZdstW3eqBJ7TpwPkudQKVd_g2wNqUsGSMUKOzXpCF9M', 'notAfter' => 4102444800],
        ];
    }

    /** Production session signing keys, current and next. */
    public static function pinnedSessionKeys(): array
    {
        return [
            ['kid' => 'cd7e0df68b55c9ce', 'alg' => 'Ed25519', 'pub' => 'WlDajxX_FgHup2I3O4qlujgfgBhZdwBIhs5dqqDrXwM', 'notAfter' => 4102444800],
            ['kid' => 'e3386ef628ea8430', 'alg' => 'Ed25519', 'pub' => 'oDW6PsK0hRuxprSto16YCyuY_tcZcI4aH1TyhUfD6Ms', 'notAfter' => 4102444800],
        ];
    }

    /**
     * The public TEST bundle keys (their seeds are public), for conformance runs only. The
     * Firewall refuses them unless the site key is non-canonical and the API base is loopback.
     *
     * @return list<array{kid:string,alg:string,pub:string,notAfter:int}>
     */
    public static function testPolicyKeys(): array
    {
        return [
            ['kid' => '3d75ce3772a93b6e', 'alg' => 'Ed25519', 'pub' => 'mkgsn6TedEnh1On988cT8ujJnUMDF1SaeTPCjRaasF0', 'notAfter' => 4102444800],
            ['kid' => '30c94a60406a6ea6', 'alg' => 'Ed25519', 'pub' => 'nvfcYJX2dOZjA0fjvFW_XkspaP7RVu5_Shw-muGLXj0', 'notAfter' => 4102444800],
            ['kid' => '990ae9db448cb6fd', 'alg' => 'Ed25519', 'pub' => 'JMmCSFznt-U2yeFyfLpLykQcWQoyuZXv701HS8xeFxw', 'notAfter' => 1700000000],
        ];
    }

    public static function isTestKey(array $k): bool
    {
        foreach (self::testPolicyKeys() as $t) {
            if ($k['kid'] === $t['kid'] || $k['pub'] === $t['pub']) {
                return true;
            }
        }
        return false;
    }
}
