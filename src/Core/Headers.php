<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/** Header helpers: the x-rg-* strip set, the score bucket and the return-path check. */
final class Headers
{
    /** True for a name that, case-insensitively and with "_" read as "-", starts with "x-rg-". */
    public static function isRgHeader(string $name): bool
    {
        return str_starts_with(strtr(strtolower($name), '_', '-'), 'x-rg-');
    }

    /**
     * The names (in order, with duplicates) to delete on ingress.
     *
     * @param list<string> $names
     * @return list<string>
     */
    public static function stripRgHeaders(array $names): array
    {
        $out = [];
        foreach ($names as $n) {
            if (self::isRgHeader($n)) {
                $out[] = $n;
            }
        }
        return $out;
    }

    /** X-RG-Score: the score floored to a multiple of 10 on 0-100; NaN, infinities and negatives give "0". */
    public static function scoreBucket(float $score): string
    {
        if (is_nan($score) || is_infinite($score) || $score <= 0) {
            return '0';
        }
        if ($score >= 1) {
            return '100';
        }
        return (string) ((int) floor(floor($score * 1e6 + 0.5) / 1e5) * 10);
    }

    /**
     * Whether $p is safe as a return path (__Host-rg_r, Location after /__rg/return): a relative path
     * starting with a single "/", no backslash, space, control or non-ASCII byte, no "//" or dot
     * segment (encoded or not) in the path part, no encoded "/" or "\" in the path part (and no
     * encoded control anywhere), at most 2048 characters, and not pointing into /__rg/.
     */
    public static function isSafeReturnPath(string $p): bool
    {
        if ($p === '' || Util::utf16Len($p) > Limits::MAX_RETURN_PATH_LENGTH) {
            return false;
        }
        if ($p[0] !== '/' || (strlen($p) > 1 && ($p[1] === '/' || $p[1] === '\\'))) {
            return false;
        }
        for ($i = 0, $n = strlen($p); $i < $n; $i++) {
            $c = ord($p[$i]);
            if ($c <= 0x20 || $c >= 0x7f || $c === 0x5c) {
                return false;
            }
        }
        if (preg_match('/%(?:[01][0-9A-Fa-f]|7[Ff])/D', $p) === 1) {
            return false;
        }
        $path = substr($p, 0, strcspn($p, '?#'));
        if (preg_match('/%(?:2[Ff]|5[Cc])/D', $path) === 1 || str_contains($path, '//')) {
            return false;
        }
        if (preg_match('#(?:\A|/)(?:\.|%2[Ee]){1,2}(?:/|\z)#D', $path) === 1) {
            return false;
        }
        return !($path === '/__rg' || str_starts_with($path, '/__rg/'));
    }
}
