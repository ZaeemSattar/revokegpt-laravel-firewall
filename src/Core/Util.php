<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/** Small byte-string helpers shared by the core. */
final class Util
{
    /**
     * Length in UTF-16 code units, which is what the reference (JavaScript string length) counts for
     * every length limit. An invalid byte counts as one unit (it would read as U+FFFD).
     */
    public static function utf16Len(string $s): int
    {
        $n = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len;) {
            $c = ord($s[$i]);
            $size = 1;
            $units = 1;
            if ($c >= 0xc2 && $c <= 0xdf) {
                $size = 2;
            } elseif ($c >= 0xe0 && $c <= 0xef) {
                $size = 3;
            } elseif ($c >= 0xf0 && $c <= 0xf4) {
                $size = 4;
                $units = 2;
            }
            if ($size > 1) {
                // Only count a well-formed sequence as one character; otherwise one invalid byte.
                $ok = $i + $size <= $len && self::validSequence($s, $i, $size);
                if (!$ok) {
                    $size = 1;
                    $units = 1;
                }
            }
            $n += $units;
            $i += $size;
        }
        return $n;
    }

    private static function validSequence(string $s, int $i, int $size): bool
    {
        $lead = ord($s[$i]);
        $lo = 0x80;
        $hi = 0xbf;
        if ($lead === 0xe0) {
            $lo = 0xa0;
        } elseif ($lead === 0xed) {
            $hi = 0x9f;
        } elseif ($lead === 0xf0) {
            $lo = 0x90;
        } elseif ($lead === 0xf4) {
            $hi = 0x8f;
        }
        $b1 = ord($s[$i + 1]);
        if ($b1 < $lo || $b1 > $hi) {
            return false;
        }
        for ($j = 2; $j < $size; $j++) {
            $b = ord($s[$i + $j]);
            if ($b < 0x80 || $b > 0xbf) {
                return false;
            }
        }
        return true;
    }

    public static function hexVal(string $c): int
    {
        $o = ord($c);
        if ($o >= 48 && $o <= 57) {
            return $o - 48;
        }
        if ($o >= 65 && $o <= 70) {
            return $o - 65 + 10;
        }
        if ($o >= 97 && $o <= 102) {
            return $o - 97 + 10;
        }
        return -1;
    }

    public static function pct(int $c): string
    {
        return '%' . strtoupper(str_pad(dechex($c), 2, '0', STR_PAD_LEFT));
    }

    /** True when $s is valid UTF-8. */
    public static function validUtf8(string $s): bool
    {
        return preg_match('//u', $s) === 1;
    }

    /** Code points of a valid UTF-8 string. */
    public static function codepoints(string $s): array
    {
        $out = [];
        $len = strlen($s);
        for ($i = 0; $i < $len;) {
            $c = ord($s[$i]);
            if ($c < 0x80) {
                $out[] = $c;
                $i++;
            } elseif ($c < 0xe0) {
                $out[] = (($c & 0x1f) << 6) | (ord($s[$i + 1]) & 0x3f);
                $i += 2;
            } elseif ($c < 0xf0) {
                $out[] = (($c & 0x0f) << 12) | ((ord($s[$i + 1]) & 0x3f) << 6) | (ord($s[$i + 2]) & 0x3f);
                $i += 3;
            } else {
                $out[] = (($c & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3f) << 12) | ((ord($s[$i + 2]) & 0x3f) << 6)
                    | (ord($s[$i + 3]) & 0x3f);
                $i += 4;
            }
        }
        return $out;
    }
}
