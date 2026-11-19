<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * Path normalisation (protocol v1, section 18.3). Works on bytes: a raw non-ASCII byte is invalid
 * in request mode and is percent-encoded as upper-case UTF-8 in glob mode.
 *
 * A result is an array: ['ok' => true, 'path' => ..., 'collapsed' => ...] or
 * ['ok' => false, 'reason' => 'invalid'|'non-canonical', 'detail' => ...].
 */
final class Normalize
{
    /** @return array{ok:false,reason:string,detail:string} */
    private static function bad(string $reason, string $detail): array
    {
        return ['ok' => false, 'reason' => $reason, 'detail' => $detail];
    }

    /** @return array{0:int,1:int,2:int}|null length, lo, hi of the sequence led by $lead */
    private static function utf8Shape(int $lead): ?array
    {
        if ($lead >= 0xc2 && $lead <= 0xdf) {
            return [2, 0x80, 0xbf];
        }
        if ($lead === 0xe0) {
            return [3, 0xa0, 0xbf];
        }
        if ($lead === 0xed) {
            return [3, 0x80, 0x9f];
        }
        if ($lead >= 0xe1 && $lead <= 0xef) {
            return [3, 0x80, 0xbf];
        }
        if ($lead === 0xf0) {
            return [4, 0x90, 0xbf];
        }
        if ($lead === 0xf4) {
            return [4, 0x80, 0x8f];
        }
        if ($lead >= 0xf1 && $lead <= 0xf3) {
            return [4, 0x80, 0xbf];
        }
        return null;
    }

    /** Bytes that stay percent-encoded in the canonical spelling: % ? # space [ ] { } | ^ " < > backtick. */
    private static function keepEncoded(int $b): bool
    {
        return in_array($b, [0x25, 0x3f, 0x23, 0x20, 0x5b, 0x5d, 0x7b, 0x7d, 0x7c, 0x5e, 0x22, 0x3c, 0x3e, 0x60], true);
    }

    /**
     * Canonical spelling of one path fragment holding no "/" (a request segment or a glob piece).
     *
     * @return array{ok:bool,text?:string,escaped?:bool,reason?:string,detail?:string}
     */
    public static function decodeSegment(string $raw, bool $encodeNonAscii): array
    {
        $out = '';
        $escaped = false;
        $n = strlen($raw);
        $i = 0;
        while ($i < $n) {
            $c = ord($raw[$i]);
            if ($c === 0x25) {
                $bytes = [];
                while ($i < $n && $raw[$i] === '%') {
                    $h = $i + 1 < $n ? Util::hexVal($raw[$i + 1]) : -1;
                    $l = $i + 2 < $n ? Util::hexVal($raw[$i + 2]) : -1;
                    if ($h < 0 || $l < 0) {
                        return self::bad('invalid', 'bad-escape');
                    }
                    $bytes[] = $h * 16 + $l;
                    $i += 3;
                }
                $escaped = true;
                $bc = count($bytes);
                $k = 0;
                while ($k < $bc) {
                    $b = $bytes[$k];
                    if ($b < 0x80) {
                        if ($b === 0x2f || $b === 0x5c) {
                            return self::bad('non-canonical', 'encoded-separator');
                        }
                        if ($b === 0x3b) {
                            return self::bad('non-canonical', 'encoded-semicolon');
                        }
                        if ($b < 0x20 || $b === 0x7f) {
                            return self::bad('non-canonical', 'encoded-control');
                        }
                        $out .= self::keepEncoded($b) ? Util::pct($b) : chr($b);
                        $k++;
                        continue;
                    }
                    $shape = self::utf8Shape($b);
                    if ($shape === null || $k + $shape[0] > $bc) {
                        return self::bad('non-canonical', 'invalid-utf8');
                    }
                    $out .= Util::pct($b);
                    for ($j = 1; $j < $shape[0]; $j++) {
                        $cb = $bytes[$k + $j];
                        $lo = $j === 1 ? $shape[1] : 0x80;
                        $hi = $j === 1 ? $shape[2] : 0xbf;
                        if ($cb < $lo || $cb > $hi) {
                            return self::bad('non-canonical', 'invalid-utf8');
                        }
                        $out .= Util::pct($cb);
                    }
                    $k += $shape[0];
                }
                continue;
            }
            if ($c === 0x3b) {
                return self::bad('non-canonical', 'path-parameter');
            }
            if ($c === 0x5c) {
                return self::bad('invalid', 'backslash');
            }
            if ($c < 0x20 || $c === 0x7f) {
                return self::bad('invalid', 'control-character');
            }
            if ($c === 0x3f || $c === 0x23) {
                return self::bad('invalid', 'reserved-character');
            }
            if ($c > 0x7e) {
                if (!$encodeNonAscii) {
                    return self::bad('invalid', 'non-ascii');
                }
                $shape = self::utf8Shape($c);
                if ($shape === null || $i + $shape[0] > $n) {
                    return self::bad('invalid', 'lone-surrogate');
                }
                $out .= Util::pct($c);
                for ($j = 1; $j < $shape[0]; $j++) {
                    $cb = ord($raw[$i + $j]);
                    $lo = $j === 1 ? $shape[1] : 0x80;
                    $hi = $j === 1 ? $shape[2] : 0xbf;
                    if ($cb < $lo || $cb > $hi) {
                        return self::bad('invalid', 'lone-surrogate');
                    }
                    $out .= Util::pct($cb);
                }
                $i += $shape[0];
                continue;
            }
            $out .= self::keepEncoded($c) ? Util::pct($c) : $raw[$i];
            $i++;
        }
        return ['ok' => true, 'text' => $out, 'escaped' => $escaped];
    }

    /** RFC 3986 5.2.4 on a path starting with "/". Empty segments are kept. */
    public static function removeDotSegments(string $path): string
    {
        $segs = explode('/', $path);
        $out = [];
        $trailing = false;
        $count = count($segs);
        for ($i = 1; $i < $count; $i++) {
            $s = $segs[$i];
            $last = $i === $count - 1;
            if ($s === '.') {
                $trailing = $last;
            } elseif ($s === '..') {
                if ($out !== []) {
                    array_pop($out);
                }
                $trailing = $last;
            } else {
                $out[] = $s;
                $trailing = false;
            }
        }
        if ($trailing) {
            $out[] = '';
        }
        return '/' . implode('/', $out);
    }

    private static function dropTrailingSlash(string $p): string
    {
        return strlen($p) > 1 && str_ends_with($p, '/') ? substr($p, 0, -1) : $p;
    }

    private static function collapseSlashes(string $s): string
    {
        return preg_replace('#/{2,}#', '/', $s) ?? $s;
    }

    /**
     * Normalises a raw request target (origin-form: path and optional query). Pass the raw
     * REQUEST_URI, never a framework-decoded path.
     *
     * @return array{ok:bool,path?:string,collapsed?:string,reason?:string,detail?:string}
     */
    public static function normalize(string $rawTarget): array
    {
        $len = strlen($rawTarget);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($rawTarget[$i]);
            if ($c < 0x20 || $c === 0x7f) {
                return self::bad('invalid', 'control-character');
            }
        }
        if ($len === 0 || $rawTarget[0] !== '/') {
            return self::bad('invalid', 'not-origin-form');
        }
        $end = strcspn($rawTarget, '?#');
        $raw = substr($rawTarget, 0, $end);
        if (Util::utf16Len($raw) > Limits::MAX_RAW_PATH_BYTES) {
            return self::bad('non-canonical', 'path-too-long');
        }
        $decoded = '';
        foreach (explode('/', $raw) as $i => $p) {
            $r = self::decodeSegment($p, false);
            if (!$r['ok']) {
                return self::bad($r['reason'], $r['detail']);
            }
            if (($r['text'] === '.' || $r['text'] === '..') && $r['escaped']) {
                return self::bad('non-canonical', 'encoded-dot-segment');
            }
            if ($i > 0) {
                $decoded .= '/';
            }
            $decoded .= $r['text'];
        }
        return [
            'ok' => true,
            'path' => self::dropTrailingSlash(self::removeDotSegments($decoded)),
            'collapsed' => self::dropTrailingSlash(self::removeDotSegments(self::collapseSlashes($decoded))),
        ];
    }
}
