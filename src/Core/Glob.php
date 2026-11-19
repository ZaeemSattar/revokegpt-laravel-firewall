<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * A compiled path glob (protocol v1, section 18.2): "**" segments (zero or more whole segments)
 * and segments whose only metacharacter is "*". No regex, no recursion.
 */
final class Glob
{
    /**
     * @param list<array{0:bool,1:string}> $segments [doubleStar, pattern]
     */
    private function __construct(
        public readonly string $source,
        public readonly string $canonical,
        private readonly array $segments,
    ) {
    }

    /** Compiles a glob, or returns null when it is not valid. */
    public static function compile(string $p): ?self
    {
        if ($p === '' || Util::utf16Len($p) > Limits::MAX_GLOB_LENGTH) {
            return null;
        }
        if ($p[0] !== '/') {
            return null;
        }
        $body = strlen($p) > 1 && str_ends_with($p, '/') ? substr($p, 0, -1) : $p;
        if ($body === '/') {
            return new self($p, '/', []);
        }
        $segs = [];
        $canon = [];
        $wildcards = 0;
        foreach (explode('/', substr($body, 1)) as $s) {
            if ($s === '') {
                return null;
            }
            if ($s === '**') {
                $wildcards++;
                $segs[] = [true, ''];
                $canon[] = '**';
                continue;
            }
            if (str_contains($s, '**')) {
                return null;
            }
            $pieces = explode('*', $s);
            $wildcards += count($pieces) - 1;
            $cp = [];
            foreach ($pieces as $piece) {
                if ($piece === '') {
                    $cp[] = '';
                    continue;
                }
                $r = Normalize::decodeSegment($piece, true);
                if (!$r['ok'] || str_contains($r['text'], '*')) {
                    return null;
                }
                $cp[] = $r['text'];
            }
            $seg = implode('*', $cp);
            if ($seg === '.' || $seg === '..') {
                return null;
            }
            $segs[] = [false, $seg];
            $canon[] = $seg;
        }
        if ($wildcards > Limits::MAX_WILDCARDS) {
            return null;
        }
        return new self($p, '/' . implode('/', $canon), $segs);
    }

    private static function segmentMatches(string $p, string $s): bool
    {
        $pl = strlen($p);
        $sl = strlen($s);
        $pi = 0;
        $si = 0;
        $star = -1;
        $mark = 0;
        while ($si < $sl) {
            if ($pi < $pl && $p[$pi] === '*') {
                $star = $pi;
                $pi++;
                $mark = $si;
            } elseif ($pi < $pl && $p[$pi] === $s[$si]) {
                $pi++;
                $si++;
            } elseif ($star >= 0) {
                $pi = $star + 1;
                $mark++;
                $si = $mark;
            } else {
                return false;
            }
        }
        while ($pi < $pl && $p[$pi] === '*') {
            $pi++;
        }
        return $pi === $pl;
    }

    /** Matches a normalised path (starting with "/"). One saved restart point per level, O(N x P x L). */
    public function matches(string $path): bool
    {
        if ($path === '' || $path[0] !== '/') {
            return false;
        }
        $ps = $path === '/' ? [] : explode('/', substr($path, 1));
        $m = count($this->segments);
        $n = count($ps);
        $pi = 0;
        $si = 0;
        $starP = -1;
        $starS = 0;
        while ($si < $n) {
            if ($pi < $m && $this->segments[$pi][0]) {
                $starP = $pi;
                $pi++;
                $starS = $si;
            } elseif ($pi < $m && self::segmentMatches($this->segments[$pi][1], $ps[$si])) {
                $pi++;
                $si++;
            } elseif ($starP >= 0) {
                $pi = $starP + 1;
                $starS++;
                $si = $starS;
            } else {
                return false;
            }
        }
        while ($pi < $m && $this->segments[$pi][0]) {
            $pi++;
        }
        return $pi === $m;
    }
}
