<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

use RevokeGPT\Internal\Json as SdkJson;
use stdClass;

/**
 * Strict JSON reading: the SDK's implementation, one copy. JSON objects stay stdClass (so {} and [] differ); a failure
 * is a null/false result, never a throw. Numbers are int or float.
 */
final class Json
{
    /** @return array{0:bool,1:mixed} [ok, value] for exactly one JSON value. */
    public static function parse(string $text): array
    {
        return SdkJson::parse($text);
    }

    /** @return list<string> */
    public static function keys(stdClass $o): array
    {
        return SdkJson::keys($o);
    }

    public static function has(stdClass $o, string $k): bool
    {
        return SdkJson::has($o, $k);
    }

    public static function get(stdClass $o, string $k): mixed
    {
        return SdkJson::get($o, $k);
    }

    /**
     * The object if it has no key outside $allowed and every key in $required; else null.
     *
     * @param list<string> $allowed
     * @param list<string> $required
     */
    public static function strictObject(mixed $v, array $allowed, array $required): ?stdClass
    {
        return SdkJson::strictObject($v, $allowed, $required);
    }

    public static function asInt(mixed $v, int $min, int $max): ?int
    {
        return SdkJson::asInt($v, $min, $max);
    }

    public static function asFloat(mixed $v): ?float
    {
        return SdkJson::asFloat($v);
    }

    /** @return list<string>|null */
    public static function asStringArray(mixed $v, int $min, int $max): ?array
    {
        return SdkJson::asStringArray($v, $min, $max);
    }
}
