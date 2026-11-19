<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

use RevokeGPT\Internal\Punycode as SdkPunycode;

/** Punycode (RFC 3492): the SDK's implementation, one copy. */
final class Punycode
{
    /** @return list<int>|null code points, or null */
    public static function decode(string $input): ?array
    {
        return SdkPunycode::decode($input);
    }

    /** @param list<int> $in */
    public static function encode(array $in): ?string
    {
        return SdkPunycode::encode($in);
    }
}
