<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

use RevokeGPT\Internal\Host as SdkHost;

/** Host canonicalisation and matching (protocol v1, sections 3 and 18): the SDK's implementation, one copy. */
final class Host
{
    public static function canonicalize(string $input): ?string
    {
        return SdkHost::canonicalize($input);
    }

    /** A canonical exact hostname, or "*." plus a canonical hostname of at least two labels (last label not numeric). */
    public static function isValidHostnamePattern(string $p): bool
    {
        return SdkHost::isValidHostnamePattern($p);
    }

    /** Host equals the exact pattern, or is a strict subdomain of a "*." pattern. */
    public static function hostnameMatches(string $host, string $pattern): bool
    {
        return SdkHost::hostnameMatches($host, $pattern);
    }

    /** The canonical host of a Host header (an optional ":port" removed), or null. */
    public static function requestHost(string $host): ?string
    {
        return SdkHost::requestHost($host);
    }

    /** Matches a rule host pattern against a request host (a port is stripped first). */
    public static function hostMatches(string $pattern, string $host): bool
    {
        return SdkHost::hostMatches($pattern, $host);
    }
}
