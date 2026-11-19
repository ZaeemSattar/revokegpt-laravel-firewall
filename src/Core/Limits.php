<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Core;

/**
 * Policy limits (protocol v1, section 18.1). Reference: POLICY_LIMITS in
 * packages/protocol/src/policy/limits.ts. Strings here are PHP byte strings (UTF-8 text); every
 * length limit counts UTF-16 code units as the reference does (see Util::utf16Len).
 */
final class Limits
{
    public const MAX_POLICIES = 100;
    public const MAX_ACTIONS_PER_RULE = 8;
    public const MAX_GLOB_LENGTH = 200;
    public const MAX_WILDCARDS = 8;
    public const MAX_HOSTS_PER_RULE = 16;
    public const MAX_METHODS_PER_RULE = 8;
    public const MAX_SITE_HOSTS = 64;
    public const MAX_BUNDLE_BYTES = 65536;
    public const MAX_SERVED_BYTES = 98304;
    public const MAX_RAW_PATH_BYTES = 8192;
    public const MAX_REVOKED_JTI = 1000;
    public const MAX_SET_HEADER_VALUE = 256;
    public const MAX_SET_HEADER_NAME = 64;
    public const MAX_RULE_NAME = 64;
    public const MAX_COOKIE_BYTES = 4096;
    public const MAX_SESSION_TOKEN_LEN = 4096;
    public const STALE_GRACE_SECONDS = 21600;
    public const CLOCK_SKEW_SECONDS = 300;
    public const MAX_RETURN_PATH_LENGTH = 2048;
    public const MAX_SAFE_INTEGER = 9007199254740991;

    public const POLICY_SIGNATURE_DOMAIN = "rg-policy-v1\0";
    public const SESSION_SIGNATURE_DOMAIN = "rg-session-v1\0";

    public const COOKIE_SESSION = '__Host-rg_s';
    public const COOKIE_CLEARANCE = '__Host-rg_c';
    public const COOKIE_RETURN_PATH = '__Host-rg_r';
    public const COOKIE_ATTRIBUTES = 'HttpOnly; Secure; SameSite=Lax; Path=/';

    public const PATH_RETURN = '/__rg/return';
    public const PATH_SESSION = '/__rg/session';
    public const RETURN_BODY_LIMIT = 4096;
    public const RETURN_FIELD = 'rg_clearance';
    public const SESSION_INIT_HEADER = 'X-RG-Session-Init';
}
