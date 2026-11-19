<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Http;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * A cookie that serialises to exactly the Set-Cookie value of protocol v1, section 18.7:
 * "name=value; Max-Age=N; HttpOnly; Secure; SameSite=Lax; Path=/". Symfony's own serialisation
 * (lower-case attributes, Expires, "deleted" for an empty value) is not the wire format of the
 * spec, and the value is never URL-encoded (a return path stays a readable path).
 */
final class RawCookie extends Cookie
{
    private function __construct(private readonly string $header, string $name, string $value, private readonly int $maxAge)
    {
        parent::__construct($name, $value, $maxAge > 0 ? time() + $maxAge : 1, '/', null, true, true, true, Cookie::SAMESITE_LAX);
    }

    public static function make(string $name, string $value, int $maxAge, string $attributes): self
    {
        return new self($name . '=' . $value . '; Max-Age=' . $maxAge . '; ' . $attributes, $name, $value, $maxAge);
    }

    public function getMaxAge(): int
    {
        return $this->maxAge;
    }

    public function __toString(): string
    {
        return $this->header;
    }
}
