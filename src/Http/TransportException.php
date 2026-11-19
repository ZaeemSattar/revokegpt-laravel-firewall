<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Http;

/**
 * A network-level failure of the API transport. {@see $timeout} is true for a timeout (never retried);
 * {@see $connect} is true only when the connection could not be established (nothing was sent), the
 * one case that may be retried.
 */
final class TransportException extends \RuntimeException
{
    public function __construct(string $message, public readonly bool $timeout = false, public readonly bool $connect = false)
    {
        parent::__construct($message);
    }
}
