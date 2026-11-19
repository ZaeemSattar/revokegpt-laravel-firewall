<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use RevokeGPT\Firewall\Core\Sig;
use RevokeGPT\Firewall\Http\RevokeGPTMiddleware;

/**
 * Registers the Firewall (cache-backed) and, unless turned off, prepends RevokeGPTMiddleware to
 * the global middleware stack so it sees the request before routing or any other middleware.
 */
final class RevokeGPTServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/revokegpt.php', 'revokegpt');

        $this->app->singleton(Firewall::class, function ($app): Firewall {
            /** @var array<string,mixed> $c */
            $c = $app['config']->get('revokegpt');
            $cfg = [
                'siteKey' => $c['site_key'],
                'secretKey' => self::blank($c['secret_key'] ?? null),
                'apiBase' => self::blank($c['api_base'] ?? null),
                'siteId' => self::blank($c['site_id'] ?? null),
                'initialFailMode' => self::blank($c['initial_fail_mode'] ?? null),
                'sigSecret' => self::blank($c['sig_secret'] ?? null),
            ];
            $ms = self::blank($c['bundle_refresh_ms'] ?? null);
            if ($ms !== null && (int) $ms > 0) {
                $cfg['refreshIntervalMs'] = (int) $ms;
            }
            if (!empty($c['pin_test_keys'])) {
                $cfg['pinnedKeys'] = Sig::testPolicyKeys();
            }
            $store = self::blank($c['cache_store'] ?? null);
            $log = $app->bound(LoggerInterface::class) ? $app->make(LoggerInterface::class) : null;

            return new Firewall($cfg, $app['cache']->store($store), null, null, $log);
        });

        $this->app->singleton(RevokeGPTMiddleware::class, function ($app): RevokeGPTMiddleware {
            $log = $app->bound(LoggerInterface::class) ? $app->make(LoggerInterface::class) : null;
            return new RevokeGPTMiddleware($app->make(Firewall::class), $log);
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/revokegpt.php' => $this->app->configPath('revokegpt.php')], 'revokegpt-config');

        $c = $this->app['config']->get('revokegpt');
        if (self::blank($c['site_key'] ?? null) === null) {
            return;
        }
        // Resolve now so a bad configuration (for example TEST keys with a canonical site key) fails at boot.
        $this->app->make(Firewall::class);
        if ($c['auto_register'] ?? true) {
            $this->app->make(Kernel::class)->prependMiddleware(RevokeGPTMiddleware::class);
        }
    }

    private static function blank(mixed $v): ?string
    {
        return is_string($v) && trim($v) !== '' ? $v : null;
    }
}
