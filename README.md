# RevokeGPT firewall for Laravel (global middleware)

Composer package `revokegpt/firewall-laravel`, PHP 8.2+ (built and tested on PHP 8.5.12),
Laravel 11 and 12 (`illuminate/*` `^11.0 || ^12.0`, `composer.lock` committed). Requires `ext-sodium`,
`ext-curl`, `ext-mbstring`, `ext-json`.

It evaluates the site's signed policy bundle in front of your application with the same decisions
as the reference implementation (`packages/protocol/src/policy`, protocol v1 section 18). The
shared vectors in `packages/protocol/test-vectors/policy.json` are the arbiter: every row of every
section passes (`tests/VectorsTest.php`), including `sig-non-canonical-s`.

```
RG_SITE_KEY=rgpk_...
RG_SECRET_KEY=rgsk_...        # needed for requireToken rules
```

The service provider (auto-discovered) prepends `RevokeGPTMiddleware` to the global stack, so it
runs before routing and before every other middleware. Config (`php artisan vendor:publish --tag=revokegpt-config`):
`site_key`, `secret_key`, `api_base`, `site_id`, `initial_fail_mode` (`open` default, or `closed`),
`bundle_refresh_ms`, `sig_secret`, `pin_test_keys`, `cache_store`, `auto_register`.

## What it does

- The raw target is the server's `REQUEST_URI` (what `$request->getRequestUri()` returns), never the
  router's decoded path. It strips every `x-rg-*` header from `$request->headers`, and every
  `HTTP_X_RG_*` (the `X_RG_*` forms collapse to the same variable) from `$request->server` and
  `$_SERVER`, then sets `X-RG-Rule`, and `X-RG-Score` / `X-RG-Verdict` / `X-RG-Path` where the
  decision says so. `setHeader` values go to the origin only, never into a block, redirect or
  challenge response.
- Action tokens (`requireToken`) come only from the `X-RG-Token` header. The only route that reads a
  body is `POST /__rg/return` (urlencoded, at most 4 KiB, field `rg_clearance`). `POST /__rg/session`
  reads the token from `X-RG-Session-Init`. The cookies `__Host-rg_s`, `__Host-rg_c`, `__Host-rg_r`
  go out as exactly `name=value; Max-Age=N; HttpOnly; Secure; SameSite=Lax; Path=/` (`RawCookie`, a
  Symfony `Cookie` that serialises to the spec's wire format). The rest of `/__rg/` answers 404.
- Responses that block, challenge or set a cookie carry `Cache-Control: no-store`; `Vary: Cookie`
  is added when a rule can depend on a cookie. A fetch/XHR request never gets a redirect, only
  `403` + `X-RG-Action: challenge`.
- Siteverify: `POST /v1/siteverify`, Bearer secret, `X-RG-Integration: laravel/0.1.1`, 2 s timeout,
  one 2 s budget for connect, send and the full body (cURL's total timeout); at most one retry, only when the connection could not be established (`CURLE_COULDNT_CONNECT`, `CURLE_COULDNT_RESOLVE_HOST`, `CURLE_SSL_CONNECT_ERROR`) and only while budget remains (never after a timeout or once the request may have been written); no redirects followed. A circuit
  breaker opens after 5 consecutive failures for 30 s (its counters live in the cache store, so
  it spans requests). Tokens outside 20..4096 characters or outside base64url and `.` are rejected
  before any call.
- Bundle: PHP serves each request in a fresh process, so the bundle cache is the Laravel `Cache`
  store (APCu or file): the signed envelope exactly as served, its ETag, the refresh schedule, the
  highest accepted version and the breaker. **The signature, site binding and key are checked again
  every time the cached bundle is read**, so a tampered cache entry is never trusted (and no object
  goes through the cache serializer). A cold start fetches under `Cache::lock` (single-flight). A due
  bundle is refreshed after the response (`terminate()`), under a non-blocking lock, every 60 s plus
  0 to 20 s of jitter; a failure keeps the last good bundle (stale-while-error) and the fail mode
  applies after `expiresAt + 6 h`. With no bundle ever verified: `initial_fail_mode` (`open` passes with
  `X-RG-Verdict: none`, `closed` gives a 503). An authentic 404 (no policies) always passes. Without
  APCu use the file store (`tests/MiddlewareTest.php` covers it); a store with no lock support still works
  (no single-flight).
- Ed25519 uses `sodium_crypto_sign_verify_detached`. **The canonical-S check (`S < L`) is done in PHP
  before libsodium is called**, so a non-canonical S is rejected explicitly
  (`Sig::isCanonicalS`, tested with S = L, S = L - 1 and S >= 2^255).
- Logging (PSR logger): the decision id, the rule index and the action. Never a token, cookie, key or query.

## Routing must stay case-sensitive (Ruling 14)

The firewall matches paths case-sensitively, so `/ADMIN` is not `/admin`. Laravel's router (Symfony routing)
is case-sensitive by default; do not add case-insensitive route patterns (`(?i)`), case-folding middleware
or rewrites in front of the application.

## `;` path parameters

`/admin;jsessionid=1` is non-canonical. Under the default `onNonCanonical: block-writes` a GET passes marked
`X-RG-Path: non-canonical` and your routing sees whatever the server hands it; the origin must honour
`X-RG-Path` (or the site sets `onNonCanonical: block`). Writes are a 403.

## Client `x-rg-*` headers and the SAPI

The middleware scrubs `$request->headers`, `$request->server` and `$_SERVER` (including `REDIRECT_` forms), so
`$request->header()`, `$_SERVER` and Laravel code never see client copies. `getallheaders()` and
`apache_request_headers()` read the SAPI's own request header table, which PHP offers no way to modify from
userland, so they still show what the client sent. Origin code must read the Laravel `Request`, never the SAPI headers.

## Shared state

The `array` cache store is per process (every request is a cold fetch), and clearing the cache loses the
rollback floor; use APCu or file. Where a store has no lock support the refresh is not single-flight, and the floor update (read, then write) can race: two refreshes may both write, and the lower version can win until the next refresh (the cached bundle's own version is also used as a floor, which bounds the window). The `array` store keeps no floor between requests at all.

## Keys

`Sig::pinnedPolicyKeys()` are **placeholders** that fail closed (`kid`) until the owner supplies the
real keys (the `pinnedKeys` config key of `Firewall`). The public TEST keys are accepted only for a
non-canonical site key (for example `rgpk_conformance`) with a loopback API base (`127.0.0.1`,
`[::1]`, `localhost`); anything else is a configuration error at boot. A canonical site key always
checks the bundle's `siteKey`.

## Runtime facts

- PHP's SAPI parses an urlencoded POST body into `$_POST` before any middleware runs; the firewall
  never reads it and never takes a token from it.
- The server joins duplicate `X-RG-Token` headers into one comma-separated value, which is not
  base64url, so it is rejected before any call (as the other ports treat duplicates).
- The built-in server (`php -S`) closes the connection without an answer for a lower-case method
  and for raw non-ASCII bytes in the request target; that is a refusal and never an allow
  (`decide/lowercase-method-refused`, `decide/raw-non-ascii-request-is-400`).
- A non-ASCII `Host` header must be valid UTF-8 (browsers send punycode). The harness sends the raw
  Latin-1 byte, which is refused with a 400 (`decide/punycode-host-from-unicode`), like the Go port.

## Laravel version

The example uses **Laravel 12**, not 11 as the plan said. Laravel 11 does support PHP 8.5 (the library
installs and passes all 588 tests on `illuminate/*` 11.51.0 as well as 12.72.0), but every
`laravel/framework` 11.x release is blocked by Composer's security advisories (the 11 line is end of
life), and the advisories are not ignored. 12.72.0 is the line that installs cleanly. Library tests: run against
`illuminate/*` 12.72.0 (the lock); the 11 line was verified separately with the same suite.

## Commands

MIT. Hostname canonicalization, punycode and strict JSON reading are `revokegpt/revokegpt`'s (pinned to the exact version, `0.1.1`: the firewall uses SDK internals, so the two release in lockstep): in the monorepo
`composer.json` has a path repository to `../../php` (the unpublished SDK, symlinked); the mirror export drops it and
the package comes from Packagist.

```
composer install && vendor/bin/phpunit      # 596 tests: all vector rows, middleware, file cache
```

`example/` is a Laravel 12 application: the provider-registered middleware in front of
`ProxyToOrigin`, a terminal global middleware that forwards to `RG_ORIGIN` over a raw socket (the
target byte for byte, the original `Host`). Run it with PHP's built-in server and `public/index.php`
as the router, which is what `php artisan serve` wraps (without its request log line):

```
cd example && composer install
RG_API_BASE=http://127.0.0.1:5410 RG_SITE_KEY=rgpk_conformance RG_SECRET_KEY=rgsk_conformance \
RG_ORIGIN=http://127.0.0.1:5411 RG_BUNDLE_REFRESH_MS=200 RG_PIN_TEST_KEYS=1 \
CACHE_STORE=file APP_ENV=production LOG_CHANNEL=stderr PHP_CLI_SERVER_WORKERS=4 \
php -S 127.0.0.1:5413 -t public public/index.php
```

It honours the env contract of `tools/policy-conformance/README.md` (`PORT` is the `-S` port).

With `CACHE_STORE=file` the held bundle and its version live in `example/storage/framework/cache/data`
across runs (rollback protection works as designed). `rg-conformance` restarts its fake API at version
1000, so empty that directory (keep `.gitignore`) before each conformance run or the example refuses
the fake API's lower versions.

## Signed header `X-RG-Sig` (opt-in)

When the bundle's settings turn it on (`sigHeader: true`) and `sig_secret` (`RG_SIG_SECRET`, 16+
characters) is configured, allowed requests reach the origin with
`X-RG-Sig: t=<unix seconds>,v1=<hex HMAC-SHA256>`. The MAC is over `t`, host, method, normalized path
(empty if not normalizable), `X-RG-Score`, `X-RG-Verdict` and `X-RG-Rule` joined by `\n`. Without a
secret no header is sent and a one-time config warning is logged. A client-sent `X-RG-Sig` is stripped
like every `x-rg-*` header.
