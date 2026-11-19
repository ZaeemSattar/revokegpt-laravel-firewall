<?php

declare(strict_types=1);

return [
    // rgpk_... names the bundle to fetch. The firewall is off while this is empty.
    'site_key' => env('RG_SITE_KEY'),

    // rgsk_... for siteverify. Without it a requireToken rule never passes (the rule's onError applies).
    'secret_key' => env('RG_SECRET_KEY'),

    // API origin: https (http only for localhost, 127.0.0.1 and [::1]); no path, query or userinfo.
    'api_base' => env('RG_API_BASE'),

    // Optional site UUID to pin; otherwise the site id of the first verified bundle is pinned.
    'site_id' => env('RG_SITE_ID'),

    // "open" (default) or "closed": what happens while no bundle has ever been verified.
    'initial_fail_mode' => env('RG_INITIAL_FAIL_MODE'),

    // Optional (16+ characters). Signs X-RG-Sig toward the origin when the bundle's settings turn it on;
    // without it the header is never sent (a one-time config warning is logged).
    'sig_secret' => env('RG_SIG_SECRET'),

    // Bundle refresh interval in ms (conformance runs). Empty keeps 60 s plus 0 to 20 s of jitter.
    'bundle_refresh_ms' => env('RG_BUNDLE_REFRESH_MS'),

    // Conformance runs only: pin the public TEST bundle keys. Accepted only for a non-canonical site
    // key with a loopback API base; any other combination is a configuration error at boot.
    'pin_test_keys' => (bool) env('RG_PIN_TEST_KEYS', false),

    // The cache store that holds the verified bundle (APCu or file recommended). Null: the default store.
    'cache_store' => env('RG_CACHE_STORE'),

    // Prepend the middleware to the global stack. Turn off to register it yourself.
    'auto_register' => (bool) env('RG_AUTO_REGISTER', true),
];
