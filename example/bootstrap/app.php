<?php

use App\Http\Middleware\ProxyToOrigin;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // The global stack is just the proxy. RevokeGPTMiddleware is prepended to it by the
        // package's service provider, so it runs first and sees the raw request.
        $middleware->use([ProxyToOrigin::class]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
    })
    ->create();
