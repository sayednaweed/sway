<?php

namespace Sway\Providers;

use Sway\Guards\ApiGuard;
use Sway\Services\RedisService;
use Sway\Services\JWTTokenService;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Sway\Middleware\AuthenticateSwayMiddleware;
use Sway\Middleware\MultiAuthenticateSwayMiddleware;

class SwayAuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Bind the RedisService as a singleton
        $this->app->singleton(RedisService::class, function ($app) {
            return new RedisService();
        });
        // Bind the JWTTokenService as a singleton, injecting RedisService into the constructor
        $this->app->singleton(JWTTokenService::class, function ($app) {
            $redisService = $app->make(RedisService::class); // Get RedisService from the container
            return new JWTTokenService($redisService); // Pass RedisService into JWTTokenService
        });
    }

    public function boot()
    {
        // Publish the configuration file to the app's config directory
        $this->publishes([
            __DIR__ . '/../config/sway.php' => config_path('sway.php'),
        ], 'config');

        $this->publishes([
            __DIR__ . '/../database/migrations' => database_path('migrations'),
        ], 'migrations');

        // Register the middleware
        $this->app['router']->aliasMiddleware('authorized', AuthenticateSwayMiddleware::class);

        // Register the new middleware
        $this->app['router']->aliasMiddleware('multiAuthorized', MultiAuthenticateSwayMiddleware::class);  // Register new middleware

        // Register the custom 'custom-api' guard for dynamic model resolution
        Auth::extend('sway', function ($app, $name, array $config) {
            $provider = $config['provider'];

            // Dynamically resolve the model provider for the guard
            $providerInstance = new DynamicModelProvider($provider);

            // Get the TokenService instance
            $tokenService = $app->make(JWTTokenService::class);
            // Get the RedisService instance
            $redisService = $app->make(RedisService::class);

            return new ApiGuard($providerInstance, $tokenService, $redisService);
        });
    }
}
