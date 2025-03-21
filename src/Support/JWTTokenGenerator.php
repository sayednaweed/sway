<?php

namespace Sway\Support;

use Sway\Services\JWTTokenService;

class JWTTokenGenerator
{
    /**
     * Generate a new access token.
     *
     * @return array{access_token: string}|null
     */
    public static function refreshToken(): array
    {
        return app(JWTTokenService::class)->refreshToken();
    }
}
