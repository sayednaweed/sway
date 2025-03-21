<?php

namespace Sway\Support;

use Sway\Services\JWTTokenService;

class JWTTokenGenerator
{
    /**
     * Generate a new access token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public static function refreshToken(): array
    {
        return app(JWTTokenService::class)->refreshToken();
    }
}
