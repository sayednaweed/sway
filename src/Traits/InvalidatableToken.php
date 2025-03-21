<?php

namespace Sway\Traits;

use Sway\Services\JWTTokenService; // Assuming the service exists

trait InvalidatableToken
{
    /**
     * Invalidate the token for the current user.
     *
     * @return mixed
     */
    public function invalidateToken()
    {
        return app(JWTTokenService::class)->invalidateToken($this);
    }
    /**
     * Invalidate the token for the current user.
     *
     * @return mixed
     */
    public function refreshToken()
    {
        return app(JWTTokenService::class)->refreshToken();
    }
}
