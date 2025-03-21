<?php

namespace Sway\Services;

use Illuminate\Support\Facades\Redis;

class RedisService
{
    private static $expiration;

    public function __construct()
    {
        self::$expiration = config('sway.redis.expiration', 900); // Default to 15 minutes if not set
    }
    // Store token in Redis
    public function storeToken($key, $value)
    {
        Redis::set($key, $value);
    }
    public function storeTokenWithExpiry($key, $value)
    {
        Redis::setex($key, self::$expiration,  $value);
    }

    // Get token from Redis
    public function getToken($key)
    {
        return Redis::get($key);
    }

    // Delete token from Redis
    public function deleteToken($key)
    {
        Redis::del($key);
    }
}
