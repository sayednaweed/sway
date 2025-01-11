<?php

namespace Sway\Guards;

use Sway\Utils\StringUtils;
use Sway\Models\RefreshToken;
use Sway\Services\RedisService;
use Sway\Services\JWTTokenService;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Support\Facades\Hash;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class ApiGuard implements Guard
{
    protected $user;
    protected $provider;
    protected $tokenService; // Declare the service
    protected $redisService;


    public function __construct(UserProvider $provider, JWTTokenService $tokenService, RedisService $redisService)
    {
        $this->provider = (object) $provider;
        $this->user = null;
        $this->tokenService = $tokenService;
        $this->redisService = $redisService;
    }

    /**
     * Retrieve the user for the current request.
     *
     * @param string|null $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user($token = null)
    {
        if (!$token && $this->user) {
            return $this->user;
        }
        // Retrieve token from request if not provided
        $token = $token ?: request()->bearerToken();

        // Authenticate the user with the token
        $user = $this->authenticateWithToken($token);

        if ($user) {
            $this->user = $user;
        }

        return $this->user;
    }

    /**
     * Authenticate the user by the provided token.
     *
     * @param string|null $accessToken
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    protected function authenticateWithToken($accessToken)
    {
        // 1. validate token
        $payload = $this->tokenService->decodeToken($accessToken);
        // 2. Check token in Redis
        $key = StringUtils::getRedisKey($payload->getType(), $payload->getTokenableId());
        $result = $this->redisService->getToken($key, $accessToken);
        if ($result) {
            // 1. Token Found
            return $this->provider->retrieveById($payload->getTokenableId());
        } else {
            // 3. If access_token not exist in Redis check database
            $tokenRecord = RefreshToken::where('access_token', $accessToken)->first();
            if (!$tokenRecord) {
                return null;
            }

            // 2. Store token in Redis
            $this->redisService->storeTokenWithExpiry($key, $accessToken);
            // Use the provider linked to the guard to resolve the correct model
            return $this->provider->retrieveById($tokenRecord->tokenable_id);
        }
    }

    public function check()
    {
        return !is_null($this->user);
    }

    public function id()
    {
        // Check if $this->user is an instance of Authenticatable
        if ($this->user instanceof Authenticatable) {
            return $this->user->getAuthIdentifier();  // Use getAuthIdentifier() instead of getKey()
        }

        return null;  // Or handle it appropriately if not an Authenticatable instance
    }

    /**
     * Determine if the user is a guest (not authenticated).
     *
     * @return bool
     */
    public function guest()
    {
        return is_null($this->user);
    }

    /**
     * Validate the user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        return !is_null($user);
    }

    /**
     * Check if the guard has a user.
     *
     * @return bool
     */
    public function hasUser()
    {
        return !is_null($this->user);
    }

    /**
     * Set a user for the guard.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Attempt to authenticate the user and generate tokens.
     */
    public function attempt(array $credentials = [])
    {
        // Find the user by their credentials (e.g., email and password)
        $user = $this->provider->retrieveByCredentials($credentials);
        // Check if user exists and password matches
        if ($user && Hash::check($credentials['password'], $user->password)) {
            // Generate and store the access and refresh tokens
            return [
                "user" => $user,
                "tokens" => $this->generateTokens($user)
            ];
        }
        return null;
    }
    /**
     * Generate access and refresh tokens and store them.
     */
    private function generateTokens(Authenticatable $user)
    {
        return $this->tokenService->generateToken($user, $this->provider->getModel());
    }
}
