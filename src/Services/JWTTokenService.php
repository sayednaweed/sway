<?php

namespace Sway\Services;

use Exception;
use Carbon\Carbon;
use Sway\Types\Payload;
use Sway\Utils\StringUtils;
use Sway\Models\RefreshToken;
use Sway\Services\RedisService;
use Illuminate\Contracts\Auth\Authenticatable;

class JWTTokenService
{
    // The secret key for signing the JWT
    private static $secretKey;
    private static $accessTokenExpiration;
    private static $refreshTokenExpiration;
    protected $redisService;

    public function __construct(RedisService $redisService)
    {
        $this->redisService = $redisService;
        self::$secretKey = config('sway.token.secret_key', "GGPoDl2y3ayUszNnw/wQQ8++RR5r89poozLQOc8t4OM="); // Default to 60 minutes if not set
        self::$accessTokenExpiration = config('sway.token.access_token_expiration', 60); // Default to 60 minutes if not set
        self::$refreshTokenExpiration = config('sway.token.refresh_token_expiration', 14); // Default to (14) if not set
    }

    /**
     * Generate JWT token
     * 
     * @param Authenticatable $user
     * @param string $model
     * @return string
     */
    public function generateToken(Authenticatable $user, $model)
    {
        $modelName = StringUtils::getModelName($model);
        // Set token expiration times
        $accessTokenExpiresAt = now()->addMinutes(self::$accessTokenExpiration); // Access token expires in 1 hour
        $refreshTokenExpiresAt = now()->addDays(self::$refreshTokenExpiration); // Refresh token expires in 2 weeks
        // $refreshTokenExpiresAt = now()->addDays(self::$refreshTokenExpiration); // Refresh token expires in 2 weeks

        $accessPayload = [
            'tokenable_id' =>  $user->id,
            'type' =>  $modelName,
            'expires_at' => $refreshTokenExpiresAt,
            'secret_key' => self::$secretKey . bin2hex(random_bytes(32)),
        ];
        $refreshPayload = [
            'tokenable_id' =>  $user->id,
            'type' =>  $modelName,
            'expires_at' => $refreshTokenExpiresAt,
            'secret_key' => self::$secretKey . bin2hex(random_bytes(32)),
        ];
        $accessToken = $this->encode($accessPayload);
        $refreshToken = $this->encode($refreshPayload);
        // Store the tokens in the RefreshToken model
        $token =  RefreshToken::create([
            'tokenable_id' => $user->id,  // Ensure you provide the tokenable_id
            'tokenable_type' => $model,
            'access_token' => $accessToken, // Save hashed access token for security
            'refresh_token' => $refreshToken, // Save hashed refresh token for security
            'access_token_expires_at' => $accessTokenExpiresAt,
            'refresh_token_expires_at' => $refreshTokenExpiresAt,
        ]);

        // Generate key
        $key = StringUtils::getRedisKey($modelName, $user->id);

        $this->redisService->storeTokenWithExpiry($key, $accessToken);
        return [
            "access_token" => $token->access_token,
            "refresh_token" => $token->refresh_token,
        ];
    }

    /**
     * Generate JWT token
     * 
     * @param Authenticatable $user
     * @return bool
     */
    public function invalidateToken(Authenticatable $user)
    {
        $token = request()->bearerToken();

        // 1. Remove Fron Redis
        $payload = $this->decodeToken($token);
        // 2. Check token in Redis
        $key = StringUtils::getRedisKey($payload->getType(), $payload->getTokenableId());
        $this->redisService->deleteToken($key);
        // 2. Remove from database
        $deletedCount = RefreshToken::where('access_token', $token)
            ->where('tokenable_id', $user->id)
            ->delete();

        if ($deletedCount > 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Encode the payload into a JWT token
     * 
     * @param array $payload
     * @return string
     */
    private function encode(array $payload)
    {
        // Base64 encode the header
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));

        // Base64 encode the payload
        $payloadBase64 = base64_encode(json_encode($payload));

        // Create the signature
        $signature = $this->sign($header, $payloadBase64);

        // Return the JWT token
        return $header . '.' . $payloadBase64 . '.' . $signature;
    }

    /**
     * Create the signature for the JWT
     * 
     * @param string $header
     * @param string $payload
     * @return string
     */
    private function sign($header, $payload)
    {
        $data = $header . '.' . $payload;

        // Generate the HMAC hash using the secret key
        return base64_encode(hash_hmac('sha256', $data, self::$secretKey, true));
    }

    /**
     * Decode the JWT token
     * 
     * @param string $token
     * @return Payload
     * @throws Exception
     */
    public function decodeToken($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new Exception('Invalid token structure');
        }

        list($header, $payload, $signature) = $parts;

        // Decode the payload and header from Base64
        // $decodedHeader = json_decode(base64_decode($header), true);
        $decodedPayload = json_decode(base64_decode($payload), true);

        // Validate the signature
        if (!$this->validateSignature($header, $payload, $signature)) {
            throw new Exception('Invalid signature');
        }

        // Check if the token has expired
        $expiresAtTimestamp = Carbon::parse($decodedPayload['expires_at'])->timestamp;
        if (Carbon::now()->timestamp > $expiresAtTimestamp) {
            throw new Exception('Token has expired');
        }

        $payload = new Payload(
            $decodedPayload['tokenable_id'],
            $decodedPayload['type'],
            $decodedPayload['expires_at'],
            $decodedPayload['secret_key'],
        );

        return $payload;
    }

    /**
     * Validate the signature of the JWT token
     * 
     * @param string $header
     * @param string $payload
     * @param string $signature
     * @return bool
     */
    private function validateSignature($header, $payload, $signature)
    {
        $expectedSignature = $this->sign($header, $payload);
        return hash_equals($expectedSignature, $signature);
    }
}
