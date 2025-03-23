<?php

namespace Sway\Providers;

use Illuminate\Support\Facades\Hash;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Log;

class DynamicModelProvider implements UserProvider
{
    protected $modelClass;
    protected $provider;

    /**
     * Dynamically set the model class based on the provider name.
     */
    public function __construct($provider)
    {
        $this->modelClass = config("auth.providers.{$provider}.model");
        $this->provider = $provider;

        if (!$this->modelClass) {
            throw new \InvalidArgumentException("Model class not found for provider {$provider}");
        }
    }

    /**
     * Retrieve a user by their unique identifier (ID).
     */
    public function retrieveById($identifier)
    {
        $tokenableId = $identifier['tokenableId'];
        $type = $identifier['type'];
        $device = $identifier['device'];
        $passedType = "App\Models\\{$type}";
        if (strcasecmp($this->modelClass, $passedType) === 0) {
            // Same model token
            return $this->modelClass::where('tokenable_id', $tokenableId)
                ->where('tokenable_type', $type)
                ->where('device', $device)
                ->first();
        } else {
            return null;
        }
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByToken($identifier, $token)
    {
        return $this->modelClass::find($identifier); // Eloquent method
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return true; // Customize validation logic as needed.
    }

    /**
     * Retrieve the user by the given credentials.
     */
    public function retrieveByCredentials(array $credentials)
    {
        $column = "email_id";
        if (isset($credentials["email"])) {
            $column = 'email';  // Use "email" if it's present
        }
        // Search by email or email_id in table
        return $this->modelClass::where($column, $credentials[$column])->first(); // Eloquent method
        // return $this->modelClass::where("email", $credentials['email'])->first(); // Eloquent method
    }

    /**
     * Update the "remember me" token for the user.
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        if ($user instanceof \Illuminate\Database\Eloquent\Model) {
            $user->setRememberToken($token);
            $user->save();
        }
    }

    /**
     * Rehash the password if required.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param array $credentials
     * @param bool $force
     * @return string
     */
    public function rehashPasswordIfRequired(
        Authenticatable $user,
        array $credentials = [],
        bool $force = false
    ) {
        // Retrieve the password from credentials (assuming it's in the 'password' field)
        $password = $credentials['password'] ?? '';

        // If no password is provided, return the original password
        if (empty($password)) {
            return $user->getAuthPassword();
        }

        // Check if the password needs to be rehashed or if forced
        if ($force || Hash::needsRehash($password)) {
            // Rehash and return the new password
            return Hash::make($password);
        }

        // Return the original password if no rehashing is required
        return $password;
    }
    public function getModel()
    {
        return $this->modelClass;
    }
}
