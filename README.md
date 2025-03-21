# Notion Sway

### What is Included:

- **Project Introduction**: Brief overview of the package.
- **Features**: Key features of the package listed in bullet points.
- **Installation**: Step-by-step guide to install and publish the configuration file.
- **Usage**: How to configure and use the package in your Laravel project.
- **Configuration**: Details of the `config/sway.php` file and how to adjust settings.
- **Contribute**: How users can contribute to the project.
- **License**: Specifies that the package is licensed under the MIT License.

🎉 **Notion Sway** is a custom Laravel authentication package that provides a flexible JWT-based authentication system with database fallback options for API authentication.

## Features

- **JWT token-based API authentication**: Secure API authentication with JWT tokens.
- **Redis and database fallback authentication methods**: Provides fallback methods in case the primary authentication method fails.
- **Customizable guards**: Easily customize authentication guards and configuration.
- **Middleware to protect routes**: Use middleware to protect routes with custom authentication.
- **Easy integration into Laravel**: Quick and simple integration into your existing Laravel applications.
- **Fully configurable**: Configure JWT token expiration time and token prefix.
- **Flexible authentication**: Supports multiple authentication methods (Redis, Database).

## Installation

To install the package, run the following command in your Laravel project:

## Installation

```
$ composer require notion/sway
$ php artisan vendor:publish --provider="Sway\Providers\SwayAuthServiceProvider"
```

## Usage

### Configure Authentication Guard

In your `config/auth.php` file, configure the `sway` guard by adding it to the `guards` array:

```php
'guards' => [
    'user:api' => [
        'driver' => 'sway',
        'provider' => 'users',  // Define the provider for your model
    ],
    'admin:api' => [
        'driver' => 'sway',
        'provider' => 'admins',  // Define the provider for your model
    ],
],
```

### Protect Routes with Middleware

In your `routes/web.php` or `routes/api.php` file, set `authorized` middleware then pass the guard to middleware. This is required to get correct auth user while in controller:

```php
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->middleware(["authorized:" . 'user:api'])->group(function () {
    // Your routes
});

Route::prefix('v1')->middleware(["authorized:" . 'admin:api'])->group(function () {
    // Your routes
});
```

### Generate token

In order to generate token call `attempt()` method on the `guard`

- **Important**: Make sure to pass array and must hold email and password data.
- **Output**: After success it will return `access_token` and `refresh_token`.

```php
public function login(Request $request)
    {
        // Validate the request input
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);


        $credentials = $request->only('email', 'password');

        // Use the custom guard to attempt login and generate tokens
        $accessToken = Auth::guard('user:api')->attempt($credentials);

        return response()->json([
            'tokens' => $accessToken,
            'token_type' => 'bearer',
        ]);
    }
```

### Get Authenticated User

To obtain the `auth user` you can get through `Guard` or `Request`:

```php
// Get Authenticated User model
Auth::guard('user:api')->user();
// Get Authenticated Admin model
Auth::guard('admin:api')->user();
```

- **OR**:

```php
// Recomended approach
$request->user()
```

### Invalidate Token

- **Update Model**: use `InvalidatableToken` on your model:

```php
use Sway\Traits\InvalidatableToken;

class User extends Authenticatable
{
    use InvalidatableToken;
}
```

- **Clear Token**: call `invalidateToken` to delete token:

```php
public function logout(Request $request)
{
    $user = $request->user();
    $deleted = $user->invalidateToken(); // Calls the invalidateToken method defined in the trait

    return response()->json([
        'success' => $deleted,
    ]);
}
```

---

## Contributors

[![Contributors](https://img.shields.io/github/contributors/sayednaweed/sway)](https://github.com/sayednaweed/sway/graphs/contributors)
