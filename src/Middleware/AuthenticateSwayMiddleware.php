<?php

namespace Sway\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateSwayMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, $guard = null): Response
    {
        $guardType = $guard ? $guard : "user:api";
        // 1. Get user if Berear exist
        $user = Auth::guard($guardType)->user();
        // If the user is authenticated, bind the user to the request
        if ($user) {
            $request->setUserResolver(function () use ($user) {
                return $user;  // Return the authenticated user
            });
        } else {
            // You can redirect to a custom login route or return an error message for API users
            return response()->json(['message' => 'access to the requested resource is forbidden'], 403);
        }

        return $next($request);
    }
}
