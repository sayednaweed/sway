<?php

namespace Sway\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class MultiAuthenticateSwayMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, ...$guards): Response
    {
        $user = null;

        // Iterate through each guard and try to authenticate the user
        foreach ($guards as $guard) {
            // Attempt to get the user for each guard
            $user = Auth::guard($guard)->user();

            // If the user is found, break out of the loop
            if ($user) {
                break;
            }
        }

        // If the user is authenticated, bind the user to the request
        if ($user) {
            $request->setUserResolver(function () use ($user) {
                return $user;  // Return the authenticated user
            });
        } else {
            // Return unauthorized response if no user found
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
