<?php

namespace Elpsy\Http\Middleware;

use Auth;

class AddQueuedToken
{
    public function handle($request, \Closure $next)
    {
        $response = $next($request);

        $guard = Auth::guard(config("elpsy-jwt.guard"));

        if ($guard->shouldDeliver()) {
            $response = $guard->deliverToken($response);
        }

        return $response;
    }
}
