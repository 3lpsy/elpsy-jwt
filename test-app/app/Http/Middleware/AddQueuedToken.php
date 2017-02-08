<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Http\Middleware;

class AddQueuedToken
{
    public function handle($request, \Closure $next)
    {
        $response = $next($request);

        $guard = app('auth')->guard('api');


        if ($guard->shouldDeliver()) {
            $response = $guard->deliverToken($response);
        }

        return $response;
    }
}
