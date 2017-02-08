<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Elpsy\Http\Middleware;

class AddQueuedToken extends BaseMiddleware
{
    public function __construct(\Auth $auth)
    {
        $this->auth = $auth;
    }

    public function handle($request, \Closure $next)
    {
        $response = $next($request);

        $guard = $auth->guard('api');

        if ($guard->shouldDeliver()) {
            $response = $guard->deliverToken($response);
        }
        dd($response);

        return $response;
    }
}
