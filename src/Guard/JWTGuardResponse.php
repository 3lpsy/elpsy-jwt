<?php

namespace Elpsy\JWT\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

trait JWTGuardResponse
{
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    public function shouldDeliver()
    {
        return !! $this->shouldDeliver && $this->token;
    }

    // token and shouldDeliver should be set
    public function deliverToken($response)
    {
        if ($this->deliver === 'header') {
            return $this->attachHeader($response);
        } elseif ($this->deliver === 'cookie') {
            return $this->attachCookie($response);
        }

        return $response;
    }

    protected function attachHeader($response)
    {
        $response->headers->set(
            $this->config('header.name'),
            $this->config('header.prefix') . $this->token
        );

        return $response;
    }

    protected function attachCookie($response)
    {
        $response->cookie(
            $this->config('cookie.name'),
            $this->token,
            $this->config('cookie.minutes'),
            $this->config('cookie.path'),
            $this->config('cookie.domain'),
            $this->config('cookie.secure'),
            $this->config('cookie.httpOnly')
        );

        return $response;
    }
}
