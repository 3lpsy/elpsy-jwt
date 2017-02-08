<?php

namespace Elpsy\JWT\Guard;

use Illuminate\Contracts\Auth\Authenticatable;

trait JWTGuardEvents
{
    public function setDispatcher()
    {
    }
    
    protected function fireFailedEvent($user, $credentials)
    {
    }

    protected function fireLoginEvent($user, $credentials)
    {
    }
}
