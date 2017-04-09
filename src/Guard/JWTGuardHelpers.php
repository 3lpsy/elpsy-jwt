<?php

namespace Elpsy\JWT\Guard;

use Illuminate\Contracts\Auth\Authenticatable;

trait JWTGuardHelpers
{

    /**
     * Determine if the current user is authenticated.
     */
    public function check()
    {
        return ! is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id()
    {
        if ($user = $this->user()) {
            return $user->getAuthIdentifier();
        }
    }

    /**
     * Set the current user.
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        return $this;
    }

    /**
     * Remove the user from the guard.
     */
    public function removeUser()
    {
        $this->user = null;
        return $this;
    }

    /**
     * Set the token on the guard.
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     * Remove the token on the guard.
     */

    public function removeToken()
    {
        $this->token = null;
        return $this;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = [])
    {
        $token = $this->$jwt->attempt($credentials);

        $this->setToken($token);

        return !! $token;
    }

    /**
     * Validate credentials against a user
     */

    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }


    protected function config($key, $default = null)
    {
        return config("elpsy-jwt.$key", $default);
    }
}
