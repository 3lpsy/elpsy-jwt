<?php

namespace Elpsy\JWT\Guard;

use Illuminate\Contracts\Auth\Guard;
use Tymon\JWTAuth\JWTAuth;

use Elpsy\JWT\Guard\JWTGuardHelpers;
use Elpsy\JWT\Guard\JWTGuardEvents;
use Elpsy\JWT\Guard\JWTGuardResponse;

use Illuminate\Contracts\Auth\Authenticatable;
use Tymon\JWTAuth\Validators\PayloadValidator;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

use Tymon\JWTAuth\Exceptions\JWTException;

class JWTGuard implements Guard
{
    use JWTGuardHelpers,
        JWTGuardResponse,
        JWTGuardEvents;

    // driver name
    protected $name;

    // driver name
    protected $request;

    // jwt package
    protected $jwt;

    // user provider
    protected $provider;

    // driver config
    protected $driver;

    // log out user without modifying token
    protected $loggedOut;

    // cached user
    protected $user;

    // last attempted
    protected $lastAttempted;

    // current token
    protected $token;

    protected $refreshAttempted;

    protected $deliver;

    protected $shouldDeliver;


    public function __construct($name, JWTAuth $jwt, $provider, array $driver = [])
    {
        $this->name = $name;
        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->driver = $driver;
        $this->deliver = $this->config('deliver', null);
    }

    public function token()
    {
        if ($this->loggedOut) {
            return;
        }

        if (! is_null($this->token)) {
            return $this->token;
        }

        $token = $this->getToken();

        if (! $token) {
            return null;
        }

        $this->setToken($token);

        return $token;
    }

    protected function getToken()
    {
        try {
            return $this->jwt->getToken();
        } catch (\Exception $e) {
            $this->removeToken();
            throw $e;
        }
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }

        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $token = $this->token()) {
            return null;
        }
        if (! $user = $this->authenticate($token)) {
            return null;
        }

        $this->setUser($user);

        return $user;
    }

    protected function authenticate($token)
    {
        try {
            $user = $this->jwt->authenticate($token);
        } catch (TokenExpiredException $e) {
            if (! $this->refreshAttempted) {
                return $this->authenticate($this->refresh());
            }
            $this->removeUser();
            return null;
        } catch (TokenInvalidException $e) {
            $this->removeUser();
            return null;
        } catch (TokenBlacklistedException $e) {
            $this->removeUser();
            return null;
        } catch (JWTException $e) {
            $this->removeUser();
            return null;
        }
        return $user;
    }

    public function attempt(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user);

            $this->fireLoginEvent($user, $credentials);

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    public function refresh()
    {
        \Log::info("REFRESH");
        try {
            return $this->refreshToken($this->token();
        } catch (TokenExpiredException $e) {
            $this->removeToken();
            return null;
        } catch (TokenInvalidException $e) {
            $this->removeToken();
            return null;
        } catch (TokenBlacklistedException $e) {
            $this->removeToken();
            return null;
        } catch (JWTException $e) {
            $this->removeToken();
            return null;
        }
    }

    protected function refreshToken($token)
    {
        try {
            \Log::info("OLD TOKEN ". $token);
            $this->removeToken();
            $this->refreshAttempted = true;
            $newToken = $this->jwt->refresh($token);
            $this->setToken($newToken);
            $this->shouldDeliver = true;
            return $newToken;
        } catch (\Exception $e) {
            \Log::info($e->getMessage());
            return null;
        }
    }

    public function invalidate($token)
    {
        $this->jwt->invalidate($token);
        $this->setToken(null);
        return $this;
    }


    public function login(Authenticatable $user)
    {
        $oldToken = $this->token();

        if ($oldToken) {
            $this->invalidate($oldToken);
        }

        $this->setToken($this->jwt->fromUser($user));

        $this->setUser($user);

        $this->shouldDeliver = true;
    }
}
