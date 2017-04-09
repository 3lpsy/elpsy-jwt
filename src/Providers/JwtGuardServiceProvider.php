<?php

namespace Elpsy\Providers;

use Illuminate\Support\ServiceProvider;
use Elpsy\Guard\JWTGuard;

class JwtGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */

     public function boot()
     {
         $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
             $jwt = $app['tymon.jwt.auth'];
             $provider = $app['auth']->createUserProvider($config['provider']);
             return new JwtGuard($name, $jwt, $provider);
         });
     }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
