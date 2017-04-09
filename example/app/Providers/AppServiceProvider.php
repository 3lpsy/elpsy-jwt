<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Elpsy\JWT\Guard\JWTGuard;

class AppServiceProvider extends ServiceProvider
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
             return new JwtGuard($name, $jwt, $provider, $config);
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
