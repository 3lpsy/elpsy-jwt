<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


Route::post('/auth/jwt', [
    'as' => 'api.auth.jwt.store',
    'uses' => 'Api\Auth\JwtController@store'
]);
// this route will be used to blacklist our token (logout)
Route::delete('/auth/login', [
    'as' => 'api.auth.jwt.destroy',
    'uses' => 'Api\Auth\JwtController@destroy'
]);

// this route will be used to return information about the
Route::get('/user', function (Request $request) {
    return app('auth')->guard('api')->user();
})->middleware('auth:api');
