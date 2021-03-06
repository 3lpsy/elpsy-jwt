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

Route::get('/auth/jwt', [
    'as' => 'api.auth.jwt.index',
    'uses' => 'Auth\JwtController@index'
]);

Route::post('/auth/jwt', [
    'as' => 'api.auth.jwt.store',
    'uses' => 'Auth\JwtController@store'
]);
// this route will be used to blacklist our token (logout)
Route::delete('/auth/login', [
    'as' => 'api.auth.jwt.destroy',
    'uses' => 'Auth\JwtController@destroy'
]);

// this route will be used to return information about the
Route::get('/user', function (Request $request) {
    return \Auth::guard('api')->user();
})->middleware(['auth:api', 'jwt.token.queue']);
