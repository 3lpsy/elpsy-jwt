<?php

return [
    'deliver' => 'header',
    'guard' => 'api',
    'header' => [
        'name' => 'Authorization',
        'prefix' => 'Bearer '
    ],
    'cookie' => [
        'name' => 'token',
        'minutes' => 60,
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', false),
        'http_only' => true,
    ]
];
