<?php

return [
    'deliver' => 'header',
    'header' => [
        'name' => 'Authorization',
        'prefix' => 'Bearer '
    ],
    'cookie' => [
        'name' => 'token',
        'minutes' => 1,
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', false),
        'http_only' => true,
    ]
];
