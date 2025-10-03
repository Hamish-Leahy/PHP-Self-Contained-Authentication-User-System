<?php
declare(strict_types=1);

return [
    'database' => [
        'dsn' => 'mysql:host=127.0.0.1;port=3306;dbname=auth;charset=utf8mb4',
        'username' => 'root',
        'password' => '',
        'options' => [],
    ],

    'security' => [
        'password_algo' => PASSWORD_DEFAULT,
        'password_cost' => 12,
        'pepper' => '',
    ],

    'tokens' => [
        'email_verification_ttl' => '2 days',
        'password_reset_ttl' => '2 hours',
    ],

    'session' => [
        'name' => 'AUTHSESSID',
        'cookie_secure' => true,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'lifetime' => 0,
    ],

    'jwt' => [
        'enabled' => false,
        'issuer' => 'your-app',
        'audience' => null,
        'signing_key' => '',
        'ttl' => '15 minutes',
        'refresh_ttl' => '14 days',
        'algorithm' => 'HS256',
    ],

    'mail' => [
        'driver' => 'php_mail',
        'from' => ['email' => 'no-reply@example.com', 'name' => 'App Auth'],
    ],
];


