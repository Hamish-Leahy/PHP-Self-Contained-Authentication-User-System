<?php
declare(strict_types=1);

use AuthKit\Support\Autoloader;
use AuthKit\Database\DatabaseConnection;

$__root = __DIR__;

require_once $__root . '/src/Support/Autoloader.php';

$autoloader = new Autoloader($__root . '/src');
$autoloader->register();

$config = require $__root . '/config/auth.php';

$dbConnection = new DatabaseConnection($config['database']);

$sessionConfig = $config['session'] ?? [];
if (PHP_SESSION_NONE === session_status()) {
    if (isset($sessionConfig['name'])) {
        session_name((string)$sessionConfig['name']);
    }
    $cookieParams = session_get_cookie_params();
    $cookieParams['lifetime'] = (int)($sessionConfig['lifetime'] ?? $cookieParams['lifetime']);
    $cookieParams['secure'] = (bool)($sessionConfig['cookie_secure'] ?? $cookieParams['secure']);
    $cookieParams['httponly'] = (bool)($sessionConfig['cookie_httponly'] ?? $cookieParams['httponly']);
    $cookieParams['samesite'] = (string)($sessionConfig['cookie_samesite'] ?? ($cookieParams['samesite'] ?? 'Lax'));
    session_set_cookie_params($cookieParams);
    @session_start();
}

return [
    'config' => $config,
    'pdo' => $dbConnection->pdo(),
];


