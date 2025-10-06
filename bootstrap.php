<?php
declare(strict_types=1);

use AuthKit\Support\Autoloader;
use AuthKit\Database\DatabaseConnection;
use AuthKit\Repository\PDOUserRepository;
use AuthKit\Repository\PDOEmailTokenRepository;
use AuthKit\Security\PasswordHasher;
use AuthKit\Security\RandomTokenGenerator;
use AuthKit\Support\Session\PhpSession;
use AuthKit\Support\Clock\SystemClock;
use AuthKit\Security\Jwt\HsJwtSigner;
use AuthKit\Mail\PhpMailMailer;
use AuthKit\Mail\NullMailer;
use AuthKit\Service\AuthService;
use AuthKit\Support\Auth\CurrentUser;
use AuthKit\Support\Config\ConfigValidator;

$__root = __DIR__;

require_once $__root . '/src/Support/Autoloader.php';

$autoloader = new Autoloader($__root . '/src');
$autoloader->register();

$config = require $__root . '/config/auth.php';

$validator = new ConfigValidator();
$validator->validate($config);

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
    'services' => (function () use ($config, $dbConnection) {
        $pdo = $dbConnection->pdo();
        $userRepo = new PDOUserRepository($pdo);
        $tokenRepo = new PDOEmailTokenRepository($pdo);
        $hasher = new PasswordHasher($config['security']);
        $session = new PhpSession();
        $clock = new SystemClock();
        $random = new RandomTokenGenerator();
        $mailer = ($config['mail']['driver'] ?? 'php_mail') === 'php_mail' ? new PhpMailMailer() : new NullMailer();
        $jwt = !empty($config['jwt']['enabled']) ? new HsJwtSigner($config['jwt']) : null;

        $auth = new AuthService($userRepo, $tokenRepo, $hasher, $session, $clock, $mailer, $random, $jwt, $config);
        $currentUser = new CurrentUser($session, $jwt, $userRepo);
        return [
            'auth' => $auth,
            'current_user' => $currentUser,
        ];
    })(),
];


