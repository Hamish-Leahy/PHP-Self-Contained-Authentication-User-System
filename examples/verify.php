<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

$userId = (int)($_GET['uid'] ?? 0);
$token = (string)($_GET['token'] ?? '');

if ($userId && $token) {
    if ($auth->verifyEmail($userId, $token)) {
        echo 'Email verified. You can now log in.';
    } else {
        http_response_code(400);
        echo 'Invalid or expired token.';
    }
} else {
    http_response_code(400);
    echo 'Missing parameters.';
}
