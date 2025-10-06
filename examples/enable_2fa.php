<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$auth = $kit['services']['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = (int)($_POST['user_id'] ?? 0);
    $code = (string)($_POST['code'] ?? '');
    try {
        $result = $auth->completeTwoFactor($code);
        echo '2FA complete. Logged in.';
    } catch (Throwable $e) {
        http_response_code(400);
        echo 'Invalid code';
    }
    exit;
}

echo '2FA example: call your app-specific flow to begin and display QR from `TwoFactorService::beginEnable`.';
