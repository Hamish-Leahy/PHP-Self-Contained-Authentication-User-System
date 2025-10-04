<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = (int)($_POST['uid'] ?? 0);
    $token = (string)($_POST['token'] ?? '');
    $new = (string)($_POST['password'] ?? '');
    if ($auth->completePasswordReset($userId, $token, $new)) {
        echo 'Password updated. You can now log in.';
    } else {
        http_response_code(400);
        echo 'Invalid or expired token.';
    }
    exit;
}

$userId = (int)($_GET['uid'] ?? 0);
$token = (string)($_GET['token'] ?? '');
?>
<form method="post">
  <input type="hidden" name="uid" value="<?php echo (int)$userId; ?>" />
  <input type="hidden" name="token" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>" />
  <input type="password" name="password" placeholder="New password" required />
  <button type="submit">Reset Password</button>
</form>
