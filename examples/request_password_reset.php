<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $auth->startPasswordReset($email, '/examples/reset_password.php');
    echo 'If the email exists, a reset link was sent.';
    exit;
}
?>
<form method="post">
  <input type="email" name="email" placeholder="Email" required />
  <button type="submit">Send Reset Link</button>
</form>
