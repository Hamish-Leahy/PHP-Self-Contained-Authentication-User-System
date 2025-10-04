<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    try {
        $auth->register($email, $password, '/examples/verify.php');
        echo 'Check your email for a verification link.';
    } catch (Throwable $e) {
        http_response_code(400);
        echo 'Error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    }
    exit;
}
?>
<form method="post">
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />
  <button type="submit">Register</button>
</form>
