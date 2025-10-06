<?php
declare(strict_types=1);

use AuthKit\Security\CsrfSessionTokenProvider;
use AuthKit\Support\Session\PhpSession;
use AuthKit\Security\RandomTokenGenerator;

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

$csrf = new CsrfSessionTokenProvider(new PhpSession(), new RandomTokenGenerator());
$key = 'register_form';
$token = $csrf->getToken($key);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $submitted = (string)($_POST['_csrf'] ?? '');
    if (!$csrf->validateToken($key, $submitted)) {
        http_response_code(400);
        echo 'Invalid CSRF token';
        exit;
    }
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
  <input type="hidden" name="_csrf" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>" />
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />
  <button type="submit">Register</button>
</form>
