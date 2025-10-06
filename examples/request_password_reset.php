<?php
declare(strict_types=1);

use AuthKit\Security\CsrfSessionTokenProvider;
use AuthKit\Support\Session\PhpSession;
use AuthKit\Security\RandomTokenGenerator;

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

$csrf = new CsrfSessionTokenProvider(new PhpSession(), new RandomTokenGenerator());
$key = 'reset_request_form';
$token = $csrf->getToken($key);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $submitted = (string)($_POST['_csrf'] ?? '');
    if (!$csrf->validateToken($key, $submitted)) {
        http_response_code(400);
        echo 'Invalid CSRF token';
        exit;
    }
    $auth->startPasswordReset($email, '/examples/reset_password.php');
    echo 'If the email exists, a reset link was sent.';
    exit;
}
?>
<form method="post">
  <input type="hidden" name="_csrf" value="<?php echo htmlspecialchars($token, ENT_QUOTES, 'UTF-8'); ?>" />
  <input type="email" name="email" placeholder="Email" required />
  <button type="submit">Send Reset Link</button>
</form>
