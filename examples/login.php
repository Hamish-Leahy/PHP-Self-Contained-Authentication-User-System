<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    try {
        $result = $auth->login($email, $password);
        if (isset($result['jwt'])) {
            header('Content-Type: application/json');
            echo json_encode(['token' => $result['jwt'], 'user_id' => $result['user_id']]);
        } else {
            echo 'Logged in as user #' . (int)$result['user_id'];
        }
    } catch (Throwable $e) {
        http_response_code(401);
        echo 'Invalid credentials';
    }
    exit;
}
?>
<form method="post">
  <input type="email" name="email" placeholder="Email" required />
  <input type="password" name="password" placeholder="Password" required />
  <button type="submit">Login</button>
</form>
