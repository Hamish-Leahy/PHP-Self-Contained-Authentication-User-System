<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$auth = $kit['services']['auth'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $refresh = (string)($_POST['refresh_token'] ?? '');
    try {
        $result = $auth->refreshJwt($refresh);
        header('Content-Type: application/json');
        echo json_encode($result);
    } catch (Throwable $e) {
        http_response_code(401);
        echo 'Invalid refresh token';
    }
    exit;
}
?>
<form method="post">
  <input type="text" name="refresh_token" placeholder="Refresh token" required />
  <button type="submit">Refresh</button>
</form>
