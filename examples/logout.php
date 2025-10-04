<?php
declare(strict_types=1);

$kit = require __DIR__ . '/../bootstrap.php';
$services = $kit['services'];
$auth = $services['auth'];

$auth->logout();
echo 'Logged out';
