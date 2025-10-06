<?php
declare(strict_types=1);

namespace AuthKit\Support\Logging;

use AuthKit\Contracts\LoggerInterface;

final class NullLogger implements LoggerInterface
{
    public function info(string $message, array $context = []): void {}
    public function warning(string $message, array $context = []): void {}
    public function error(string $message, array $context = []): void {}
}


