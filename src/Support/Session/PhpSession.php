<?php
declare(strict_types=1);

namespace AuthKit\Support\Session;

use AuthKit\Contracts\SessionInterface;

final class PhpSession implements SessionInterface
{
    public function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    public function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    public function regenerate(): void
    {
        if (PHP_SESSION_ACTIVE === session_status()) {
            session_regenerate_id(true);
        }
    }
}


