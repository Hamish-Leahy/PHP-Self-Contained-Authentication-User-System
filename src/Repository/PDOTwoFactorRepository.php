<?php
declare(strict_types=1);

namespace AuthKit\Repository;

use AuthKit\Contracts\TwoFactorRepositoryInterface;
use PDO;

final class PDOTwoFactorRepository implements TwoFactorRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function setSecret(int $userId, string $secret): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET two_factor_secret = :s, updated_at = :now WHERE id = :id');
        $stmt->execute([':id' => $userId, ':s' => $secret, ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
    }

    public function clearSecret(int $userId): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET two_factor_secret = NULL, updated_at = :now WHERE id = :id');
        $stmt->execute([':id' => $userId, ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
    }

    public function enable(int $userId): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET two_factor_enabled = 1, updated_at = :now WHERE id = :id');
        $stmt->execute([':id' => $userId, ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
    }

    public function disable(int $userId): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL, updated_at = :now WHERE id = :id');
        $stmt->execute([':id' => $userId, ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
    }
}


