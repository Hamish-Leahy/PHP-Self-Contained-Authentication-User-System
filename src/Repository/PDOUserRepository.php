<?php
declare(strict_types=1);

namespace AuthKit\Repository;

use AuthKit\Contracts\UserRepositoryInterface;
use AuthKit\Domain\Entity\User;
use PDO;

final class PDOUserRepository implements UserRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->hydrate($row) : null;
    }

    public function findByEmail(string $email): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email');
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->hydrate($row) : null;
    }

    public function create(string $email, string $passwordHash, string $passwordAlgo): User
    {
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO users (email, password_hash, password_algo, is_email_verified, created_at, updated_at) VALUES (:email, :hash, :algo, 0, :now, :now)');
        $stmt->execute([
            ':email' => $email,
            ':hash' => $passwordHash,
            ':algo' => $passwordAlgo,
            ':now' => $now,
        ]);
        $id = (int)$this->pdo->lastInsertId();
        return $this->findById($id);
    }

    public function markEmailVerified(int $userId): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET is_email_verified = 1, updated_at = :now WHERE id = :id');
        $stmt->execute([':id' => $userId, ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
    }

    public function updatePassword(int $userId, string $newHash, string $passwordAlgo): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET password_hash = :hash, password_algo = :algo, updated_at = :now WHERE id = :id');
        $stmt->execute([
            ':id' => $userId,
            ':hash' => $newHash,
            ':algo' => $passwordAlgo,
            ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }

    public function updateLastLoginAt(int $userId, \DateTimeImmutable $when): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET last_login_at = :when, updated_at = :now WHERE id = :id');
        $stmt->execute([
            ':id' => $userId,
            ':when' => $when->format('Y-m-d H:i:s'),
            ':now' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }

    /** @param array<string,mixed> $row */
    private function hydrate(array $row): User
    {
        $createdAt = new \DateTimeImmutable($row['created_at']);
        $updatedAt = new \DateTimeImmutable($row['updated_at']);
        $lastLoginAt = isset($row['last_login_at']) && $row['last_login_at'] !== null ? new \DateTimeImmutable($row['last_login_at']) : null;
        $lockedUntil = isset($row['locked_until']) && $row['locked_until'] !== null ? new \DateTimeImmutable($row['locked_until']) : null;
        return new User(
            id: (int)$row['id'],
            email: (string)$row['email'],
            passwordHash: (string)$row['password_hash'],
            passwordAlgo: (string)$row['password_algo'],
            isEmailVerified: (bool)$row['is_email_verified'],
            createdAt: $createdAt,
            updatedAt: $updatedAt,
            lastLoginAt: $lastLoginAt,
            lockedUntil: $lockedUntil,
        );
    }
}


