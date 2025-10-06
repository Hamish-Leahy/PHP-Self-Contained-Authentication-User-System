<?php
declare(strict_types=1);

namespace AuthKit\Repository;

use AuthKit\Contracts\RecoveryCodeRepositoryInterface;
use PDO;

final class PDORecoveryCodeRepository implements RecoveryCodeRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function store(int $userId, array $codeHashes): void
    {
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (:uid, :hash, :now)');
        foreach ($codeHashes as $hash) {
            $stmt->execute([':uid' => $userId, ':hash' => $hash, ':now' => $now]);
        }
    }

    public function consume(int $userId, string $codeHash): bool
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('SELECT id FROM user_recovery_codes WHERE user_id = :uid AND code_hash = :hash AND used_at IS NULL FOR UPDATE');
            $stmt->execute([':uid' => $userId, ':hash' => $codeHash]);
            $id = $stmt->fetchColumn();
            if (!$id) { $this->pdo->rollBack(); return false; }
            $stmt = $this->pdo->prepare('UPDATE user_recovery_codes SET used_at = :when WHERE id = :id');
            $stmt->execute([':id' => (int)$id, ':when' => (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
            $this->pdo->commit();
            return true;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
            return false;
        }
    }
}


