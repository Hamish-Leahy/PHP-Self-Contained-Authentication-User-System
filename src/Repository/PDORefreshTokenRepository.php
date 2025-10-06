<?php
declare(strict_types=1);

namespace AuthKit\Repository;

use AuthKit\Contracts\RefreshTokenRepositoryInterface;
use PDO;

final class PDORefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function create(int $userId, string $tokenHash, \DateTimeImmutable $expiresAt): int
    {
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO jwt_refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (:uid, :hash, :exp, :now)');
        $stmt->execute([':uid' => $userId, ':hash' => $tokenHash, ':exp' => $expiresAt->format('Y-m-d H:i:s'), ':now' => $now]);
        return (int)$this->pdo->lastInsertId();
    }

    public function revokeChain(int $tokenId, \DateTimeImmutable $when): void
    {
        $stmt = $this->pdo->prepare('UPDATE jwt_refresh_tokens SET revoked_at = :when WHERE id = :id');
        $stmt->execute([':id' => $tokenId, ':when' => $when->format('Y-m-d H:i:s')]);
    }

    public function rotate(int $oldTokenId, string $newTokenHash, \DateTimeImmutable $newExpiresAt, \DateTimeImmutable $when): int
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('INSERT INTO jwt_refresh_tokens (user_id, token_hash, expires_at, created_at) SELECT user_id, :hash, :exp, :now FROM jwt_refresh_tokens WHERE id = :old');
            $stmt->execute([':hash' => $newTokenHash, ':exp' => $newExpiresAt->format('Y-m-d H:i:s'), ':now' => $when->format('Y-m-d H:i:s'), ':old' => $oldTokenId]);
            $newId = (int)$this->pdo->lastInsertId();
            $stmt = $this->pdo->prepare('UPDATE jwt_refresh_tokens SET revoked_at = :when, replaced_by_id = :new WHERE id = :old');
            $stmt->execute([':when' => $when->format('Y-m-d H:i:s'), ':new' => $newId, ':old' => $oldTokenId]);
            $this->pdo->commit();
            return $newId;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
            throw $e;
        }
    }

    public function findValidByHash(string $tokenHash, \DateTimeImmutable $now): ?array
    {
        $stmt = $this->pdo->prepare('SELECT id, user_id FROM jwt_refresh_tokens WHERE token_hash = :hash AND revoked_at IS NULL AND expires_at > :now');
        $stmt->execute([':hash' => $tokenHash, ':now' => $now->format('Y-m-d H:i:s')]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) { return null; }
        return ['id' => (int)$row['id'], 'user_id' => (int)$row['user_id']];
    }
}


