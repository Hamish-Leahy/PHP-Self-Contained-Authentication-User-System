<?php
declare(strict_types=1);

namespace AuthKit\Repository;

use AuthKit\Contracts\EmailTokenRepositoryInterface;
use AuthKit\Domain\Entity\EmailToken;
use AuthKit\Domain\Token\EmailTokenType;
use PDO;

final class PDOEmailTokenRepository implements EmailTokenRepositoryInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function create(int $userId, string $tokenHash, EmailTokenType $type, \DateTimeImmutable $expiresAt): EmailToken
    {
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO auth_email_tokens (user_id, token_hash, token_type, expires_at, created_at) VALUES (:uid, :hash, :type, :exp, :now)');
        $stmt->execute([
            ':uid' => $userId,
            ':hash' => $tokenHash,
            ':type' => $type->value,
            ':exp' => $expiresAt->format('Y-m-d H:i:s'),
            ':now' => $now,
        ]);
        $id = (int)$this->pdo->lastInsertId();
        return new EmailToken(
            id: $id,
            userId: $userId,
            tokenHash: $tokenHash,
            tokenType: $type,
            expiresAt: $expiresAt,
            usedAt: null,
            createdAt: new \DateTimeImmutable($now),
        );
    }

    public function findValidByHash(int $userId, string $tokenHash, EmailTokenType $type, \DateTimeImmutable $now): ?EmailToken
    {
        $stmt = $this->pdo->prepare('SELECT * FROM auth_email_tokens WHERE user_id = :uid AND token_hash = :hash AND token_type = :type AND used_at IS NULL AND expires_at > :now');
        $stmt->execute([
            ':uid' => $userId,
            ':hash' => $tokenHash,
            ':type' => $type->value,
            ':now' => $now->format('Y-m-d H:i:s'),
        ]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) { return null; }
        return new EmailToken(
            id: (int)$row['id'],
            userId: (int)$row['user_id'],
            tokenHash: (string)$row['token_hash'],
            tokenType: EmailTokenType::from((string)$row['token_type']),
            expiresAt: new \DateTimeImmutable((string)$row['expires_at']),
            usedAt: isset($row['used_at']) && $row['used_at'] !== null ? new \DateTimeImmutable((string)$row['used_at']) : null,
            createdAt: new \DateTimeImmutable((string)$row['created_at']),
        );
    }

    public function markUsed(int $tokenId, \DateTimeImmutable $when): void
    {
        $stmt = $this->pdo->prepare('UPDATE auth_email_tokens SET used_at = :when WHERE id = :id');
        $stmt->execute([':id' => $tokenId, ':when' => $when->format('Y-m-d H:i:s')]);
    }

    public function deleteExpired(\DateTimeImmutable $now): int
    {
        $stmt = $this->pdo->prepare('DELETE FROM auth_email_tokens WHERE (used_at IS NOT NULL) OR (expires_at <= :now)');
        $stmt->execute([':now' => $now->format('Y-m-d H:i:s')]);
        return $stmt->rowCount();
    }
}


