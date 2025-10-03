<?php
declare(strict_types=1);

namespace AuthKit\Domain\Entity;

use AuthKit\Domain\Token\EmailTokenType;

final class EmailToken
{
    public function __construct(
        public readonly ?int $id,
        public readonly int $userId,
        public readonly string $tokenHash,
        public readonly EmailTokenType $tokenType,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly ?\DateTimeImmutable $usedAt,
        public readonly \DateTimeImmutable $createdAt,
    ) {
    }
}


