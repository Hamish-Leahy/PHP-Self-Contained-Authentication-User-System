<?php
declare(strict_types=1);

namespace AuthKit\Domain\Entity;

final class User
{
    public function __construct(
        public readonly ?int $id,
        public readonly string $email,
        public readonly string $passwordHash,
        public readonly string $passwordAlgo,
        public readonly bool $isEmailVerified,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt,
        public readonly ?\DateTimeImmutable $lastLoginAt,
        public readonly ?\DateTimeImmutable $lockedUntil,
    ) {
    }
}


