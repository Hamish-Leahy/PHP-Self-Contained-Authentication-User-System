<?php
declare(strict_types=1);

namespace AuthKit\Contracts;

use AuthKit\Domain\Entity\EmailToken;
use AuthKit\Domain\Token\EmailTokenType;

interface EmailTokenRepositoryInterface
{
    public function create(int $userId, string $tokenHash, EmailTokenType $type, \DateTimeImmutable $expiresAt): EmailToken;
    public function findValidByHash(int $userId, string $tokenHash, EmailTokenType $type, \DateTimeImmutable $now): ?EmailToken;
    public function markUsed(int $tokenId, \DateTimeImmutable $when): void;
    public function deleteExpired(\DateTimeImmutable $now): int;
}


