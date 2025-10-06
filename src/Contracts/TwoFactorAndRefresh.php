<?php
declare(strict_types=1);

namespace AuthKit\Contracts;

interface TwoFactorRepositoryInterface
{
    public function setSecret(int $userId, string $secret): void;
    public function clearSecret(int $userId): void;
    public function enable(int $userId): void;
    public function disable(int $userId): void;
}

interface RecoveryCodeRepositoryInterface
{
    /** @param string[] $codeHashes */
    public function store(int $userId, array $codeHashes): void;
    public function consume(int $userId, string $codeHash): bool;
}

interface RefreshTokenRepositoryInterface
{
    public function create(int $userId, string $tokenHash, \DateTimeImmutable $expiresAt): int; // returns id
    public function revokeChain(int $tokenId, \DateTimeImmutable $when): void;
    public function rotate(int $oldTokenId, string $newTokenHash, \DateTimeImmutable $newExpiresAt, \DateTimeImmutable $when): int; // returns new id
    public function findValidByHash(string $tokenHash, \DateTimeImmutable $now): ?array; // ['id'=>int,'user_id'=>int]
}

interface TotpInterface
{
    public function generateSecret(int $bytes = 20): string; // Base32
    public function getOtp(string $secret, int $timestamp = null): string;
    public function verify(string $secret, string $code, int $window = 1): bool;
    public function provisioningUri(string $secret, string $accountName, string $issuer): string;
}


