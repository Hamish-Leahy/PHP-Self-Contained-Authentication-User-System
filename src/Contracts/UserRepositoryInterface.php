<?php
declare(strict_types=1);

namespace AuthKit\Contracts;

use AuthKit\Domain\Entity\User;

interface UserRepositoryInterface
{
    public function findById(int $id): ?User;
    public function findByEmail(string $email): ?User;
    public function create(string $email, string $passwordHash, string $passwordAlgo): User;
    public function markEmailVerified(int $userId): void;
    public function updatePassword(int $userId, string $newHash, string $passwordAlgo): void;
    public function updateLastLoginAt(int $userId, \DateTimeImmutable $when): void;
}


