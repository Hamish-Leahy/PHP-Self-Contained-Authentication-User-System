<?php
declare(strict_types=1);

namespace AuthKit\Contracts;

interface PasswordHasherInterface
{
    public function hash(string $password): string;
    public function verify(string $password, string $hash): bool;
    public function needsRehash(string $hash): bool;
}

interface CsrfTokenProviderInterface
{
    public function getToken(string $key): string;
    public function validateToken(string $key, string $token): bool;
}

interface JwtSignerInterface
{
    /** @param array<string,mixed> $claims */
    public function sign(array $claims): string;
    /** @return array<string,mixed>|null */
    public function verify(string $jwt): ?array;
}

interface RandomTokenGeneratorInterface
{
    public function generate(int $bytes = 32): string; // raw bytes
    public function generateHex(int $bytes = 32): string; // hex encoded
}


