<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\PasswordHasherInterface;

final class PasswordHasher implements PasswordHasherInterface
{
    private int|string $algo;
    private int $cost;
    private string $pepper;

    /**
     * @param array{password_algo?:int|string,password_cost?:int,pepper?:string} $securityConfig
     */
    public function __construct(array $securityConfig)
    {
        $this->algo = $securityConfig['password_algo'] ?? PASSWORD_DEFAULT;
        $this->cost = (int)($securityConfig['password_cost'] ?? 12);
        $this->pepper = (string)($securityConfig['pepper'] ?? '');
    }

    public function hash(string $password): string
    {
        $options = ['cost' => $this->cost];
        return password_hash($password . $this->pepper, $this->algo, $options);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password . $this->pepper, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        $options = ['cost' => $this->cost];
        return password_needs_rehash($hash, $this->algo, $options);
    }
}


