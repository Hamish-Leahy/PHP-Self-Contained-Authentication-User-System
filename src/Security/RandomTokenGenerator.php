<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\RandomTokenGeneratorInterface;

final class RandomTokenGenerator implements RandomTokenGeneratorInterface
{
    public function generate(int $bytes = 32): string
    {
        return random_bytes($bytes);
    }

    public function generateHex(int $bytes = 32): string
    {
        return bin2hex($this->generate($bytes));
    }
}


