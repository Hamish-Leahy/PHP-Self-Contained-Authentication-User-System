<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\CsrfTokenProviderInterface;
use AuthKit\Contracts\RandomTokenGeneratorInterface;
use AuthKit\Contracts\SessionInterface;

final class CsrfSessionTokenProvider implements CsrfTokenProviderInterface
{
    private const SESSION_KEY = '_csrf_tokens';

    public function __construct(
        private readonly SessionInterface $session,
        private readonly RandomTokenGeneratorInterface $tokenGenerator
    ) {
    }

    public function getToken(string $key): string
    {
        $tokens = $this->session->get(self::SESSION_KEY, []);
        if (!is_array($tokens)) {
            $tokens = [];
        }
        if (!isset($tokens[$key])) {
            $tokens[$key] = bin2hex($this->tokenGenerator->generate(32));
            $this->session->set(self::SESSION_KEY, $tokens);
        }
        return (string)$tokens[$key];
    }

    public function validateToken(string $key, string $token): bool
    {
        $tokens = $this->session->get(self::SESSION_KEY, []);
        if (!is_array($tokens) || !isset($tokens[$key])) {
            return false;
        }
        $valid = hash_equals((string)$tokens[$key], $token);
        if ($valid) {
            unset($tokens[$key]);
            $this->session->set(self::SESSION_KEY, $tokens);
        }
        return $valid;
    }
}


