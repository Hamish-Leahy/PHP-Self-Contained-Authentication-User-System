<?php
declare(strict_types=1);

namespace AuthKit\Service;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\JwtSignerInterface;
use AuthKit\Contracts\MailerInterface;
use AuthKit\Contracts\PasswordHasherInterface;
use AuthKit\Contracts\RandomTokenGeneratorInterface;
use AuthKit\Contracts\SessionInterface;
use AuthKit\Contracts\UserRepositoryInterface;
use AuthKit\Contracts\EmailTokenRepositoryInterface;
use AuthKit\Domain\Token\EmailTokenType;

final class AuthService
{
    public function __construct(
        private readonly UserRepositoryInterface $users,
        private readonly EmailTokenRepositoryInterface $emailTokens,
        private readonly PasswordHasherInterface $hasher,
        private readonly SessionInterface $session,
        private readonly ClockInterface $clock,
        private readonly MailerInterface $mailer,
        private readonly RandomTokenGeneratorInterface $random,
        private readonly ?JwtSignerInterface $jwt,
        private readonly array $config
    ) {
    }

    public function register(string $email, string $password, string $verifyUrlBase): void
    {
        $email = strtolower(trim($email));
        if ($email === '' || $password === '') {
            throw new \InvalidArgumentException('Email and password required');
        }
        $existing = $this->users->findByEmail($email);
        if ($existing) {
            throw new \RuntimeException('Email already in use');
        }
        $hash = $this->hasher->hash($password);
        $user = $this->users->create($email, $hash, (string)$this->config['security']['password_algo']);

        $emailService = new EmailTokenService($this->emailTokens, $this->mailer, $this->random, $this->clock, $this->config);
        $emailService->issueVerificationToken($user->id ?? 0, $email, $verifyUrlBase);
    }

    public function verifyEmail(int $userId, string $token): bool
    {
        $emailService = new EmailTokenService($this->emailTokens, $this->mailer, $this->random, $this->clock, $this->config);
        $ok = $emailService->consumeToken($userId, $token, EmailTokenType::VerifyEmail);
        if ($ok) {
            $this->users->markEmailVerified($userId);
        }
        return $ok;
    }

    public function login(string $email, string $password): array
    {
        $email = strtolower(trim($email));
        $user = $this->users->findByEmail($email);
        if (!$user) {
            throw new \RuntimeException('Invalid credentials');
        }
        // Lockout check
        if ($user->lockedUntil && $this->clock->now() < $user->lockedUntil) {
            throw new \RuntimeException('Account temporarily locked');
        }
        if (!$this->hasher->verify($password, $user->passwordHash)) {
            $max = (int)($this->config['lockout']['max_attempts'] ?? 5);
            $windowSpec = (string)($this->config['lockout']['window'] ?? '15 minutes');
            $now = $this->clock->now();
            $windowStart = $now->sub(\DateInterval::createFromDateString($windowSpec));
            $this->users->incrementFailedLoginAndMaybeLock($user->id ?? 0, $windowStart, $now, $max, (string)($this->config['lockout']['lock_duration'] ?? '30 minutes'));
            throw new \RuntimeException('Invalid credentials');
        }
        if ($this->hasher->needsRehash($user->passwordHash)) {
            $newHash = $this->hasher->hash($password);
            $this->users->updatePassword($user->id ?? 0, $newHash, (string)$this->config['security']['password_algo']);
        }
        $this->session->regenerate();
        $this->session->set('auth_user_id', $user->id);
        $this->users->updateLastLoginAt($user->id ?? 0, $this->clock->now());
        $this->users->resetFailedLogins($user->id ?? 0);

        $result = ['user_id' => $user->id];
        if ($this->jwt) {
            $result['jwt'] = $this->jwt->sign(['sub' => $user->id]);
        }
        return $result;
    }

    // removed direct-PDO fallback; repository handles lockout atomically

    public function logout(): void
    {
        $this->session->remove('auth_user_id');
        $this->session->regenerate();
    }

    public function startPasswordReset(string $email, string $resetUrlBase): void
    {
        $user = $this->users->findByEmail(strtolower(trim($email)));
        if (!$user) {
            // Don't reveal if email exists
            return;
        }
        $emailService = new EmailTokenService($this->emailTokens, $this->mailer, $this->random, $this->clock, $this->config);
        $emailService->issuePasswordResetToken($user->id ?? 0, $user->email, $resetUrlBase);
    }

    public function completePasswordReset(int $userId, string $token, string $newPassword): bool
    {
        $emailService = new EmailTokenService($this->emailTokens, $this->mailer, $this->random, $this->clock, $this->config);
        $ok = $emailService->consumeToken($userId, $token, EmailTokenType::PasswordReset);
        if (!$ok) { return false; }
        $newHash = $this->hasher->hash($newPassword);
        $this->users->updatePassword($userId, $newHash, (string)$this->config['security']['password_algo']);
        return true;
    }
}


