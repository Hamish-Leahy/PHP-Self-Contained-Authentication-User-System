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
use AuthKit\Contracts\LoggerInterface;

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
        private readonly array $config,
        private readonly ?TwoFactorService $twoFactor = null,
        private readonly ?RefreshTokenService $refresh = null,
        private readonly ?LoggerInterface $logger = null,
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
            $this->logger?->warning('login_user_not_found', ['email' => $email]);
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
            $this->logger?->warning('login_failed', ['user_id' => $user->id]);
            throw new \RuntimeException('Invalid credentials');
        }
        if ($this->hasher->needsRehash($user->passwordHash)) {
            $newHash = $this->hasher->hash($password);
            $this->users->updatePassword($user->id ?? 0, $newHash, (string)$this->config['security']['password_algo']);
        }
        // 2FA challenge
        if ($user->twoFactorEnabled && $this->twoFactor !== null) {
            $this->session->set('pending_2fa_user_id', $user->id);
            return ['requires_2fa' => true];
        }

        $this->session->regenerate();
        $this->session->set('auth_user_id', $user->id);
        $this->users->updateLastLoginAt($user->id ?? 0, $this->clock->now());
        $this->users->resetFailedLogins($user->id ?? 0);

        $result = ['user_id' => $user->id];
        if ($this->jwt) {
            $result['jwt'] = $this->jwt->sign(['sub' => $user->id]);
            if ($this->refresh) {
                $refresh = $this->refresh->issue($user->id ?? 0);
                $result['refresh_token'] = $refresh['token'];
            }
        }
        $this->logger?->info('login_success', ['user_id' => $user->id]);
        return $result;
    }

    public function completeTwoFactor(string $code): array
    {
        if (!$this->twoFactor) { throw new \RuntimeException('2FA not supported'); }
        $userId = (int)($this->session->get('pending_2fa_user_id') ?? 0);
        if (!$userId) { throw new \RuntimeException('No 2FA pending'); }
        if (!$this->twoFactor->verifyCodeOrRecovery($userId, $code)) {
            throw new \RuntimeException('Invalid 2FA code');
        }
        $this->session->remove('pending_2fa_user_id');
        $this->session->regenerate();
        $this->session->set('auth_user_id', $userId);
        $result = ['user_id' => $userId];
        if ($this->jwt) {
            $result['jwt'] = $this->jwt->sign(['sub' => $userId]);
            if ($this->refresh) {
                $refresh = $this->refresh->issue($userId);
                $result['refresh_token'] = $refresh['token'];
            }
        }
        return $result;
    }

    public function refreshJwt(string $refreshToken): array
    {
        if (!$this->jwt || !$this->refresh) { throw new \RuntimeException('Refresh not supported'); }
        $rotated = $this->refresh->rotate($refreshToken);
        $jwt = $this->jwt->sign(['sub' => $rotated['user_id']]);
        return ['jwt' => $jwt, 'refresh_token' => $rotated['token']];
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


