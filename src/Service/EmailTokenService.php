<?php
declare(strict_types=1);

namespace AuthKit\Service;

use AuthKit\Contracts\EmailTokenRepositoryInterface;
use AuthKit\Contracts\MailerInterface;
use AuthKit\Contracts\RandomTokenGeneratorInterface;
use AuthKit\Contracts\ClockInterface;
use AuthKit\Domain\Token\EmailTokenType;

final class EmailTokenService
{
    public function __construct(
        private readonly EmailTokenRepositoryInterface $tokens,
        private readonly MailerInterface $mailer,
        private readonly RandomTokenGeneratorInterface $random,
        private readonly ClockInterface $clock,
        private readonly array $config
    ) {
    }

    public function issueVerificationToken(int $userId, string $email, string $verifyUrlBase): string
    {
        $ttl = (string)($this->config['tokens']['email_verification_ttl'] ?? '2 days');
        return $this->issueToken($userId, $email, $verifyUrlBase, EmailTokenType::VerifyEmail, 'Verify your email', $ttl);
    }

    public function issuePasswordResetToken(int $userId, string $email, string $resetUrlBase): string
    {
        $ttl = (string)($this->config['tokens']['password_reset_ttl'] ?? '2 hours');
        return $this->issueToken($userId, $email, $resetUrlBase, EmailTokenType::PasswordReset, 'Reset your password', $ttl);
    }

    public function consumeToken(int $userId, string $rawToken, EmailTokenType $type): bool
    {
        $hash = hash('sha256', $rawToken);
        $now = $this->clock->now();
        $record = $this->tokens->findValidByHash($userId, $hash, $type, $now);
        if (!$record) {
            return false;
        }
        $this->tokens->markUsed($record->id ?? 0, $now);
        return true;
    }

    private function issueToken(int $userId, string $email, string $urlBase, EmailTokenType $type, string $subject, string $ttlSpec): string
    {
        $rawToken = $this->random->generateHex(32);
        $hash = hash('sha256', $rawToken);
        $expiresAt = $this->clock->now()->add(\DateInterval::createFromDateString($ttlSpec));
        $this->tokens->create($userId, $hash, $type, $expiresAt);

        $url = rtrim($urlBase, '/') . '?uid=' . urlencode((string)$userId) . '&token=' . urlencode($rawToken);
        $from = $this->config['mail']['from'] ?? ['email' => 'no-reply@example.com'];
        $html = '<p>Click the link to continue:</p><p><a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '">Continue</a></p>';
        $this->mailer->send($from, ['email' => $email], $subject, $html, strip_tags($html));
        return $rawToken;
    }
}


