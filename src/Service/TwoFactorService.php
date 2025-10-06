<?php
declare(strict_types=1);

namespace AuthKit\Service;

use AuthKit\Contracts\RecoveryCodeRepositoryInterface;
use AuthKit\Contracts\TwoFactorRepositoryInterface;
use AuthKit\Contracts\TotpInterface;
use AuthKit\Contracts\RandomTokenGeneratorInterface;
use AuthKit\Contracts\ClockInterface;

final class TwoFactorService
{
    public function __construct(
        private readonly TwoFactorRepositoryInterface $twofactor,
        private readonly RecoveryCodeRepositoryInterface $recovery,
        private readonly TotpInterface $totp,
        private readonly RandomTokenGeneratorInterface $random,
        private readonly ClockInterface $clock,
        private readonly array $config,
    ) {
    }

    public function beginEnable(int $userId, string $accountLabel): array
    {
        $secret = $this->totp->generateSecret();
        $issuer = (string)($this->config['two_factor']['issuer'] ?? 'AuthKit');
        $uri = $this->totp->provisioningUri($secret, $accountLabel, $issuer);
        $this->twofactor->setSecret($userId, $secret);
        return ['secret' => $secret, 'uri' => $uri];
    }

    public function confirmEnable(int $userId, string $code): bool
    {
        // we would read secret from DB via user repo; for simplicity, pass in separately or reuse a method
        // As a minimal approach, we trust the setSecret stored and verify via a SELECT
        // In a real app, inject UserRepository and fetch secret; omitted here for brevity
        return $this->verifyAndEnable($userId, $code);
    }

    private function verifyAndEnable(int $userId, string $code): bool
    {
        // Fetch secret
        // Minimal inline fetch due to avoiding new repository methods on UserRepository
        if (!method_exists($this->twofactor, 'getPdo')) {
            // Can't verify without reading secret; treat as failure in this minimal abstraction
            return false;
        }
        $pdo = $this->twofactor->getPdo();
        $stmt = $pdo->prepare('SELECT two_factor_secret FROM users WHERE id = :id');
        $stmt->execute([':id' => $userId]);
        $secret = (string)$stmt->fetchColumn();
        if ($secret === '') { return false; }
        if (!$this->totp->verify($secret, $code)) { return false; }
        $this->twofactor->enable($userId);

        // Generate recovery codes
        $codes = [];
        $hashes = [];
        for ($i = 0; $i < 8; $i++) {
            $code = strtoupper(bin2hex($this->random->generate(4)));
            $codes[] = $code;
            $hashes[] = hash('sha256', $code);
        }
        $this->recovery->store($userId, $hashes);
        return true;
    }

    public function disable(int $userId): void
    {
        $this->twofactor->disable($userId);
    }

    public function verifyCodeOrRecovery(int $userId, string $code): bool
    {
        if (!method_exists($this->twofactor, 'getPdo')) { return false; }
        $pdo = $this->twofactor->getPdo();
        $stmt = $pdo->prepare('SELECT two_factor_secret FROM users WHERE id = :id AND two_factor_enabled = 1');
        $stmt->execute([':id' => $userId]);
        $secret = $stmt->fetchColumn();
        if ($secret && $this->totp->verify((string)$secret, $code)) {
            return true;
        }
        $hash = hash('sha256', $code);
        return $this->recovery->consume($userId, $hash);
    }
}


