<?php
declare(strict_types=1);

namespace AuthKit\Service;

use AuthKit\Contracts\RefreshTokenRepositoryInterface;
use AuthKit\Contracts\RandomTokenGeneratorInterface;
use AuthKit\Contracts\ClockInterface;

final class RefreshTokenService
{
    public function __construct(
        private readonly RefreshTokenRepositoryInterface $repo,
        private readonly RandomTokenGeneratorInterface $random,
        private readonly ClockInterface $clock,
        private readonly array $config,
    ) {
    }

    public function issue(int $userId): array
    {
        $raw = bin2hex($this->random->generate(32));
        $hash = hash('sha256', $raw);
        $ttl = (string)($this->config['jwt']['refresh_ttl'] ?? '14 days');
        $exp = $this->clock->now()->add(\DateInterval::createFromDateString($ttl));
        $id = $this->repo->create($userId, $hash, $exp);
        return ['token' => $raw, 'id' => $id, 'expires_at' => $exp];
    }

    public function rotate(string $raw): array
    {
        $hash = hash('sha256', $raw);
        $found = $this->repo->findValidByHash($hash, $this->clock->now());
        if (!$found) { throw new \RuntimeException('Invalid refresh token'); }
        $newRaw = bin2hex($this->random->generate(32));
        $newHash = hash('sha256', $newRaw);
        $ttl = (string)($this->config['jwt']['refresh_ttl'] ?? '14 days');
        $exp = $this->clock->now()->add(\DateInterval::createFromDateString($ttl));
        $newId = $this->repo->rotate($found['id'], $newHash, $exp, $this->clock->now());
        return ['token' => $newRaw, 'id' => $newId, 'user_id' => $found['user_id'], 'expires_at' => $exp];
    }

    public function revoke(string $raw): void
    {
        $hash = hash('sha256', $raw);
        $found = $this->repo->findValidByHash($hash, $this->clock->now());
        if ($found) {
            $this->repo->revokeChain($found['id'], $this->clock->now());
        }
    }
}


