<?php
declare(strict_types=1);

namespace AuthKit\Middleware;

use AuthKit\Contracts\LoggerInterface;
use AuthKit\Contracts\ClockInterface;
use Redis;
use RedisException;

final class RateLimiter
{
    private const SLIDING_WINDOW_SCRIPT = '
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local identifier = ARGV[4]
        
        local current = redis.call("ZCARD", key)
        if current < limit then
            redis.call("ZADD", key, now, identifier)
            redis.call("EXPIRE", key, window)
            return {1, limit - current - 1, window}
        else
            local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
            if #oldest > 0 and tonumber(oldest[2]) < now - window then
                redis.call("ZREMRANGEBYSCORE", key, 0, now - window)
                redis.call("ZADD", key, now, identifier)
                redis.call("EXPIRE", key, window)
                return {1, limit - redis.call("ZCARD", key), window}
            else
                local ttl = redis.call("TTL", key)
                return {0, 0, ttl > 0 and ttl or window}
            end
        end
    ';

    public function __construct(
        private readonly Redis $redis,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function checkLimit(
        string $identifier,
        int $limit,
        int $windowSeconds,
        string $action = 'default'
    ): RateLimitResult {
        $key = "rate_limit:{$action}:{$identifier}";
        $now = $this->clock->now()->getTimestamp();
        
        try {
            $result = $this->redis->eval(
                self::SLIDING_WINDOW_SCRIPT,
                [$key],
                [$windowSeconds, $limit, $now, $identifier]
            );
            
            $allowed = (bool) $result[0];
            $remaining = (int) $result[1];
            $resetTime = $now + (int) $result[2];
            
            $rateLimitResult = new RateLimitResult($allowed, $remaining, $resetTime);
            
            if (!$allowed) {
                $this->logger?->warning('rate_limit_exceeded', [
                    'identifier' => $identifier,
                    'action' => $action,
                    'limit' => $limit,
                    'window' => $windowSeconds
                ]);
            }
            
            return $rateLimitResult;
            
        } catch (RedisException $e) {
            $this->logger?->error('rate_limiter_redis_error', [
                'error' => $e->getMessage(),
                'identifier' => $identifier,
                'action' => $action
            ]);
            
            // Fail open - allow request if Redis is down
            return new RateLimitResult(true, $limit, $now + $windowSeconds);
        }
    }

    public function checkMultipleLimits(
        string $identifier,
        array $limits,
        string $action = 'default'
    ): array {
        $results = [];
        
        foreach ($limits as $name => $config) {
            $results[$name] = $this->checkLimit(
                $identifier,
                $config['limit'],
                $config['window'],
                "{$action}:{$name}"
            );
        }
        
        return $results;
    }

    public function resetLimit(string $identifier, string $action = 'default'): bool
    {
        $key = "rate_limit:{$action}:{$identifier}";
        
        try {
            return $this->redis->del($key) > 0;
        } catch (RedisException $e) {
            $this->logger?->error('rate_limiter_reset_error', [
                'error' => $e->getMessage(),
                'identifier' => $identifier,
                'action' => $action
            ]);
            return false;
        }
    }

    public function getRemainingLimit(string $identifier, int $limit, int $windowSeconds, string $action = 'default'): int
    {
        $key = "rate_limit:{$action}:{$identifier}";
        $now = $this->clock->now()->getTimestamp();
        
        try {
            $count = $this->redis->zcount($key, $now - $windowSeconds, '+inf');
            return max(0, $limit - $count);
        } catch (RedisException $e) {
            $this->logger?->error('rate_limiter_check_error', [
                'error' => $e->getMessage(),
                'identifier' => $identifier,
                'action' => $action
            ]);
            return $limit; // Fail open
        }
    }
}

final class RateLimitResult
{
    public function __construct(
        public readonly bool $allowed,
        public readonly int $remaining,
        public readonly int $resetTime
    ) {
    }

    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'remaining' => $this->remaining,
            'reset_time' => $this->resetTime,
            'retry_after' => max(0, $this->resetTime - time())
        ];
    }
}
