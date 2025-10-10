<?php
declare(strict_types=1);

namespace AuthKit\Cache;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use Redis;
use RedisException;
use RuntimeException;

final class CacheManager
{
    private const DEFAULT_TTL = 3600; // 1 hour
    private const MAX_MEMORY_USAGE = 0.8; // 80% of memory limit
    private const CACHE_PREFIX = 'authkit:';

    public function __construct(
        private readonly Redis $redis,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        try {
            $fullKey = $this->buildKey($key);
            $value = $this->redis->get($fullKey);
            
            if ($value === false) {
                $this->logger?->debug('cache_miss', ['key' => $key]);
                return $default;
            }
            
            $decoded = json_decode($value, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger?->warning('cache_decode_error', [
                    'key' => $key,
                    'error' => json_last_error_msg()
                ]);
                return $default;
            }
            
            $this->logger?->debug('cache_hit', ['key' => $key]);
            return $decoded;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_get_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return $default;
        }
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        try {
            $fullKey = $this->buildKey($key);
            $serialized = json_encode($value, JSON_UNESCAPED_UNICODE);
            
            if ($serialized === false) {
                $this->logger?->error('cache_serialize_failed', [
                    'key' => $key,
                    'error' => json_last_error_msg()
                ]);
                return false;
            }
            
            $ttl = $ttl ?? self::DEFAULT_TTL;
            $result = $this->redis->setex($fullKey, $ttl, $serialized);
            
            if ($result) {
                $this->logger?->debug('cache_set', [
                    'key' => $key,
                    'ttl' => $ttl
                ]);
            }
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_set_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function delete(string $key): bool
    {
        try {
            $fullKey = $this->buildKey($key);
            $result = $this->redis->del($fullKey);
            
            $this->logger?->debug('cache_delete', [
                'key' => $key,
                'deleted' => $result > 0
            ]);
            
            return $result > 0;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_delete_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function deletePattern(string $pattern): int
    {
        try {
            $fullPattern = $this->buildKey($pattern);
            $keys = $this->redis->keys($fullPattern);
            
            if (empty($keys)) {
                return 0;
            }
            
            $result = $this->redis->del($keys);
            
            $this->logger?->info('cache_delete_pattern', [
                'pattern' => $pattern,
                'keys_deleted' => $result
            ]);
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_delete_pattern_failed', [
                'pattern' => $pattern,
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function exists(string $key): bool
    {
        try {
            $fullKey = $this->buildKey($key);
            return $this->redis->exists($fullKey) > 0;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_exists_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function increment(string $key, int $value = 1): int
    {
        try {
            $fullKey = $this->buildKey($key);
            $result = $this->redis->incrBy($fullKey, $value);
            
            $this->logger?->debug('cache_increment', [
                'key' => $key,
                'value' => $value,
                'result' => $result
            ]);
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_increment_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function decrement(string $key, int $value = 1): int
    {
        try {
            $fullKey = $this->buildKey($key);
            $result = $this->redis->decrBy($fullKey, $value);
            
            $this->logger?->debug('cache_decrement', [
                'key' => $key,
                'value' => $value,
                'result' => $result
            ]);
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_decrement_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function remember(string $key, callable $callback, ?int $ttl = null): mixed
    {
        $value = $this->get($key);
        
        if ($value !== null) {
            return $value;
        }
        
        $value = $callback();
        $this->set($key, $value, $ttl);
        
        return $value;
    }

    public function rememberForever(string $key, callable $callback): mixed
    {
        return $this->remember($key, $callback, 0);
    }

    public function flush(): bool
    {
        try {
            $result = $this->redis->flushDB();
            
            $this->logger?->info('cache_flush', ['success' => $result]);
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_flush_failed', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function getMultiple(array $keys): array
    {
        try {
            $fullKeys = array_map([$this, 'buildKey'], $keys);
            $values = $this->redis->mget($fullKeys);
            
            $result = [];
            foreach ($keys as $index => $key) {
                $value = $values[$index];
                if ($value !== false) {
                    $decoded = json_decode($value, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $result[$key] = $decoded;
                    } else {
                        $result[$key] = null;
                    }
                } else {
                    $result[$key] = null;
                }
            }
            
            $this->logger?->debug('cache_get_multiple', [
                'keys_count' => count($keys),
                'hits' => count(array_filter($result, fn($v) => $v !== null))
            ]);
            
            return $result;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_get_multiple_failed', [
                'keys' => $keys,
                'error' => $e->getMessage()
            ]);
            return array_fill_keys($keys, null);
        }
    }

    public function setMultiple(array $values, ?int $ttl = null): bool
    {
        try {
            $pipeline = $this->redis->pipeline();
            $ttl = $ttl ?? self::DEFAULT_TTL;
            
            foreach ($values as $key => $value) {
                $fullKey = $this->buildKey($key);
                $serialized = json_encode($value, JSON_UNESCAPED_UNICODE);
                
                if ($serialized !== false) {
                    $pipeline->setex($fullKey, $ttl, $serialized);
                }
            }
            
            $results = $pipeline->exec();
            $success = !in_array(false, $results, true);
            
            $this->logger?->debug('cache_set_multiple', [
                'keys_count' => count($values),
                'success' => $success
            ]);
            
            return $success;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_set_multiple_failed', [
                'values_count' => count($values),
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function getStats(): array
    {
        try {
            $info = $this->redis->info();
            
            return [
                'memory_usage' => $info['used_memory_human'] ?? 'unknown',
                'memory_peak' => $info['used_memory_peak_human'] ?? 'unknown',
                'connected_clients' => $info['connected_clients'] ?? 0,
                'total_commands_processed' => $info['total_commands_processed'] ?? 0,
                'keyspace_hits' => $info['keyspace_hits'] ?? 0,
                'keyspace_misses' => $info['keyspace_misses'] ?? 0,
                'hit_rate' => $this->calculateHitRate($info),
                'uptime' => $info['uptime_in_seconds'] ?? 0
            ];
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_stats_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function optimize(): bool
    {
        try {
            // Check memory usage
            $info = $this->redis->info();
            $memoryUsage = $info['used_memory'] ?? 0;
            $maxMemory = $info['maxmemory'] ?? 0;
            
            if ($maxMemory > 0 && $memoryUsage > ($maxMemory * self::MAX_MEMORY_USAGE)) {
                $this->logger?->info('cache_optimization_triggered', [
                    'memory_usage' => $memoryUsage,
                    'max_memory' => $maxMemory,
                    'threshold' => self::MAX_MEMORY_USAGE
                ]);
                
                // Remove expired keys
                $this->redis->eval("
                    local keys = redis.call('keys', ARGV[1])
                    for i=1,#keys do
                        local ttl = redis.call('ttl', keys[i])
                        if ttl == -1 then
                            redis.call('del', keys[i])
                        end
                    end
                ", 0, self::CACHE_PREFIX . '*');
                
                return true;
            }
            
            return false;
            
        } catch (RedisException $e) {
            $this->logger?->error('cache_optimization_failed', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function createTaggedCache(string $tag): TaggedCache
    {
        return new TaggedCache($this, $tag);
    }

    public function createDistributedCache(): DistributedCache
    {
        return new DistributedCache($this);
    }

    private function buildKey(string $key): string
    {
        return self::CACHE_PREFIX . $key;
    }

    private function calculateHitRate(array $info): float
    {
        $hits = $info['keyspace_hits'] ?? 0;
        $misses = $info['keyspace_misses'] ?? 0;
        $total = $hits + $misses;
        
        return $total > 0 ? round(($hits / $total) * 100, 2) : 0.0;
    }
}

final class TaggedCache
{
    public function __construct(
        private readonly CacheManager $cache,
        private readonly string $tag
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->cache->get($this->buildKey($key), $default);
    }

    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        return $this->cache->set($this->buildKey($key), $value, $ttl);
    }

    public function delete(string $key): bool
    {
        return $this->cache->delete($this->buildKey($key));
    }

    public function flush(): bool
    {
        return $this->cache->deletePattern($this->tag . ':*');
    }

    private function buildKey(string $key): string
    {
        return $this->tag . ':' . $key;
    }
}

final class DistributedCache
{
    public function __construct(
        private readonly CacheManager $cache
    ) {
    }

    public function lock(string $key, int $ttl = 10): bool
    {
        $lockKey = 'lock:' . $key;
        $lockValue = uniqid();
        
        $result = $this->cache->redis->set($lockKey, $lockValue, ['nx', 'ex' => $ttl]);
        
        return $result !== false;
    }

    public function unlock(string $key): bool
    {
        $lockKey = 'lock:' . $key;
        return $this->cache->delete($lockKey);
    }

    public function atomicIncrement(string $key, int $value = 1): int
    {
        $script = "
            local current = redis.call('get', KEYS[1])
            if current == false then
                current = 0
            else
                current = tonumber(current)
            end
            local new = current + tonumber(ARGV[1])
            redis.call('set', KEYS[1], new)
            return new
        ";
        
        return $this->cache->redis->eval($script, [$key], [$value]);
    }
}
