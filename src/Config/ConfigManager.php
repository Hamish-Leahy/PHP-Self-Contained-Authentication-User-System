<?php
declare(strict_types=1);

namespace AuthKit\Config;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;

final class ConfigManager
{
    private const CONFIG_TABLE = 'dynamic_config';
    private const CONFIG_CACHE_TTL = 300; // 5 minutes

    private array $cache = [];
    private array $cacheTimestamps = [];

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        // Check cache first
        if ($this->isCached($key)) {
            return $this->cache[$key];
        }

        // Load from database
        $value = $this->loadFromDatabase($key);
        
        if ($value !== null) {
            $this->cache[$key] = $value;
            $this->cacheTimestamps[$key] = $this->clock->now()->getTimestamp();
            return $value;
        }

        return $default;
    }

    public function set(string $key, mixed $value, ?string $description = null): bool
    {
        try {
            $pdo = $this->db->pdo();
            
            // Check if key exists
            $stmt = $pdo->prepare("
                SELECT id FROM " . self::CONFIG_TABLE . " 
                WHERE config_key = ?
            ");
            $stmt->execute([$key]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $now = $this->clock->now();
            
            if ($existing) {
                // Update existing
                $stmt = $pdo->prepare("
                    UPDATE " . self::CONFIG_TABLE . " 
                    SET config_value = ?, description = ?, updated_at = ? 
                    WHERE config_key = ?
                ");
                $stmt->execute([
                    json_encode($value),
                    $description,
                    $now->format('Y-m-d H:i:s'),
                    $key
                ]);
            } else {
                // Insert new
                $stmt = $pdo->prepare("
                    INSERT INTO " . self::CONFIG_TABLE . " 
                    (config_key, config_value, description, created_at, updated_at) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $key,
                    json_encode($value),
                    $description,
                    $now->format('Y-m-d H:i:s'),
                    $now->format('Y-m-d H:i:s')
                ]);
            }
            
            // Update cache
            $this->cache[$key] = $value;
            $this->cacheTimestamps[$key] = $now->getTimestamp();
            
            $this->logger?->info('config_updated', [
                'key' => $key,
                'value_type' => gettype($value)
            ]);
            
            return true;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_set_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function delete(string $key): bool
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                DELETE FROM " . self::CONFIG_TABLE . " 
                WHERE config_key = ?
            ");
            
            $result = $stmt->execute([$key]);
            
            if ($result) {
                // Remove from cache
                unset($this->cache[$key]);
                unset($this->cacheTimestamps[$key]);
                
                $this->logger?->info('config_deleted', ['key' => $key]);
            }
            
            return $result;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_delete_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function getAll(array $filters = []): array
    {
        try {
            $pdo = $this->db->pdo();
            
            $sql = "SELECT * FROM " . self::CONFIG_TABLE . " WHERE 1=1";
            $params = [];
            
            if (!empty($filters['prefix'])) {
                $sql .= " AND config_key LIKE ?";
                $params[] = $filters['prefix'] . '%';
            }
            
            if (!empty($filters['updated_since'])) {
                $sql .= " AND updated_at >= ?";
                $params[] = $filters['updated_since'];
            }
            
            $sql .= " ORDER BY config_key ASC";
            
            if (!empty($filters['limit'])) {
                $sql .= " LIMIT ?";
                $params[] = $filters['limit'];
            }
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            
            $configs = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $configs[$row['config_key']] = [
                    'value' => json_decode($row['config_value'], true),
                    'description' => $row['description'],
                    'created_at' => $row['created_at'],
                    'updated_at' => $row['updated_at']
                ];
            }
            
            return $configs;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_get_all_failed', [
                'filters' => $filters,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getByPrefix(string $prefix): array
    {
        return $this->getAll(['prefix' => $prefix]);
    }

    public function bulkSet(array $configs): bool
    {
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            $now = $this->clock->now();
            
            foreach ($configs as $key => $config) {
                $value = $config['value'] ?? $config;
                $description = $config['description'] ?? null;
                
                // Check if key exists
                $stmt = $pdo->prepare("
                    SELECT id FROM " . self::CONFIG_TABLE . " 
                    WHERE config_key = ?
                ");
                $stmt->execute([$key]);
                $existing = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($existing) {
                    // Update existing
                    $stmt = $pdo->prepare("
                        UPDATE " . self::CONFIG_TABLE . " 
                        SET config_value = ?, description = ?, updated_at = ? 
                        WHERE config_key = ?
                    ");
                    $stmt->execute([
                        json_encode($value),
                        $description,
                        $now->format('Y-m-d H:i:s'),
                        $key
                    ]);
                } else {
                    // Insert new
                    $stmt = $pdo->prepare("
                        INSERT INTO " . self::CONFIG_TABLE . " 
                        (config_key, config_value, description, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([
                        $key,
                        json_encode($value),
                        $description,
                        $now->format('Y-m-d H:i:s'),
                        $now->format('Y-m-d H:i:s')
                    ]);
                }
                
                // Update cache
                $this->cache[$key] = $value;
                $this->cacheTimestamps[$key] = $now->getTimestamp();
            }
            
            $pdo->commit();
            
            $this->logger?->info('config_bulk_set', [
                'count' => count($configs),
                'keys' => array_keys($configs)
            ]);
            
            return true;
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('config_bulk_set_failed', [
                'count' => count($configs),
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function importFromArray(array $configs, bool $overwrite = false): int
    {
        $imported = 0;
        
        foreach ($configs as $key => $value) {
            if (!$overwrite && $this->get($key) !== null) {
                continue; // Skip existing keys
            }
            
            if ($this->set($key, $value)) {
                $imported++;
            }
        }
        
        $this->logger?->info('config_imported', [
            'imported' => $imported,
            'total' => count($configs),
            'overwrite' => $overwrite
        ]);
        
        return $imported;
    }

    public function exportToArray(array $filters = []): array
    {
        $configs = $this->getAll($filters);
        $export = [];
        
        foreach ($configs as $key => $config) {
            $export[$key] = $config['value'];
        }
        
        return $export;
    }

    public function validateConfig(array $config): array
    {
        $errors = [];
        
        foreach ($config as $key => $value) {
            // Basic validation rules
            if (str_contains($key, ' ')) {
                $errors[] = "Config key '{$key}' contains spaces";
            }
            
            if (strlen($key) > 255) {
                $errors[] = "Config key '{$key}' is too long (max 255 characters)";
            }
            
            if (is_resource($value)) {
                $errors[] = "Config value for '{$key}' cannot be a resource";
            }
        }
        
        return $errors;
    }

    public function getConfigHistory(string $key, int $limit = 10): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM config_history 
                WHERE config_key = ? 
                ORDER BY updated_at DESC 
                LIMIT ?
            ");
            
            $stmt->execute([$key, $limit]);
            $history = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $history[] = [
                    'old_value' => json_decode($row['old_value'], true),
                    'new_value' => json_decode($row['new_value'], true),
                    'updated_at' => $row['updated_at'],
                    'updated_by' => $row['updated_by']
                ];
            }
            
            return $history;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_history_fetch_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function createConfigGroup(string $name, array $configs): bool
    {
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            $now = $this->clock->now();
            
            // Create group
            $stmt = $pdo->prepare("
                INSERT INTO config_groups (name, created_at, updated_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([
                $name,
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $groupId = $pdo->lastInsertId();
            
            // Add configs to group
            foreach ($configs as $key => $value) {
                $stmt = $pdo->prepare("
                    INSERT INTO config_group_items (group_id, config_key, config_value) 
                    VALUES (?, ?, ?)
                ");
                $stmt->execute([
                    $groupId,
                    $key,
                    json_encode($value)
                ]);
            }
            
            $pdo->commit();
            
            $this->logger?->info('config_group_created', [
                'name' => $name,
                'configs_count' => count($configs)
            ]);
            
            return true;
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('config_group_creation_failed', [
                'name' => $name,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function applyConfigGroup(string $name): bool
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT cgi.config_key, cgi.config_value 
                FROM config_groups cg
                JOIN config_group_items cgi ON cg.id = cgi.group_id
                WHERE cg.name = ?
            ");
            
            $stmt->execute([$name]);
            $configs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            if (empty($configs)) {
                return false;
            }
            
            $applied = 0;
            foreach ($configs as $config) {
                if ($this->set($config['config_key'], json_decode($config['config_value'], true))) {
                    $applied++;
                }
            }
            
            $this->logger?->info('config_group_applied', [
                'name' => $name,
                'applied' => $applied,
                'total' => count($configs)
            ]);
            
            return $applied > 0;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_group_apply_failed', [
                'name' => $name,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function clearCache(): void
    {
        $this->cache = [];
        $this->cacheTimestamps = [];
        
        $this->logger?->debug('config_cache_cleared');
    }

    public function getCacheStats(): array
    {
        return [
            'cached_items' => count($this->cache),
            'cache_size' => strlen(serialize($this->cache)),
            'oldest_cached' => !empty($this->cacheTimestamps) ? min($this->cacheTimestamps) : null,
            'newest_cached' => !empty($this->cacheTimestamps) ? max($this->cacheTimestamps) : null
        ];
    }

    private function isCached(string $key): bool
    {
        if (!isset($this->cache[$key])) {
            return false;
        }
        
        $cachedAt = $this->cacheTimestamps[$key] ?? 0;
        $now = $this->clock->now()->getTimestamp();
        
        return ($now - $cachedAt) < self::CONFIG_CACHE_TTL;
    }

    private function loadFromDatabase(string $key): mixed
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT config_value FROM " . self::CONFIG_TABLE . " 
                WHERE config_key = ?
            ");
            
            $stmt->execute([$key]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            $value = json_decode($row['config_value'], true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger?->error('config_decode_failed', [
                    'key' => $key,
                    'error' => json_last_error_msg()
                ]);
                return null;
            }
            
            return $value;
            
        } catch (PDOException $e) {
            $this->logger?->error('config_load_failed', [
                'key' => $key,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }
}
