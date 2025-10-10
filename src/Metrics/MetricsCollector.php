<?php
declare(strict_types=1);

namespace AuthKit\Metrics;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;

final class MetricsCollector
{
    private const METRICS_TABLE = 'metrics';
    private const AGGREGATED_METRICS_TABLE = 'aggregated_metrics';
    private const BATCH_SIZE = 1000;

    private array $metricsBuffer = [];
    private int $bufferSize = 0;

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function increment(string $name, float $value = 1.0, array $tags = []): void
    {
        $this->recordMetric($name, $value, 'counter', $tags);
    }

    public function gauge(string $name, float $value, array $tags = []): void
    {
        $this->recordMetric($name, $value, 'gauge', $tags);
    }

    public function histogram(string $name, float $value, array $tags = []): void
    {
        $this->recordMetric($name, $value, 'histogram', $tags);
    }

    public function timer(string $name, callable $callback, array $tags = []): mixed
    {
        $startTime = microtime(true);
        
        try {
            $result = $callback();
            $this->recordMetric($name, microtime(true) - $startTime, 'timer', $tags);
            return $result;
        } catch (Exception $e) {
            $this->recordMetric($name, microtime(true) - $startTime, 'timer', array_merge($tags, ['error' => 'true']));
            throw $e;
        }
    }

    public function recordCustomMetric(string $name, float $value, string $type, array $tags = []): void
    {
        $this->recordMetric($name, $value, $type, $tags);
    }

    public function getMetrics(string $name, ?string $type = null, array $filters = []): array
    {
        try {
            $pdo = $this->db->pdo();
            
            $sql = "SELECT * FROM " . self::METRICS_TABLE . " WHERE name = ?";
            $params = [$name];
            
            if ($type) {
                $sql .= " AND type = ?";
                $params[] = $type;
            }
            
            if (!empty($filters['start_time'])) {
                $sql .= " AND created_at >= ?";
                $params[] = $filters['start_time'];
            }
            
            if (!empty($filters['end_time'])) {
                $sql .= " AND created_at <= ?";
                $params[] = $filters['end_time'];
            }
            
            $sql .= " ORDER BY created_at DESC";
            
            if (!empty($filters['limit'])) {
                $sql .= " LIMIT ?";
                $params[] = $filters['limit'];
            }
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            
            $metrics = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $metrics[] = $this->rowToMetric($row);
            }
            
            return $metrics;
            
        } catch (PDOException $e) {
            $this->logger?->error('metrics_fetch_failed', [
                'name' => $name,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getAggregatedMetrics(string $name, string $period = '1h'): array
    {
        try {
            $pdo = $this->db->pdo();
            
            $interval = $this->getIntervalForPeriod($period);
            $sql = "
                SELECT 
                    name,
                    type,
                    DATE_FORMAT(created_at, ?) as time_bucket,
                    COUNT(*) as count,
                    AVG(value) as avg_value,
                    MIN(value) as min_value,
                    MAX(value) as max_value,
                    SUM(value) as sum_value
                FROM " . self::METRICS_TABLE . " 
                WHERE name = ? AND created_at >= ?
                GROUP BY name, type, time_bucket
                ORDER BY time_bucket DESC
            ";
            
            $startTime = $this->getStartTimeForPeriod($period);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                $interval,
                $name,
                $startTime->format('Y-m-d H:i:s')
            ]);
            
            $aggregated = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $aggregated[] = [
                    'name' => $row['name'],
                    'type' => $row['type'],
                    'time_bucket' => $row['time_bucket'],
                    'count' => (int) $row['count'],
                    'avg_value' => round((float) $row['avg_value'], 4),
                    'min_value' => (float) $row['min_value'],
                    'max_value' => (float) $row['max_value'],
                    'sum_value' => (float) $row['sum_value']
                ];
            }
            
            return $aggregated;
            
        } catch (PDOException $e) {
            $this->logger?->error('aggregated_metrics_fetch_failed', [
                'name' => $name,
                'period' => $period,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getSystemMetrics(): array
    {
        return [
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
            'memory_limit' => ini_get('memory_limit'),
            'cpu_usage' => $this->getCpuUsage(),
            'disk_usage' => $this->getDiskUsage(),
            'load_average' => sys_getloadavg(),
            'uptime' => $this->getUptime(),
            'php_version' => PHP_VERSION,
            'timestamp' => $this->clock->now()->format('c')
        ];
    }

    public function getApplicationMetrics(): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Database connections
            $stmt = $pdo->prepare("SHOW STATUS LIKE 'Threads_connected'");
            $stmt->execute();
            $dbConnections = $stmt->fetch(PDO::FETCH_ASSOC)['Value'] ?? 0;
            
            // Active sessions
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as active_sessions 
                FROM active_sessions 
                WHERE is_active = 1
            ");
            $stmt->execute();
            $activeSessions = $stmt->fetch(PDO::FETCH_ASSOC)['active_sessions'] ?? 0;
            
            // Queue status
            $stmt = $pdo->prepare("
                SELECT 
                    queue,
                    COUNT(*) as pending_jobs
                FROM queue_jobs 
                WHERE status = 'pending'
                GROUP BY queue
            ");
            $stmt->execute();
            $queueStatus = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            return [
                'database_connections' => (int) $dbConnections,
                'active_sessions' => (int) $activeSessions,
                'queue_status' => $queueStatus,
                'timestamp' => $this->clock->now()->format('c')
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('application_metrics_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function createDashboard(array $config): array
    {
        $dashboard = [
            'title' => $config['title'] ?? 'System Dashboard',
            'created_at' => $this->clock->now()->format('c'),
            'widgets' => []
        ];
        
        foreach ($config['widgets'] as $widgetConfig) {
            $widget = $this->createWidget($widgetConfig);
            if ($widget) {
                $dashboard['widgets'][] = $widget;
            }
        }
        
        return $dashboard;
    }

    public function exportMetrics(array $filters = []): array
    {
        try {
            $pdo = $this->db->pdo();
            
            $sql = "SELECT * FROM " . self::METRICS_TABLE . " WHERE 1=1";
            $params = [];
            
            if (!empty($filters['start_time'])) {
                $sql .= " AND created_at >= ?";
                $params[] = $filters['start_time'];
            }
            
            if (!empty($filters['end_time'])) {
                $sql .= " AND created_at <= ?";
                $params[] = $filters['end_time'];
            }
            
            if (!empty($filters['names'])) {
                $placeholders = str_repeat('?,', count($filters['names']) - 1) . '?';
                $sql .= " AND name IN ($placeholders)";
                $params = array_merge($params, $filters['names']);
            }
            
            $sql .= " ORDER BY created_at DESC";
            
            if (!empty($filters['limit'])) {
                $sql .= " LIMIT ?";
                $params[] = $filters['limit'];
            }
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            
            $metrics = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $metrics[] = $this->rowToMetric($row);
            }
            
            return [
                'exported_at' => $this->clock->now()->format('c'),
                'filters' => $filters,
                'count' => count($metrics),
                'metrics' => $metrics
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('metrics_export_failed', [
                'filters' => $filters,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function flush(): void
    {
        if (empty($this->metricsBuffer)) {
            return;
        }

        try {
            $this->insertBatch($this->metricsBuffer);
            $this->metricsBuffer = [];
            $this->bufferSize = 0;
        } catch (PDOException $e) {
            $this->logger?->error('metrics_flush_failed', [
                'buffer_size' => count($this->metricsBuffer),
                'error' => $e->getMessage()
            ]);
            
            // Reset buffer to prevent memory issues
            $this->metricsBuffer = [];
            $this->bufferSize = 0;
        }
    }

    private function recordMetric(string $name, float $value, string $type, array $tags): void
    {
        $this->metricsBuffer[] = [
            'name' => $name,
            'value' => $value,
            'type' => $type,
            'tags' => $tags,
            'timestamp' => $this->clock->now()
        ];
        
        $this->bufferSize++;
        
        if ($this->bufferSize >= self::BATCH_SIZE) {
            $this->flush();
        }
    }

    private function insertBatch(array $metrics): void
    {
        $pdo = $this->db->pdo();
        
        $sql = "INSERT INTO " . self::METRICS_TABLE . " 
                (name, value, type, tags, created_at) 
                VALUES (?, ?, ?, ?, ?)";
        
        $stmt = $pdo->prepare($sql);
        
        foreach ($metrics as $metric) {
            $stmt->execute([
                $metric['name'],
                $metric['value'],
                $metric['type'],
                json_encode($metric['tags']),
                $metric['timestamp']->format('Y-m-d H:i:s')
            ]);
        }
    }

    private function createWidget(array $config): ?array
    {
        $type = $config['type'] ?? 'chart';
        
        switch ($type) {
            case 'chart':
                return $this->createChartWidget($config);
            case 'gauge':
                return $this->createGaugeWidget($config);
            case 'table':
                return $this->createTableWidget($config);
            case 'counter':
                return $this->createCounterWidget($config);
            default:
                return null;
        }
    }

    private function createChartWidget(array $config): array
    {
        $data = $this->getAggregatedMetrics($config['metric'], $config['period'] ?? '1h');
        
        return [
            'type' => 'chart',
            'title' => $config['title'],
            'metric' => $config['metric'],
            'data' => $data,
            'chart_type' => $config['chart_type'] ?? 'line'
        ];
    }

    private function createGaugeWidget(array $config): array
    {
        $metrics = $this->getMetrics($config['metric'], null, ['limit' => 1]);
        $currentValue = !empty($metrics) ? $metrics[0]->value : 0;
        
        return [
            'type' => 'gauge',
            'title' => $config['title'],
            'metric' => $config['metric'],
            'value' => $currentValue,
            'min' => $config['min'] ?? 0,
            'max' => $config['max'] ?? 100
        ];
    }

    private function createTableWidget(array $config): array
    {
        $data = $this->getMetrics($config['metric'], null, $config['filters'] ?? []);
        
        return [
            'type' => 'table',
            'title' => $config['title'],
            'metric' => $config['metric'],
            'data' => array_slice($data, 0, $config['limit'] ?? 10)
        ];
    }

    private function createCounterWidget(array $config): array
    {
        $metrics = $this->getMetrics($config['metric'], 'counter', $config['filters'] ?? []);
        $total = array_sum(array_column($metrics, 'value'));
        
        return [
            'type' => 'counter',
            'title' => $config['title'],
            'metric' => $config['metric'],
            'value' => $total
        ];
    }

    private function getIntervalForPeriod(string $period): string
    {
        return match ($period) {
            '1m' => '%Y-%m-%d %H:%i:00',
            '5m' => '%Y-%m-%d %H:%i:00',
            '1h' => '%Y-%m-%d %H:00:00',
            '1d' => '%Y-%m-%d 00:00:00',
            default => '%Y-%m-%d %H:00:00'
        };
    }

    private function getStartTimeForPeriod(string $period): \DateTimeImmutable
    {
        return match ($period) {
            '1m' => $this->clock->now()->sub(new \DateInterval('PT1M')),
            '5m' => $this->clock->now()->sub(new \DateInterval('PT5M')),
            '1h' => $this->clock->now()->sub(new \DateInterval('PT1H')),
            '1d' => $this->clock->now()->sub(new \DateInterval('P1D')),
            default => $this->clock->now()->sub(new \DateInterval('PT1H'))
        };
    }

    private function getCpuUsage(): float
    {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            return $load[0] ?? 0.0;
        }
        return 0.0;
    }

    private function getDiskUsage(): array
    {
        $total = disk_total_space('/');
        $free = disk_free_space('/');
        
        return [
            'total' => $total,
            'free' => $free,
            'used' => $total - $free,
            'percentage' => $total > 0 ? round((($total - $free) / $total) * 100, 2) : 0
        ];
    }

    private function getUptime(): int
    {
        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            return (int) explode(' ', $uptime)[0];
        }
        return 0;
    }

    private function rowToMetric(array $row): Metric
    {
        return new Metric(
            id: $row['id'],
            name: $row['name'],
            value: (float) $row['value'],
            type: $row['type'],
            tags: json_decode($row['tags'], true),
            createdAt: new \DateTimeImmutable($row['created_at'])
        );
    }

    public function __destruct()
    {
        $this->flush();
    }
}

final class Metric
{
    public function __construct(
        public readonly int $id,
        public readonly string $name,
        public readonly float $value,
        public readonly string $type,
        public readonly array $tags,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}
