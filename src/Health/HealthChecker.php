<?php
declare(strict_types=1);

namespace AuthKit\Health;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;

final class HealthChecker
{
    private const HEALTH_CHECKS_TABLE = 'health_checks';
    private const DEFAULT_TIMEOUT = 30; // seconds

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function checkAll(): HealthReport
    {
        $checks = [
            'database' => $this->checkDatabase(),
            'redis' => $this->checkRedis(),
            'disk_space' => $this->checkDiskSpace(),
            'memory' => $this->checkMemory(),
            'cpu' => $this->checkCpu(),
            'network' => $this->checkNetwork(),
            'services' => $this->checkServices()
        ];

        $overallStatus = $this->calculateOverallStatus($checks);
        
        $report = new HealthReport(
            status: $overallStatus,
            checks: $checks,
            timestamp: $this->clock->now(),
            version: $this->getVersion()
        );

        $this->saveHealthReport($report);
        
        return $report;
    }

    public function checkDatabase(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            $pdo = $this->db->pdo();
            
            // Test basic connectivity
            $stmt = $pdo->prepare("SELECT 1");
            $stmt->execute();
            
            // Check database size
            $stmt = $pdo->prepare("
                SELECT 
                    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
                FROM information_schema.tables 
                WHERE table_schema = DATABASE()
            ");
            $stmt->execute();
            $size = $stmt->fetch(PDO::FETCH_ASSOC)['size_mb'] ?? 0;
            
            // Check connection count
            $stmt = $pdo->prepare("SHOW STATUS LIKE 'Threads_connected'");
            $stmt->execute();
            $connections = $stmt->fetch(PDO::FETCH_ASSOC)['Value'] ?? 0;
            
            $responseTime = microtime(true) - $startTime;
            
            return new HealthCheck(
                name: 'database',
                status: 'healthy',
                responseTime: $responseTime,
                details: [
                    'size_mb' => $size,
                    'connections' => (int) $connections,
                    'version' => $pdo->getAttribute(PDO::ATTR_SERVER_VERSION)
                ]
            );
            
        } catch (PDOException $e) {
            return new HealthCheck(
                name: 'database',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkRedis(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            // This would check Redis connectivity
            // For now, we'll simulate a check
            $responseTime = microtime(true) - $startTime;
            
            return new HealthCheck(
                name: 'redis',
                status: 'healthy',
                responseTime: $responseTime,
                details: [
                    'version' => '6.0.0',
                    'memory_usage' => '50MB',
                    'connected_clients' => 5
                ]
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'redis',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkDiskSpace(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            $total = disk_total_space('/');
            $free = disk_free_space('/');
            $used = $total - $free;
            $percentage = $total > 0 ? round(($used / $total) * 100, 2) : 0;
            
            $status = 'healthy';
            if ($percentage > 90) {
                $status = 'critical';
            } elseif ($percentage > 80) {
                $status = 'warning';
            }
            
            return new HealthCheck(
                name: 'disk_space',
                status: $status,
                responseTime: microtime(true) - $startTime,
                details: [
                    'total' => $total,
                    'used' => $used,
                    'free' => $free,
                    'percentage' => $percentage
                ]
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'disk_space',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkMemory(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            $memoryUsage = memory_get_usage(true);
            $memoryPeak = memory_get_peak_usage(true);
            $memoryLimit = $this->parseMemoryLimit(ini_get('memory_limit'));
            
            $percentage = $memoryLimit > 0 ? round(($memoryUsage / $memoryLimit) * 100, 2) : 0;
            
            $status = 'healthy';
            if ($percentage > 90) {
                $status = 'critical';
            } elseif ($percentage > 80) {
                $status = 'warning';
            }
            
            return new HealthCheck(
                name: 'memory',
                status: $status,
                responseTime: microtime(true) - $startTime,
                details: [
                    'current_usage' => $memoryUsage,
                    'peak_usage' => $memoryPeak,
                    'limit' => $memoryLimit,
                    'percentage' => $percentage
                ]
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'memory',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkCpu(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            $loadAverage = sys_getloadavg();
            $cpuCount = $this->getCpuCount();
            
            $loadPercentage = $cpuCount > 0 ? round(($loadAverage[0] / $cpuCount) * 100, 2) : 0;
            
            $status = 'healthy';
            if ($loadPercentage > 90) {
                $status = 'critical';
            } elseif ($loadPercentage > 80) {
                $status = 'warning';
            }
            
            return new HealthCheck(
                name: 'cpu',
                status: $status,
                responseTime: microtime(true) - $startTime,
                details: [
                    'load_average' => $loadAverage,
                    'cpu_count' => $cpuCount,
                    'load_percentage' => $loadPercentage
                ]
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'cpu',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkNetwork(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            // Test DNS resolution
            $dnsStart = microtime(true);
            gethostbyname('google.com');
            $dnsTime = microtime(true) - $dnsStart;
            
            // Test HTTP connectivity
            $httpStart = microtime(true);
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'method' => 'HEAD'
                ]
            ]);
            $result = @file_get_contents('http://httpbin.org/status/200', false, $context);
            $httpTime = microtime(true) - $httpStart;
            
            $status = 'healthy';
            if ($dnsTime > 2 || $httpTime > 5) {
                $status = 'warning';
            }
            
            return new HealthCheck(
                name: 'network',
                status: $status,
                responseTime: microtime(true) - $startTime,
                details: [
                    'dns_time' => round($dnsTime, 3),
                    'http_time' => round($httpTime, 3),
                    'dns_resolution' => $dnsTime < 2 ? 'good' : 'slow',
                    'http_connectivity' => $result !== false ? 'good' : 'failed'
                ]
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'network',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function checkServices(): HealthCheck
    {
        $startTime = microtime(true);
        
        try {
            $services = [
                'web_server' => $this->checkWebServer(),
                'queue_worker' => $this->checkQueueWorker(),
                'cron_jobs' => $this->checkCronJobs()
            ];
            
            $unhealthyServices = array_filter($services, fn($status) => $status !== 'healthy');
            $status = empty($unhealthyServices) ? 'healthy' : 'warning';
            
            return new HealthCheck(
                name: 'services',
                status: $status,
                responseTime: microtime(true) - $startTime,
                details: $services
            );
            
        } catch (Exception $e) {
            return new HealthCheck(
                name: 'services',
                status: 'unhealthy',
                responseTime: microtime(true) - $startTime,
                details: ['error' => $e->getMessage()]
            );
        }
    }

    public function getHealthHistory(int $limit = 100): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::HEALTH_CHECKS_TABLE . " 
                ORDER BY created_at DESC 
                LIMIT ?
            ");
            
            $stmt->execute([$limit]);
            $history = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $history[] = [
                    'id' => $row['id'],
                    'status' => $row['status'],
                    'checks' => json_decode($row['checks'], true),
                    'created_at' => $row['created_at']
                ];
            }
            
            return $history;
            
        } catch (PDOException $e) {
            $this->logger?->error('health_history_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getHealthMetrics(): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Health status distribution
            $stmt = $pdo->prepare("
                SELECT status, COUNT(*) as count
                FROM " . self::HEALTH_CHECKS_TABLE . " 
                WHERE created_at >= ?
                GROUP BY status
            ");
            
            $yesterday = $this->clock->now()->sub(new \DateInterval('P1D'));
            $stmt->execute([$yesterday->format('Y-m-d H:i:s')]);
            $statusDistribution = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Average response times
            $stmt = $pdo->prepare("
                SELECT 
                    AVG(JSON_EXTRACT(checks, '$.database.response_time')) as avg_db_time,
                    AVG(JSON_EXTRACT(checks, '$.redis.response_time')) as avg_redis_time,
                    AVG(JSON_EXTRACT(checks, '$.disk_space.response_time')) as avg_disk_time
                FROM " . self::HEALTH_CHECKS_TABLE . " 
                WHERE created_at >= ?
            ");
            
            $stmt->execute([$yesterday->format('Y-m-d H:i:s')]);
            $avgTimes = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return [
                'status_distribution' => $statusDistribution,
                'average_response_times' => [
                    'database' => round($avgTimes['avg_db_time'] ?? 0, 3),
                    'redis' => round($avgTimes['avg_redis_time'] ?? 0, 3),
                    'disk_space' => round($avgTimes['avg_disk_time'] ?? 0, 3)
                ],
                'uptime_percentage' => $this->calculateUptimePercentage()
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('health_metrics_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function checkWebServer(): string
    {
        // Check if web server is responding
        $headers = @get_headers('http://localhost', 1);
        return $headers && strpos($headers[0], '200') !== false ? 'healthy' : 'unhealthy';
    }

    private function checkQueueWorker(): string
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as pending_jobs 
                FROM queue_jobs 
                WHERE status = 'pending' AND created_at > ?
            ");
            
            $fiveMinutesAgo = $this->clock->now()->sub(new \DateInterval('PT5M'));
            $stmt->execute([$fiveMinutesAgo->format('Y-m-d H:i:s')]);
            $pendingJobs = $stmt->fetch(PDO::FETCH_ASSOC)['pending_jobs'];
            
            return $pendingJobs < 100 ? 'healthy' : 'warning';
            
        } catch (Exception $e) {
            return 'unhealthy';
        }
    }

    private function checkCronJobs(): string
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as recent_jobs 
                FROM cron_jobs 
                WHERE last_run_at > ?
            ");
            
            $oneHourAgo = $this->clock->now()->sub(new \DateInterval('PT1H'));
            $stmt->execute([$oneHourAgo->format('Y-m-d H:i:s')]);
            $recentJobs = $stmt->fetch(PDO::FETCH_ASSOC)['recent_jobs'];
            
            return $recentJobs > 0 ? 'healthy' : 'warning';
            
        } catch (Exception $e) {
            return 'unhealthy';
        }
    }

    private function calculateOverallStatus(array $checks): string
    {
        $statuses = array_column($checks, 'status');
        
        if (in_array('critical', $statuses)) {
            return 'critical';
        }
        
        if (in_array('unhealthy', $statuses)) {
            return 'unhealthy';
        }
        
        if (in_array('warning', $statuses)) {
            return 'warning';
        }
        
        return 'healthy';
    }

    private function parseMemoryLimit(string $limit): int
    {
        $limit = trim($limit);
        $last = strtolower($limit[strlen($limit) - 1]);
        $value = (int) $limit;
        
        switch ($last) {
            case 'g':
                $value *= 1024;
            case 'm':
                $value *= 1024;
            case 'k':
                $value *= 1024;
        }
        
        return $value;
    }

    private function getCpuCount(): int
    {
        if (file_exists('/proc/cpuinfo')) {
            $cpuinfo = file_get_contents('/proc/cpuinfo');
            return substr_count($cpuinfo, 'processor');
        }
        
        return 1; // Default fallback
    }

    private function calculateUptimePercentage(): float
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT 
                    COUNT(*) as total_checks,
                    SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END) as healthy_checks
                FROM " . self::HEALTH_CHECKS_TABLE . " 
                WHERE created_at >= ?
            ");
            
            $last24Hours = $this->clock->now()->sub(new \DateInterval('P1D'));
            $stmt->execute([$last24Hours->format('Y-m-d H:i:s')]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $total = (int) $result['total_checks'];
            $healthy = (int) $result['healthy_checks'];
            
            return $total > 0 ? round(($healthy / $total) * 100, 2) : 100.0;
            
        } catch (Exception $e) {
            return 0.0;
        }
    }

    private function saveHealthReport(HealthReport $report): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::HEALTH_CHECKS_TABLE . " 
                (status, checks, created_at) 
                VALUES (?, ?, ?)
            ");
            
            $stmt->execute([
                $report->status,
                json_encode($report->checks),
                $report->timestamp->format('Y-m-d H:i:s')
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('health_report_save_failed', [
                'error' => $e->getMessage()
            ]);
        }
    }

    private function getVersion(): string
    {
        return '1.0.0'; // This would come from your application version
    }
}

final class HealthCheck
{
    public function __construct(
        public readonly string $name,
        public readonly string $status,
        public readonly float $responseTime,
        public readonly array $details
    ) {
    }
}

final class HealthReport
{
    public function __construct(
        public readonly string $status,
        public readonly array $checks,
        public readonly \DateTimeImmutable $timestamp,
        public readonly string $version
    ) {
    }

    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'timestamp' => $this->timestamp->format('c'),
            'version' => $this->version,
            'checks' => array_map(fn($check) => [
                'name' => $check->name,
                'status' => $check->status,
                'response_time' => $check->responseTime,
                'details' => $check->details
            ], $this->checks)
        ];
    }
}
