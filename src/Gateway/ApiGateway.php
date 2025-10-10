<?php
declare(strict_types=1);

namespace AuthKit\Gateway;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;

final class ApiGateway
{
    private const ROUTES_TABLE = 'api_routes';
    private const CIRCUIT_BREAKER_TABLE = 'circuit_breakers';
    private const LOAD_BALANCER_TABLE = 'load_balancers';

    private const CIRCUIT_STATES = [
        'CLOSED' => 'closed',
        'OPEN' => 'open',
        'HALF_OPEN' => 'half_open'
    ];

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function registerRoute(
        string $path,
        string $method,
        string $targetUrl,
        array $options = []
    ): ApiRoute {
        $routeId = $this->generateRouteId();
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::ROUTES_TABLE . " 
                (id, path, method, target_url, options, is_active, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $routeId,
                $path,
                $method,
                $targetUrl,
                json_encode($options),
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $route = new ApiRoute(
                id: $routeId,
                path: $path,
                method: $method,
                targetUrl: $targetUrl,
                options: $options,
                isActive: true,
                createdAt: $now,
                updatedAt: $now
            );
            
            $this->logger?->info('api_route_registered', [
                'route_id' => $routeId,
                'path' => $path,
                'method' => $method,
                'target_url' => $targetUrl
            ]);
            
            return $route;
            
        } catch (PDOException $e) {
            $this->logger?->error('api_route_registration_failed', [
                'path' => $path,
                'method' => $method,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to register API route');
        }
    }

    public function routeRequest(string $path, string $method, array $requestData): GatewayResponse
    {
        $route = $this->findRoute($path, $method);
        
        if (!$route) {
            return new GatewayResponse(
                statusCode: 404,
                body: ['error' => 'Route not found'],
                headers: ['Content-Type' => 'application/json']
            );
        }
        
        // Check circuit breaker
        if ($this->isCircuitOpen($route->id)) {
            return new GatewayResponse(
                statusCode: 503,
                body: ['error' => 'Service temporarily unavailable'],
                headers: ['Content-Type' => 'application/json']
            );
        }
        
        // Load balancing
        $targetUrl = $this->selectTargetUrl($route);
        
        try {
            $response = $this->forwardRequest($targetUrl, $requestData, $route->options);
            
            // Record success
            $this->recordSuccess($route->id);
            
            return $response;
            
        } catch (RequestException $e) {
            // Record failure
            $this->recordFailure($route->id, $e->getCode());
            
            return new GatewayResponse(
                statusCode: $e->getCode() ?: 500,
                body: ['error' => 'Internal server error'],
                headers: ['Content-Type' => 'application/json']
            );
        }
    }

    public function createLoadBalancer(
        string $name,
        array $targets,
        string $algorithm = 'round_robin'
    ): LoadBalancer {
        $balancerId = $this->generateLoadBalancerId();
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::LOAD_BALANCER_TABLE . " 
                (id, name, targets, algorithm, is_active, created_at, updated_at) 
                VALUES (?, ?, ?, ?, 1, ?, ?)
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $balancerId,
                $name,
                json_encode($targets),
                $algorithm,
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $balancer = new LoadBalancer(
                id: $balancerId,
                name: $name,
                targets: $targets,
                algorithm: $algorithm,
                isActive: true,
                createdAt: $now,
                updatedAt: $now
            );
            
            $this->logger?->info('load_balancer_created', [
                'balancer_id' => $balancerId,
                'name' => $name,
                'targets_count' => count($targets)
            ]);
            
            return $balancer;
            
        } catch (PDOException $e) {
            $this->logger?->error('load_balancer_creation_failed', [
                'name' => $name,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to create load balancer');
        }
    }

    public function createCircuitBreaker(
        string $routeId,
        int $failureThreshold = 5,
        int $timeout = 60,
        int $successThreshold = 3
    ): CircuitBreaker {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::CIRCUIT_BREAKER_TABLE . " 
                (route_id, failure_threshold, timeout, success_threshold, state, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                failure_threshold = VALUES(failure_threshold),
                timeout = VALUES(timeout),
                success_threshold = VALUES(success_threshold),
                updated_at = VALUES(updated_at)
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $routeId,
                $failureThreshold,
                $timeout,
                $successThreshold,
                self::CIRCUIT_STATES['CLOSED'],
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $circuitBreaker = new CircuitBreaker(
                routeId: $routeId,
                failureThreshold: $failureThreshold,
                timeout: $timeout,
                successThreshold: $successThreshold,
                state: self::CIRCUIT_STATES['CLOSED'],
                createdAt: $now,
                updatedAt: $now
            );
            
            $this->logger?->info('circuit_breaker_created', [
                'route_id' => $routeId,
                'failure_threshold' => $failureThreshold,
                'timeout' => $timeout
            ]);
            
            return $circuitBreaker;
            
        } catch (PDOException $e) {
            $this->logger?->error('circuit_breaker_creation_failed', [
                'route_id' => $routeId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to create circuit breaker');
        }
    }

    public function getRouteMetrics(string $routeId): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Request count
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as total_requests 
                FROM api_metrics 
                WHERE route_id = ? AND created_at > ?
            ");
            $yesterday = $this->clock->now()->sub(new \DateInterval('P1D'));
            $stmt->execute([$routeId, $yesterday->format('Y-m-d H:i:s')]);
            $totalRequests = $stmt->fetch(PDO::FETCH_ASSOC)['total_requests'];
            
            // Success rate
            $stmt = $pdo->prepare("
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status_code < 400 THEN 1 ELSE 0 END) as successful
                FROM api_metrics 
                WHERE route_id = ? AND created_at > ?
            ");
            $stmt->execute([$routeId, $yesterday->format('Y-m-d H:i:s')]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $successRate = $result['total'] > 0 ? round(($result['successful'] / $result['total']) * 100, 2) : 0;
            
            // Average response time
            $stmt = $pdo->prepare("
                SELECT AVG(response_time) as avg_response_time 
                FROM api_metrics 
                WHERE route_id = ? AND created_at > ?
            ");
            $stmt->execute([$routeId, $yesterday->format('Y-m-d H:i:s')]);
            $avgResponseTime = $stmt->fetch(PDO::FETCH_ASSOC)['avg_response_time'] ?? 0;
            
            return [
                'total_requests' => (int) $totalRequests,
                'success_rate' => $successRate,
                'avg_response_time' => round($avgResponseTime, 2)
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('route_metrics_fetch_failed', [
                'route_id' => $routeId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function healthCheck(): array
    {
        $routes = $this->getAllRoutes();
        $healthStatus = [];
        
        foreach ($routes as $route) {
            $isHealthy = $this->checkRouteHealth($route);
            $healthStatus[$route->id] = [
                'route' => $route->path,
                'healthy' => $isHealthy,
                'circuit_state' => $this->getCircuitState($route->id)
            ];
        }
        
        return $healthStatus;
    }

    private function findRoute(string $path, string $method): ?ApiRoute
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::ROUTES_TABLE . " 
                WHERE path = ? AND method = ? AND is_active = 1
                ORDER BY created_at DESC
                LIMIT 1
            ");
            
            $stmt->execute([$path, $method]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $row ? $this->rowToRoute($row) : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('route_lookup_failed', [
                'path' => $path,
                'method' => $method,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function selectTargetUrl(ApiRoute $route): string
    {
        // Simple round-robin implementation
        // In production, you'd implement more sophisticated algorithms
        return $route->targetUrl;
    }

    private function forwardRequest(string $targetUrl, array $requestData, array $options): GatewayResponse
    {
        $client = new Client([
            'timeout' => $options['timeout'] ?? 30,
            'connect_timeout' => $options['connect_timeout'] ?? 10
        ]);
        
        $startTime = microtime(true);
        
        $response = $client->request(
            $requestData['method'] ?? 'GET',
            $targetUrl,
            [
                'headers' => $requestData['headers'] ?? [],
                'json' => $requestData['body'] ?? null,
                'query' => $requestData['query'] ?? []
            ]
        );
        
        $responseTime = microtime(true) - $startTime;
        
        // Record metrics
        $this->recordMetrics($requestData['route_id'] ?? '', $response->getStatusCode(), $responseTime);
        
        return new GatewayResponse(
            statusCode: $response->getStatusCode(),
            body: json_decode($response->getBody()->getContents(), true),
            headers: $response->getHeaders(),
            responseTime: $responseTime
        );
    }

    private function isCircuitOpen(string $routeId): bool
    {
        $circuitBreaker = $this->getCircuitBreaker($routeId);
        
        if (!$circuitBreaker) {
            return false;
        }
        
        if ($circuitBreaker->state === self::CIRCUIT_STATES['OPEN']) {
            // Check if timeout has passed
            $timeoutTime = $circuitBreaker->updatedAt->add(new \DateInterval('PT' . $circuitBreaker->timeout . 'S'));
            if ($this->clock->now() > $timeoutTime) {
                $this->setCircuitState($routeId, self::CIRCUIT_STATES['HALF_OPEN']);
                return false;
            }
            return true;
        }
        
        return false;
    }

    private function recordSuccess(string $routeId): void
    {
        $circuitBreaker = $this->getCircuitBreaker($routeId);
        
        if (!$circuitBreaker) {
            return;
        }
        
        if ($circuitBreaker->state === self::CIRCUIT_STATES['HALF_OPEN']) {
            $successCount = $this->getSuccessCount($routeId);
            if ($successCount >= $circuitBreaker->successThreshold) {
                $this->setCircuitState($routeId, self::CIRCUIT_STATES['CLOSED']);
                $this->resetFailureCount($routeId);
            }
        }
    }

    private function recordFailure(string $routeId, int $statusCode): void
    {
        $circuitBreaker = $this->getCircuitBreaker($routeId);
        
        if (!$circuitBreaker) {
            return;
        }
        
        $failureCount = $this->incrementFailureCount($routeId);
        
        if ($failureCount >= $circuitBreaker->failureThreshold) {
            $this->setCircuitState($routeId, self::CIRCUIT_STATES['OPEN']);
        }
    }

    private function getCircuitBreaker(string $routeId): ?CircuitBreaker
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::CIRCUIT_BREAKER_TABLE . " 
                WHERE route_id = ?
            ");
            
            $stmt->execute([$routeId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $row ? $this->rowToCircuitBreaker($row) : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('circuit_breaker_fetch_failed', [
                'route_id' => $routeId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function setCircuitState(string $routeId, string $state): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::CIRCUIT_BREAKER_TABLE . " 
                SET state = ?, updated_at = ? 
                WHERE route_id = ?
            ");
            
            $stmt->execute([
                $state,
                $this->clock->now()->format('Y-m-d H:i:s'),
                $routeId
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('circuit_state_update_failed', [
                'route_id' => $routeId,
                'state' => $state,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function incrementFailureCount(string $routeId): int
    {
        // Implementation would increment failure count in database
        return 1; // Simplified for demo
    }

    private function getSuccessCount(string $routeId): int
    {
        // Implementation would get success count from database
        return 1; // Simplified for demo
    }

    private function resetFailureCount(string $routeId): void
    {
        // Implementation would reset failure count in database
    }

    private function recordMetrics(string $routeId, int $statusCode, float $responseTime): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO api_metrics 
                (route_id, status_code, response_time, created_at) 
                VALUES (?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $routeId,
                $statusCode,
                $responseTime,
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('metrics_recording_failed', [
                'route_id' => $routeId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function checkRouteHealth(ApiRoute $route): bool
    {
        try {
            $client = new Client(['timeout' => 5]);
            $response = $client->get($route->targetUrl . '/health');
            return $response->getStatusCode() === 200;
        } catch (Exception $e) {
            return false;
        }
    }

    private function getCircuitState(string $routeId): string
    {
        $circuitBreaker = $this->getCircuitBreaker($routeId);
        return $circuitBreaker?->state ?? self::CIRCUIT_STATES['CLOSED'];
    }

    private function getAllRoutes(): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::ROUTES_TABLE . " 
                WHERE is_active = 1
            ");
            
            $stmt->execute();
            $routes = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $routes[] = $this->rowToRoute($row);
            }
            
            return $routes;
            
        } catch (PDOException $e) {
            $this->logger?->error('routes_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function rowToRoute(array $row): ApiRoute
    {
        return new ApiRoute(
            id: $row['id'],
            path: $row['path'],
            method: $row['method'],
            targetUrl: $row['target_url'],
            options: json_decode($row['options'], true),
            isActive: (bool) $row['is_active'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }

    private function rowToCircuitBreaker(array $row): CircuitBreaker
    {
        return new CircuitBreaker(
            routeId: $row['route_id'],
            failureThreshold: (int) $row['failure_threshold'],
            timeout: (int) $row['timeout'],
            successThreshold: (int) $row['success_threshold'],
            state: $row['state'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }

    private function generateRouteId(): string
    {
        return 'route_' . bin2hex(random_bytes(8));
    }

    private function generateLoadBalancerId(): string
    {
        return 'lb_' . bin2hex(random_bytes(8));
    }
}

final class ApiRoute
{
    public function __construct(
        public readonly string $id,
        public readonly string $path,
        public readonly string $method,
        public readonly string $targetUrl,
        public readonly array $options,
        public readonly bool $isActive,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }
}

final class LoadBalancer
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly array $targets,
        public readonly string $algorithm,
        public readonly bool $isActive,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }
}

final class CircuitBreaker
{
    public function __construct(
        public readonly string $routeId,
        public readonly int $failureThreshold,
        public readonly int $timeout,
        public readonly int $successThreshold,
        public readonly string $state,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }
}

final class GatewayResponse
{
    public function __construct(
        public readonly int $statusCode,
        public readonly array $body,
        public readonly array $headers,
        public readonly float $responseTime = 0.0
    ) {
    }
}
