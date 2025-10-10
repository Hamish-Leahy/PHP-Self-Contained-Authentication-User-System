<?php
declare(strict_types=1);

namespace AuthKit\Middleware;

use AuthKit\Contracts\LoggerInterface;
use AuthKit\Contracts\ClockInterface;

final class RequestLogger
{
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly ClockInterface $clock,
        private readonly array $config = []
    ) {
    }

    public function logRequest(array $requestData): void
    {
        $logData = $this->buildLogData($requestData);
        
        $this->logger->info('request_received', $logData);
        
        // Log to different levels based on configuration
        if ($this->shouldLogDetailed($requestData)) {
            $this->logger->debug('request_detailed', array_merge($logData, [
                'headers' => $this->sanitizeHeaders($requestData['headers'] ?? []),
                'body' => $this->sanitizeBody($requestData['body'] ?? ''),
                'query_params' => $requestData['query_params'] ?? []
            ]));
        }
    }

    public function logResponse(array $responseData, array $requestData): void
    {
        $logData = $this->buildResponseLogData($responseData, $requestData);
        
        $this->logger->info('response_sent', $logData);
    }

    public function logError(\Throwable $error, array $requestData): void
    {
        $logData = [
            'error_type' => get_class($error),
            'error_message' => $error->getMessage(),
            'error_code' => $error->getCode(),
            'file' => $error->getFile(),
            'line' => $error->getLine(),
            'trace' => $this->formatStackTrace($error->getTrace()),
            'request_id' => $requestData['request_id'] ?? null,
            'user_id' => $requestData['user_id'] ?? null,
            'ip_address' => $requestData['ip_address'] ?? null,
            'user_agent' => $requestData['user_agent'] ?? null,
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s')
        ];
        
        $this->logger->error('request_error', $logData);
    }

    public function logSecurityEvent(string $event, array $context = []): void
    {
        $logData = array_merge($context, [
            'event_type' => 'security',
            'event_name' => $event,
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s'),
            'severity' => $this->getEventSeverity($event)
        ]);
        
        $this->logger->warning('security_event', $logData);
    }

    public function logPerformanceMetrics(array $metrics): void
    {
        $logData = array_merge($metrics, [
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s'),
            'event_type' => 'performance'
        ]);
        
        $this->logger->info('performance_metrics', $logData);
    }

    private function buildLogData(array $requestData): array
    {
        return [
            'request_id' => $requestData['request_id'] ?? $this->generateRequestId(),
            'method' => $requestData['method'] ?? $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN',
            'uri' => $requestData['uri'] ?? $_SERVER['REQUEST_URI'] ?? '/',
            'ip_address' => $requestData['ip_address'] ?? $this->getClientIp(),
            'user_agent' => $requestData['user_agent'] ?? $_SERVER['HTTP_USER_AGENT'] ?? '',
            'user_id' => $requestData['user_id'] ?? null,
            'session_id' => $requestData['session_id'] ?? session_id(),
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s'),
            'content_length' => $requestData['content_length'] ?? $_SERVER['CONTENT_LENGTH'] ?? 0,
            'content_type' => $requestData['content_type'] ?? $_SERVER['CONTENT_TYPE'] ?? '',
            'referer' => $requestData['referer'] ?? $_SERVER['HTTP_REFERER'] ?? null,
            'accept_language' => $requestData['accept_language'] ?? $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null
        ];
    }

    private function buildResponseLogData(array $responseData, array $requestData): array
    {
        return [
            'request_id' => $requestData['request_id'] ?? null,
            'status_code' => $responseData['status_code'] ?? 200,
            'response_time' => $responseData['response_time'] ?? 0,
            'memory_usage' => $responseData['memory_usage'] ?? memory_get_usage(true),
            'peak_memory' => $responseData['peak_memory'] ?? memory_get_peak_usage(true),
            'content_length' => $responseData['content_length'] ?? 0,
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s')
        ];
    }

    private function shouldLogDetailed(array $requestData): bool
    {
        $logLevel = $this->config['log_level'] ?? 'info';
        
        if ($logLevel === 'debug') {
            return true;
        }
        
        // Log detailed for sensitive endpoints
        $sensitiveEndpoints = $this->config['sensitive_endpoints'] ?? ['/auth', '/admin', '/api'];
        $uri = $requestData['uri'] ?? $_SERVER['REQUEST_URI'] ?? '';
        
        foreach ($sensitiveEndpoints as $endpoint) {
            if (str_starts_with($uri, $endpoint)) {
                return true;
            }
        }
        
        return false;
    }

    private function sanitizeHeaders(array $headers): array
    {
        $sensitiveHeaders = [
            'authorization', 'cookie', 'x-api-key', 'x-api-secret',
            'x-csrf-token', 'x-auth-token', 'x-session-id'
        ];
        
        $sanitized = [];
        
        foreach ($headers as $name => $value) {
            $lowerName = strtolower($name);
            
            if (in_array($lowerName, $sensitiveHeaders)) {
                $sanitized[$name] = '[REDACTED]';
            } else {
                $sanitized[$name] = $value;
            }
        }
        
        return $sanitized;
    }

    private function sanitizeBody(string $body): string
    {
        if (empty($body)) {
            return $body;
        }
        
        // Check if body contains sensitive data
        $sensitivePatterns = [
            '/password["\']?\s*[:=]\s*["\']?[^"\']+["\']?/i',
            '/token["\']?\s*[:=]\s*["\']?[^"\']+["\']?/i',
            '/secret["\']?\s*[:=]\s*["\']?[^"\']+["\']?/i',
            '/key["\']?\s*[:=]\s*["\']?[^"\']+["\']?/i'
        ];
        
        $sanitized = $body;
        
        foreach ($sensitivePatterns as $pattern) {
            $sanitized = preg_replace($pattern, '[REDACTED]', $sanitized);
        }
        
        return $sanitized;
    }

    private function formatStackTrace(array $trace): array
    {
        $formatted = [];
        
        foreach ($trace as $index => $frame) {
            $formatted[] = [
                'index' => $index,
                'file' => $frame['file'] ?? 'unknown',
                'line' => $frame['line'] ?? 0,
                'function' => $frame['function'] ?? 'unknown',
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? null
            ];
        }
        
        return $formatted;
    }

    private function getEventSeverity(string $event): string
    {
        $criticalEvents = [
            'account_compromise', 'data_breach', 'privilege_escalation',
            'unauthorized_access', 'malicious_activity'
        ];
        
        $highEvents = [
            'failed_login_brute_force', 'suspicious_activity', 'rate_limit_exceeded',
            'invalid_credentials', 'session_hijack'
        ];
        
        if (in_array($event, $criticalEvents)) {
            return 'critical';
        } elseif (in_array($event, $highEvents)) {
            return 'high';
        }
        
        return 'medium';
    }

    private function generateRequestId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function getClientIp(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function logDatabaseQuery(string $query, array $params = [], float $executionTime = 0): void
    {
        $logData = [
            'query_type' => 'database',
            'query' => $this->sanitizeQuery($query),
            'params' => $this->sanitizeParams($params),
            'execution_time' => $executionTime,
            'timestamp' => $this->clock->now()->format('Y-m-d H:i:s')
        ];
        
        $this->logger->debug('database_query', $logData);
    }

    private function sanitizeQuery(string $query): string
    {
        // Remove sensitive data from queries
        $sensitivePatterns = [
            '/password\s*=\s*["\']?[^"\']+["\']?/i',
            '/token\s*=\s*["\']?[^"\']+["\']?/i',
            '/secret\s*=\s*["\']?[^"\']+["\']?/i'
        ];
        
        $sanitized = $query;
        
        foreach ($sensitivePatterns as $pattern) {
            $sanitized = preg_replace($pattern, '[REDACTED]', $sanitized);
        }
        
        return $sanitized;
    }

    private function sanitizeParams(array $params): array
    {
        $sensitiveKeys = ['password', 'token', 'secret', 'key', 'hash'];
        $sanitized = [];
        
        foreach ($params as $key => $value) {
            $lowerKey = strtolower($key);
            $isSensitive = false;
            
            foreach ($sensitiveKeys as $sensitiveKey) {
                if (str_contains($lowerKey, $sensitiveKey)) {
                    $isSensitive = true;
                    break;
                }
            }
            
            $sanitized[$key] = $isSensitive ? '[REDACTED]' : $value;
        }
        
        return $sanitized;
    }
}
