<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\LoggerInterface;
use AuthKit\Contracts\ClockInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;

final class AuditLogger implements LoggerInterface
{
    private const AUDIT_TABLE = 'audit_logs';
    private const MAX_BATCH_SIZE = 100;
    
    private array $logBuffer = [];
    private int $bufferSize = 0;

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $fallbackLogger = null
    ) {
    }

    public function emergency(string $message, array $context = []): void
    {
        $this->log('emergency', $message, $context);
    }

    public function alert(string $message, array $context = []): void
    {
        $this->log('alert', $message, $context);
    }

    public function critical(string $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    public function notice(string $message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    public function log(string $level, string $message, array $context = []): void
    {
        $this->addToBuffer($level, $message, $context);
        
        if ($this->bufferSize >= self::MAX_BATCH_SIZE) {
            $this->flush();
        }
    }

    private function addToBuffer(string $level, string $message, array $context): void
    {
        $this->logBuffer[] = [
            'level' => $level,
            'message' => $message,
            'context' => $this->sanitizeContext($context),
            'timestamp' => $this->clock->now(),
            'ip_address' => $this->getClientIp(),
            'user_agent' => $this->getUserAgent(),
            'session_id' => $this->getSessionId(),
            'user_id' => $context['user_id'] ?? null,
            'request_id' => $this->getRequestId()
        ];
        
        $this->bufferSize++;
    }

    public function flush(): void
    {
        if (empty($this->logBuffer)) {
            return;
        }

        try {
            $this->insertBatch($this->logBuffer);
            $this->logBuffer = [];
            $this->bufferSize = 0;
        } catch (PDOException $e) {
            $this->fallbackLogger?->error('audit_log_insert_failed', [
                'error' => $e->getMessage(),
                'batch_size' => count($this->logBuffer)
            ]);
            
            // Reset buffer to prevent memory issues
            $this->logBuffer = [];
            $this->bufferSize = 0;
        }
    }

    private function insertBatch(array $logs): void
    {
        $pdo = $this->db->pdo();
        
        $sql = "INSERT INTO " . self::AUDIT_TABLE . " 
                (level, message, context, timestamp, ip_address, user_agent, session_id, user_id, request_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $pdo->prepare($sql);
        
        foreach ($logs as $log) {
            $stmt->execute([
                $log['level'],
                $log['message'],
                json_encode($log['context']),
                $log['timestamp']->format('Y-m-d H:i:s'),
                $log['ip_address'],
                $log['user_agent'],
                $log['session_id'],
                $log['user_id'],
                $log['request_id']
            ]);
        }
    }

    private function sanitizeContext(array $context): array
    {
        $sensitive = ['password', 'token', 'secret', 'key', 'hash'];
        $sanitized = [];
        
        foreach ($context as $key => $value) {
            $lowerKey = strtolower($key);
            $isSensitive = false;
            
            foreach ($sensitive as $sensitiveKey) {
                if (str_contains($lowerKey, $sensitiveKey)) {
                    $isSensitive = true;
                    break;
                }
            }
            
            if ($isSensitive) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value) || is_object($value)) {
                $sanitized[$key] = json_encode($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }

    private function getClientIp(): ?string
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
        
        return $_SERVER['REMOTE_ADDR'] ?? null;
    }

    private function getUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }

    private function getSessionId(): ?string
    {
        return session_id() ?: null;
    }

    private function getRequestId(): string
    {
        static $requestId = null;
        
        if ($requestId === null) {
            $requestId = bin2hex(random_bytes(16));
        }
        
        return $requestId;
    }

    public function logSecurityEvent(string $event, array $context = []): void
    {
        $this->warning("security_event: {$event}", array_merge($context, [
            'event_type' => 'security',
            'severity' => $this->getSecuritySeverity($event)
        ]));
    }

    private function getSecuritySeverity(string $event): string
    {
        $criticalEvents = [
            'account_compromise',
            'privilege_escalation',
            'data_breach',
            'admin_access'
        ];
        
        $highEvents = [
            'failed_login_brute_force',
            'suspicious_activity',
            'unusual_location',
            'password_breach'
        ];
        
        if (in_array($event, $criticalEvents)) {
            return 'critical';
        } elseif (in_array($event, $highEvents)) {
            return 'high';
        }
        
        return 'medium';
    }

    public function __destruct()
    {
        $this->flush();
    }
}
