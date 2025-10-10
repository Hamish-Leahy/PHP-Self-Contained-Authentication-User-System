<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use AuthKit\Contracts\SessionInterface;
use PDO;
use PDOException;
use RuntimeException;

final class SessionManager
{
    private const SESSION_TABLE = 'active_sessions';
    private const MAX_CONCURRENT_SESSIONS = 5;
    private const SESSION_TIMEOUT = 1800; // 30 minutes

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly SessionInterface $session,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function createSession(int $userId, array $deviceInfo = []): SessionInfo
    {
        $sessionId = $this->generateSessionId();
        $now = $this->clock->now();
        
        // Check concurrent session limit
        $this->enforceSessionLimit($userId);
        
        try {
            $this->storeSession($userId, $sessionId, $deviceInfo, $now);
            
            $this->logger?->info('session_created', [
                'user_id' => $userId,
                'session_id' => $sessionId,
                'device_info' => $deviceInfo
            ]);
            
            return new SessionInfo(
                sessionId: $sessionId,
                userId: $userId,
                createdAt: $now,
                lastActivity: $now,
                expiresAt: $now->add(new \DateInterval('PT' . self::SESSION_TIMEOUT . 'S')),
                deviceInfo: $deviceInfo,
                isActive: true
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('session_creation_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to create session');
        }
    }

    public function validateSession(string $sessionId): ?SessionInfo
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::SESSION_TABLE . " 
                WHERE session_id = ? AND is_active = 1 AND expires_at > ?
            ");
            
            $stmt->execute([
                $sessionId,
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            // Update last activity
            $this->updateLastActivity($sessionId);
            
            return $this->rowToSessionInfo($row);
            
        } catch (PDOException $e) {
            $this->logger?->error('session_validation_failed', [
                'session_id' => $sessionId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function destroySession(string $sessionId): bool
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::SESSION_TABLE . " 
                SET is_active = 0, destroyed_at = ? 
                WHERE session_id = ?
            ");
            
            $result = $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $sessionId
            ]);
            
            if ($result) {
                $this->logger?->info('session_destroyed', [
                    'session_id' => $sessionId
                ]);
            }
            
            return $result;
            
        } catch (PDOException $e) {
            $this->logger?->error('session_destruction_failed', [
                'session_id' => $sessionId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function destroyAllUserSessions(int $userId): int
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::SESSION_TABLE . " 
                SET is_active = 0, destroyed_at = ? 
                WHERE user_id = ? AND is_active = 1
            ");
            
            $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $userId
            ]);
            
            $count = $stmt->rowCount();
            
            $this->logger?->info('all_sessions_destroyed', [
                'user_id' => $userId,
                'count' => $count
            ]);
            
            return $count;
            
        } catch (PDOException $e) {
            $this->logger?->error('destroy_all_sessions_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function getUserSessions(int $userId): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::SESSION_TABLE . " 
                WHERE user_id = ? AND is_active = 1 
                ORDER BY last_activity_at DESC
            ");
            
            $stmt->execute([$userId]);
            $sessions = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $sessions[] = $this->rowToSessionInfo($row);
            }
            
            return $sessions;
            
        } catch (PDOException $e) {
            $this->logger?->error('get_user_sessions_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function refreshSession(string $sessionId): bool
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::SESSION_TABLE . " 
                SET last_activity_at = ?, expires_at = ? 
                WHERE session_id = ? AND is_active = 1
            ");
            
            $now = $this->clock->now();
            $newExpiry = $now->add(new \DateInterval('PT' . self::SESSION_TIMEOUT . 'S'));
            
            $result = $stmt->execute([
                $now->format('Y-m-d H:i:s'),
                $newExpiry->format('Y-m-d H:i:s'),
                $sessionId
            ]);
            
            if ($result) {
                $this->logger?->debug('session_refreshed', [
                    'session_id' => $sessionId
                ]);
            }
            
            return $result;
            
        } catch (PDOException $e) {
            $this->logger?->error('session_refresh_failed', [
                'session_id' => $sessionId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function cleanupExpiredSessions(): int
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::SESSION_TABLE . " 
                SET is_active = 0, destroyed_at = ? 
                WHERE expires_at < ? AND is_active = 1
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $count = $stmt->rowCount();
            
            if ($count > 0) {
                $this->logger?->info('expired_sessions_cleaned', [
                    'count' => $count
                ]);
            }
            
            return $count;
            
        } catch (PDOException $e) {
            $this->logger?->error('session_cleanup_failed', [
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function detectSuspiciousActivity(int $userId, array $currentDeviceInfo): array
    {
        $sessions = $this->getUserSessions($userId);
        $suspiciousFactors = [];
        
        // Check for multiple locations
        $locations = [];
        foreach ($sessions as $session) {
            $deviceInfo = $session->deviceInfo;
            if (isset($deviceInfo['country'], $deviceInfo['city'])) {
                $location = $deviceInfo['country'] . ':' . $deviceInfo['city'];
                $locations[$location] = ($locations[$location] ?? 0) + 1;
            }
        }
        
        if (count($locations) > 3) {
            $suspiciousFactors[] = 'multiple_locations';
        }
        
        // Check for rapid session creation
        $recentSessions = array_filter($sessions, function($session) {
            $timeDiff = $this->clock->now()->getTimestamp() - $session->createdAt->getTimestamp();
            return $timeDiff < 3600; // Last hour
        });
        
        if (count($recentSessions) > 5) {
            $suspiciousFactors[] = 'rapid_session_creation';
        }
        
        return [
            'is_suspicious' => !empty($suspiciousFactors),
            'factors' => $suspiciousFactors,
            'active_sessions' => count($sessions),
            'recent_sessions' => count($recentSessions)
        ];
    }

    private function enforceSessionLimit(int $userId): void
    {
        $activeSessions = $this->getUserSessions($userId);
        
        if (count($activeSessions) >= self::MAX_CONCURRENT_SESSIONS) {
            // Destroy oldest sessions
            $sessionsToDestroy = array_slice($activeSessions, self::MAX_CONCURRENT_SESSIONS - 1);
            
            foreach ($sessionsToDestroy as $session) {
                $this->destroySession($session->sessionId);
            }
            
            $this->logger?->warning('session_limit_enforced', [
                'user_id' => $userId,
                'destroyed_count' => count($sessionsToDestroy)
            ]);
        }
    }

    private function storeSession(int $userId, string $sessionId, array $deviceInfo, \DateTimeImmutable $now): void
    {
        $pdo = $this->db->pdo();
        $expiresAt = $now->add(new \DateInterval('PT' . self::SESSION_TIMEOUT . 'S'));
        
        $stmt = $pdo->prepare("
            INSERT INTO " . self::SESSION_TABLE . " 
            (user_id, session_id, device_info, created_at, last_activity_at, expires_at, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ");
        
        $stmt->execute([
            $userId,
            $sessionId,
            json_encode($deviceInfo),
            $now->format('Y-m-d H:i:s'),
            $now->format('Y-m-d H:i:s'),
            $expiresAt->format('Y-m-d H:i:s')
        ]);
    }

    private function updateLastActivity(string $sessionId): void
    {
        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare("
            UPDATE " . self::SESSION_TABLE . " 
            SET last_activity_at = ? 
            WHERE session_id = ?
        ");
        
        $stmt->execute([
            $this->clock->now()->format('Y-m-d H:i:s'),
            $sessionId
        ]);
    }

    private function generateSessionId(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function rowToSessionInfo(array $row): SessionInfo
    {
        return new SessionInfo(
            sessionId: $row['session_id'],
            userId: (int) $row['user_id'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            lastActivity: new \DateTimeImmutable($row['last_activity_at']),
            expiresAt: new \DateTimeImmutable($row['expires_at']),
            deviceInfo: json_decode($row['device_info'], true) ?? [],
            isActive: (bool) $row['is_active']
        );
    }
}

final class SessionInfo
{
    public function __construct(
        public readonly string $sessionId,
        public readonly int $userId,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $lastActivity,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly array $deviceInfo,
        public readonly bool $isActive
    ) {
    }

    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now > $this->expiresAt;
    }

    public function getTimeUntilExpiry(\DateTimeImmutable $now): int
    {
        return max(0, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }

    public function toArray(): array
    {
        return [
            'session_id' => $this->sessionId,
            'user_id' => $this->userId,
            'created_at' => $this->createdAt->format('Y-m-d H:i:s'),
            'last_activity' => $this->lastActivity->format('Y-m-d H:i:s'),
            'expires_at' => $this->expiresAt->format('Y-m-d H:i:s'),
            'device_info' => $this->deviceInfo,
            'is_active' => $this->isActive
        ];
    }
}
