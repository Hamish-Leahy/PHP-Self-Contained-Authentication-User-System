<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;

final class DeviceTracker
{
    private const DEVICE_TABLE = 'user_devices';
    private const FINGERPRINT_TABLE = 'device_fingerprints';

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function trackDevice(int $userId, array $requestData): DeviceInfo
    {
        $fingerprint = $this->generateFingerprint($requestData);
        $deviceInfo = $this->createDeviceInfo($requestData, $fingerprint);
        
        try {
            $this->storeDeviceInfo($userId, $deviceInfo);
            $this->logger?->info('device_tracked', [
                'user_id' => $userId,
                'device_id' => $deviceInfo->deviceId,
                'fingerprint' => $fingerprint
            ]);
        } catch (PDOException $e) {
            $this->logger?->error('device_tracking_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to track device');
        }

        return $deviceInfo;
    }

    public function identifyDevice(int $userId, array $requestData): ?DeviceInfo
    {
        $fingerprint = $this->generateFingerprint($requestData);
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT d.*, f.fingerprint_data 
                FROM " . self::DEVICE_TABLE . " d
                JOIN " . self::FINGERPRINT_TABLE . " f ON d.fingerprint_id = f.id
                WHERE d.user_id = ? AND f.fingerprint_hash = ?
                AND d.is_active = 1
                ORDER BY d.last_seen_at DESC
                LIMIT 1
            ");
            
            $stmt->execute([$userId, $fingerprint]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($row) {
                $this->updateLastSeen($row['id']);
                return $this->rowToDeviceInfo($row);
            }
            
            return null;
            
        } catch (PDOException $e) {
            $this->logger?->error('device_identification_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function getKnownDevices(int $userId): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT d.*, f.fingerprint_data 
                FROM " . self::DEVICE_TABLE . " d
                JOIN " . self::FINGERPRINT_TABLE . " f ON d.fingerprint_id = f.id
                WHERE d.user_id = ? AND d.is_active = 1
                ORDER BY d.last_seen_at DESC
            ");
            
            $stmt->execute([$userId]);
            $devices = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $devices[] = $this->rowToDeviceInfo($row);
            }
            
            return $devices;
            
        } catch (PDOException $e) {
            $this->logger?->error('get_devices_failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function revokeDevice(int $userId, string $deviceId): bool
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::DEVICE_TABLE . " 
                SET is_active = 0, revoked_at = ? 
                WHERE user_id = ? AND device_id = ?
            ");
            
            $result = $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $userId,
                $deviceId
            ]);
            
            if ($result) {
                $this->logger?->info('device_revoked', [
                    'user_id' => $userId,
                    'device_id' => $deviceId
                ]);
            }
            
            return $result;
            
        } catch (PDOException $e) {
            $this->logger?->error('device_revocation_failed', [
                'user_id' => $userId,
                'device_id' => $deviceId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function detectSuspiciousActivity(int $userId, array $requestData): array
    {
        $currentDevice = $this->identifyDevice($userId, $requestData);
        $knownDevices = $this->getKnownDevices($userId);
        
        $suspiciousFactors = [];
        
        if (!$currentDevice) {
            $suspiciousFactors[] = 'unknown_device';
        }
        
        if ($currentDevice) {
            $locationChanged = $this->checkLocationChange($currentDevice, $requestData);
            if ($locationChanged) {
                $suspiciousFactors[] = 'location_change';
            }
            
            $timeAnomaly = $this->checkTimeAnomaly($currentDevice, $requestData);
            if ($timeAnomaly) {
                $suspiciousFactors[] = 'time_anomaly';
            }
        }
        
        $riskScore = $this->calculateRiskScore($suspiciousFactors);
        
        return [
            'is_suspicious' => $riskScore > 0.5,
            'risk_score' => $riskScore,
            'factors' => $suspiciousFactors,
            'device_info' => $currentDevice
        ];
    }

    private function generateFingerprint(array $requestData): string
    {
        $components = [
            'user_agent' => $requestData['user_agent'] ?? '',
            'accept_language' => $requestData['accept_language'] ?? '',
            'accept_encoding' => $requestData['accept_encoding'] ?? '',
            'screen_resolution' => $requestData['screen_resolution'] ?? '',
            'timezone' => $requestData['timezone'] ?? '',
            'platform' => $requestData['platform'] ?? '',
            'cookie_enabled' => $requestData['cookie_enabled'] ?? false,
            'do_not_track' => $requestData['do_not_track'] ?? false
        ];
        
        $fingerprintString = json_encode($components, JSON_SORT_KEYS);
        return hash('sha256', $fingerprintString);
    }

    private function createDeviceInfo(array $requestData, string $fingerprint): DeviceInfo
    {
        return new DeviceInfo(
            deviceId: bin2hex(random_bytes(16)),
            fingerprint: $fingerprint,
            userAgent: $requestData['user_agent'] ?? '',
            ipAddress: $requestData['ip_address'] ?? '',
            country: $requestData['country'] ?? '',
            city: $requestData['city'] ?? '',
            browser: $this->detectBrowser($requestData['user_agent'] ?? ''),
            os: $this->detectOS($requestData['user_agent'] ?? ''),
            isMobile: $this->isMobile($requestData['user_agent'] ?? ''),
            firstSeen: $this->clock->now(),
            lastSeen: $this->clock->now()
        );
    }

    private function storeDeviceInfo(int $userId, DeviceInfo $deviceInfo): void
    {
        $pdo = $this->db->pdo();
        
        // Store fingerprint
        $pdo->beginTransaction();
        
        try {
            $stmt = $pdo->prepare("
                INSERT INTO " . self::FINGERPRINT_TABLE . " 
                (fingerprint_hash, fingerprint_data, created_at) 
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE fingerprint_data = VALUES(fingerprint_data)
            ");
            
            $stmt->execute([
                $deviceInfo->fingerprint,
                json_encode($deviceInfo->toArray()),
                $deviceInfo->firstSeen->format('Y-m-d H:i:s')
            ]);
            
            $fingerprintId = $pdo->lastInsertId();
            
            // Store device
            $stmt = $pdo->prepare("
                INSERT INTO " . self::DEVICE_TABLE . " 
                (user_id, device_id, fingerprint_id, user_agent, ip_address, 
                 country, city, browser, os, is_mobile, first_seen_at, last_seen_at, is_active) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ");
            
            $stmt->execute([
                $userId,
                $deviceInfo->deviceId,
                $fingerprintId,
                $deviceInfo->userAgent,
                $deviceInfo->ipAddress,
                $deviceInfo->country,
                $deviceInfo->city,
                $deviceInfo->browser,
                $deviceInfo->os,
                $deviceInfo->isMobile ? 1 : 0,
                $deviceInfo->firstSeen->format('Y-m-d H:i:s'),
                $deviceInfo->lastSeen->format('Y-m-d H:i:s')
            ]);
            
            $pdo->commit();
            
        } catch (Exception $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    private function updateLastSeen(int $deviceId): void
    {
        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare("
            UPDATE " . self::DEVICE_TABLE . " 
            SET last_seen_at = ? 
            WHERE id = ?
        ");
        
        $stmt->execute([
            $this->clock->now()->format('Y-m-d H:i:s'),
            $deviceId
        ]);
    }

    private function rowToDeviceInfo(array $row): DeviceInfo
    {
        return new DeviceInfo(
            deviceId: $row['device_id'],
            fingerprint: $row['fingerprint_hash'],
            userAgent: $row['user_agent'],
            ipAddress: $row['ip_address'],
            country: $row['country'],
            city: $row['city'],
            browser: $row['browser'],
            os: $row['os'],
            isMobile: (bool) $row['is_mobile'],
            firstSeen: new \DateTimeImmutable($row['first_seen_at']),
            lastSeen: new \DateTimeImmutable($row['last_seen_at'])
        );
    }

    private function checkLocationChange(DeviceInfo $device, array $requestData): bool
    {
        $currentCountry = $requestData['country'] ?? '';
        $currentCity = $requestData['city'] ?? '';
        
        return $device->country !== $currentCountry || $device->city !== $currentCity;
    }

    private function checkTimeAnomaly(DeviceInfo $device, array $requestData): bool
    {
        $lastSeen = $device->lastSeen;
        $now = $this->clock->now();
        $timeDiff = $now->getTimestamp() - $lastSeen->getTimestamp();
        
        // Consider it anomalous if last seen was more than 24 hours ago
        return $timeDiff > 86400;
    }

    private function calculateRiskScore(array $factors): float
    {
        $weights = [
            'unknown_device' => 0.8,
            'location_change' => 0.6,
            'time_anomaly' => 0.4
        ];
        
        $score = 0.0;
        foreach ($factors as $factor) {
            $score += $weights[$factor] ?? 0.1;
        }
        
        return min(1.0, $score);
    }

    private function detectBrowser(string $userAgent): string
    {
        if (str_contains($userAgent, 'Chrome')) return 'Chrome';
        if (str_contains($userAgent, 'Firefox')) return 'Firefox';
        if (str_contains($userAgent, 'Safari')) return 'Safari';
        if (str_contains($userAgent, 'Edge')) return 'Edge';
        return 'Unknown';
    }

    private function detectOS(string $userAgent): string
    {
        if (str_contains($userAgent, 'Windows')) return 'Windows';
        if (str_contains($userAgent, 'Mac OS')) return 'macOS';
        if (str_contains($userAgent, 'Linux')) return 'Linux';
        if (str_contains($userAgent, 'Android')) return 'Android';
        if (str_contains($userAgent, 'iOS')) return 'iOS';
        return 'Unknown';
    }

    private function isMobile(string $userAgent): bool
    {
        $mobileKeywords = ['Mobile', 'Android', 'iPhone', 'iPad', 'BlackBerry', 'Windows Phone'];
        
        foreach ($mobileKeywords as $keyword) {
            if (str_contains($userAgent, $keyword)) {
                return true;
            }
        }
        
        return false;
    }
}

final class DeviceInfo
{
    public function __construct(
        public readonly string $deviceId,
        public readonly string $fingerprint,
        public readonly string $userAgent,
        public readonly string $ipAddress,
        public readonly string $country,
        public readonly string $city,
        public readonly string $browser,
        public readonly string $os,
        public readonly bool $isMobile,
        public readonly \DateTimeImmutable $firstSeen,
        public readonly \DateTimeImmutable $lastSeen
    ) {
    }

    public function toArray(): array
    {
        return [
            'device_id' => $this->deviceId,
            'fingerprint' => $this->fingerprint,
            'user_agent' => $this->userAgent,
            'ip_address' => $this->ipAddress,
            'country' => $this->country,
            'city' => $this->city,
            'browser' => $this->browser,
            'os' => $this->os,
            'is_mobile' => $this->isMobile,
            'first_seen' => $this->firstSeen->format('Y-m-d H:i:s'),
            'last_seen' => $this->lastSeen->format('Y-m-d H:i:s')
        ];
    }
}
