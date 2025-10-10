<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;

final class ThreatDetector
{
    private const THREAT_TABLE = 'threat_events';
    private const ANOMALY_TABLE = 'anomaly_detection';
    private const RISK_SCORES = [
        'low' => 1,
        'medium' => 3,
        'high' => 7,
        'critical' => 10
    ];

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function analyzeRequest(array $requestData, ?int $userId = null): ThreatAnalysis
    {
        $threats = [];
        $riskScore = 0;
        $anomalies = [];

        // IP-based analysis
        $ipThreats = $this->analyzeIpAddress($requestData['ip_address'] ?? '');
        $threats = array_merge($threats, $ipThreats);

        // User agent analysis
        $uaThreats = $this->analyzeUserAgent($requestData['user_agent'] ?? '');
        $threats = array_merge($threats, $uaThreats);

        // Geographic analysis
        $geoThreats = $this->analyzeGeographicLocation($requestData);
        $threats = array_merge($threats, $geoThreats);

        // Behavioral analysis
        if ($userId) {
            $behaviorThreats = $this->analyzeBehavior($userId, $requestData);
            $threats = array_merge($threats, $behaviorThreats);
        }

        // Rate limiting analysis
        $rateThreats = $this->analyzeRateLimiting($requestData);
        $threats = array_merge($threats, $rateThreats);

        // Calculate risk score
        foreach ($threats as $threat) {
            $riskScore += $threat['risk_score'];
        }

        // Detect anomalies
        $anomalies = $this->detectAnomalies($requestData, $userId);

        $analysis = new ThreatAnalysis(
            isThreat: $riskScore >= 5,
            riskScore: min(10, $riskScore),
            threats: $threats,
            anomalies: $anomalies,
            recommendations: $this->generateRecommendations($threats, $anomalies)
        );

        // Store threat event if significant
        if ($riskScore >= 3) {
            $this->storeThreatEvent($analysis, $requestData, $userId);
        }

        $this->logger?->info('threat_analysis_completed', [
            'user_id' => $userId,
            'risk_score' => $riskScore,
            'threat_count' => count($threats),
            'anomaly_count' => count($anomalies)
        ]);

        return $analysis;
    }

    public function detectBruteForceAttack(string $identifier, string $type = 'login'): bool
    {
        $window = 900; // 15 minutes
        $maxAttempts = 10;
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempt_count 
                FROM " . self::THREAT_TABLE . " 
                WHERE identifier = ? AND threat_type = ? AND created_at > ?
            ");
            
            $windowStart = $this->clock->now()->sub(new \DateInterval('PT15M'));
            $stmt->execute([
                $identifier,
                "brute_force_{$type}",
                $windowStart->format('Y-m-d H:i:s')
            ]);
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $attemptCount = (int) $result['attempt_count'];
            
            if ($attemptCount >= $maxAttempts) {
                $this->logger?->warning('brute_force_detected', [
                    'identifier' => $identifier,
                    'type' => $type,
                    'attempts' => $attemptCount
                ]);
                return true;
            }
            
            return false;
            
        } catch (PDOException $e) {
            $this->logger?->error('brute_force_detection_failed', [
                'identifier' => $identifier,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function detectAccountTakeover(int $userId, array $requestData): bool
    {
        $suspiciousFactors = 0;
        
        // Check for unusual location
        if ($this->isUnusualLocation($userId, $requestData)) {
            $suspiciousFactors++;
        }
        
        // Check for unusual time
        if ($this->isUnusualTime($userId, $requestData)) {
            $suspiciousFactors++;
        }
        
        // Check for device change
        if ($this->isNewDevice($userId, $requestData)) {
            $suspiciousFactors++;
        }
        
        // Check for rapid password changes
        if ($this->hasRapidPasswordChanges($userId)) {
            $suspiciousFactors++;
        }
        
        $isTakeover = $suspiciousFactors >= 3;
        
        if ($isTakeover) {
            $this->logger?->critical('account_takeover_detected', [
                'user_id' => $userId,
                'suspicious_factors' => $suspiciousFactors,
                'request_data' => $requestData
            ]);
        }
        
        return $isTakeover;
    }

    public function detectDataExfiltration(int $userId, array $requestData): bool
    {
        // Check for unusual data access patterns
        $unusualAccess = $this->checkUnusualDataAccess($userId);
        
        // Check for bulk operations
        $bulkOperations = $this->checkBulkOperations($userId);
        
        // Check for API abuse
        $apiAbuse = $this->checkApiAbuse($userId, $requestData);
        
        $isExfiltration = $unusualAccess || $bulkOperations || $apiAbuse;
        
        if ($isExfiltration) {
            $this->logger?->critical('data_exfiltration_detected', [
                'user_id' => $userId,
                'unusual_access' => $unusualAccess,
                'bulk_operations' => $bulkOperations,
                'api_abuse' => $apiAbuse
            ]);
        }
        
        return $isExfiltration;
    }

    public function getThreatIntelligence(string $ipAddress): array
    {
        // In a real implementation, this would query threat intelligence feeds
        $knownThreats = [
            'malware' => false,
            'botnet' => false,
            'tor_exit' => false,
            'proxy' => false,
            'vpn' => false,
            'reputation_score' => 50
        ];
        
        // Simulate threat intelligence lookup
        if (str_starts_with($ipAddress, '192.168.') || str_starts_with($ipAddress, '10.')) {
            $knownThreats['reputation_score'] = 90; // Private IP
        } elseif (str_starts_with($ipAddress, '127.')) {
            $knownThreats['reputation_score'] = 100; // Localhost
        }
        
        return $knownThreats;
    }

    private function analyzeIpAddress(string $ipAddress): array
    {
        $threats = [];
        
        if (empty($ipAddress)) {
            return $threats;
        }
        
        // Check if IP is in known threat lists
        $threatIntel = $this->getThreatIntelligence($ipAddress);
        
        if ($threatIntel['reputation_score'] < 30) {
            $threats[] = [
                'type' => 'suspicious_ip',
                'description' => 'IP address has low reputation score',
                'risk_score' => self::RISK_SCORES['high'],
                'details' => $threatIntel
            ];
        }
        
        // Check for Tor exit nodes
        if ($threatIntel['tor_exit']) {
            $threats[] = [
                'type' => 'tor_exit_node',
                'description' => 'Request from Tor exit node',
                'risk_score' => self::RISK_SCORES['medium'],
                'details' => $threatIntel
            ];
        }
        
        // Check for VPN/Proxy usage
        if ($threatIntel['vpn'] || $threatIntel['proxy']) {
            $threats[] = [
                'type' => 'anonymizing_service',
                'description' => 'Request from VPN or proxy service',
                'risk_score' => self::RISK_SCORES['low'],
                'details' => $threatIntel
            ];
        }
        
        return $threats;
    }

    private function analyzeUserAgent(string $userAgent): array
    {
        $threats = [];
        
        if (empty($userAgent)) {
            $threats[] = [
                'type' => 'missing_user_agent',
                'description' => 'No user agent provided',
                'risk_score' => self::RISK_SCORES['medium'],
                'details' => []
            ];
            return $threats;
        }
        
        // Check for known bot user agents
        $botPatterns = [
            '/bot/i', '/crawler/i', '/spider/i', '/scraper/i',
            '/curl/i', '/wget/i', '/python/i', '/java/i'
        ];
        
        foreach ($botPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                $threats[] = [
                    'type' => 'bot_user_agent',
                    'description' => 'User agent indicates automated request',
                    'risk_score' => self::RISK_SCORES['medium'],
                    'details' => ['pattern' => $pattern, 'user_agent' => $userAgent]
                ];
                break;
            }
        }
        
        // Check for suspicious user agent patterns
        if (strlen($userAgent) < 10) {
            $threats[] = [
                'type' => 'suspicious_user_agent',
                'description' => 'User agent is unusually short',
                'risk_score' => self::RISK_SCORES['low'],
                'details' => ['user_agent' => $userAgent]
            ];
        }
        
        return $threats;
    }

    private function analyzeGeographicLocation(array $requestData): array
    {
        $threats = [];
        
        $country = $requestData['country'] ?? '';
        $city = $requestData['city'] ?? '';
        
        if (empty($country)) {
            return $threats;
        }
        
        // Check for high-risk countries
        $highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
        if (in_array($country, $highRiskCountries)) {
            $threats[] = [
                'type' => 'high_risk_country',
                'description' => "Request from high-risk country: {$country}",
                'risk_score' => self::RISK_SCORES['medium'],
                'details' => ['country' => $country, 'city' => $city]
            ];
        }
        
        // Check for impossible travel
        if (isset($requestData['previous_location'])) {
            $previous = $requestData['previous_location'];
            $distance = $this->calculateDistance(
                $previous['lat'] ?? 0,
                $previous['lon'] ?? 0,
                $requestData['lat'] ?? 0,
                $requestData['lon'] ?? 0
            );
            
            $timeDiff = $requestData['timestamp'] - ($previous['timestamp'] ?? 0);
            $maxSpeed = 1000; // km/h (commercial aircraft speed)
            $maxDistance = ($timeDiff / 3600) * $maxSpeed;
            
            if ($distance > $maxDistance) {
                $threats[] = [
                    'type' => 'impossible_travel',
                    'description' => 'Impossible travel detected',
                    'risk_score' => self::RISK_SCORES['high'],
                    'details' => [
                        'distance' => $distance,
                        'time_diff' => $timeDiff,
                        'max_distance' => $maxDistance
                    ]
                ];
            }
        }
        
        return $threats;
    }

    private function analyzeBehavior(int $userId, array $requestData): array
    {
        $threats = [];
        
        // Check for unusual login times
        $hour = (int) date('H');
        if ($hour < 6 || $hour > 22) {
            $threats[] = [
                'type' => 'unusual_login_time',
                'description' => 'Login outside normal hours',
                'risk_score' => self::RISK_SCORES['low'],
                'details' => ['hour' => $hour]
            ];
        }
        
        // Check for rapid successive requests
        $rapidRequests = $this->checkRapidRequests($userId);
        if ($rapidRequests) {
            $threats[] = [
                'type' => 'rapid_requests',
                'description' => 'Unusually rapid successive requests',
                'risk_score' => self::RISK_SCORES['medium'],
                'details' => ['request_count' => $rapidRequests]
            ];
        }
        
        return $threats;
    }

    private function analyzeRateLimiting(array $requestData): array
    {
        $threats = [];
        
        // This would integrate with your rate limiting system
        // For now, we'll simulate some checks
        
        return $threats;
    }

    private function detectAnomalies(array $requestData, ?int $userId): array
    {
        $anomalies = [];
        
        // Check for unusual request patterns
        if ($this->isUnusualRequestPattern($requestData)) {
            $anomalies[] = [
                'type' => 'unusual_request_pattern',
                'description' => 'Request pattern deviates from normal behavior',
                'severity' => 'medium'
            ];
        }
        
        // Check for data anomalies
        if ($this->hasDataAnomalies($requestData)) {
            $anomalies[] = [
                'type' => 'data_anomaly',
                'description' => 'Request contains anomalous data',
                'severity' => 'low'
            ];
        }
        
        return $anomalies;
    }

    private function generateRecommendations(array $threats, array $anomalies): array
    {
        $recommendations = [];
        
        foreach ($threats as $threat) {
            switch ($threat['type']) {
                case 'suspicious_ip':
                    $recommendations[] = 'Block IP address or require additional verification';
                    break;
                case 'bot_user_agent':
                    $recommendations[] = 'Implement CAPTCHA or rate limiting';
                    break;
                case 'impossible_travel':
                    $recommendations[] = 'Require additional authentication or notify user';
                    break;
                case 'rapid_requests':
                    $recommendations[] = 'Implement stricter rate limiting';
                    break;
            }
        }
        
        return array_unique($recommendations);
    }

    private function storeThreatEvent(ThreatAnalysis $analysis, array $requestData, ?int $userId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::THREAT_TABLE . " 
                (user_id, threat_type, risk_score, description, request_data, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $userId,
                'threat_analysis',
                $analysis->riskScore,
                json_encode($analysis->threats),
                json_encode($requestData),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('threat_event_storage_failed', [
                'error' => $e->getMessage(),
                'user_id' => $userId
            ]);
        }
    }

    private function isUnusualLocation(int $userId, array $requestData): bool
    {
        // Implementation would check against user's historical locations
        return false;
    }

    private function isUnusualTime(int $userId, array $requestData): bool
    {
        // Implementation would check against user's historical login times
        return false;
    }

    private function isNewDevice(int $userId, array $requestData): bool
    {
        // Implementation would check against user's known devices
        return false;
    }

    private function hasRapidPasswordChanges(int $userId): bool
    {
        // Implementation would check password change history
        return false;
    }

    private function checkUnusualDataAccess(int $userId): bool
    {
        // Implementation would check data access patterns
        return false;
    }

    private function checkBulkOperations(int $userId): bool
    {
        // Implementation would check for bulk operations
        return false;
    }

    private function checkApiAbuse(int $userId, array $requestData): bool
    {
        // Implementation would check API usage patterns
        return false;
    }

    private function checkRapidRequests(int $userId): int
    {
        // Implementation would check request frequency
        return 0;
    }

    private function isUnusualRequestPattern(array $requestData): bool
    {
        // Implementation would analyze request patterns
        return false;
    }

    private function hasDataAnomalies(array $requestData): bool
    {
        // Implementation would check for data anomalies
        return false;
    }

    private function calculateDistance(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $earthRadius = 6371; // km
        
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        
        $a = sin($dLat/2) * sin($dLat/2) + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon/2) * sin($dLon/2);
        $c = 2 * atan2(sqrt($a), sqrt(1-$a));
        
        return $earthRadius * $c;
    }
}

final class ThreatAnalysis
{
    public function __construct(
        public readonly bool $isThreat,
        public readonly int $riskScore,
        public readonly array $threats,
        public readonly array $anomalies,
        public readonly array $recommendations
    ) {
    }

    public function getRiskLevel(): string
    {
        if ($this->riskScore >= 8) return 'critical';
        if ($this->riskScore >= 6) return 'high';
        if ($this->riskScore >= 4) return 'medium';
        if ($this->riskScore >= 2) return 'low';
        return 'minimal';
    }

    public function toArray(): array
    {
        return [
            'is_threat' => $this->isThreat,
            'risk_score' => $this->riskScore,
            'risk_level' => $this->getRiskLevel(),
            'threats' => $this->threats,
            'anomalies' => $this->anomalies,
            'recommendations' => $this->recommendations
        ];
    }
}
