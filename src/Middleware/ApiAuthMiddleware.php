<?php
declare(strict_types=1);

namespace AuthKit\Middleware;

use AuthKit\Contracts\JwtSignerInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\UserRepositoryInterface;
use AuthKit\Domain\Entity\User;
use InvalidArgumentException;
use RuntimeException;

final class ApiAuthMiddleware
{
    private const BEARER_PREFIX = 'Bearer ';
    private const API_KEY_HEADER = 'X-API-Key';
    private const API_SECRET_HEADER = 'X-API-Secret';

    public function __construct(
        private readonly ?JwtSignerInterface $jwtSigner,
        private readonly UserRepositoryInterface $userRepository,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function authenticate(array $headers, array $queryParams = []): AuthResult
    {
        try {
            // Try JWT authentication first
            if ($this->jwtSigner) {
                $jwtResult = $this->authenticateJwt($headers);
                if ($jwtResult->isValid()) {
                    return $jwtResult;
                }
            }

            // Try API key authentication
            $apiKeyResult = $this->authenticateApiKey($headers);
            if ($apiKeyResult->isValid()) {
                return $apiKeyResult;
            }

            // Try session-based authentication
            $sessionResult = $this->authenticateSession($headers);
            if ($sessionResult->isValid()) {
                return $sessionResult;
            }

            return AuthResult::invalid('No valid authentication method found');

        } catch (Exception $e) {
            $this->logger?->error('api_auth_error', [
                'error' => $e->getMessage(),
                'headers' => $this->sanitizeHeaders($headers)
            ]);
            
            return AuthResult::invalid('Authentication error: ' . $e->getMessage());
        }
    }

    private function authenticateJwt(array $headers): AuthResult
    {
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        
        if (!str_starts_with($authHeader, self::BEARER_PREFIX)) {
            return AuthResult::invalid('Missing or invalid Bearer token');
        }

        $token = substr($authHeader, strlen(self::BEARER_PREFIX));
        
        try {
            $payload = $this->jwtSigner->verify($token);
            
            if (!$payload || !isset($payload['sub'])) {
                return AuthResult::invalid('Invalid JWT payload');
            }

            $userId = (int) $payload['sub'];
            $user = $this->userRepository->findById($userId);
            
            if (!$user) {
                return AuthResult::invalid('User not found');
            }

            if ($user->lockedUntil && $this->clock->now() < $user->lockedUntil) {
                return AuthResult::invalid('Account locked');
            }

            return AuthResult::valid($user, 'jwt', [
                'jwt_payload' => $payload,
                'expires_at' => $payload['exp'] ?? null,
                'issued_at' => $payload['iat'] ?? null
            ]);

        } catch (Exception $e) {
            $this->logger?->warning('jwt_verification_failed', [
                'error' => $e->getMessage(),
                'token_prefix' => substr($token, 0, 10) . '...'
            ]);
            
            return AuthResult::invalid('JWT verification failed');
        }
    }

    private function authenticateApiKey(array $headers): AuthResult
    {
        $apiKey = $headers[self::API_KEY_HEADER] ?? $headers['x-api-key'] ?? '';
        $apiSecret = $headers[self::API_SECRET_HEADER] ?? $headers['x-api-secret'] ?? '';
        
        if (empty($apiKey)) {
            return AuthResult::invalid('Missing API key');
        }

        // In a real implementation, you'd validate against stored API keys
        // For now, we'll use a simple validation approach
        $user = $this->validateApiCredentials($apiKey, $apiSecret);
        
        if (!$user) {
            $this->logger?->warning('invalid_api_key', [
                'api_key_prefix' => substr($apiKey, 0, 8) . '...'
            ]);
            return AuthResult::invalid('Invalid API credentials');
        }

        return AuthResult::valid($user, 'api_key', [
            'api_key' => $apiKey,
            'authenticated_at' => $this->clock->now()
        ]);
    }

    private function authenticateSession(array $headers): AuthResult
    {
        $sessionId = $headers['X-Session-ID'] ?? $headers['x-session-id'] ?? '';
        
        if (empty($sessionId)) {
            return AuthResult::invalid('Missing session ID');
        }

        // Validate session and get user
        $user = $this->validateSession($sessionId);
        
        if (!$user) {
            return AuthResult::invalid('Invalid or expired session');
        }

        return AuthResult::valid($user, 'session', [
            'session_id' => $sessionId,
            'authenticated_at' => $this->clock->now()
        ]);
    }

    private function validateApiCredentials(string $apiKey, string $apiSecret): ?User
    {
        // This is a simplified implementation
        // In production, you'd have an API keys table and proper validation
        if ($apiKey === 'demo_key' && $apiSecret === 'demo_secret') {
            // Return a demo user or fetch from database
            return $this->userRepository->findById(1);
        }
        
        return null;
    }

    private function validateSession(string $sessionId): ?User
    {
        // This is a simplified implementation
        // In production, you'd validate against your session store
        if (strlen($sessionId) === 40) { // Assuming 40-char session ID
            // Validate session and return user
            return $this->userRepository->findById(1);
        }
        
        return null;
    }

    private function sanitizeHeaders(array $headers): array
    {
        $sensitive = ['authorization', 'x-api-key', 'x-api-secret', 'cookie'];
        $sanitized = [];
        
        foreach ($headers as $key => $value) {
            $lowerKey = strtolower($key);
            if (in_array($lowerKey, $sensitive)) {
                $sanitized[$key] = '[REDACTED]';
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }

    public function requireRole(User $user, string $requiredRole): bool
    {
        // This would check user roles in a real implementation
        // For now, return true for demo purposes
        return true;
    }

    public function requirePermission(User $user, string $permission): bool
    {
        // This would check user permissions in a real implementation
        // For now, return true for demo purposes
        return true;
    }
}

final class AuthResult
{
    public function __construct(
        private readonly bool $valid,
        private readonly ?User $user = null,
        private readonly string $method = '',
        private readonly string $error = '',
        private readonly array $metadata = []
    ) {
    }

    public static function valid(User $user, string $method, array $metadata = []): self
    {
        return new self(true, $user, $method, '', $metadata);
    }

    public static function invalid(string $error): self
    {
        return new self(false, null, '', $error);
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'user_id' => $this->user?->id,
            'method' => $this->method,
            'error' => $this->error,
            'metadata' => $this->metadata
        ];
    }
}
