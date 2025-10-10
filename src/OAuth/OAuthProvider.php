<?php
declare(strict_types=1);

namespace AuthKit\OAuth;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use AuthKit\Contracts\UserRepositoryInterface;
use PDO;
use PDOException;
use RuntimeException;

final class OAuthProvider
{
    private const CLIENTS_TABLE = 'oauth_clients';
    private const CODES_TABLE = 'oauth_authorization_codes';
    private const TOKENS_TABLE = 'oauth_access_tokens';
    private const REFRESH_TABLE = 'oauth_refresh_tokens';

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly UserRepositoryInterface $userRepository,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function registerClient(string $name, string $redirectUri, array $scopes = []): OAuthClient
    {
        $clientId = $this->generateClientId();
        $clientSecret = $this->generateClientSecret();
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::CLIENTS_TABLE . " 
                (client_id, client_secret, name, redirect_uri, scopes, is_active, created_at) 
                VALUES (?, ?, ?, ?, ?, 1, ?)
            ");
            
            $stmt->execute([
                $clientId,
                password_hash($clientSecret, PASSWORD_DEFAULT),
                $name,
                $redirectUri,
                json_encode($scopes),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            $this->logger?->info('oauth_client_registered', [
                'client_id' => $clientId,
                'name' => $name,
                'redirect_uri' => $redirectUri
            ]);
            
            return new OAuthClient(
                clientId: $clientId,
                clientSecret: $clientSecret,
                name: $name,
                redirectUri: $redirectUri,
                scopes: $scopes,
                isActive: true,
                createdAt: $this->clock->now()
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_client_registration_failed', [
                'name' => $name,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to register OAuth client');
        }
    }

    public function authorizeClient(string $clientId, int $userId, array $scopes, string $state = ''): string
    {
        $client = $this->getClient($clientId);
        if (!$client || !$client->isActive) {
            throw new RuntimeException('Invalid client');
        }
        
        $code = $this->generateAuthorizationCode();
        $expiresAt = $this->clock->now()->add(new \DateInterval('PT10M')); // 10 minutes
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::CODES_TABLE . " 
                (code, client_id, user_id, scopes, state, expires_at, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $code,
                $clientId,
                $userId,
                json_encode($scopes),
                $state,
                $expiresAt->format('Y-m-d H:i:s'),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            $this->logger?->info('oauth_authorization_code_created', [
                'client_id' => $clientId,
                'user_id' => $userId,
                'scopes' => $scopes
            ]);
            
            return $code;
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_authorization_failed', [
                'client_id' => $clientId,
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to create authorization code');
        }
    }

    public function exchangeCodeForToken(string $code, string $clientId, string $clientSecret): OAuthTokenSet
    {
        $authorizationCode = $this->getAuthorizationCode($code);
        
        if (!$authorizationCode) {
            throw new RuntimeException('Invalid authorization code');
        }
        
        if ($authorizationCode->clientId !== $clientId) {
            throw new RuntimeException('Client ID mismatch');
        }
        
        if ($authorizationCode->expiresAt < $this->clock->now()) {
            throw new RuntimeException('Authorization code expired');
        }
        
        $client = $this->getClient($clientId);
        if (!$client || !password_verify($clientSecret, $client->clientSecretHash)) {
            throw new RuntimeException('Invalid client credentials');
        }
        
        // Generate access token
        $accessToken = $this->generateAccessToken();
        $accessTokenExpires = $this->clock->now()->add(new \DateInterval('PT1H')); // 1 hour
        
        // Generate refresh token
        $refreshToken = $this->generateRefreshToken();
        $refreshTokenExpires = $this->clock->now()->add(new \DateInterval('P30D')); // 30 days
        
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            // Store access token
            $stmt = $pdo->prepare("
                INSERT INTO " . self::TOKENS_TABLE . " 
                (token, client_id, user_id, scopes, expires_at, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $accessToken,
                $clientId,
                $authorizationCode->userId,
                $authorizationCode->scopes,
                $accessTokenExpires->format('Y-m-d H:i:s'),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            // Store refresh token
            $stmt = $pdo->prepare("
                INSERT INTO " . self::REFRESH_TABLE . " 
                (token, client_id, user_id, scopes, expires_at, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $refreshToken,
                $clientId,
                $authorizationCode->userId,
                $authorizationCode->scopes,
                $refreshTokenExpires->format('Y-m-d H:i:s'),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            // Mark authorization code as used
            $stmt = $pdo->prepare("
                UPDATE " . self::CODES_TABLE . " 
                SET used_at = ? 
                WHERE code = ?
            ");
            
            $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $code
            ]);
            
            $pdo->commit();
            
            $this->logger?->info('oauth_tokens_issued', [
                'client_id' => $clientId,
                'user_id' => $authorizationCode->userId,
                'scopes' => $authorizationCode->scopes
            ]);
            
            return new OAuthTokenSet(
                accessToken: $accessToken,
                refreshToken: $refreshToken,
                tokenType: 'Bearer',
                expiresIn: 3600,
                scope: implode(' ', $authorizationCode->scopes)
            );
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('oauth_token_exchange_failed', [
                'code' => $code,
                'client_id' => $clientId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to exchange code for token');
        }
    }

    public function refreshAccessToken(string $refreshToken, string $clientId, string $clientSecret): OAuthTokenSet
    {
        $refreshTokenData = $this->getRefreshToken($refreshToken);
        
        if (!$refreshTokenData) {
            throw new RuntimeException('Invalid refresh token');
        }
        
        if ($refreshTokenData->clientId !== $clientId) {
            throw new RuntimeException('Client ID mismatch');
        }
        
        if ($refreshTokenData->expiresAt < $this->clock->now()) {
            throw new RuntimeException('Refresh token expired');
        }
        
        $client = $this->getClient($clientId);
        if (!$client || !password_verify($clientSecret, $client->clientSecretHash)) {
            throw new RuntimeException('Invalid client credentials');
        }
        
        // Generate new access token
        $accessToken = $this->generateAccessToken();
        $accessTokenExpires = $this->clock->now()->add(new \DateInterval('PT1H'));
        
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            // Store new access token
            $stmt = $pdo->prepare("
                INSERT INTO " . self::TOKENS_TABLE . " 
                (token, client_id, user_id, scopes, expires_at, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $accessToken,
                $clientId,
                $refreshTokenData->userId,
                $refreshTokenData->scopes,
                $accessTokenExpires->format('Y-m-d H:i:s'),
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            // Revoke old refresh token
            $stmt = $pdo->prepare("
                UPDATE " . self::REFRESH_TABLE . " 
                SET revoked_at = ? 
                WHERE token = ?
            ");
            
            $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $refreshToken
            ]);
            
            $pdo->commit();
            
            $this->logger?->info('oauth_access_token_refreshed', [
                'client_id' => $clientId,
                'user_id' => $refreshTokenData->userId
            ]);
            
            return new OAuthTokenSet(
                accessToken: $accessToken,
                refreshToken: $refreshToken,
                tokenType: 'Bearer',
                expiresIn: 3600,
                scope: implode(' ', $refreshTokenData->scopes)
            );
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('oauth_token_refresh_failed', [
                'refresh_token' => $refreshToken,
                'client_id' => $clientId,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to refresh access token');
        }
    }

    public function validateAccessToken(string $accessToken): ?OAuthTokenInfo
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT t.*, c.name as client_name, c.redirect_uri 
                FROM " . self::TOKENS_TABLE . " t
                JOIN " . self::CLIENTS_TABLE . " c ON t.client_id = c.client_id
                WHERE t.token = ? AND t.expires_at > ? AND c.is_active = 1
            ");
            
            $stmt->execute([
                $accessToken,
                $this->clock->now()->format('Y-m-d H:i:s')
            ]);
            
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            return new OAuthTokenInfo(
                token: $row['token'],
                clientId: $row['client_id'],
                userId: (int) $row['user_id'],
                scopes: json_decode($row['scopes'], true),
                expiresAt: new \DateTimeImmutable($row['expires_at']),
                clientName: $row['client_name'],
                redirectUri: $row['redirect_uri']
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_token_validation_failed', [
                'access_token' => substr($accessToken, 0, 10) . '...',
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function revokeToken(string $token): bool
    {
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            // Revoke access token
            $stmt = $pdo->prepare("
                UPDATE " . self::TOKENS_TABLE . " 
                SET revoked_at = ? 
                WHERE token = ?
            ");
            $stmt->execute([$this->clock->now()->format('Y-m-d H:i:s'), $token]);
            
            // Revoke refresh token
            $stmt = $pdo->prepare("
                UPDATE " . self::REFRESH_TABLE . " 
                SET revoked_at = ? 
                WHERE token = ?
            ");
            $stmt->execute([$this->clock->now()->format('Y-m-d H:i:s'), $token]);
            
            $pdo->commit();
            
            $this->logger?->info('oauth_token_revoked', [
                'token' => substr($token, 0, 10) . '...'
            ]);
            
            return true;
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('oauth_token_revocation_failed', [
                'token' => substr($token, 0, 10) . '...',
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    private function getClient(string $clientId): ?OAuthClient
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::CLIENTS_TABLE . " 
                WHERE client_id = ? AND is_active = 1
            ");
            
            $stmt->execute([$clientId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            return new OAuthClient(
                clientId: $row['client_id'],
                clientSecret: '', // Don't return secret
                clientSecretHash: $row['client_secret'],
                name: $row['name'],
                redirectUri: $row['redirect_uri'],
                scopes: json_decode($row['scopes'], true),
                isActive: (bool) $row['is_active'],
                createdAt: new \DateTimeImmutable($row['created_at'])
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_client_lookup_failed', [
                'client_id' => $clientId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function getAuthorizationCode(string $code): ?AuthorizationCode
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::CODES_TABLE . " 
                WHERE code = ? AND used_at IS NULL
            ");
            
            $stmt->execute([$code]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            return new AuthorizationCode(
                code: $row['code'],
                clientId: $row['client_id'],
                userId: (int) $row['user_id'],
                scopes: json_decode($row['scopes'], true),
                state: $row['state'],
                expiresAt: new \DateTimeImmutable($row['expires_at']),
                createdAt: new \DateTimeImmutable($row['created_at'])
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_authorization_code_lookup_failed', [
                'code' => $code,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function getRefreshToken(string $token): ?RefreshToken
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::REFRESH_TABLE . " 
                WHERE token = ? AND revoked_at IS NULL
            ");
            
            $stmt->execute([$token]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$row) {
                return null;
            }
            
            return new RefreshToken(
                token: $row['token'],
                clientId: $row['client_id'],
                userId: (int) $row['user_id'],
                scopes: json_decode($row['scopes'], true),
                expiresAt: new \DateTimeImmutable($row['expires_at']),
                createdAt: new \DateTimeImmutable($row['created_at'])
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('oauth_refresh_token_lookup_failed', [
                'token' => substr($token, 0, 10) . '...',
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function generateClientId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function generateClientSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function generateAuthorizationCode(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function generateAccessToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function generateRefreshToken(): string
    {
        return bin2hex(random_bytes(32));
    }
}

final class OAuthClient
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $clientSecret,
        public readonly string $name,
        public readonly string $redirectUri,
        public readonly array $scopes,
        public readonly bool $isActive,
        public readonly \DateTimeImmutable $createdAt,
        public readonly ?string $clientSecretHash = null
    ) {
    }
}

final class AuthorizationCode
{
    public function __construct(
        public readonly string $code,
        public readonly string $clientId,
        public readonly int $userId,
        public readonly array $scopes,
        public readonly string $state,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}

final class RefreshToken
{
    public function __construct(
        public readonly string $token,
        public readonly string $clientId,
        public readonly int $userId,
        public readonly array $scopes,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}

final class OAuthTokenSet
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly string $scope
    ) {
    }

    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
            'scope' => $this->scope
        ];
    }
}

final class OAuthTokenInfo
{
    public function __construct(
        public readonly string $token,
        public readonly string $clientId,
        public readonly int $userId,
        public readonly array $scopes,
        public readonly \DateTimeImmutable $expiresAt,
        public readonly string $clientName,
        public readonly string $redirectUri
    ) {
    }
}
