<?php
declare(strict_types=1);

namespace AuthKit\Middleware;

use AuthKit\Contracts\LoggerInterface;

final class SecurityHeadersMiddleware
{
    private const DEFAULT_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'Cross-Origin-Embedder-Policy' => 'require-corp',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Cross-Origin-Resource-Policy' => 'same-origin'
    ];

    public function __construct(
        private readonly array $config = [],
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function applyHeaders(): void
    {
        $headers = $this->buildHeaders();
        
        foreach ($headers as $name => $value) {
            if (!headers_sent()) {
                header("{$name}: {$value}");
            }
        }
        
        $this->logger?->debug('security_headers_applied', [
            'headers_count' => count($headers),
            'headers' => array_keys($headers)
        ]);
    }

    public function applyCSP(): void
    {
        $csp = $this->buildCSP();
        
        if ($csp) {
            header("Content-Security-Policy: {$csp}");
            $this->logger?->debug('csp_header_applied', ['csp' => $csp]);
        }
    }

    public function applyHSTS(): void
    {
        $hsts = $this->buildHSTS();
        
        if ($hsts) {
            header("Strict-Transport-Security: {$hsts}");
            $this->logger?->debug('hsts_header_applied', ['hsts' => $hsts]);
        }
    }

    public function applyCSRFProtection(): string
    {
        $token = $this->generateCSRFToken();
        
        if (!headers_sent()) {
            header("X-CSRF-Token: {$token}");
        }
        
        $this->logger?->debug('csrf_token_generated', [
            'token_prefix' => substr($token, 0, 8) . '...'
        ]);
        
        return $token;
    }

    public function validateCSRFToken(string $providedToken): bool
    {
        $storedToken = $_SESSION['csrf_token'] ?? null;
        
        if (!$storedToken || !hash_equals($storedToken, $providedToken)) {
            $this->logger?->warning('csrf_token_validation_failed', [
                'provided_prefix' => substr($providedToken, 0, 8) . '...',
                'stored_prefix' => $storedToken ? substr($storedToken, 0, 8) . '...' : 'none'
            ]);
            return false;
        }
        
        $this->logger?->debug('csrf_token_validated');
        return true;
    }

    public function applyRateLimitHeaders(RateLimitResult $rateLimit): void
    {
        $headers = [
            'X-RateLimit-Limit' => (string) $rateLimit->remaining,
            'X-RateLimit-Remaining' => (string) $rateLimit->remaining,
            'X-RateLimit-Reset' => (string) $rateLimit->resetTime
        ];
        
        foreach ($headers as $name => $value) {
            if (!headers_sent()) {
                header("{$name}: {$value}");
            }
        }
    }

    public function applyCORS(array $allowedOrigins = []): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        
        if (empty($allowedOrigins) || in_array($origin, $allowedOrigins)) {
            header("Access-Control-Allow-Origin: {$origin}");
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-API-Key');
            header('Access-Control-Max-Age: 86400');
            
            $this->logger?->debug('cors_headers_applied', [
                'origin' => $origin,
                'allowed_origins' => $allowedOrigins
            ]);
        }
    }

    public function handlePreflightRequest(): bool
    {
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
        
        return false;
    }

    private function buildHeaders(): array
    {
        $headers = self::DEFAULT_HEADERS;
        
        // Merge with config
        if (isset($this->config['headers'])) {
            $headers = array_merge($headers, $this->config['headers']);
        }
        
        // Apply X-Frame-Options based on config
        if (isset($this->config['frame_options'])) {
            $headers['X-Frame-Options'] = $this->config['frame_options'];
        }
        
        // Apply Referrer-Policy based on config
        if (isset($this->config['referrer_policy'])) {
            $headers['Referrer-Policy'] = $this->config['referrer_policy'];
        }
        
        return $headers;
    }

    private function buildCSP(): ?string
    {
        if (!isset($this->config['csp']) || !$this->config['csp']['enabled']) {
            return null;
        }
        
        $csp = $this->config['csp'];
        $directives = [];
        
        // Default-src
        if (isset($csp['default_src'])) {
            $directives[] = "default-src " . implode(' ', $csp['default_src']);
        }
        
        // Script-src
        if (isset($csp['script_src'])) {
            $scriptSrc = implode(' ', $csp['script_src']);
            if (isset($csp['nonce_enabled']) && $csp['nonce_enabled']) {
                $nonce = $this->generateNonce();
                $scriptSrc .= " 'nonce-{$nonce}'";
                $_SESSION['csp_nonce'] = $nonce;
            }
            $directives[] = "script-src {$scriptSrc}";
        }
        
        // Style-src
        if (isset($csp['style_src'])) {
            $styleSrc = implode(' ', $csp['style_src']);
            if (isset($csp['nonce_enabled']) && $csp['nonce_enabled']) {
                $nonce = $_SESSION['csp_nonce'] ?? $this->generateNonce();
                $styleSrc .= " 'nonce-{$nonce}'";
            }
            $directives[] = "style-src {$styleSrc}";
        }
        
        // Connect-src
        if (isset($csp['connect_src'])) {
            $directives[] = "connect-src " . implode(' ', $csp['connect_src']);
        }
        
        // Img-src
        if (isset($csp['img_src'])) {
            $directives[] = "img-src " . implode(' ', $csp['img_src']);
        }
        
        // Font-src
        if (isset($csp['font_src'])) {
            $directives[] = "font-src " . implode(' ', $csp['font_src']);
        }
        
        // Object-src
        if (isset($csp['object_src'])) {
            $directives[] = "object-src " . implode(' ', $csp['object_src']);
        }
        
        // Base-uri
        if (isset($csp['base_uri'])) {
            $directives[] = "base-uri " . implode(' ', $csp['base_uri']);
        }
        
        // Form-action
        if (isset($csp['form_action'])) {
            $directives[] = "form-action " . implode(' ', $csp['form_action']);
        }
        
        // Frame-ancestors
        if (isset($csp['frame_ancestors'])) {
            $directives[] = "frame-ancestors " . implode(' ', $csp['frame_ancestors']);
        }
        
        // Upgrade-insecure-requests
        if (isset($csp['upgrade_insecure_requests']) && $csp['upgrade_insecure_requests']) {
            $directives[] = 'upgrade-insecure-requests';
        }
        
        // Block-all-mixed-content
        if (isset($csp['block_all_mixed_content']) && $csp['block_all_mixed_content']) {
            $directives[] = 'block-all-mixed-content';
        }
        
        return implode('; ', $directives);
    }

    private function buildHSTS(): ?string
    {
        if (!isset($this->config['hsts']) || !$this->config['hsts']['enabled']) {
            return null;
        }
        
        $hsts = $this->config['hsts'];
        $maxAge = $hsts['max_age'] ?? 31536000; // 1 year
        $includeSubDomains = isset($hsts['include_subdomains']) && $hsts['include_subdomains'] ? '; includeSubDomains' : '';
        $preload = isset($hsts['preload']) && $hsts['preload'] ? '; preload' : '';
        
        return "max-age={$maxAge}{$includeSubDomains}{$preload}";
    }

    private function generateCSRFToken(): string
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        return $_SESSION['csrf_token'];
    }

    private function generateNonce(): string
    {
        return base64_encode(random_bytes(16));
    }

    public function getCSPNonce(): ?string
    {
        return $_SESSION['csp_nonce'] ?? null;
    }

    public function applySecurityHeaders(): void
    {
        $this->applyHeaders();
        $this->applyCSP();
        $this->applyHSTS();
        
        // Only apply CORS if configured
        if (isset($this->config['cors']['enabled']) && $this->config['cors']['enabled']) {
            $this->applyCORS($this->config['cors']['allowed_origins'] ?? []);
        }
        
        // Handle preflight requests
        $this->handlePreflightRequest();
    }
}
