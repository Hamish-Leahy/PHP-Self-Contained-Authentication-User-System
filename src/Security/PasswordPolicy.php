<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\LoggerInterface;
use InvalidArgumentException;

final class PasswordPolicy
{
    private const COMMON_PASSWORDS = [
        'password', '123456', 'password123', 'admin', 'qwerty',
        'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
        'password1', '123456789', 'welcome123', 'admin123', 'root'
    ];

    public function __construct(
        private readonly array $config = [],
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function validatePassword(string $password, ?string $email = null, ?string $username = null): PasswordValidationResult
    {
        $violations = [];
        
        // Length check
        $minLength = $this->config['min_length'] ?? 8;
        if (strlen($password) < $minLength) {
            $violations[] = "Password must be at least {$minLength} characters long";
        }
        
        $maxLength = $this->config['max_length'] ?? 128;
        if (strlen($password) > $maxLength) {
            $violations[] = "Password must be no more than {$maxLength} characters long";
        }
        
        // Character requirements
        if ($this->config['require_uppercase'] ?? true) {
            if (!preg_match('/[A-Z]/', $password)) {
                $violations[] = 'Password must contain at least one uppercase letter';
            }
        }
        
        if ($this->config['require_lowercase'] ?? true) {
            if (!preg_match('/[a-z]/', $password)) {
                $violations[] = 'Password must contain at least one lowercase letter';
            }
        }
        
        if ($this->config['require_numbers'] ?? true) {
            if (!preg_match('/[0-9]/', $password)) {
                $violations[] = 'Password must contain at least one number';
            }
        }
        
        if ($this->config['require_symbols'] ?? true) {
            if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
                $violations[] = 'Password must contain at least one special character';
            }
        }
        
        // Common password check
        if ($this->config['reject_common_passwords'] ?? true) {
            if (in_array(strtolower($password), self::COMMON_PASSWORDS)) {
                $violations[] = 'Password is too common and easily guessable';
            }
        }
        
        // Personal information check
        if ($email && $this->config['reject_personal_info'] ?? true) {
            $emailParts = explode('@', $email);
            $username = $emailParts[0];
            
            if (str_contains(strtolower($password), strtolower($username))) {
                $violations[] = 'Password cannot contain your email username';
            }
        }
        
        if ($username && $this->config['reject_personal_info'] ?? true) {
            if (str_contains(strtolower($password), strtolower($username))) {
                $violations[] = 'Password cannot contain your username';
            }
        }
        
        // Sequential characters check
        if ($this->config['reject_sequential'] ?? true) {
            if ($this->hasSequentialCharacters($password)) {
                $violations[] = 'Password cannot contain sequential characters (e.g., abc, 123)';
            }
        }
        
        // Repeated characters check
        if ($this->config['reject_repeated'] ?? true) {
            if ($this->hasRepeatedCharacters($password)) {
                $violations[] = 'Password cannot contain repeated characters (e.g., aaa, 111)';
            }
        }
        
        // Dictionary check
        if ($this->config['reject_dictionary_words'] ?? false) {
            if ($this->containsDictionaryWords($password)) {
                $violations[] = 'Password cannot contain dictionary words';
            }
        }
        
        // Entropy check
        $minEntropy = $this->config['min_entropy'] ?? 0;
        if ($minEntropy > 0) {
            $entropy = $this->calculateEntropy($password);
            if ($entropy < $minEntropy) {
                $violations[] = "Password entropy is too low (minimum: {$minEntropy})";
            }
        }
        
        $isValid = empty($violations);
        $strength = $this->calculateStrength($password);
        
        $result = new PasswordValidationResult($isValid, $violations, $strength);
        
        if (!$isValid) {
            $this->logger?->warning('password_validation_failed', [
                'violations' => $violations,
                'strength' => $strength
            ]);
        }
        
        return $result;
    }

    public function generateSecurePassword(int $length = 16): string
    {
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';
        $numbers = '0123456789';
        $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        $allChars = $uppercase . $lowercase . $numbers . $symbols;
        $password = '';
        
        // Ensure at least one character from each category
        $password .= $uppercase[random_int(0, strlen($uppercase) - 1)];
        $password .= $lowercase[random_int(0, strlen($lowercase) - 1)];
        $password .= $numbers[random_int(0, strlen($numbers) - 1)];
        $password .= $symbols[random_int(0, strlen($symbols) - 1)];
        
        // Fill the rest randomly
        for ($i = 4; $i < $length; $i++) {
            $password .= $allChars[random_int(0, strlen($allChars) - 1)];
        }
        
        // Shuffle the password
        return str_shuffle($password);
    }

    public function checkPasswordHistory(string $password, array $passwordHistory): bool
    {
        $historyLimit = $this->config['password_history_limit'] ?? 5;
        
        if (count($passwordHistory) < $historyLimit) {
            return true;
        }
        
        foreach (array_slice($passwordHistory, -$historyLimit) as $oldPassword) {
            if (password_verify($password, $oldPassword)) {
                return false;
            }
        }
        
        return true;
    }

    public function getPasswordRequirements(): array
    {
        return [
            'min_length' => $this->config['min_length'] ?? 8,
            'max_length' => $this->config['max_length'] ?? 128,
            'require_uppercase' => $this->config['require_uppercase'] ?? true,
            'require_lowercase' => $this->config['require_lowercase'] ?? true,
            'require_numbers' => $this->config['require_numbers'] ?? true,
            'require_symbols' => $this->config['require_symbols'] ?? true,
            'reject_common_passwords' => $this->config['reject_common_passwords'] ?? true,
            'reject_personal_info' => $this->config['reject_personal_info'] ?? true,
            'reject_sequential' => $this->config['reject_sequential'] ?? true,
            'reject_repeated' => $this->config['reject_repeated'] ?? true,
            'reject_dictionary_words' => $this->config['reject_dictionary_words'] ?? false,
            'min_entropy' => $this->config['min_entropy'] ?? 0,
            'password_history_limit' => $this->config['password_history_limit'] ?? 5
        ];
    }

    private function hasSequentialCharacters(string $password): bool
    {
        $sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'zyxwvutsrqponmlkjihgfedcba',
            '0123456789',
            '9876543210'
        ];
        
        foreach ($sequences as $sequence) {
            for ($i = 0; $i <= strlen($sequence) - 3; $i++) {
                $substring = substr($sequence, $i, 3);
                if (str_contains(strtolower($password), $substring)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private function hasRepeatedCharacters(string $password): bool
    {
        return preg_match('/(.)\1{2,}/', $password) === 1;
    }

    private function containsDictionaryWords(string $password): bool
    {
        // This is a simplified implementation
        // In production, you'd use a proper dictionary
        $dictionary = [
            'password', 'admin', 'user', 'login', 'welcome',
            'system', 'account', 'profile', 'settings', 'security'
        ];
        
        $lowerPassword = strtolower($password);
        
        foreach ($dictionary as $word) {
            if (str_contains($lowerPassword, $word)) {
                return true;
            }
        }
        
        return false;
    }

    private function calculateEntropy(string $password): float
    {
        $length = strlen($password);
        $charset = 0;
        
        if (preg_match('/[a-z]/', $password)) $charset += 26;
        if (preg_match('/[A-Z]/', $password)) $charset += 26;
        if (preg_match('/[0-9]/', $password)) $charset += 10;
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $charset += 32;
        
        return $length * log($charset, 2);
    }

    private function calculateStrength(string $password): int
    {
        $score = 0;
        $length = strlen($password);
        
        // Length scoring
        if ($length >= 8) $score += 1;
        if ($length >= 12) $score += 1;
        if ($length >= 16) $score += 1;
        
        // Character variety scoring
        if (preg_match('/[a-z]/', $password)) $score += 1;
        if (preg_match('/[A-Z]/', $password)) $score += 1;
        if (preg_match('/[0-9]/', $password)) $score += 1;
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 1;
        
        // Complexity scoring
        if (!$this->hasSequentialCharacters($password)) $score += 1;
        if (!$this->hasRepeatedCharacters($password)) $score += 1;
        if (!in_array(strtolower($password), self::COMMON_PASSWORDS)) $score += 1;
        
        // Entropy scoring
        $entropy = $this->calculateEntropy($password);
        if ($entropy >= 30) $score += 1;
        if ($entropy >= 40) $score += 1;
        
        return min(10, $score);
    }
}

final class PasswordValidationResult
{
    public function __construct(
        public readonly bool $isValid,
        public readonly array $violations,
        public readonly int $strength
    ) {
    }

    public function getStrengthLevel(): string
    {
        if ($this->strength >= 8) return 'strong';
        if ($this->strength >= 6) return 'medium';
        if ($this->strength >= 4) return 'weak';
        return 'very_weak';
    }

    public function getStrengthPercentage(): int
    {
        return min(100, $this->strength * 10);
    }

    public function toArray(): array
    {
        return [
            'is_valid' => $this->isValid,
            'violations' => $this->violations,
            'strength' => $this->strength,
            'strength_level' => $this->getStrengthLevel(),
            'strength_percentage' => $this->getStrengthPercentage()
        ];
    }
}
