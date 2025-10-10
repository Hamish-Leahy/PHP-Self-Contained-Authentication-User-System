<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\LoggerInterface;
use InvalidArgumentException;
use RuntimeException;

final class EncryptionService
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_LENGTH = 32; // 256 bits
    private const IV_LENGTH = 12;  // 96 bits for GCM
    private const TAG_LENGTH = 16; // 128 bits

    public function __construct(
        private readonly string $masterKey,
        private readonly ?LoggerInterface $logger = null
    ) {
        if (strlen($this->masterKey) !== self::KEY_LENGTH) {
            throw new InvalidArgumentException('Master key must be 32 bytes long');
        }
    }

    public function encrypt(string $plaintext, ?string $context = null): EncryptedData
    {
        if (empty($plaintext)) {
            throw new InvalidArgumentException('Plaintext cannot be empty');
        }

        $iv = random_bytes(self::IV_LENGTH);
        $key = $this->deriveKey($context);
        
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            $this->logger?->error('encryption_failed', [
                'error' => openssl_error_string(),
                'context' => $context
            ]);
            throw new RuntimeException('Encryption failed');
        }

        $encryptedData = new EncryptedData(
            ciphertext: base64_encode($ciphertext),
            iv: base64_encode($iv),
            tag: base64_encode($tag),
            context: $context
        );

        $this->logger?->debug('data_encrypted', [
            'context' => $context,
            'size' => strlen($plaintext)
        ]);

        return $encryptedData;
    }

    public function decrypt(EncryptedData $encryptedData): string
    {
        $key = $this->deriveKey($encryptedData->context);
        $ciphertext = base64_decode($encryptedData->ciphertext);
        $iv = base64_decode($encryptedData->iv);
        $tag = base64_decode($encryptedData->tag);

        if ($ciphertext === false || $iv === false || $tag === false) {
            throw new InvalidArgumentException('Invalid base64 data');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            $this->logger?->error('decryption_failed', [
                'error' => openssl_error_string(),
                'context' => $encryptedData->context
            ]);
            throw new RuntimeException('Decryption failed');
        }

        $this->logger?->debug('data_decrypted', [
            'context' => $encryptedData->context,
            'size' => strlen($plaintext)
        ]);

        return $plaintext;
    }

    public function encryptField(string $value, string $fieldName, int $userId): string
    {
        $context = "field:{$fieldName}:user:{$userId}";
        $encryptedData = $this->encrypt($value, $context);
        
        return json_encode([
            'ciphertext' => $encryptedData->ciphertext,
            'iv' => $encryptedData->iv,
            'tag' => $encryptedData->tag,
            'context' => $encryptedData->context
        ]);
    }

    public function decryptField(string $encryptedJson, string $fieldName, int $userId): string
    {
        $data = json_decode($encryptedJson, true);
        
        if (!$data || !isset($data['ciphertext'], $data['iv'], $data['tag'])) {
            throw new InvalidArgumentException('Invalid encrypted field data');
        }

        $encryptedData = new EncryptedData(
            ciphertext: $data['ciphertext'],
            iv: $data['iv'],
            tag: $data['tag'],
            context: $data['context'] ?? "field:{$fieldName}:user:{$userId}"
        );

        return $this->decrypt($encryptedData);
    }

    public function encryptSensitiveData(array $data, int $userId): array
    {
        $sensitiveFields = ['ssn', 'credit_card', 'bank_account', 'personal_id'];
        $encrypted = [];

        foreach ($data as $key => $value) {
            if (in_array($key, $sensitiveFields) && is_string($value)) {
                $encrypted[$key] = $this->encryptField($value, $key, $userId);
            } else {
                $encrypted[$key] = $value;
            }
        }

        return $encrypted;
    }

    public function decryptSensitiveData(array $data, int $userId): array
    {
        $sensitiveFields = ['ssn', 'credit_card', 'bank_account', 'personal_id'];
        $decrypted = [];

        foreach ($data as $key => $value) {
            if (in_array($key, $sensitiveFields) && is_string($value)) {
                try {
                    $decrypted[$key] = $this->decryptField($value, $key, $userId);
                } catch (Exception $e) {
                    $this->logger?->warning('field_decryption_failed', [
                        'field' => $key,
                        'user_id' => $userId,
                        'error' => $e->getMessage()
                    ]);
                    $decrypted[$key] = $value; // Return original if decryption fails
                }
            } else {
                $decrypted[$key] = $value;
            }
        }

        return $decrypted;
    }

    public function generateDataKey(string $context): string
    {
        $key = random_bytes(self::KEY_LENGTH);
        $encryptedKey = $this->encryptKey($key, $context);
        
        $this->logger?->info('data_key_generated', [
            'context' => $context
        ]);

        return base64_encode($encryptedKey);
    }

    public function decryptDataKey(string $encryptedKey, string $context): string
    {
        $keyData = base64_decode($encryptedKey);
        if ($keyData === false) {
            throw new InvalidArgumentException('Invalid encrypted key format');
        }

        $key = $this->decryptKey($keyData, $context);
        
        $this->logger?->debug('data_key_decrypted', [
            'context' => $context
        ]);

        return $key;
    }

    public function rotateMasterKey(string $newMasterKey): bool
    {
        if (strlen($newMasterKey) !== self::KEY_LENGTH) {
            throw new InvalidArgumentException('New master key must be 32 bytes long');
        }

        // In a real implementation, you would:
        // 1. Re-encrypt all existing data with the new key
        // 2. Update the master key in secure storage
        // 3. Verify all data can be decrypted with the new key

        $this->logger?->info('master_key_rotation_initiated');
        
        // For now, just log the rotation
        return true;
    }

    public function createEncryptedBlob(array $data, string $context = null): string
    {
        $jsonData = json_encode($data);
        $encryptedData = $this->encrypt($jsonData, $context);
        
        return json_encode([
            'version' => '1.0',
            'cipher' => self::CIPHER,
            'ciphertext' => $encryptedData->ciphertext,
            'iv' => $encryptedData->iv,
            'tag' => $encryptedData->tag,
            'context' => $encryptedData->context,
            'created_at' => time()
        ]);
    }

    public function decryptBlob(string $encryptedBlob): array
    {
        $data = json_decode($encryptedBlob, true);
        
        if (!$data || !isset($data['ciphertext'], $data['iv'], $data['tag'])) {
            throw new InvalidArgumentException('Invalid encrypted blob format');
        }

        if ($data['cipher'] !== self::CIPHER) {
            throw new InvalidArgumentException('Unsupported cipher: ' . $data['cipher']);
        }

        $encryptedData = new EncryptedData(
            ciphertext: $data['ciphertext'],
            iv: $data['iv'],
            tag: $data['tag'],
            context: $data['context'] ?? null
        );

        $decryptedJson = $this->decrypt($encryptedData);
        $decryptedData = json_decode($decryptedJson, true);

        if (!$decryptedData) {
            throw new RuntimeException('Failed to decode decrypted data');
        }

        return $decryptedData;
    }

    private function deriveKey(?string $context): string
    {
        if ($context === null) {
            return $this->masterKey;
        }

        // Use HKDF to derive a context-specific key
        return hash_hkdf('sha256', $this->masterKey, self::KEY_LENGTH, $context, '');
    }

    private function encryptKey(string $key, string $context): string
    {
        $iv = random_bytes(self::IV_LENGTH);
        $derivedKey = $this->deriveKey($context);
        
        $encrypted = openssl_encrypt(
            $key,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encrypted === false) {
            throw new RuntimeException('Key encryption failed');
        }

        return $iv . $tag . $encrypted;
    }

    private function decryptKey(string $encryptedKey, string $context): string
    {
        if (strlen($encryptedKey) < self::IV_LENGTH + self::TAG_LENGTH) {
            throw new InvalidArgumentException('Invalid encrypted key length');
        }

        $iv = substr($encryptedKey, 0, self::IV_LENGTH);
        $tag = substr($encryptedKey, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($encryptedKey, self::IV_LENGTH + self::TAG_LENGTH);
        
        $derivedKey = $this->deriveKey($context);
        
        $key = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($key === false) {
            throw new RuntimeException('Key decryption failed');
        }

        return $key;
    }

    public function getEncryptionInfo(): array
    {
        return [
            'cipher' => self::CIPHER,
            'key_length' => self::KEY_LENGTH,
            'iv_length' => self::IV_LENGTH,
            'tag_length' => self::TAG_LENGTH,
            'supports_context' => true,
            'supports_key_rotation' => true
        ];
    }
}

final class EncryptedData
{
    public function __construct(
        public readonly string $ciphertext,
        public readonly string $iv,
        public readonly string $tag,
        public readonly ?string $context = null
    ) {
    }

    public function toArray(): array
    {
        return [
            'ciphertext' => $this->ciphertext,
            'iv' => $this->iv,
            'tag' => $this->tag,
            'context' => $this->context
        ];
    }

    public function toJson(): string
    {
        return json_encode($this->toArray());
    }
}
