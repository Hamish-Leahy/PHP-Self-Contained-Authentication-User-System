<?php
declare(strict_types=1);

namespace AuthKit\Support\Config;

final class ConfigValidator
{
    /** @param array<string,mixed> $config */
    public function validate(array $config): void
    {
        $errors = [];
        $pepper = (string)($config['security']['pepper'] ?? '');
        if ($pepper === '') {
            $errors[] = 'security.pepper must be set to a long random secret.';
        }
        if (!empty($config['jwt']['enabled'])) {
            $key = (string)($config['jwt']['signing_key'] ?? '');
            if ($key === '') {
                $errors[] = 'jwt.enabled is true but jwt.signing_key is empty';
            }
        }
        if ($errors) {
            throw new \RuntimeException('Invalid configuration: ' . implode('; ', $errors));
        }
    }
}


