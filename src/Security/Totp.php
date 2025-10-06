<?php
declare(strict_types=1);

namespace AuthKit\Security;

use AuthKit\Contracts\TotpInterface;

final class Totp implements TotpInterface
{
    public function __construct(private readonly int $digits = 6, private readonly int $period = 30)
    {
    }

    public function generateSecret(int $bytes = 20): string
    {
        return Base32::encode(random_bytes($bytes));
    }

    public function getOtp(string $secret, int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        $counter = intdiv($timestamp, $this->period);
        $key = Base32::decode($secret);
        $binCounter = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $binCounter, $key, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncated = unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF;
        $code = $truncated % (10 ** $this->digits);
        return str_pad((string)$code, $this->digits, '0', STR_PAD_LEFT);
    }

    public function verify(string $secret, string $code, int $window = 1): bool
    {
        $now = time();
        $code = preg_replace('/\s+/', '', $code);
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals($this->getOtp($secret, $now + ($i * $this->period)), $code)) {
                return true;
            }
        }
        return false;
    }

    public function provisioningUri(string $secret, string $accountName, string $issuer): string
    {
        $label = rawurlencode($issuer . ':' . $accountName);
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'digits' => $this->digits,
            'period' => $this->period,
        ]);
        return 'otpauth://totp/' . $label . '?' . $params;
    }
}


