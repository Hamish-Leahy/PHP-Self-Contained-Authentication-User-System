<?php
declare(strict_types=1);

namespace AuthKit\Security\Jwt;

use AuthKit\Contracts\JwtSignerInterface;

final class HsJwtSigner implements JwtSignerInterface
{
    private string $key;
    private string $algorithm;
    private ?string $issuer;
    private ?string $audience;
    private string $ttlSpec;

    /**
     * @param array{signing_key:string,algorithm?:string,issuer?:string|null,audience?:string|null,ttl?:string} $jwtConfig
     */
    public function __construct(array $jwtConfig)
    {
        $this->key = (string)$jwtConfig['signing_key'];
        $this->algorithm = (string)($jwtConfig['algorithm'] ?? 'HS256');
        $this->issuer = $jwtConfig['issuer'] ?? null;
        $this->audience = $jwtConfig['audience'] ?? null;
        $this->ttlSpec = (string)($jwtConfig['ttl'] ?? '15 minutes');
        if ($this->algorithm !== 'HS256') {
            throw new \InvalidArgumentException('Only HS256 is supported');
        }
    }

    /** @param array<string,mixed> $claims */
    public function sign(array $claims): string
    {
        $now = new \DateTimeImmutable('now');
        $exp = $now->add(\DateInterval::createFromDateString($this->ttlSpec));
        $payload = $claims + [
            'iat' => $now->getTimestamp(),
            'exp' => $exp->getTimestamp(),
        ];
        if ($this->issuer) { $payload['iss'] = $this->issuer; }
        if ($this->audience) { $payload['aud'] = $this->audience; }

        $header = ['typ' => 'JWT', 'alg' => $this->algorithm];
        $encodedHeader = Base64Url::encode(json_encode($header, JSON_UNESCAPED_SLASHES));
        $encodedPayload = Base64Url::encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->key, true);
        $encodedSignature = Base64Url::encode($signature);
        return $encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature;
    }

    /** @return array<string,mixed>|null */
    public function verify(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) { return null; }
        [$h, $p, $s] = $parts;

        $expected = Base64Url::encode(hash_hmac('sha256', $h . '.' . $p, $this->key, true));
        if (!hash_equals($expected, $s)) {
            return null;
        }

        $payloadJson = Base64Url::decode($p);
        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) { return null; }
        $nowTs = time();
        if (isset($payload['nbf']) && $nowTs < (int)$payload['nbf']) { return null; }
        if (isset($payload['exp']) && $nowTs >= (int)$payload['exp']) { return null; }
        if ($this->issuer !== null && isset($payload['iss']) && $payload['iss'] !== $this->issuer) { return null; }
        if ($this->audience !== null && isset($payload['aud']) && $payload['aud'] !== $this->audience) { return null; }
        return $payload;
    }
}


