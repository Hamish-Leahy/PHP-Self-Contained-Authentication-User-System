<?php
declare(strict_types=1);

namespace AuthKit\Contracts;

interface MailerInterface
{
    /**
     * @param array{email:string,name?:string|null} $from
     * @param array{email:string,name?:string|null} $to
     * @param string $subject
     * @param string $htmlBody
     * @param string|null $textBody
     */
    public function send(array $from, array $to, string $subject, string $htmlBody, ?string $textBody = null): void;
}

interface SessionInterface
{
    public function set(string $key, mixed $value): void;
    public function get(string $key, mixed $default = null): mixed;
    public function remove(string $key): void;
    public function regenerate(): void;
}

interface ClockInterface
{
    public function now(): \DateTimeImmutable;
}


