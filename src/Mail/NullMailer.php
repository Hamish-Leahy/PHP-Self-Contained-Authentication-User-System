<?php
declare(strict_types=1);

namespace AuthKit\Mail;

use AuthKit\Contracts\MailerInterface;

final class NullMailer implements MailerInterface
{
    public function send(array $from, array $to, string $subject, string $htmlBody, ?string $textBody = null): void
    {
        // Intentionally no-op. Useful for local development/testing.
    }
}


