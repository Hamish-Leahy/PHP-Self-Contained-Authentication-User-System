<?php
declare(strict_types=1);

namespace AuthKit\Mail;

use AuthKit\Contracts\MailerInterface;

final class PhpMailMailer implements MailerInterface
{
    public function send(array $from, array $to, string $subject, string $htmlBody, ?string $textBody = null): void
    {
        $headers = [];
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        if (!empty($from['email'])) {
            $fromName = $from['name'] ?? '';
            $headers[] = 'From: ' . ($fromName ? ($fromName . ' <' . $from['email'] . '>') : $from['email']);
        }
        $headersStr = implode("\r\n", $headers);
        @mail($to['email'], $subject, $htmlBody, $headersStr);
    }
}


