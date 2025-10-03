<?php
declare(strict_types=1);

namespace AuthKit\Domain\Token;

enum EmailTokenType: string
{
    case VerifyEmail = 'verify_email';
    case PasswordReset = 'password_reset';
}


