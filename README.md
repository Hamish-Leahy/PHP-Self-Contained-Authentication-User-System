# PHP Self‑Contained Authentication & User System

Zero-dependency, drop-in PHP authentication kit providing: registration, login, logout, email verification, password reset, sessions, and optional JWT for APIs. Works with plain PHP—no frameworks required.

## Quickstart

1) Create database and run the schema:

```sql
-- Create DB then run:
SOURCE schema.sql;
```

2) Configure `config/auth.php` (DSN, credentials, secrets).

3) Bootstrap in your project:

```php
$kit = require __DIR__ . '/bootstrap.php';
// Access services
$pdo = $kit['pdo'];
$config = $kit['config'];
```

You can now use the upcoming `AuthService` for register/login/password-reset flows, or call lower-level utilities directly if desired.

## Goals

- Minimal setup: include `bootstrap.php` and configure a few lines
- No external dependencies
- Secure by default: modern password hashing, CSRF utilities, token hashing
- Optional JWT support for API use-cases
- Simple, framework-agnostic architecture

## Master Plan

1. Scaffold project structure, autoloader, config, bootstrap, and SQL schema
2. Define contracts and domain entities (user, repos, mail, tokens)
3. Implement security utilities: password hasher, CSRF, JWT
4. Implement database layer: PDO connection, user repo, token store
5. Implement session management utilities
6. Implement mailers (PHP mail, null/log)
7. Implement EmailTokenService for verification and password reset
8. Implement AuthService: register, login, logout, reset, verify, JWT
9. Provide example endpoints (web forms + JSON API)
10. Write SQL schema and quickstart docs in README

## Configuration

Edit `config/auth.php`. Important keys:

- `database.dsn`: e.g. `mysql:host=127.0.0.1;dbname=auth;charset=utf8mb4`
- `security.password_cost`, `security.pepper`
- `session.*`: cookie settings (secure, httponly, samesite)
- `jwt.*`: set `enabled` and `signing_key` to use JWT
- `mail.*`: `php_mail` or `null` sender

## Requirements

- PHP 8.1+
- MySQL 5.7+/8.0+ (or compatible)

## Installation

1) Copy this folder into your project (e.g. `authkit/`).

2) Create a database and run the provided schema:

```sql
-- In your MySQL client
SOURCE /absolute/path/to/authkit/schema.sql;
```

3) Configure `config/auth.php` with your DSN, credentials, and secrets.

4) Include the bootstrap in your application entrypoints (e.g. front controller):

```php
$kit = require __DIR__ . '/authkit/bootstrap.php';
```

### Bootstrapping services (optional now, will be wired into AuthService later)

```php
use AuthKit\Security\PasswordHasher;
use AuthKit\Security\RandomTokenGenerator;
use AuthKit\Support\Session\PhpSession;
use AuthKit\Support\Clock\SystemClock;
use AuthKit\Security\CsrfSessionTokenProvider;
use AuthKit\Security\Jwt\HsJwtSigner;

$pdo = $kit['pdo'];
$config = $kit['config'];

$hasher = new PasswordHasher($config['security']);
$tokens = new RandomTokenGenerator();
$session = new PhpSession();
$clock = new SystemClock();
$csrf = new CsrfSessionTokenProvider($session, $tokens);
$jwt = $config['jwt']['enabled'] ? new HsJwtSigner($config['jwt']) : null;
```

## Configuration Reference

Edit `config/auth.php`.

```php
return [
    'database' => [
        'dsn' => 'mysql:host=127.0.0.1;port=3306;dbname=auth;charset=utf8mb4',
        'username' => 'root',
        'password' => '',
        'options' => [],
    ],

    'security' => [
        'password_algo' => PASSWORD_DEFAULT, // PASSWORD_DEFAULT, PASSWORD_BCRYPT, etc.
        'password_cost' => 12,               // cost/work factor
        'pepper' => '',                      // global secret added to password before hashing
    ],

    'tokens' => [
        'email_verification_ttl' => '2 days',
        'password_reset_ttl' => '2 hours',
    ],

    'session' => [
        'name' => 'AUTHSESSID',
        'cookie_secure' => true,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax', // Lax/Strict/None
        'lifetime' => 0,            // 0 = session cookie
    ],

    'jwt' => [
        'enabled' => false,
        'issuer' => 'your-app',
        'audience' => null,
        'signing_key' => '',       // required when enabled
        'ttl' => '15 minutes',
        'refresh_ttl' => '14 days',
        'algorithm' => 'HS256',
    ],

    'mail' => [
        'driver' => 'php_mail',
        'from' => ['email' => 'no-reply@example.com', 'name' => 'App Auth'],
    ],
];
```

Notes:

- Set `security.pepper` to a long random secret (32+ bytes). Store outside VCS.
- When enabling JWT, set a strong `jwt.signing_key` (32+ random bytes).
- For production, set `session.cookie_secure = true` and serve over HTTPS.

## Schema Overview

Tables installed by `schema.sql`:

- `users`
  - `email` unique index
  - `password_hash`, `password_algo`
  - `is_email_verified` flag
  - timestamps: `created_at`, `updated_at`, `last_login_at`
  - optional `locked_until` for basic account lockout windows

- `auth_email_tokens`
  - For email verification and password reset flows
  - Stores only `token_hash` (SHA-256) and not the raw token
  - `expires_at`, `used_at`, with FK to `users`

## Features

- Registration with email verification link
- Login with password hashing (pepper + `password_hash`), last-login tracking
- Logout, session regeneration, CSRF utilities
- Password reset via email token
- Optional JWT issuance for API clients
- Zero external dependencies; single package; framework-agnostic

## Architecture

- Support
  - `Autoloader`, `bootstrap.php`, `DatabaseConnection`
  - `Support/Session/PhpSession`, `Support/Clock/SystemClock`

- Domain
  - Entities: `User`, `EmailToken`
  - Enums: `EmailTokenType`

- Contracts (interfaces)
  - Repos: `UserRepositoryInterface`, `EmailTokenRepositoryInterface`
  - Security: `PasswordHasherInterface`, `CsrfTokenProviderInterface`, `JwtSignerInterface`, `RandomTokenGeneratorInterface`
  - Platform: `MailerInterface`, `SessionInterface`, `ClockInterface`

- Security Utils
  - `PasswordHasher`, `RandomTokenGenerator`, `CsrfSessionTokenProvider`, `Jwt` (HS256)

Repositories (PDO implementations) and `AuthService` are part of the next steps in this plan.

## Usage Examples (Web)

Below are minimal examples that show how this package will be used. The exact `AuthService` API may evolve slightly, but the shape will be similar.

### Registration (with email verification)

```php
// register.php
$kit = require __DIR__ . '/authkit/bootstrap.php';

// TODO: wire repositories and AuthService in future steps
// $auth = new AuthService(...); 

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    // $auth->register($email, $password); // sends verification email
    echo 'If this were wired, you would now receive a verification email.';
    exit;
}
```

### Login

```php
// login.php
$kit = require __DIR__ . '/authkit/bootstrap.php';

// $auth = new AuthService(...);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    // $auth->login($email, $password);
    echo 'If wired, you would be logged in and session regenerated.';
    exit;
}
```

### CSRF token example (forms)

```php
use AuthKit\Security\CsrfSessionTokenProvider;
use AuthKit\Support\Session\PhpSession;
use AuthKit\Security\RandomTokenGenerator;

$csrf = new CsrfSessionTokenProvider(new PhpSession(), new RandomTokenGenerator());
$token = $csrf->getToken('register_form');
```

## Usage Examples (API with JWT)

When `jwt.enabled = true` and a signing key is configured, you can issue tokens upon login and verify them on subsequent requests.

```php
use AuthKit\Security\Jwt\HsJwtSigner;

$jwt = new HsJwtSigner($config['jwt']);
$token = $jwt->sign(['sub' => $userId]);
// Return $token in JSON. Client sends `Authorization: Bearer <token>`.

// To verify:
$claims = $jwt->verify($token);
if ($claims === null) {
    http_response_code(401);
}
```

## Security Notes

- Passwords are hashed with PHP's `password_hash`, plus an application-level pepper.
- Email tokens are stored as hashes; raw tokens are only sent to users via email.
- CSRF tokens are per-key and deleted upon successful validation.
- JWTs use HS256 and include `iat`/`exp` by default; `iss`/`aud` optional.
- Always serve over HTTPS in production and set secure cookies.

## Deployment Guidance

- Set `session.cookie_secure = true` and use `SameSite=Lax` or `Strict` unless cross-site required.
- Ensure time synchronization (UTC). `SystemClock` uses server time; configure NTP.
- Configure `php.ini` for `session.use_strict_mode = 1` and appropriate `session.save_path`.
- Rotate `security.pepper` and `jwt.signing_key` carefully (support key rotation by temporarily accepting old keys during transition if you add that in your app).

## Extensibility

- Swap interfaces with your implementations:
  - `MailerInterface` to integrate with SMTP or provider APIs
  - `SessionInterface` for custom session backends
  - `JwtSignerInterface` for different algorithms or key management
- Add fields to `users` (e.g., display name) and extend the repositories accordingly.

## Troubleshooting

- Autoloader not working? Ensure `bootstrap.php` is included and namespace `AuthKit\\` is preserved.
- Database connection errors? Verify DSN, credentials, and that MySQL accepts connections.
- Emails not sending? Start with `php_mail` driver; check server mail transport. You can stub with a `null` driver.

## Roadmap

- Implement PDO repositories for users and tokens
- Implement `EmailTokenService` and `AuthService`
- Provide production-ready mailer implementations and example endpoints
- Add CLI helpers for generating secrets and migrating schema

