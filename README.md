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
