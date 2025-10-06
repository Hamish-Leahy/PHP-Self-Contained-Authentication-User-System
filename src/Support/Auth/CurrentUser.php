<?php
declare(strict_types=1);

namespace AuthKit\Support\Auth;

use AuthKit\Contracts\SessionInterface;
use AuthKit\Contracts\JwtSignerInterface;
use AuthKit\Contracts\UserRepositoryInterface;
use AuthKit\Domain\Entity\User;

final class CurrentUser
{
    public function __construct(
        private readonly SessionInterface $session,
        private readonly ?JwtSignerInterface $jwt,
        private readonly UserRepositoryInterface $users,
    ) {
    }

    public function idFromSession(): ?int
    {
        $id = $this->session->get('auth_user_id');
        return is_int($id) ? $id : null;
    }

    public function idFromJwtHeader(): ?int
    {
        if (!$this->jwt) { return null; }
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!str_starts_with($header, 'Bearer ')) { return null; }
        $token = substr($header, 7);
        $claims = $this->jwt->verify($token);
        if (!$claims || !isset($claims['sub'])) { return null; }
        return (int)$claims['sub'];
    }

    public function getUser(): ?User
    {
        $id = $this->idFromSession();
        if ($id === null) { $id = $this->idFromJwtHeader(); }
        if ($id === null) { return null; }
        return $this->users->findById($id);
    }

    public function requireAuthenticated(): void
    {
        if ($this->getUser() === null) {
            http_response_code(401);
            exit('Unauthorized');
        }
    }

    public function requireGuest(): void
    {
        if ($this->getUser() !== null) {
            http_response_code(400);
            exit('Already authenticated');
        }
    }
}


