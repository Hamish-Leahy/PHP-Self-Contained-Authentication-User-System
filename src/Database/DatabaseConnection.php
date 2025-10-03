<?php
declare(strict_types=1);

namespace AuthKit\Database;

use PDO;
use PDOException;

final class DatabaseConnection
{
    private PDO $pdo;

    /**
     * @param array{dsn:string,username?:string|null,password?:string|null,options?:array} $config
     */
    public function __construct(array $config)
    {
        $dsn = $config['dsn'] ?? '';
        $username = $config['username'] ?? null;
        $password = $config['password'] ?? null;
        $options = $config['options'] ?? [];

        $defaultOptions = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];

        $options = $options + $defaultOptions;

        $this->pdo = new PDO($dsn, $username, $password, $options);
        $this->pdo->exec('SET NAMES utf8mb4');
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }
}


