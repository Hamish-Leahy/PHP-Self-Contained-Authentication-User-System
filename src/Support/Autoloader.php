<?php
declare(strict_types=1);

namespace AuthKit\Support;

final class Autoloader
{
    private string $baseDir;

    public function __construct(string $baseDir)
    {
        $this->baseDir = rtrim($baseDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    }

    public function register(): void
    {
        spl_autoload_register([$this, 'autoload']);
    }

    private function autoload(string $class): void
    {
        if (str_starts_with($class, 'AuthKit\\')) {
            $relative = substr($class, strlen('AuthKit\\'));
            $relativePath = str_replace('\\', DIRECTORY_SEPARATOR, $relative) . '.php';
            $file = $this->baseDir . $relativePath;
            if (is_file($file)) {
                require $file;
            }
        }
    }
}


