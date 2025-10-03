<?php
declare(strict_types=1);

namespace AuthKit\Support\Clock;

use AuthKit\Contracts\ClockInterface;

final class SystemClock implements ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now');
    }
}


