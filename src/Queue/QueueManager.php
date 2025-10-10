<?php
declare(strict_types=1);

namespace AuthKit\Queue;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;
use Redis;
use RedisException;

final class QueueManager
{
    private const JOBS_TABLE = 'queue_jobs';
    private const FAILED_JOBS_TABLE = 'failed_jobs';
    private const MAX_ATTEMPTS = 3;
    private const DEFAULT_TIMEOUT = 60; // seconds

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly Redis $redis,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function push(string $queue, string $jobClass, array $payload = [], array $options = []): string
    {
        $jobId = $this->generateJobId();
        $delay = $options['delay'] ?? 0;
        $priority = $options['priority'] ?? 0;
        $attempts = $options['attempts'] ?? self::MAX_ATTEMPTS;
        $timeout = $options['timeout'] ?? self::DEFAULT_TIMEOUT;
        
        $availableAt = $this->clock->now()->add(new \DateInterval('PT' . $delay . 'S'));
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::JOBS_TABLE . " 
                (id, queue, job_class, payload, attempts, timeout, priority, available_at, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $jobId,
                $queue,
                $jobClass,
                json_encode($payload),
                $attempts,
                $timeout,
                $priority,
                $availableAt->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            // Add to Redis queue for immediate processing
            $this->addToRedisQueue($queue, $jobId, $priority);
            
            $this->logger?->info('job_pushed', [
                'job_id' => $jobId,
                'queue' => $queue,
                'job_class' => $jobClass,
                'delay' => $delay
            ]);
            
            return $jobId;
            
        } catch (PDOException $e) {
            $this->logger?->error('job_push_failed', [
                'queue' => $queue,
                'job_class' => $jobClass,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to push job to queue');
        }
    }

    public function pop(string $queue): ?Job
    {
        try {
            // Try Redis first for immediate processing
            $jobId = $this->popFromRedisQueue($queue);
            
            if (!$jobId) {
                // Fallback to database for delayed jobs
                $jobId = $this->popFromDatabaseQueue($queue);
            }
            
            if (!$jobId) {
                return null;
            }
            
            $job = $this->getJob($jobId);
            if (!$job) {
                return null;
            }
            
            // Mark as processing
            $this->markJobAsProcessing($jobId);
            
            return $job;
            
        } catch (Exception $e) {
            $this->logger?->error('job_pop_failed', [
                'queue' => $queue,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function process(Job $job): void
    {
        $startTime = microtime(true);
        
        try {
            $this->logger?->info('job_processing_started', [
                'job_id' => $job->id,
                'queue' => $job->queue,
                'job_class' => $job->jobClass
            ]);
            
            // Create job instance and execute
            $jobInstance = new $job->jobClass();
            $jobInstance->handle($job->payload);
            
            // Mark as completed
            $this->markJobAsCompleted($job->id);
            
            $processingTime = microtime(true) - $startTime;
            
            $this->logger?->info('job_processing_completed', [
                'job_id' => $job->id,
                'processing_time' => round($processingTime, 3)
            ]);
            
        } catch (Exception $e) {
            $this->handleJobFailure($job, $e);
        }
    }

    public function retry(string $jobId): bool
    {
        try {
            $job = $this->getJob($jobId);
            if (!$job) {
                return false;
            }
            
            if ($job->attempts >= $job->maxAttempts) {
                $this->markJobAsFailed($jobId, 'Max attempts exceeded');
                return false;
            }
            
            // Increment attempts and reset status
            $this->incrementJobAttempts($jobId);
            $this->resetJobStatus($jobId);
            
            // Re-queue the job
            $this->addToRedisQueue($job->queue, $jobId, $job->priority);
            
            $this->logger?->info('job_retried', [
                'job_id' => $jobId,
                'attempts' => $job->attempts + 1
            ]);
            
            return true;
            
        } catch (Exception $e) {
            $this->logger?->error('job_retry_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function getFailedJobs(int $limit = 50, int $offset = 0): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::FAILED_JOBS_TABLE . " 
                ORDER BY failed_at DESC 
                LIMIT ? OFFSET ?
            ");
            
            $stmt->execute([$limit, $offset]);
            $jobs = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $jobs[] = $this->rowToFailedJob($row);
            }
            
            return $jobs;
            
        } catch (PDOException $e) {
            $this->logger?->error('failed_jobs_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getQueueStats(string $queue): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Pending jobs
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as pending 
                FROM " . self::JOBS_TABLE . " 
                WHERE queue = ? AND status = 'pending'
            ");
            $stmt->execute([$queue]);
            $pending = $stmt->fetch(PDO::FETCH_ASSOC)['pending'];
            
            // Processing jobs
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as processing 
                FROM " . self::JOBS_TABLE . " 
                WHERE queue = ? AND status = 'processing'
            ");
            $stmt->execute([$queue]);
            $processing = $stmt->fetch(PDO::FETCH_ASSOC)['processing'];
            
            // Failed jobs
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as failed 
                FROM " . self::FAILED_JOBS_TABLE . " 
                WHERE queue = ?
            ");
            $stmt->execute([$queue]);
            $failed = $stmt->fetch(PDO::FETCH_ASSOC)['failed'];
            
            // Redis queue length
            $redisLength = $this->redis->llen("queue:{$queue}");
            
            return [
                'pending' => (int) $pending,
                'processing' => (int) $processing,
                'failed' => (int) $failed,
                'redis_length' => $redisLength,
                'total' => $pending + $processing + $failed
            ];
            
        } catch (Exception $e) {
            $this->logger?->error('queue_stats_fetch_failed', [
                'queue' => $queue,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function clearQueue(string $queue): int
    {
        try {
            $pdo = $this->db->pdo();
            
            // Clear pending jobs
            $stmt = $pdo->prepare("
                DELETE FROM " . self::JOBS_TABLE . " 
                WHERE queue = ? AND status = 'pending'
            ");
            $stmt->execute([$queue]);
            $deleted = $stmt->rowCount();
            
            // Clear Redis queue
            $this->redis->del("queue:{$queue}");
            
            $this->logger?->info('queue_cleared', [
                'queue' => $queue,
                'jobs_deleted' => $deleted
            ]);
            
            return $deleted;
            
        } catch (Exception $e) {
            $this->logger?->error('queue_clear_failed', [
                'queue' => $queue,
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function scheduleJob(string $queue, string $jobClass, array $payload, \DateTimeImmutable $scheduleAt): string
    {
        return $this->push($queue, $jobClass, $payload, [
            'delay' => $scheduleAt->getTimestamp() - $this->clock->now()->getTimestamp()
        ]);
    }

    public function processScheduledJobs(): int
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT id FROM " . self::JOBS_TABLE . " 
                WHERE status = 'pending' 
                AND available_at <= ? 
                ORDER BY priority DESC, created_at ASC
                LIMIT 100
            ");
            
            $now = $this->clock->now();
            $stmt->execute([$now->format('Y-m-d H:i:s')]);
            
            $jobIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $processed = 0;
            
            foreach ($jobIds as $jobId) {
                $job = $this->getJob($jobId);
                if ($job) {
                    $this->addToRedisQueue($job->queue, $jobId, $job->priority);
                    $processed++;
                }
            }
            
            if ($processed > 0) {
                $this->logger?->info('scheduled_jobs_processed', [
                    'count' => $processed
                ]);
            }
            
            return $processed;
            
        } catch (Exception $e) {
            $this->logger?->error('scheduled_jobs_processing_failed', [
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    private function addToRedisQueue(string $queue, string $jobId, int $priority): void
    {
        try {
            $this->redis->lpush("queue:{$queue}", $jobId);
        } catch (RedisException $e) {
            $this->logger?->error('redis_queue_add_failed', [
                'queue' => $queue,
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function popFromRedisQueue(string $queue): ?string
    {
        try {
            return $this->redis->rpop("queue:{$queue}");
        } catch (RedisException $e) {
            $this->logger?->error('redis_queue_pop_failed', [
                'queue' => $queue,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function popFromDatabaseQueue(string $queue): ?string
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT id FROM " . self::JOBS_TABLE . " 
                WHERE queue = ? AND status = 'pending' 
                AND available_at <= ? 
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
            ");
            
            $now = $this->clock->now();
            $stmt->execute([$queue, $now->format('Y-m-d H:i:s')]);
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result ? $result['id'] : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('database_queue_pop_failed', [
                'queue' => $queue,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function getJob(string $jobId): ?Job
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::JOBS_TABLE . " 
                WHERE id = ?
            ");
            
            $stmt->execute([$jobId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $row ? $this->rowToJob($row) : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('job_fetch_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function markJobAsProcessing(string $jobId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::JOBS_TABLE . " 
                SET status = 'processing', started_at = ? 
                WHERE id = ?
            ");
            
            $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $jobId
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('job_mark_processing_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function markJobAsCompleted(string $jobId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::JOBS_TABLE . " 
                SET status = 'completed', completed_at = ? 
                WHERE id = ?
            ");
            
            $stmt->execute([
                $this->clock->now()->format('Y-m-d H:i:s'),
                $jobId
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('job_mark_completed_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function handleJobFailure(Job $job, Exception $e): void
    {
        $this->logger?->error('job_processing_failed', [
            'job_id' => $job->id,
            'queue' => $job->queue,
            'job_class' => $job->jobClass,
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        
        if ($job->attempts >= $job->maxAttempts) {
            $this->markJobAsFailed($job->id, $e->getMessage());
        } else {
            $this->incrementJobAttempts($job->id);
            $this->resetJobStatus($job->id);
        }
    }

    private function markJobAsFailed(string $jobId, string $error): void
    {
        try {
            $pdo = $this->db->pdo();
            $pdo->beginTransaction();
            
            // Get job details
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::JOBS_TABLE . " 
                WHERE id = ?
            ");
            $stmt->execute([$jobId]);
            $job = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($job) {
                // Move to failed jobs table
                $stmt = $pdo->prepare("
                    INSERT INTO " . self::FAILED_JOBS_TABLE . " 
                    (id, queue, job_class, payload, error, failed_at) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ");
                
                $stmt->execute([
                    $jobId,
                    $job['queue'],
                    $job['job_class'],
                    $job['payload'],
                    $error,
                    $this->clock->now()->format('Y-m-d H:i:s')
                ]);
                
                // Delete from jobs table
                $stmt = $pdo->prepare("
                    DELETE FROM " . self::JOBS_TABLE . " 
                    WHERE id = ?
                ");
                $stmt->execute([$jobId]);
            }
            
            $pdo->commit();
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            $this->logger?->error('job_mark_failed_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function incrementJobAttempts(string $jobId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::JOBS_TABLE . " 
                SET attempts = attempts + 1 
                WHERE id = ?
            ");
            
            $stmt->execute([$jobId]);
            
        } catch (PDOException $e) {
            $this->logger?->error('job_increment_attempts_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function resetJobStatus(string $jobId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::JOBS_TABLE . " 
                SET status = 'pending', started_at = NULL, completed_at = NULL 
                WHERE id = ?
            ");
            
            $stmt->execute([$jobId]);
            
        } catch (PDOException $e) {
            $this->logger?->error('job_reset_status_failed', [
                'job_id' => $jobId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function rowToJob(array $row): Job
    {
        return new Job(
            id: $row['id'],
            queue: $row['queue'],
            jobClass: $row['job_class'],
            payload: json_decode($row['payload'], true),
            attempts: (int) $row['attempts'],
            maxAttempts: (int) $row['attempts'],
            timeout: (int) $row['timeout'],
            priority: (int) $row['priority'],
            status: $row['status'],
            createdAt: new \DateTimeImmutable($row['created_at'])
        );
    }

    private function rowToFailedJob(array $row): FailedJob
    {
        return new FailedJob(
            id: $row['id'],
            queue: $row['queue'],
            jobClass: $row['job_class'],
            payload: json_decode($row['payload'], true),
            error: $row['error'],
            failedAt: new \DateTimeImmutable($row['failed_at'])
        );
    }

    private function generateJobId(): string
    {
        return 'job_' . bin2hex(random_bytes(16));
    }
}

final class Job
{
    public function __construct(
        public readonly string $id,
        public readonly string $queue,
        public readonly string $jobClass,
        public readonly array $payload,
        public readonly int $attempts,
        public readonly int $maxAttempts,
        public readonly int $timeout,
        public readonly int $priority,
        public readonly string $status,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}

final class FailedJob
{
    public function __construct(
        public readonly string $id,
        public readonly string $queue,
        public readonly string $jobClass,
        public readonly array $payload,
        public readonly string $error,
        public readonly \DateTimeImmutable $failedAt
    ) {
    }
}

interface JobInterface
{
    public function handle(array $payload): void;
}
