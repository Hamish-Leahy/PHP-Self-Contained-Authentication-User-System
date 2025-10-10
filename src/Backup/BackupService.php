<?php
declare(strict_types=1);

namespace AuthKit\Backup;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;
use ZipArchive;

final class BackupService
{
    private const BACKUP_TABLE = 'backup_records';
    private const MAX_BACKUP_AGE = 30; // days
    private const MAX_BACKUP_SIZE = 1024 * 1024 * 1024; // 1GB

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly string $backupPath,
        private readonly ?LoggerInterface $logger = null
    ) {
        if (!is_dir($this->backupPath)) {
            mkdir($this->backupPath, 0755, true);
        }
    }

    public function createBackup(string $type = 'full', array $options = []): BackupRecord
    {
        $backupId = $this->generateBackupId();
        $backupPath = $this->backupPath . '/' . $backupId;
        
        try {
            // Create backup directory
            if (!is_dir($backupPath)) {
                mkdir($backupPath, 0755, true);
            }
            
            $startTime = $this->clock->now();
            
            // Create backup record
            $record = new BackupRecord(
                id: $backupId,
                type: $type,
                status: 'in_progress',
                path: $backupPath,
                size: 0,
                createdAt: $startTime,
                completedAt: null
            );
            
            $this->saveBackupRecord($record);
            
            $this->logger?->info('backup_started', [
                'backup_id' => $backupId,
                'type' => $type
            ]);
            
            // Perform backup based on type
            switch ($type) {
                case 'full':
                    $this->createFullBackup($record, $options);
                    break;
                case 'database':
                    $this->createDatabaseBackup($record, $options);
                    break;
                case 'files':
                    $this->createFilesBackup($record, $options);
                    break;
                case 'incremental':
                    $this->createIncrementalBackup($record, $options);
                    break;
                default:
                    throw new RuntimeException("Unknown backup type: {$type}");
            }
            
            // Calculate backup size
            $size = $this->calculateBackupSize($backupPath);
            
            // Update record
            $record = new BackupRecord(
                id: $backupId,
                type: $type,
                status: 'completed',
                path: $backupPath,
                size: $size,
                createdAt: $startTime,
                completedAt: $this->clock->now()
            );
            
            $this->saveBackupRecord($record);
            
            $this->logger?->info('backup_completed', [
                'backup_id' => $backupId,
                'type' => $type,
                'size' => $size,
                'duration' => $record->completedAt->getTimestamp() - $startTime->getTimestamp()
            ]);
            
            return $record;
            
        } catch (Exception $e) {
            // Mark backup as failed
            $record = new BackupRecord(
                id: $backupId,
                type: $type,
                status: 'failed',
                path: $backupPath,
                size: 0,
                createdAt: $startTime,
                completedAt: $this->clock->now()
            );
            
            $this->saveBackupRecord($record);
            
            $this->logger?->error('backup_failed', [
                'backup_id' => $backupId,
                'type' => $type,
                'error' => $e->getMessage()
            ]);
            
            throw $e;
        }
    }

    public function restoreBackup(string $backupId, array $options = []): bool
    {
        try {
            $record = $this->getBackupRecord($backupId);
            if (!$record) {
                throw new RuntimeException("Backup not found: {$backupId}");
            }
            
            if ($record->status !== 'completed') {
                throw new RuntimeException("Backup is not completed: {$backupId}");
            }
            
            $this->logger?->info('backup_restore_started', [
                'backup_id' => $backupId,
                'type' => $record->type
            ]);
            
            // Perform restore based on type
            switch ($record->type) {
                case 'full':
                    $this->restoreFullBackup($record, $options);
                    break;
                case 'database':
                    $this->restoreDatabaseBackup($record, $options);
                    break;
                case 'files':
                    $this->restoreFilesBackup($record, $options);
                    break;
                case 'incremental':
                    $this->restoreIncrementalBackup($record, $options);
                    break;
                default:
                    throw new RuntimeException("Unknown backup type: {$record->type}");
            }
            
            $this->logger?->info('backup_restore_completed', [
                'backup_id' => $backupId,
                'type' => $record->type
            ]);
            
            return true;
            
        } catch (Exception $e) {
            $this->logger?->error('backup_restore_failed', [
                'backup_id' => $backupId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function listBackups(array $filters = []): array
    {
        try {
            $pdo = $this->db->pdo();
            
            $sql = "SELECT * FROM " . self::BACKUP_TABLE . " WHERE 1=1";
            $params = [];
            
            if (!empty($filters['type'])) {
                $sql .= " AND type = ?";
                $params[] = $filters['type'];
            }
            
            if (!empty($filters['status'])) {
                $sql .= " AND status = ?";
                $params[] = $filters['status'];
            }
            
            if (!empty($filters['created_since'])) {
                $sql .= " AND created_at >= ?";
                $params[] = $filters['created_since'];
            }
            
            $sql .= " ORDER BY created_at DESC";
            
            if (!empty($filters['limit'])) {
                $sql .= " LIMIT ?";
                $params[] = $filters['limit'];
            }
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            
            $backups = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $backups[] = $this->rowToBackupRecord($row);
            }
            
            return $backups;
            
        } catch (PDOException $e) {
            $this->logger?->error('backup_list_failed', [
                'filters' => $filters,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function deleteBackup(string $backupId): bool
    {
        try {
            $record = $this->getBackupRecord($backupId);
            if (!$record) {
                return false;
            }
            
            // Delete backup files
            if (is_dir($record->path)) {
                $this->deleteDirectory($record->path);
            }
            
            // Delete record from database
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                DELETE FROM " . self::BACKUP_TABLE . " 
                WHERE id = ?
            ");
            
            $result = $stmt->execute([$backupId]);
            
            if ($result) {
                $this->logger?->info('backup_deleted', [
                    'backup_id' => $backupId,
                    'type' => $record->type
                ]);
            }
            
            return $result;
            
        } catch (Exception $e) {
            $this->logger?->error('backup_delete_failed', [
                'backup_id' => $backupId,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    public function cleanupOldBackups(): int
    {
        try {
            $cutoffDate = $this->clock->now()->sub(new \DateInterval('P' . self::MAX_BACKUP_AGE . 'D'));
            
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::BACKUP_TABLE . " 
                WHERE created_at < ?
            ");
            
            $stmt->execute([$cutoffDate->format('Y-m-d H:i:s')]);
            $oldBackups = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $deleted = 0;
            foreach ($oldBackups as $backup) {
                if ($this->deleteBackup($backup['id'])) {
                    $deleted++;
                }
            }
            
            if ($deleted > 0) {
                $this->logger?->info('old_backups_cleaned', [
                    'deleted_count' => $deleted,
                    'cutoff_date' => $cutoffDate->format('Y-m-d H:i:s')
                ]);
            }
            
            return $deleted;
            
        } catch (Exception $e) {
            $this->logger?->error('backup_cleanup_failed', [
                'error' => $e->getMessage()
            ]);
            return 0;
        }
    }

    public function getBackupStats(): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Total backups
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as total FROM " . self::BACKUP_TABLE . "
            ");
            $stmt->execute();
            $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            // Total size
            $stmt = $pdo->prepare("
                SELECT SUM(size) as total_size FROM " . self::BACKUP_TABLE . "
                WHERE status = 'completed'
            ");
            $stmt->execute();
            $totalSize = $stmt->fetch(PDO::FETCH_ASSOC)['total_size'] ?? 0;
            
            // By type
            $stmt = $pdo->prepare("
                SELECT type, COUNT(*) as count, SUM(size) as size
                FROM " . self::BACKUP_TABLE . "
                WHERE status = 'completed'
                GROUP BY type
            ");
            $stmt->execute();
            $byType = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // By status
            $stmt = $pdo->prepare("
                SELECT status, COUNT(*) as count
                FROM " . self::BACKUP_TABLE . "
                GROUP BY status
            ");
            $stmt->execute();
            $byStatus = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            return [
                'total_backups' => (int) $total,
                'total_size' => (int) $totalSize,
                'by_type' => $byType,
                'by_status' => $byStatus,
                'disk_usage' => $this->getDiskUsage()
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('backup_stats_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function createFullBackup(BackupRecord $record, array $options): void
    {
        // Create database backup
        $this->createDatabaseBackup($record, $options);
        
        // Create files backup
        $this->createFilesBackup($record, $options);
        
        // Create configuration backup
        $this->createConfigBackup($record, $options);
    }

    private function createDatabaseBackup(BackupRecord $record, array $options): void
    {
        $dbPath = $record->path . '/database.sql';
        
        // Get database configuration
        $config = $this->getDatabaseConfig();
        
        // Create mysqldump command
        $command = sprintf(
            'mysqldump --host=%s --port=%s --user=%s --password=%s %s > %s',
            escapeshellarg($config['host']),
            escapeshellarg($config['port']),
            escapeshellarg($config['username']),
            escapeshellarg($config['password']),
            escapeshellarg($config['database']),
            escapeshellarg($dbPath)
        );
        
        exec($command, $output, $returnCode);
        
        if ($returnCode !== 0) {
            throw new RuntimeException('Database backup failed');
        }
        
        $this->logger?->debug('database_backup_created', [
            'backup_id' => $record->id,
            'path' => $dbPath
        ]);
    }

    private function createFilesBackup(BackupRecord $record, array $options): void
    {
        $filesPath = $record->path . '/files.zip';
        $sourcePath = $options['source_path'] ?? __DIR__ . '/../../';
        
        $zip = new ZipArchive();
        if ($zip->open($filesPath, ZipArchive::CREATE) !== TRUE) {
            throw new RuntimeException('Cannot create files backup');
        }
        
        $this->addDirectoryToZip($zip, $sourcePath, '');
        $zip->close();
        
        $this->logger?->debug('files_backup_created', [
            'backup_id' => $record->id,
            'path' => $filesPath
        ]);
    }

    private function createConfigBackup(BackupRecord $record, array $options): void
    {
        $configPath = $record->path . '/config.json';
        
        $config = [
            'php_version' => PHP_VERSION,
            'backup_created_at' => $this->clock->now()->format('c'),
            'backup_type' => $record->type,
            'options' => $options
        ];
        
        file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT));
        
        $this->logger?->debug('config_backup_created', [
            'backup_id' => $record->id,
            'path' => $configPath
        ]);
    }

    private function createIncrementalBackup(BackupRecord $record, array $options): void
    {
        // Get last backup
        $lastBackup = $this->getLastBackup();
        
        if (!$lastBackup) {
            // No previous backup, create full backup
            $this->createFullBackup($record, $options);
            return;
        }
        
        // Create incremental backup based on changes since last backup
        $this->createFilesBackup($record, array_merge($options, [
            'since' => $lastBackup->createdAt
        ]));
    }

    private function restoreFullBackup(BackupRecord $record, array $options): void
    {
        $this->restoreDatabaseBackup($record, $options);
        $this->restoreFilesBackup($record, $options);
    }

    private function restoreDatabaseBackup(BackupRecord $record, array $options): void
    {
        $dbPath = $record->path . '/database.sql';
        
        if (!file_exists($dbPath)) {
            throw new RuntimeException('Database backup file not found');
        }
        
        $config = $this->getDatabaseConfig();
        
        $command = sprintf(
            'mysql --host=%s --port=%s --user=%s --password=%s %s < %s',
            escapeshellarg($config['host']),
            escapeshellarg($config['port']),
            escapeshellarg($config['username']),
            escapeshellarg($config['password']),
            escapeshellarg($config['database']),
            escapeshellarg($dbPath)
        );
        
        exec($command, $output, $returnCode);
        
        if ($returnCode !== 0) {
            throw new RuntimeException('Database restore failed');
        }
    }

    private function restoreFilesBackup(BackupRecord $record, array $options): void
    {
        $filesPath = $record->path . '/files.zip';
        
        if (!file_exists($filesPath)) {
            throw new RuntimeException('Files backup not found');
        }
        
        $zip = new ZipArchive();
        if ($zip->open($filesPath) !== TRUE) {
            throw new RuntimeException('Cannot open files backup');
        }
        
        $zip->extractTo($options['target_path'] ?? __DIR__ . '/../../');
        $zip->close();
    }

    private function restoreIncrementalBackup(BackupRecord $record, array $options): void
    {
        // Restore base backup first
        $baseBackup = $this->getLastFullBackup();
        if ($baseBackup) {
            $this->restoreFullBackup($baseBackup, $options);
        }
        
        // Then apply incremental changes
        $this->restoreFilesBackup($record, $options);
    }

    private function addDirectoryToZip(ZipArchive $zip, string $dir, string $zipPath): void
    {
        $files = scandir($dir);
        
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }
            
            $fullPath = $dir . '/' . $file;
            $zipFullPath = $zipPath . $file;
            
            if (is_dir($fullPath)) {
                $zip->addEmptyDir($zipFullPath);
                $this->addDirectoryToZip($zip, $fullPath, $zipFullPath . '/');
            } else {
                $zip->addFile($fullPath, $zipFullPath);
            }
        }
    }

    private function deleteDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }
        
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->deleteDirectory($path) : unlink($path);
        }
        
        return rmdir($dir);
    }

    private function calculateBackupSize(string $path): int
    {
        $size = 0;
        
        if (is_file($path)) {
            return filesize($path);
        }
        
        if (is_dir($path)) {
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path)
            );
            
            foreach ($files as $file) {
                if ($file->isFile()) {
                    $size += $file->getSize();
                }
            }
        }
        
        return $size;
    }

    private function getDiskUsage(): array
    {
        $total = disk_total_space($this->backupPath);
        $free = disk_free_space($this->backupPath);
        $used = $total - $free;
        
        return [
            'total' => $total,
            'used' => $used,
            'free' => $free,
            'percentage' => $total > 0 ? round(($used / $total) * 100, 2) : 0
        ];
    }

    private function getDatabaseConfig(): array
    {
        // This would typically come from your database configuration
        return [
            'host' => '127.0.0.1',
            'port' => '3306',
            'username' => 'root',
            'password' => '',
            'database' => 'auth'
        ];
    }

    private function getLastBackup(): ?BackupRecord
    {
        $backups = $this->listBackups(['limit' => 1]);
        return !empty($backups) ? $backups[0] : null;
    }

    private function getLastFullBackup(): ?BackupRecord
    {
        $backups = $this->listBackups(['type' => 'full', 'limit' => 1]);
        return !empty($backups) ? $backups[0] : null;
    }

    private function saveBackupRecord(BackupRecord $record): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::BACKUP_TABLE . " 
                (id, type, status, path, size, created_at, completed_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                status = VALUES(status),
                path = VALUES(path),
                size = VALUES(size),
                completed_at = VALUES(completed_at)
            ");
            
            $stmt->execute([
                $record->id,
                $record->type,
                $record->status,
                $record->path,
                $record->size,
                $record->createdAt->format('Y-m-d H:i:s'),
                $record->completedAt?->format('Y-m-d H:i:s')
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('backup_record_save_failed', [
                'backup_id' => $record->id,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function getBackupRecord(string $backupId): ?BackupRecord
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::BACKUP_TABLE . " 
                WHERE id = ?
            ");
            
            $stmt->execute([$backupId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $row ? $this->rowToBackupRecord($row) : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('backup_record_fetch_failed', [
                'backup_id' => $backupId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function rowToBackupRecord(array $row): BackupRecord
    {
        return new BackupRecord(
            id: $row['id'],
            type: $row['type'],
            status: $row['status'],
            path: $row['path'],
            size: (int) $row['size'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            completedAt: $row['completed_at'] ? new \DateTimeImmutable($row['completed_at']) : null
        );
    }

    private function generateBackupId(): string
    {
        return 'backup_' . bin2hex(random_bytes(16));
    }
}

final class BackupRecord
{
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $status,
        public readonly string $path,
        public readonly int $size,
        public readonly \DateTimeImmutable $createdAt,
        public readonly ?\DateTimeImmutable $completedAt
    ) {
    }
}
