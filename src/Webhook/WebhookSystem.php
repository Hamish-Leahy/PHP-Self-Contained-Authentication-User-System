<?php
declare(strict_types=1);

namespace AuthKit\Webhook;

use AuthKit\Contracts\ClockInterface;
use AuthKit\Contracts\LoggerInterface;
use AuthKit\Database\DatabaseConnection;
use PDO;
use PDOException;
use RuntimeException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

final class WebhookSystem
{
    private const WEBHOOKS_TABLE = 'webhooks';
    private const DELIVERIES_TABLE = 'webhook_deliveries';
    private const MAX_RETRIES = 3;
    private const RETRY_DELAYS = [1, 5, 15]; // seconds

    public function __construct(
        private readonly DatabaseConnection $db,
        private readonly ClockInterface $clock,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    public function registerWebhook(
        string $name,
        string $url,
        array $events,
        array $headers = [],
        string $secret = null,
        bool $isActive = true
    ): Webhook {
        $webhookId = $this->generateWebhookId();
        $secret = $secret ?: $this->generateSecret();
        
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::WEBHOOKS_TABLE . " 
                (id, name, url, events, headers, secret, is_active, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $now = $this->clock->now();
            $stmt->execute([
                $webhookId,
                $name,
                $url,
                json_encode($events),
                json_encode($headers),
                $secret,
                $isActive ? 1 : 0,
                $now->format('Y-m-d H:i:s'),
                $now->format('Y-m-d H:i:s')
            ]);
            
            $webhook = new Webhook(
                id: $webhookId,
                name: $name,
                url: $url,
                events: $events,
                headers: $headers,
                secret: $secret,
                isActive: $isActive,
                createdAt: $now,
                updatedAt: $now
            );
            
            $this->logger?->info('webhook_registered', [
                'webhook_id' => $webhookId,
                'name' => $name,
                'url' => $url,
                'events' => $events
            ]);
            
            return $webhook;
            
        } catch (PDOException $e) {
            $this->logger?->error('webhook_registration_failed', [
                'name' => $name,
                'url' => $url,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to register webhook');
        }
    }

    public function triggerWebhook(string $event, array $payload, array $context = []): array
    {
        $webhooks = $this->getWebhooksForEvent($event);
        $results = [];
        
        foreach ($webhooks as $webhook) {
            try {
                $delivery = $this->createDelivery($webhook, $event, $payload, $context);
                $this->deliverWebhook($webhook, $delivery);
                $results[] = [
                    'webhook_id' => $webhook->id,
                    'status' => 'success',
                    'delivery_id' => $delivery->id
                ];
            } catch (Exception $e) {
                $this->logger?->error('webhook_delivery_failed', [
                    'webhook_id' => $webhook->id,
                    'event' => $event,
                    'error' => $e->getMessage()
                ]);
                
                $results[] = [
                    'webhook_id' => $webhook->id,
                    'status' => 'failed',
                    'error' => $e->getMessage()
                ];
            }
        }
        
        return $results;
    }

    public function deliverWebhook(Webhook $webhook, WebhookDelivery $delivery): void
    {
        $client = new Client([
            'timeout' => 30,
            'connect_timeout' => 10,
            'verify' => true
        ]);
        
        $payload = $this->buildPayload($delivery);
        $headers = $this->buildHeaders($webhook, $payload);
        
        try {
            $response = $client->post($webhook->url, [
                'headers' => $headers,
                'json' => $payload,
                'http_errors' => false
            ]);
            
            $this->updateDeliveryStatus(
                $delivery->id,
                'delivered',
                $response->getStatusCode(),
                $response->getBody()->getContents()
            );
            
            $this->logger?->info('webhook_delivered', [
                'webhook_id' => $webhook->id,
                'delivery_id' => $delivery->id,
                'status_code' => $response->getStatusCode()
            ]);
            
        } catch (RequestException $e) {
            $this->handleDeliveryFailure($delivery, $e);
        }
    }

    public function retryFailedDeliveries(): int
    {
        $failedDeliveries = $this->getFailedDeliveries();
        $retryCount = 0;
        
        foreach ($failedDeliveries as $delivery) {
            if ($delivery->retryCount >= self::MAX_RETRIES) {
                $this->markDeliveryAsPermanentlyFailed($delivery->id);
                continue;
            }
            
            $webhook = $this->getWebhook($delivery->webhookId);
            if (!$webhook) {
                continue;
            }
            
            try {
                $this->deliverWebhook($webhook, $delivery);
                $retryCount++;
            } catch (Exception $e) {
                $this->incrementRetryCount($delivery->id);
                $this->logger?->warning('webhook_retry_failed', [
                    'delivery_id' => $delivery->id,
                    'retry_count' => $delivery->retryCount + 1,
                    'error' => $e->getMessage()
                ]);
            }
        }
        
        return $retryCount;
    }

    public function getWebhookDeliveries(string $webhookId, int $limit = 50, int $offset = 0): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::DELIVERIES_TABLE . " 
                WHERE webhook_id = ? 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            ");
            
            $stmt->execute([$webhookId, $limit, $offset]);
            $deliveries = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $deliveries[] = $this->rowToDelivery($row);
            }
            
            return $deliveries;
            
        } catch (PDOException $e) {
            $this->logger?->error('webhook_deliveries_fetch_failed', [
                'webhook_id' => $webhookId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    public function getWebhookStats(string $webhookId): array
    {
        try {
            $pdo = $this->db->pdo();
            
            // Total deliveries
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as total FROM " . self::DELIVERIES_TABLE . " 
                WHERE webhook_id = ?
            ");
            $stmt->execute([$webhookId]);
            $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            // Successful deliveries
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as successful FROM " . self::DELIVERIES_TABLE . " 
                WHERE webhook_id = ? AND status = 'delivered'
            ");
            $stmt->execute([$webhookId]);
            $successful = $stmt->fetch(PDO::FETCH_ASSOC)['successful'];
            
            // Failed deliveries
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as failed FROM " . self::DELIVERIES_TABLE . " 
                WHERE webhook_id = ? AND status = 'failed'
            ");
            $stmt->execute([$webhookId]);
            $failed = $stmt->fetch(PDO::FETCH_ASSOC)['failed'];
            
            // Recent deliveries (last 24 hours)
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as recent FROM " . self::DELIVERIES_TABLE . " 
                WHERE webhook_id = ? AND created_at > ?
            ");
            $yesterday = $this->clock->now()->sub(new \DateInterval('P1D'));
            $stmt->execute([$webhookId, $yesterday->format('Y-m-d H:i:s')]);
            $recent = $stmt->fetch(PDO::FETCH_ASSOC)['recent'];
            
            return [
                'total_deliveries' => (int) $total,
                'successful_deliveries' => (int) $successful,
                'failed_deliveries' => (int) $failed,
                'success_rate' => $total > 0 ? round(($successful / $total) * 100, 2) : 0,
                'recent_deliveries' => (int) $recent
            ];
            
        } catch (PDOException $e) {
            $this->logger?->error('webhook_stats_fetch_failed', [
                'webhook_id' => $webhookId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function getWebhooksForEvent(string $event): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::WEBHOOKS_TABLE . " 
                WHERE is_active = 1 AND JSON_CONTAINS(events, ?)
            ");
            
            $stmt->execute([json_encode($event)]);
            $webhooks = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $webhooks[] = $this->rowToWebhook($row);
            }
            
            return $webhooks;
            
        } catch (PDOException $e) {
            $this->logger?->error('webhooks_fetch_failed', [
                'event' => $event,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function createDelivery(Webhook $webhook, string $event, array $payload, array $context): WebhookDelivery
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                INSERT INTO " . self::DELIVERIES_TABLE . " 
                (id, webhook_id, event, payload, context, status, created_at) 
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
            ");
            
            $deliveryId = $this->generateDeliveryId();
            $now = $this->clock->now();
            
            $stmt->execute([
                $deliveryId,
                $webhook->id,
                $event,
                json_encode($payload),
                json_encode($context),
                $now->format('Y-m-d H:i:s')
            ]);
            
            return new WebhookDelivery(
                id: $deliveryId,
                webhookId: $webhook->id,
                event: $event,
                payload: $payload,
                context: $context,
                status: 'pending',
                retryCount: 0,
                createdAt: $now
            );
            
        } catch (PDOException $e) {
            $this->logger?->error('delivery_creation_failed', [
                'webhook_id' => $webhook->id,
                'event' => $event,
                'error' => $e->getMessage()
            ]);
            throw new RuntimeException('Failed to create delivery');
        }
    }

    private function buildPayload(WebhookDelivery $delivery): array
    {
        return [
            'id' => $delivery->id,
            'event' => $delivery->event,
            'data' => $delivery->payload,
            'context' => $delivery->context,
            'timestamp' => $delivery->createdAt->format('c'),
            'version' => '1.0'
        ];
    }

    private function buildHeaders(Webhook $webhook, array $payload): array
    {
        $headers = array_merge([
            'Content-Type' => 'application/json',
            'User-Agent' => 'AuthKit-Webhook/1.0',
            'X-Webhook-Event' => $payload['event'],
            'X-Webhook-Delivery' => $payload['id']
        ], $webhook->headers);
        
        if ($webhook->secret) {
            $signature = $this->generateSignature($payload, $webhook->secret);
            $headers['X-Webhook-Signature'] = $signature;
        }
        
        return $headers;
    }

    private function generateSignature(array $payload, string $secret): string
    {
        $payloadString = json_encode($payload, JSON_UNESCAPED_SLASHES);
        return 'sha256=' . hash_hmac('sha256', $payloadString, $secret);
    }

    private function updateDeliveryStatus(
        string $deliveryId,
        string $status,
        int $responseCode = null,
        string $responseBody = null
    ): void {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::DELIVERIES_TABLE . " 
                SET status = ?, response_code = ?, response_body = ?, delivered_at = ? 
                WHERE id = ?
            ");
            
            $stmt->execute([
                $status,
                $responseCode,
                $responseBody,
                $this->clock->now()->format('Y-m-d H:i:s'),
                $deliveryId
            ]);
            
        } catch (PDOException $e) {
            $this->logger?->error('delivery_status_update_failed', [
                'delivery_id' => $deliveryId,
                'status' => $status,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function handleDeliveryFailure(WebhookDelivery $delivery, RequestException $e): void
    {
        $this->updateDeliveryStatus(
            $delivery->id,
            'failed',
            $e->getCode(),
            $e->getMessage()
        );
        
        $this->incrementRetryCount($delivery->id);
    }

    private function getFailedDeliveries(): array
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::DELIVERIES_TABLE . " 
                WHERE status = 'failed' AND retry_count < ? 
                ORDER BY created_at ASC
            ");
            
            $stmt->execute([self::MAX_RETRIES]);
            $deliveries = [];
            
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $deliveries[] = $this->rowToDelivery($row);
            }
            
            return $deliveries;
            
        } catch (PDOException $e) {
            $this->logger?->error('failed_deliveries_fetch_failed', [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    private function incrementRetryCount(string $deliveryId): void
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                UPDATE " . self::DELIVERIES_TABLE . " 
                SET retry_count = retry_count + 1 
                WHERE id = ?
            ");
            
            $stmt->execute([$deliveryId]);
            
        } catch (PDOException $e) {
            $this->logger?->error('retry_count_increment_failed', [
                'delivery_id' => $deliveryId,
                'error' => $e->getMessage()
            ]);
        }
    }

    private function markDeliveryAsPermanentlyFailed(string $deliveryId): void
    {
        $this->updateDeliveryStatus($deliveryId, 'permanently_failed');
    }

    private function getWebhook(string $webhookId): ?Webhook
    {
        try {
            $pdo = $this->db->pdo();
            $stmt = $pdo->prepare("
                SELECT * FROM " . self::WEBHOOKS_TABLE . " 
                WHERE id = ?
            ");
            
            $stmt->execute([$webhookId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $row ? $this->rowToWebhook($row) : null;
            
        } catch (PDOException $e) {
            $this->logger?->error('webhook_fetch_failed', [
                'webhook_id' => $webhookId,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    private function rowToWebhook(array $row): Webhook
    {
        return new Webhook(
            id: $row['id'],
            name: $row['name'],
            url: $row['url'],
            events: json_decode($row['events'], true),
            headers: json_decode($row['headers'], true),
            secret: $row['secret'],
            isActive: (bool) $row['is_active'],
            createdAt: new \DateTimeImmutable($row['created_at']),
            updatedAt: new \DateTimeImmutable($row['updated_at'])
        );
    }

    private function rowToDelivery(array $row): WebhookDelivery
    {
        return new WebhookDelivery(
            id: $row['id'],
            webhookId: $row['webhook_id'],
            event: $row['event'],
            payload: json_decode($row['payload'], true),
            context: json_decode($row['context'], true),
            status: $row['status'],
            retryCount: (int) $row['retry_count'],
            createdAt: new \DateTimeImmutable($row['created_at'])
        );
    }

    private function generateWebhookId(): string
    {
        return 'wh_' . bin2hex(random_bytes(16));
    }

    private function generateDeliveryId(): string
    {
        return 'del_' . bin2hex(random_bytes(16));
    }

    private function generateSecret(): string
    {
        return bin2hex(random_bytes(32));
    }
}

final class Webhook
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $url,
        public readonly array $events,
        public readonly array $headers,
        public readonly string $secret,
        public readonly bool $isActive,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt
    ) {
    }
}

final class WebhookDelivery
{
    public function __construct(
        public readonly string $id,
        public readonly string $webhookId,
        public readonly string $event,
        public readonly array $payload,
        public readonly array $context,
        public readonly string $status,
        public readonly int $retryCount,
        public readonly \DateTimeImmutable $createdAt
    ) {
    }
}
