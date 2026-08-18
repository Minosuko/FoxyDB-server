<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;

final readonly class Config
{
    public function __construct(
        public string $host,
        public int $port,
        public string $dataDirectory,
        public int $maxFrameBytes = 8_388_608,
        public int $chunkBytes = 1_048_576,
        public int $inlineValueBytes = 65_536,
        public int $maxMaterializedBytes = 67_108_864,
        public int $idleTimeoutSeconds = 300,
        public bool $syncWrites = true,
        public int $maxConnections = 256,
        public int $maxTransfersPerClient = 8,
        public int $maxGlobalTransfers = 64,
        public int $maxUploadBytes = 1_073_741_824,
        public ?string $logDirectory = null,
        public int $logMaxBytes = 10_485_760,
        public int $logMaxFiles = 5,
        public int $slowQueryMilliseconds = 1_000,
        public bool $enableLog = true,
        public ?string $socket = null,
        public ?string $logError = null,
        public bool $slowQueryLog = false,
        public ?string $slowQueryLogFile = null,
        public int $maxConcurrentQueries = 32,
        public int $maxQueuedQueriesPerClient = 8,
        public bool $replicationEnabled = false,
        public int $replicationRetentionHours = 24,
        public bool $tlsEnabled = false,
    ) {
        if ($port < 1 || $port > 65_535) {
            throw new FoxyException('Port must be between 1 and 65535.', 'INVALID_CONFIG');
        }
        if ($maxFrameBytes < 1_024 || $maxFrameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || $chunkBytes < 1 || $inlineValueBytes < 0) {
            throw new FoxyException('Invalid frame or chunk size configuration.', 'INVALID_CONFIG');
        }
        if ($maxMaterializedBytes < 1 || $maxMaterializedBytes > PHP_INT_MAX
            || $idleTimeoutSeconds < 1
            || $maxConnections < 1 || $maxTransfersPerClient < 1 || $maxGlobalTransfers < 1
            || $maxConcurrentQueries < 1 || $maxQueuedQueriesPerClient < 1
            || $maxUploadBytes < 1 || $logMaxBytes < 1_024 || $logMaxFiles < 1
            || $slowQueryMilliseconds < 0) {
            throw new FoxyException('Resource limits must be positive.', 'INVALID_CONFIG');
        }
        if ($socket !== null && $socket === '') {
            throw new FoxyException('Socket path must not be empty.', 'INVALID_CONFIG');
        }
        if ($replicationRetentionHours < 0) {
            throw new FoxyException('Replication retention must not be negative.', 'INVALID_CONFIG');
        }
    }

    public static function fromEnvironment(?string $baseDirectory = null): self
    {
        $baseDirectory ??= dirname(__DIR__);
        $data = self::env('FOXYDB_DATA_DIR') ?? $baseDirectory . DIRECTORY_SEPARATOR . 'data';
        $dataDirectory = self::absolutePath($data, $baseDirectory);
        $ini = self::readIniFile($dataDirectory);
        return new self(
            host: self::env('FOXYDB_HOST') ?? $ini['host'] ?? '127.0.0.1',
            port: self::envInt('FOXYDB_PORT', (int) ($ini['port'] ?? 2002)),
            dataDirectory: isset($ini['datadir']) ? self::absolutePath($ini['datadir'], $baseDirectory) : $dataDirectory,
            maxFrameBytes: self::envInt('FOXYDB_MAX_FRAME_BYTES', 8_388_608),
            chunkBytes: self::envInt('FOXYDB_CHUNK_BYTES', 1_048_576),
            inlineValueBytes: self::envInt('FOXYDB_INLINE_VALUE_BYTES', 65_536),
            maxMaterializedBytes: self::envInt('FOXYDB_MAX_MATERIALIZED_BYTES', 67_108_864),
            idleTimeoutSeconds: self::envInt('FOXYDB_IDLE_TIMEOUT', 300),
            syncWrites: self::envBool('FOXYDB_SYNC_WRITES', true),
            maxConnections: self::envInt('FOXYDB_MAX_CONNECTIONS', 256),
            maxTransfersPerClient: self::envInt('FOXYDB_MAX_TRANSFERS', 8),
            maxGlobalTransfers: self::envInt('FOXYDB_MAX_GLOBAL_TRANSFERS', 64),
            maxUploadBytes: self::envInt('FOXYDB_MAX_UPLOAD_BYTES', 1_073_741_824),
            logDirectory: self::env('FOXYDB_LOG_DIR') ?? null,
            logMaxBytes: self::envInt('FOXYDB_LOG_MAX_BYTES', 10_485_760),
            logMaxFiles: self::envInt('FOXYDB_LOG_MAX_FILES', 5),
            slowQueryMilliseconds: self::envInt('FOXYDB_SLOW_QUERY_MS', isset($ini['long_query_time']) ? (int) ((float) $ini['long_query_time'] * 1000) : 1_000),
            enableLog: self::envBool('FOXYDB_ENABLE_LOG', true),
            socket: self::env('FOXYDB_SOCKET') ?? $ini['socket'] ?? null,
            logError: self::env('FOXYDB_LOG_ERROR') ?? $ini['log_error'] ?? null,
            slowQueryLog: self::envBool('FOXYDB_SLOW_QUERY_LOG', self::iniBool($ini['slow_query_log'] ?? null, false)),
            slowQueryLogFile: self::env('FOXYDB_SLOW_QUERY_LOG_FILE') ?? $ini['slow_query_log_file'] ?? null,
            maxConcurrentQueries: self::envInt('FOXYDB_MAX_CONCURRENT_QUERIES', 32),
            maxQueuedQueriesPerClient: self::envInt('FOXYDB_MAX_QUEUED_QUERIES', 8),
            replicationEnabled: self::envBool('FOXYDB_REPLICATION', false),
            replicationRetentionHours: self::envInt('FOXYDB_REPLICATION_RETENTION_HOURS', 24),
            tlsEnabled: self::envBool('FOXYDB_TLS', self::iniBool($ini['tls'] ?? null, false)),
        );
    }

    public function withOverrides(array $overrides): self
    {
        return new self(
            host: (string) ($overrides['host'] ?? $this->host),
            port: (int) ($overrides['port'] ?? $this->port),
            dataDirectory: (string) ($overrides['dataDirectory'] ?? $this->dataDirectory),
            maxFrameBytes: (int) ($overrides['maxFrameBytes'] ?? $this->maxFrameBytes),
            chunkBytes: (int) ($overrides['chunkBytes'] ?? $this->chunkBytes),
            inlineValueBytes: (int) ($overrides['inlineValueBytes'] ?? $this->inlineValueBytes),
            maxMaterializedBytes: (int) ($overrides['maxMaterializedBytes'] ?? $this->maxMaterializedBytes),
            idleTimeoutSeconds: (int) ($overrides['idleTimeoutSeconds'] ?? $this->idleTimeoutSeconds),
            syncWrites: (bool) ($overrides['syncWrites'] ?? $this->syncWrites),
            maxConnections: (int) ($overrides['maxConnections'] ?? $this->maxConnections),
            maxTransfersPerClient: (int) ($overrides['maxTransfersPerClient'] ?? $this->maxTransfersPerClient),
            maxGlobalTransfers: (int) ($overrides['maxGlobalTransfers'] ?? $this->maxGlobalTransfers),
            maxUploadBytes: (int) ($overrides['maxUploadBytes'] ?? $this->maxUploadBytes),
            logDirectory: array_key_exists('logDirectory', $overrides)
                ? ($overrides['logDirectory'] === null ? null : (string) $overrides['logDirectory'])
                : $this->logDirectory,
            logMaxBytes: (int) ($overrides['logMaxBytes'] ?? $this->logMaxBytes),
            logMaxFiles: (int) ($overrides['logMaxFiles'] ?? $this->logMaxFiles),
            slowQueryMilliseconds: (int) ($overrides['slowQueryMilliseconds'] ?? $this->slowQueryMilliseconds),
            enableLog: (bool) ($overrides['enableLog'] ?? $this->enableLog),
            socket: array_key_exists('socket', $overrides)
                ? ($overrides['socket'] === null ? null : (string) $overrides['socket'])
                : $this->socket,
            logError: array_key_exists('logError', $overrides)
                ? ($overrides['logError'] === null ? null : (string) $overrides['logError'])
                : $this->logError,
            slowQueryLog: (bool) ($overrides['slowQueryLog'] ?? $this->slowQueryLog),
            slowQueryLogFile: array_key_exists('slowQueryLogFile', $overrides)
                ? ($overrides['slowQueryLogFile'] === null ? null : (string) $overrides['slowQueryLogFile'])
                : $this->slowQueryLogFile,
            maxConcurrentQueries: (int) ($overrides['maxConcurrentQueries'] ?? $this->maxConcurrentQueries),
            maxQueuedQueriesPerClient: (int) ($overrides['maxQueuedQueriesPerClient'] ?? $this->maxQueuedQueriesPerClient),
            replicationEnabled: (bool) ($overrides['replicationEnabled'] ?? $this->replicationEnabled),
            replicationRetentionHours: (int) ($overrides['replicationRetentionHours'] ?? $this->replicationRetentionHours),
            tlsEnabled: (bool) ($overrides['tlsEnabled'] ?? $this->tlsEnabled),
        );
    }

    private static function env(string $name): ?string
    {
        $value = getenv($name);
        return $value === false ? null : $value;
    }

    private static function envInt(string $name, int $default): int
    {
        $value = self::env($name);
        if ($value === null || filter_var($value, FILTER_VALIDATE_INT) === false) {
            return $default;
        }
        return (int) $value;
    }

    private static function envBool(string $name, bool $default): bool
    {
        $value = self::env($name);
        if ($value === null) {
            return $default;
        }
        $parsed = filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        return $parsed ?? $default;
    }

    private static function environmentPath(string $name, string $baseDirectory): ?string
    {
        $path = self::env($name);
        return $path === null ? null : self::absolutePath($path, $baseDirectory);
    }

    private static function absolutePath(string $path, string $baseDirectory): string
    {
        if (preg_match('/^(?:[A-Za-z]:[\\\\\/]|[\\\\\/]{2}|\/)/', $path) === 1) {
            return rtrim($path, '\\/');
        }
        return rtrim($baseDirectory, '\\/') . DIRECTORY_SEPARATOR . $path;
    }

    private static function readIniFile(string $dataDirectory): array
    {
        $path = $dataDirectory . DIRECTORY_SEPARATOR . 'foxydb.ini';
        if (!is_file($path)) {
            return [];
        }
        $parsed = @parse_ini_file($path, false, INI_SCANNER_TYPED);
        return is_array($parsed) ? $parsed : [];
    }

    private static function iniBool(mixed $value, bool $default): bool
    {
        if ($value === null) {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }
        $parsed = filter_var((string) $value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        return $parsed ?? $default;
    }
}
