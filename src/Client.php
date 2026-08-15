<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Value\BinaryValue;

final class Client
{
    private int $nextRequestId = 1;

    private function __construct(
        private $stream,
        private int $maximumFrameBytes,
        private int $uploadChunkBytes,
        private readonly int $maximumResultRows,
        private readonly int $maximumDownloadBytes,
        private readonly array $tlsInformation,
    ) {
    }

    public static function connect(
        string $host = '127.0.0.1',
        int $port = 2002,
        string $username = 'root',
        string $password = 'root',
        float $timeoutSeconds = 10.0,
        int $maximumFrameBytes = 8_388_608,
        int $uploadChunkBytes = 262_144,
        int $maximumResultRows = 100_000,
        int $maximumDownloadBytes = 67_108_864,
        ?TlsOptions $tlsOptions = null,
        bool $interactive = false,
    ): self {
        if ($port < 1 || $port > 65_535 || !is_finite($timeoutSeconds) || $timeoutSeconds <= 0
            || $maximumFrameBytes < 1_024 || $maximumFrameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || $uploadChunkBytes < 1
            || $maximumResultRows < 1 || $maximumDownloadBytes < 1
            || $username === '' || $password === '') {
            throw new FoxyException('Invalid client connection or resource limits.', 'INVALID_CONFIG');
        }
        $tlsOptions ??= new TlsOptions();
        $stream = false;
        $tlsInformation = [];
        $errors = [];
        foreach ($tlsOptions->connectionSchemes() as $scheme) {
            $errorCode = 0;
            $errorMessage = '';
            $context = $scheme === 'tls'
                ? stream_context_create(['ssl' => $tlsOptions->contextOptions($host)])
                : stream_context_create();
            $stream = @stream_socket_client(
                "{$scheme}://{$host}:{$port}",
                $errorCode,
                $errorMessage,
                $timeoutSeconds,
                STREAM_CLIENT_CONNECT,
                $context,
            );
            if ($stream === false) {
                $errors[] = "{$scheme}: {$errorMessage}";
                continue;
            }
            stream_set_blocking($stream, true);
            stream_set_timeout($stream, (int) $timeoutSeconds, (int) (($timeoutSeconds - floor($timeoutSeconds)) * 1_000_000));
            try {
                $tlsInformation = $scheme === 'tls'
                    ? $tlsOptions->validateSession($stream, $host, $port)
                    : [];
                break;
            } catch (FoxyException $exception) {
                fclose($stream);
                $stream = false;
                $errors[] = "{$scheme}: {$exception->getMessage()}";
                throw $exception;
            }
        }
        if ($stream === false) {
            throw new FoxyException(
                'Unable to connect to FoxyDB: ' . implode('; ', $errors),
                'CONNECTION_FAILED',
            );
        }
        $client = new self(
            $stream,
            $maximumFrameBytes,
            $uploadChunkBytes,
            $maximumResultRows,
            $maximumDownloadBytes,
            $tlsInformation,
        );
        $hello = $client->read();
        if (($hello['type'] ?? null) !== 'hello' || ($hello['protocol'] ?? null) !== FrameCodec::VERSION) {
            $client->close();
            throw new FoxyException('Server sent an invalid greeting.', 'PROTOCOL_ERROR');
        }
        $client->applyServerLimits($hello);
        if (($hello['authenticated'] ?? false) !== true) {
            $response = $client->request([
                'type' => 'auth',
                'username' => $username,
                'password' => $password,
                'interactive' => $interactive,
                'limits' => $client->clientLimits(),
            ]);
            $client->assertSuccess($response, 'auth');
        }
        $tlsOptions->persistSession($tlsInformation);
        return $client;
    }

    public function tlsInfo(): array
    {
        return $this->tlsInformation;
    }

    public function query(string $sql, array $parameters = []): QueryResult
    {
        try {
            return $this->executeQuery($sql, $parameters);
        } catch (FoxyException $exception) {
            if (in_array($exception->errorCode, [
                'PROTOCOL_ERROR', 'RESOURCE_LIMIT', 'CONNECTION_CLOSED', 'CONNECTION_IO',
                'CONNECTION_TIMEOUT', 'FRAME_TOO_LARGE',
            ], true)) {
                $this->close();
            }
            throw $exception;
        }
    }

    private function executeQuery(string $sql, array $parameters): QueryResult
    {
        foreach ($parameters as $key => $value) {
            $parameters[$key] = $this->encodeParameter($value);
        }
        $id = $this->nextRequestId++;
        $this->write(['type' => 'query', 'id' => $id, 'sql' => $sql, 'params' => $parameters]);
        $response = $this->read();
        if (($response['id'] ?? null) !== $id) {
            if (($response['type'] ?? null) === 'error' && ($response['id'] ?? null) === null) {
                $this->throwResponseError($response);
            }
            throw new FoxyException('Response identifier does not match the query.', 'PROTOCOL_ERROR');
        }
        if (($response['type'] ?? null) === 'error') {
            $this->throwResponseError($response);
        }
        if (($response['type'] ?? null) === 'result') {
            $affectedRows = $response['affected_rows'] ?? null;
            $lastInsertId = $response['last_insert_id'] ?? null;
            if (($response['ok'] ?? false) !== true || ($response['kind'] ?? null) !== 'command'
                || !is_int($affectedRows) || $affectedRows < 0
                || (!is_int($lastInsertId) && !is_string($lastInsertId) && $lastInsertId !== null)) {
                throw new FoxyException('Server sent an invalid command result.', 'PROTOCOL_ERROR');
            }
            return QueryResult::command(
                $affectedRows,
                $lastInsertId,
                is_array($response['metadata'] ?? null) ? $response['metadata'] : [],
            );
        }
        if (($response['type'] ?? null) !== 'result_start' || ($response['ok'] ?? false) !== true
            || ($response['kind'] ?? null) !== 'rows' || !is_array($response['columns'] ?? null)
            || !array_is_list($response['columns'])) {
            throw new FoxyException('Server sent an invalid query response.', 'PROTOCOL_ERROR');
        }
        foreach ($response['columns'] as $column) {
            if (!is_string($column)) {
                throw new FoxyException('Server sent an invalid result column.', 'PROTOCOL_ERROR');
            }
        }

        $rows = [];
        $downloads = [];
        $referencedDownloads = [];
        $downloadedBytes = 0;
        while (true) {
            $frame = $this->read();
            if (($frame['id'] ?? null) !== $id) {
                throw new FoxyException('Unexpected response identifier.', 'PROTOCOL_ERROR');
            }
            $type = $frame['type'] ?? null;
            if ($type === 'row') {
                if (!is_array($frame['row'] ?? null)) {
                    throw new FoxyException('Server sent an invalid row.', 'PROTOCOL_ERROR');
                }
                if (count($rows) >= $this->maximumResultRows) {
                    throw new FoxyException('Result exceeds the client row limit.', 'RESOURCE_LIMIT');
                }
                $rowBytes = FrameCodec::encodedValueBytes($frame['row'], $this->maximumFrameBytes);
                $downloadedBytes += $rowBytes;
                if ($downloadedBytes > $this->maximumDownloadBytes) {
                    throw new FoxyException('Result exceeds the client download limit.', 'RESOURCE_LIMIT');
                }
                foreach ($frame['row'] as $value) {
                    if (is_array($value) && isset($value['$chunk'])) {
                        $transferId = $value['$chunk'];
                        $format = $value['format'] ?? null;
                        $bytes = $value['bytes'] ?? null;
                        if (!is_string($transferId) || preg_match('/^[A-Za-z0-9_-]+$/', $transferId) !== 1
                            || !in_array($format, ['binary', 'utf8'], true) || !is_int($bytes) || $bytes < 0
                            || isset($referencedDownloads[$transferId])) {
                            throw new FoxyException('Row contains an invalid chunk reference.', 'PROTOCOL_ERROR');
                        }
                        $downloadedBytes += $bytes;
                        if ($downloadedBytes > $this->maximumDownloadBytes) {
                            throw new FoxyException('Result exceeds the client download limit.', 'RESOURCE_LIMIT');
                        }
                        $referencedDownloads[$transferId] = ['format' => $format, 'bytes' => $bytes];
                    }
                }
                $rows[] = $frame['row'];
                continue;
            }
            if ($type === 'chunk_start') {
                $transferId = $this->downloadId($frame);
                $format = $frame['format'] ?? null;
                $bytes = $frame['bytes'] ?? null;
                $direction = $frame['direction'] ?? null;
                if (!in_array($format, ['binary', 'utf8'], true) || !is_int($bytes) || $bytes < 0
                    || $direction !== 'download'
                    || !isset($referencedDownloads[$transferId]) || isset($downloads[$transferId])
                    || $referencedDownloads[$transferId] !== ['format' => $format, 'bytes' => $bytes]) {
                    throw new FoxyException('Server sent an invalid download declaration.', 'PROTOCOL_ERROR');
                }
                $downloads[$transferId] = [
                    'format' => $format,
                    'bytes' => $bytes,
                    'value' => '',
                    'state' => 'started',
                ];
                continue;
            }
            if ($type === 'chunk_data') {
                $transferId = $this->downloadId($frame);
                if (!isset($downloads[$transferId]) || $downloads[$transferId]['state'] !== 'started'
                    || !(($frame['data'] ?? null) instanceof BinaryValue)) {
                    throw new FoxyException('Server sent chunk data for an unknown download.', 'PROTOCOL_ERROR');
                }
                $data = $frame['data']->bytes;
                if ($data === '') {
                    throw new FoxyException('Server sent an empty chunk data frame.', 'PROTOCOL_ERROR');
                }
                $downloads[$transferId]['value'] .= $data;
                if (strlen($downloads[$transferId]['value']) > $downloads[$transferId]['bytes']) {
                    throw new FoxyException('Download exceeded its declared length.', 'PROTOCOL_ERROR');
                }
                continue;
            }
            if ($type === 'chunk_end') {
                $transferId = $this->downloadId($frame);
                if (!isset($downloads[$transferId]) || $downloads[$transferId]['state'] !== 'started'
                    || strlen($downloads[$transferId]['value']) !== $downloads[$transferId]['bytes']
                    || ($frame['bytes'] ?? null) !== $downloads[$transferId]['bytes']) {
                    throw new FoxyException('Download length does not match its declaration.', 'PROTOCOL_ERROR');
                }
                if ($downloads[$transferId]['format'] === 'utf8'
                    && !mb_check_encoding($downloads[$transferId]['value'], 'UTF-8')) {
                    throw new FoxyException('Downloaded text is not valid UTF-8.', 'PROTOCOL_ERROR');
                }
                $downloads[$transferId]['state'] = 'ended';
                continue;
            }
            if ($type === 'result_end') {
                if (($frame['ok'] ?? false) !== true) {
                    $this->throwResponseError($frame);
                }
                if (($frame['row_count'] ?? null) !== count($rows)) {
                    throw new FoxyException('Server result row count does not match received rows.', 'PROTOCOL_ERROR');
                }
                foreach ($referencedDownloads as $transferId => $_declaration) {
                    if (($downloads[$transferId]['state'] ?? null) !== 'ended') {
                        throw new FoxyException('Result ended before all downloads completed.', 'PROTOCOL_ERROR');
                    }
                }
                break;
            }
            if ($type === 'error') {
                $this->throwResponseError($frame);
            }
            throw new FoxyException('Server sent an unexpected result frame.', 'PROTOCOL_ERROR');
        }

        foreach ($rows as &$row) {
            foreach ($row as &$value) {
                $value = $this->decodeValue($value, $downloads);
            }
            unset($value);
        }
        unset($row);
        return QueryResult::rows(
            $response['columns'],
            $rows,
            is_array($response['metadata'] ?? null) ? $response['metadata'] : [],
        );
    }

    public function uploadFile(string $path, string $format = 'binary', ?string $transferId = null): array
    {
        if (!is_file($path) || !in_array($format, ['binary', 'utf8'], true)) {
            throw new FoxyException('Upload path or format is invalid.', 'INVALID_VALUE');
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open upload file.', 'STORAGE_IO');
        }
        $statistics = fstat($stream);
        $bytes = $statistics['size'] ?? false;
        if (!is_int($bytes) || $bytes < 0) {
            fclose($stream);
            throw new FoxyException('Upload is too large.', 'RESOURCE_LIMIT');
        }
        $transferId ??= bin2hex(random_bytes(12));
        $started = false;
        try {
            $response = $this->request([
                'type' => 'chunk_start',
                'transfer_id' => $transferId,
                'format' => $format,
                'bytes' => $bytes,
            ]);
            $this->assertSuccess($response, 'chunk_start');
            $started = true;
            $serverChunkBytes = $response['chunk_bytes'] ?? null;
            if (!is_int($serverChunkBytes) || $serverChunkBytes < 1
                || $serverChunkBytes > $this->maximumFrameBytes) {
                throw new FoxyException('Server sent an invalid upload chunk limit.', 'PROTOCOL_ERROR');
            }
            $chunkBytes = min(
                $this->uploadChunkBytes,
                $serverChunkBytes,
            );
            while (!feof($stream)) {
                $data = fread($stream, $chunkBytes);
                if ($data === false) {
                    throw new FoxyException('Unable to read upload file.', 'STORAGE_IO');
                }
                if ($data === '') {
                    break;
                }
                $this->sendUploadData($transferId, $data, $chunkBytes);
            }
            $response = $this->request(['type' => 'chunk_end', 'transfer_id' => $transferId]);
            $this->assertSuccess($response, 'chunk_end');
            $started = false;
        } catch (\Throwable $exception) {
            if ($started) {
                try {
                    $this->request(['type' => 'chunk_abort', 'transfer_id' => $transferId]);
                } catch (\Throwable) {
                }
            }
            throw $exception;
        } finally {
            fclose($stream);
        }
        return ['$transfer' => $transferId];
    }

    public function ping(): bool
    {
        $response = $this->request(['type' => 'ping']);
        return ($response['type'] ?? null) === 'pong' && ($response['ok'] ?? false) === true;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function request(array $payload): array
    {
        $id = $this->nextRequestId++;
        $payload['id'] = $id;
        $this->write($payload);
        $response = $this->read();
        if (($response['id'] ?? null) !== $id) {
            if (($response['type'] ?? null) === 'error' && ($response['id'] ?? null) === null) {
                $this->throwResponseError($response);
            }
            throw new FoxyException('Unexpected response identifier.', 'PROTOCOL_ERROR');
        }
        return $response;
    }

    private function assertSuccess(array $response, string $expectedType): void
    {
        if (($response['type'] ?? null) === 'error' || ($response['ok'] ?? false) !== true) {
            $this->throwResponseError($response);
        }
        if (($response['type'] ?? null) !== $expectedType) {
            throw new FoxyException('Server sent an unexpected response type.', 'PROTOCOL_ERROR');
        }
    }

    private function throwResponseError(array $response): never
    {
        $error = is_array($response['error'] ?? null) ? $response['error'] : [];
        throw new FoxyException(
            (string) ($error['message'] ?? 'FoxyDB request failed.'),
            (string) ($error['code'] ?? 'REMOTE_ERROR'),
            is_array($error['details'] ?? null) ? $error['details'] : [],
        );
    }

    private function decodeValue(mixed $value, array $downloads): mixed
    {
        if ($value instanceof BinaryValue) {
            return $value;
        }
        if (!is_array($value)) {
            return $value;
        }
        if (isset($value['$chunk'])) {
            $transferId = (string) $value['$chunk'];
            if (!isset($downloads[$transferId])) {
                throw new FoxyException('A result references a missing download.', 'PROTOCOL_ERROR');
            }
            return $downloads[$transferId]['format'] === 'binary'
                ? new BinaryValue($downloads[$transferId]['value'])
                : $downloads[$transferId]['value'];
        }
        return $value;
    }

    private function encodeParameter(mixed $value): mixed
    {
        if ($value instanceof BinaryValue) {
            return $value;
        }
        if (is_object($value)) {
            throw new FoxyException('Unsupported client parameter object.', 'INVALID_VALUE');
        }
        return $value;
    }

    private function downloadId(array $frame): string
    {
        $transferId = $frame['transfer_id'] ?? null;
        if (!is_string($transferId) || preg_match('/^[A-Za-z0-9_-]+$/', $transferId) !== 1) {
            throw new FoxyException('Server sent an invalid transfer identifier.', 'PROTOCOL_ERROR');
        }
        return $transferId;
    }

    private function applyServerLimits(array $hello): void
    {
        $limits = $hello['limits'] ?? null;
        $frameBytes = is_array($limits) ? ($limits['frame_payload_bytes'] ?? null) : null;
        $chunkBytes = is_array($limits) ? ($limits['chunk_payload_bytes'] ?? null) : null;
        if (!is_array($limits) || array_is_list($limits)
            || !is_int($frameBytes) || $frameBytes < 1_024 || $frameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || !is_int($chunkBytes) || $chunkBytes < 1 || $chunkBytes > $frameBytes) {
            throw new FoxyException('Server sent invalid protocol limit metadata.', 'PROTOCOL_ERROR');
        }
        $this->maximumFrameBytes = min($this->maximumFrameBytes, $frameBytes);
        $this->uploadChunkBytes = min($this->uploadChunkBytes, $chunkBytes);
    }

    private function sendUploadData(string $transferId, string $data, int &$chunkBytes): void
    {
        $offset = 0;
        while ($offset < strlen($data)) {
            $part = substr($data, $offset, min($chunkBytes, strlen($data) - $offset));
            try {
                $response = $this->request([
                    'type' => 'chunk_data',
                    'transfer_id' => $transferId,
                    'data' => new BinaryValue($part),
                ]);
                $this->assertSuccess($response, 'chunk_data');
                $offset += strlen($part);
            } catch (FoxyException $exception) {
                if ($exception->errorCode !== 'PROTOCOL_ERROR'
                    || $exception->getMessage() !== 'Chunk data is invalid or too large.' || $chunkBytes === 1) {
                    throw $exception;
                }
                $chunkBytes = max(1, intdiv($chunkBytes, 2));
            }
        }
    }

    private function write(array $payload): void
    {
        if (!is_resource($this->stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        FrameCodec::write($this->stream, $payload, $this->maximumFrameBytes);
    }

    private function read(): array
    {
        if (!is_resource($this->stream)) {
            throw new FoxyException('Client is not connected.', 'CONNECTION_CLOSED');
        }
        $payload = FrameCodec::read($this->stream, $this->maximumFrameBytes);
        if (array_key_exists('limits', $payload)) {
            $this->applyServerLimits($payload);
        }
        return $payload;
    }

    private function clientLimits(): array
    {
        $overhead = FrameCodec::encodedValueBytes([
            'type' => 'chunk_data',
            'id' => PHP_INT_MAX,
            'transfer_id' => '000000000000000000000000',
            'data' => new BinaryValue(''),
        ]);
        return [
            'frame_payload_bytes' => $this->maximumFrameBytes,
            'chunk_payload_bytes' => max(1, $this->maximumFrameBytes - $overhead),
        ];
    }
}
