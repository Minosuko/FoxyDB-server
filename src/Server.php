<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\Support\StructuredLogger;
use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;
use FoxyDB\Value\StreamValue;

final class Server
{
    private const PROTOCOL_VERSION = FrameCodec::VERSION;
    private const CONNECT_ERROR_WINDOW_SECONDS = 300;
    private const BUFFER_POOL_BYTES = 67_108_864;
    private const MINIMUM_CLIENT_OUTPUT_BYTES = 1_048_576;
    private const OUTPUT_WRITE_BYTES = 262_144;
    private const OUTPUT_STALL_TIMEOUT_SECONDS = 30;

    private bool $running = false;
    private int $activeTransfers = 0;
    private int $reservedUploadBytes = 0;
    private int $bufferedInputBytes = 0;
    private int $queuedOutputBytes = 0;
    private array $clients = [];
    private array $sessionCache = [];
    private array $connectErrors = [];
    private array $readyFibers = [];
    private array $pendingFibers = [];
    private readonly StorageEngine $storage;
    private readonly Authentication $authentication;
    private readonly SystemVariables $systemVariables;
    private readonly TlsCertificate $tlsCertificate;
    private readonly string $transferDirectory;
    private readonly StructuredLogger $logger;

    public function __construct(private readonly Config $config)
    {
        SysTable::setStartTime(microtime(true));
        if ($config->maxFrameBytes > FrameCodec::MAXIMUM_FRAME_BYTES) {
            throw new FoxyException('Configured frame size exceeds the binary protocol limit.', 'INVALID_CONFIG');
        }
        $this->logger = new StructuredLogger(
            $config->logDirectory ?? $config->dataDirectory . DIRECTORY_SEPARATOR . 'logs',
            $config->logMaxBytes,
            $config->logMaxFiles,
            $config->enableLog,
        );
        try {
            $this->storage = new StorageEngine($config);
            $this->authentication = new Authentication($this->storage, $config);
            $this->systemVariables = new SystemVariables($this->storage, $config);
            $this->systemVariables->onChange(function (string $name, mixed $value): void {
                if ($name === 'thread_cache_size') {
                    $this->sessionCache = array_slice($this->sessionCache, 0, (int) $value);
                }
            });
            $this->tlsCertificate = TlsCertificate::ensure($config);
            $this->transferDirectory = $config->dataDirectory . DIRECTORY_SEPARATOR . '.transfers';
            FileSystem::ensureDirectory($this->transferDirectory);
            $this->removeAbandonedTransfers();
        } catch (\Throwable $exception) {
            $this->logger->error('server.initialization_failed', [
                'exception' => $exception::class,
                'message' => $exception->getMessage(),
            ]);
            throw $exception;
        }
    }

    public function run(?callable $onListening = null): void
    {
        $address = 'tls://' . $this->config->host . ':' . $this->config->port;
        $listenAddress = 'tcp://' . $this->config->host . ':' . $this->config->port;
        $errorCode = 0;
        $errorMessage = '';
        $context = stream_context_create(['ssl' => $this->tlsCertificate->serverContextOptions()]);
        $server = @stream_socket_server(
            $listenAddress,
            $errorCode,
            $errorMessage,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            $context,
        );
        if ($server === false) {
            $this->logger->error('server.bind_failed', [
                'host' => $this->config->host,
                'port' => $this->config->port,
                'socket_code' => $errorCode,
                'message' => $errorMessage,
            ]);
            throw new FoxyException(
                "Unable to listen on {$address}: {$errorMessage}",
                'SERVER_BIND',
                ['socket_code' => $errorCode],
            );
        }
        stream_set_blocking($server, false);
        $this->running = true;
        if ($onListening !== null) {
            $onListening($address);
        }
        $this->logger->general('server.started', [
            'host' => $this->config->host,
            'port' => $this->config->port,
            'tls' => true,
        ]);

        try {
            while ($this->running) {
                $this->resumeReadyFibers();
                $this->processPendingFibers();
                $read = [$server];
                $write = [];
                foreach ($this->clients as $client) {
                    if (!$client['tls_ready']) {
                        $read[] = $client['stream'];
                        if ($client['tls_retry_write']) {
                            $write[] = $client['stream'];
                        }
                        continue;
                    }
                    if ($client['output_buffer'] !== '') {
                        $write[] = $client['stream'];
                    }
                    if ($client['output_buffer'] === '' && !$client['close_after_write']) {
                        $read[] = $client['stream'];
                    }
                }
                $writeSet = $write === [] ? null : $write;
                $except = null;
                $timeout = $this->readyFibers !== [] || $this->pendingFibers !== [] ? 0 : 1;
                $selected = @stream_select($read, $writeSet, $except, $timeout);
                if ($selected === false) {
                    if (!$this->running) {
                        break;
                    }
                    throw new FoxyException('TCP select failed.', 'SERVER_IO');
                }
                if ($selected > 0) {
                    $processed = [];
                    foreach (array_merge($writeSet ?? [], $read) as $stream) {
                        if ($stream === $server) {
                            $this->acceptClient($server);
                            continue;
                        }
                        $clientId = (int) $stream;
                        if (isset($processed[$clientId]) || !isset($this->clients[$clientId])) {
                            continue;
                        }
                        $processed[$clientId] = true;
                        if (!$this->clients[$clientId]['tls_ready']) {
                            $this->progressTlsHandshake(
                                $clientId,
                                in_array($stream, $writeSet ?? [], true),
                            );
                        } elseif (in_array($stream, $writeSet ?? [], true)) {
                            $this->flushClientOutput($clientId);
                        } elseif (in_array($stream, $read, true)) {
                            $this->readClient($clientId);
                        }
                    }
                }
                $this->disconnectIdleClients();
            }
        } catch (\Throwable $exception) {
            $this->logger->error('server.loop_failed', [
                'exception' => $exception::class,
                'message' => $exception->getMessage(),
            ]);
            throw $exception;
        } finally {
            foreach (array_keys($this->clients) as $clientId) {
                $this->disconnect($clientId, 'server_shutdown');
            }
            fclose($server);
            $this->running = false;
            $this->logger->general('server.stopped');
        }
    }

    public function stop(): void
    {
        $this->running = false;
    }

    private function startFiber(int $clientId, array $request): void
    {
        $context = ['clientId' => $clientId, 'request' => $request];
        $fiber = new \Fiber(function () use ($context): void {
            $this->handleRequest($context['clientId'], $context['request']);
        });
        $this->pendingFibers[] = ['fiber' => $fiber, 'clientId' => $clientId, 'started' => hrtime(true)];
    }

private function resumeReadyFibers(): void
    {
        if ($this->readyFibers === []) {
            return;
        }
        $snapshot = $this->readyFibers;
        $this->readyFibers = [];
        foreach ($snapshot as $entry) {
            $fiber = $entry['fiber'];
            $clientId = $entry['clientId'];
            if (!isset($this->clients[$clientId])) {
                continue;
            }
            if ($fiber->isTerminated()) {
                continue;
            }
            try {
                $fiber->resume();
            } catch (\Throwable $exception) {
                if (isset($this->clients[$clientId])) {
                    $this->sendError(
                        $clientId,
                        null,
                        new FoxyException('Query execution failed: ' . $exception->getMessage(), 'INTERNAL_ERROR'),
                    );
                }
                continue;
            }
            if ($fiber->isSuspended()) {
                $this->readyFibers[] = ['fiber' => $fiber, 'clientId' => $clientId];
            }
        }
    }

    private function processPendingFibers(): void
    {
        if ($this->pendingFibers === []) {
            return;
        }
        $pending = $this->pendingFibers;
        $this->pendingFibers = [];
        foreach ($pending as $entry) {
            $fiber = $entry['fiber'];
            $clientId = $entry['clientId'];
            if (!isset($this->clients[$clientId])) {
                continue;
            }
            try {
                $fiber->start();
            } catch (\Throwable $exception) {
                if (isset($this->clients[$clientId])) {
                    $this->sendError(
                        $clientId,
                        null,
                        new FoxyException('Query execution failed: ' . $exception->getMessage(), 'INTERNAL_ERROR'),
                    );
                }
                continue;
            }
            if ($fiber->isSuspended()) {
                $this->readyFibers[] = ['fiber' => $fiber, 'clientId' => $clientId];
            }
        }
    }

    public static function fiberYield(?int $delayMicroseconds = null): void
    {
        if (\Fiber::getCurrent() !== null) {
            \Fiber::suspend();
        }
        if ($delayMicroseconds !== null && $delayMicroseconds > 0) {
            usleep($delayMicroseconds);
        }
    }

    private function acceptClient($server): void
    {
        while (($stream = @stream_socket_accept($server, 0, $peer)) !== false) {
            if (count($this->clients) >= $this->config->maxConnections) {
                $this->logger->audit('connection.rejected', [
                    'peer' => $peer,
                    'reason' => 'connection_limit',
                ], 'WARNING');
                fclose($stream);
                continue;
            }
            $peerAddress = $this->peerAddress($peer);
            if ($this->connectErrorCount($peerAddress)
                >= (int) $this->systemVariables->get('max_connect_errors')) {
                $this->logger->audit('connection.rejected', [
                    'peer' => $peer,
                    'peer_address' => $peerAddress,
                    'reason' => 'max_connect_errors',
                ], 'WARNING');
                fclose($stream);
                continue;
            }
            $peerName = $peerAddress;
            if (!$this->systemVariables->get('skip_name_resolve')) {
                $resolved = @gethostbyaddr($peerAddress);
                if (is_string($resolved) && $resolved !== '') {
                    $peerName = $resolved;
                }
            }
            stream_set_blocking($stream, false);
            $id = (int) $stream;
            $this->clients[$id] = [
                'stream' => $stream,
                'peer' => $peer,
                'peer_address' => $peerAddress,
                'peer_name' => $peerName,
                'buffer' => '',
                'output_buffer' => '',
                'output_since' => null,
                'close_after_write' => false,
                'close_reason' => null,
                'session' => null,
                'tls_ready' => false,
                'tls_retry_write' => false,
                'authenticated' => false,
                'interactive' => false,
                'username' => null,
                'peer_frame_bytes' => null,
                'peer_chunk_bytes' => null,
                'transfers' => [],
                'last_activity' => time(),
                'connected_at' => time(),
            ];
            $this->logger->general('connection.accepted', $this->clientContext($id));
            $this->logger->audit('connection.accepted', $this->clientContext($id));
        }
    }

    private function progressTlsHandshake(int $clientId, bool $fromWrite): void
    {
        $stream = $this->clients[$clientId]['stream'];
        if ($fromWrite) {
            $this->clients[$clientId]['tls_retry_write'] = false;
        }
        $crypto = @stream_socket_enable_crypto(
            $stream,
            true,
            $this->tlsCertificate->serverContextOptions()['crypto_method'],
        );
        if ($crypto === 0) {
            if (!$fromWrite) {
                $this->clients[$clientId]['tls_retry_write'] = true;
            }
            return;
        }
        if ($crypto !== true) {
            $this->logger->audit('tls.failed', $this->clientContext($clientId), 'WARNING');
            $this->recordConnectError($this->clients[$clientId]['peer_address']);
            $this->disconnect($clientId, 'tls_failed');
            return;
        }
        $this->clients[$clientId]['tls_ready'] = true;
        $this->logger->audit('tls.established', $this->clientContext($clientId));
        $session = array_pop($this->sessionCache);
        $this->clients[$clientId]['session'] = $session instanceof Session
            ? $session
            : new Session($this->storage, $this->config, $this->authentication, $this->systemVariables);
        try {
            $this->send($clientId, [
                'type' => 'hello',
                'server' => 'FoxyDB',
                'protocol' => self::PROTOCOL_VERSION,
                'authenticated' => false,
                'authentication' => 'username_password',
                'tls' => [
                    'required' => true,
                    'certificate_sha256' => $this->tlsCertificate->fingerprint,
                ],
                'capabilities' => [
                    'binary_protocol', 'raw_binary', 'sql', 'parameters', 'chunked_values', 'streamed_results', 'tls',
                ],
                'limits' => $this->protocolLimits($clientId),
            ]);
        } catch (\Throwable $exception) {
            $this->logger->error('connection.greeting_failed', $this->clientContext($clientId) + [
                'exception' => $exception::class,
                'message' => $exception->getMessage(),
            ]);
            $this->disconnect($clientId, 'greeting_failed');
        }
    }

    private function readClient(int $clientId): void
    {
        $stream = $this->clients[$clientId]['stream'];
        $data = @fread($stream, 65_536);
        if ($data === false || ($data === '' && feof($stream))) {
            $this->disconnect($clientId, 'peer_closed');
            return;
        }
        if ($data === '') {
            return;
        }
        $this->clients[$clientId]['buffer'] .= $data;
        $this->bufferedInputBytes += strlen($data);

        try {
            while (isset($this->clients[$clientId])) {
                $bufferBytes = strlen($this->clients[$clientId]['buffer']);
                $request = FrameCodec::extract(
                    $this->clients[$clientId]['buffer'],
                    $this->config->maxFrameBytes,
                );
                $consumed = $bufferBytes - strlen($this->clients[$clientId]['buffer']);
                $this->bufferedInputBytes = max(0, $this->bufferedInputBytes - $consumed);
                if ($request === null) {
                    if (strlen($this->clients[$clientId]['buffer'])
                        > $this->config->maxFrameBytes + FrameCodec::HEADER_BYTES) {
                        throw new FoxyException('Frame buffer exceeds its limit.', 'FRAME_TOO_LARGE');
                    }
                    if ($this->bufferedInputBytes > $this->inputBufferLimit()) {
                        throw new FoxyException('Aggregate frame buffers exceed their limit.', 'RESOURCE_LIMIT');
                    }
                    break;
                }
                $payloadBytes = $consumed - FrameCodec::HEADER_BYTES;
                if ($payloadBytes > $this->packetLimit($clientId)) {
                    $requestId = $request['id'] ?? null;
                    $this->sendError(
                        $clientId,
                        is_int($requestId) && $requestId >= 0 ? $requestId : null,
                        new FoxyException('Protocol frame exceeds the current session limit.', 'FRAME_TOO_LARGE'),
                    );
                    continue;
                }
                $this->clients[$clientId]['last_activity'] = time();
                $requestType = $request['type'] ?? null;
                if ($requestType === 'query' && class_exists(\Fiber::class)) {
                    $this->startFiber($clientId, $request);
                } else {
                    $this->handleRequest($clientId, $request);
                }
                if (isset($this->clients[$clientId]) && $this->clients[$clientId]['close_after_write']) {
                    break;
                }
            }
        } catch (FoxyException $exception) {
            $this->logger->audit('protocol.rejected', $this->clientContext($clientId) + [
                'error_code' => $exception->errorCode,
            ], 'WARNING');
            if (isset($this->clients[$clientId])) {
                $this->scheduleDisconnect($clientId, 'protocol_error');
                $this->sendError($clientId, null, $exception);
            }
        } catch (\Throwable $exception) {
            $this->logger->error('request.internal_error', $this->clientContext($clientId) + [
                'exception' => $exception::class,
                'message' => $exception->getMessage(),
            ]);
            if (isset($this->clients[$clientId])) {
                $this->sendError(
                    $clientId,
                    null,
                    new FoxyException('Internal server error.', 'INTERNAL_ERROR'),
                );
            }
        }
    }

    private function handleRequest(int $clientId, array $request): void
    {
        $requestId = null;
        try {
            if (array_key_exists('id', $request)) {
                if (!is_int($request['id']) || $request['id'] < 0) {
                    throw new FoxyException('Request identifier must be a non-negative integer.', 'PROTOCOL_ERROR');
                }
                $requestId = $request['id'];
            }
            $type = $request['type'] ?? null;
            if (!is_string($type)) {
                throw new FoxyException('Request type is required.', 'PROTOCOL_ERROR');
            }
            if (!$this->clients[$clientId]['authenticated'] && $type !== 'auth') {
                throw new FoxyException('Authentication is required.', 'AUTH_REQUIRED');
            }
            match ($type) {
                'auth' => $this->authenticate($clientId, $request, $requestId),
                'ping' => $this->send($clientId, [
                    'type' => 'pong',
                    'id' => $requestId,
                    'ok' => true,
                    'limits' => $this->protocolLimits($clientId),
                ]),
                'query' => $this->query($clientId, $request, $requestId),
                'chunk_start' => $this->startUpload($clientId, $request, $requestId),
                'chunk_data' => $this->appendUpload($clientId, $request, $requestId),
                'chunk_end' => $this->finishUpload($clientId, $request, $requestId),
                'chunk_abort' => $this->abortUpload($clientId, $request, $requestId),
                default => throw new FoxyException("Unknown request type: {$type}", 'PROTOCOL_ERROR'),
            };
        } catch (FoxyException $exception) {
            if (isset($this->clients[$clientId])) {
                if (($request['type'] ?? null) === 'auth' || $exception->errorCode === 'PROTOCOL_ERROR') {
                    $this->scheduleDisconnect(
                        $clientId,
                        ($request['type'] ?? null) === 'auth' ? 'authentication_failed' : 'protocol_error',
                    );
                }
                $this->sendError($clientId, $requestId, $exception);
            }
        } catch (\Throwable $exception) {
            $this->logger->error('request.internal_error', $this->clientContext($clientId) + [
                'request_type' => is_string($request['type'] ?? null) ? $request['type'] : null,
                'exception' => $exception::class,
                'message' => $exception->getMessage(),
            ]);
            if (isset($this->clients[$clientId])) {
                $this->sendError($clientId, $requestId, new FoxyException('Internal server error.', 'INTERNAL_ERROR'));
            }
        }
    }

    private function authenticate(int $clientId, array $request, mixed $requestId): void
    {
        $username = $request['username'] ?? null;
        $password = $request['password'] ?? null;
        $interactive = $request['interactive'] ?? false;
        $limits = $request['limits'] ?? null;
        $peerFrameBytes = is_array($limits) ? ($limits['frame_payload_bytes'] ?? null) : null;
        $peerChunkBytes = is_array($limits) ? ($limits['chunk_payload_bytes'] ?? null) : null;
        if (!is_string($username) || !is_string($password) || !is_bool($interactive)
            || !is_array($limits) || array_is_list($limits)
            || !is_int($peerFrameBytes) || $peerFrameBytes < 1_024
            || $peerFrameBytes > FrameCodec::MAXIMUM_FRAME_BYTES
            || !is_int($peerChunkBytes) || $peerChunkBytes < 1 || $peerChunkBytes > $peerFrameBytes) {
            throw new FoxyException('Username and password are required.', 'AUTH_FAILED');
        }
        try {
            $identity = $this->authentication->authenticateIdentity($username, $password);
        } catch (FoxyException $exception) {
            $this->recordConnectError($this->clients[$clientId]['peer_address']);
            $this->logger->audit('authentication.failed', $this->clientContext($clientId) + [
                'attempted_username' => $username,
                'error_code' => $exception->errorCode,
            ], 'WARNING');
            throw $exception;
        }
        if ($identity === null) {
            $this->recordConnectError($this->clients[$clientId]['peer_address']);
            $this->logger->audit('authentication.failed', $this->clientContext($clientId) + [
                'attempted_username' => $username,
                'error_code' => 'AUTH_FAILED',
            ], 'WARNING');
            throw new FoxyException('Authentication failed.', 'AUTH_FAILED');
        }
        $authenticatedUsername = $identity['username'];
        $this->clients[$clientId]['authenticated'] = true;
        $this->clients[$clientId]['username'] = $authenticatedUsername;
        $this->clients[$clientId]['interactive'] = $interactive;
        $this->clients[$clientId]['peer_frame_bytes'] = $peerFrameBytes;
        $this->clients[$clientId]['peer_chunk_bytes'] = $peerChunkBytes;
        unset($this->connectErrors[$this->clients[$clientId]['peer_address']]);
        $this->clients[$clientId]['session']->authenticateAs($authenticatedUsername, $identity['account_id']);
        $this->logger->audit('authentication.succeeded', $this->clientContext($clientId));
        $this->send($clientId, [
            'type' => 'auth',
            'id' => $requestId,
            'ok' => true,
            'username' => $authenticatedUsername,
            'database' => Authentication::SYSTEM_DATABASE,
            'limits' => $this->protocolLimits($clientId),
        ]);
    }

    private function query(int $clientId, array $request, mixed $requestId): void
    {
        $sql = $request['sql'] ?? null;
        $parameters = $request['params'] ?? [];
        if (!is_string($sql) || !is_array($parameters)) {
            throw new FoxyException('A query requires SQL text and an object or array of parameters.', 'PROTOCOL_ERROR');
        }
        $usedTransfers = [];
        $started = hrtime(true);
        $status = 'failed';
        $errorCode = null;
        $context = $this->clientContext($clientId) + [
            'request_id' => $requestId,
            'database' => $this->clients[$clientId]['session']->currentDatabase(),
            'sql' => $sql,
            'parameter_count' => count($parameters),
        ];
        try {
            foreach ($parameters as $key => $value) {
                $parameters[$key] = $this->resolveTransfer($clientId, $value, $usedTransfers);
            }
            $result = $this->clients[$clientId]['session']->execute($sql, $parameters);
            $context['result_kind'] = $result->kind;
            $context['affected_rows'] = $result->affectedRows;
            $resultError = $this->sendResult($clientId, $requestId, $result);
            if ($resultError === null) {
                $status = 'succeeded';
            } else {
                $errorCode = $resultError->errorCode;
            }
        } catch (FoxyException $exception) {
            $errorCode = $exception->errorCode;
            throw $exception;
        } catch (\Throwable $exception) {
            $errorCode = 'INTERNAL_ERROR';
            throw $exception;
        } finally {
            foreach ($usedTransfers as $transferId) {
                $this->removeTransfer($clientId, $transferId);
            }
            $durationMilliseconds = (hrtime(true) - $started) / 1_000_000;
            $context['status'] = $status;
            $context['duration_ms'] = round($durationMilliseconds, 3);
            if ($errorCode !== null) {
                $context['error_code'] = $errorCode;
            }
            if (isset($this->clients[$clientId])) {
                $context['database'] = $this->clients[$clientId]['session']->currentDatabase();
            }
            $this->logger->query(
                $context,
                $status === 'succeeded',
                $durationMilliseconds >= $this->config->slowQueryMilliseconds,
            );
        }
    }

    private function sendResult(int $clientId, mixed $requestId, ExecutionResult $result): ?FoxyException
    {
        if ($result->kind === 'command') {
            $this->send($clientId, [
                'type' => 'result',
                'id' => $requestId,
                'ok' => true,
                'kind' => 'command',
                'affected_rows' => $result->affectedRows,
                'last_insert_id' => $result->lastInsertId,
                'metadata' => $result->metadata,
                'limits' => $this->protocolLimits($clientId),
            ]);
            return null;
        }

        $buffer = '';
        $bufferedFrames = 0;
        $start = [
            'type' => 'result_start',
            'id' => $requestId,
            'ok' => true,
            'kind' => 'rows',
            'columns' => $result->columns,
            'metadata' => $result->metadata,
            'limits' => $this->protocolLimits($clientId),
        ];
        if (is_array($result->rows)) {
            $this->queueFrame($clientId, $start, $buffer, $bufferedFrames);
        } else {
            $this->send($clientId, $start);
        }
        $rowCount = 0;
        try {
            foreach ($result->rows as $row) {
                if (!is_array($row)) {
                    throw new FoxyException('Query returned an invalid row.', 'INTERNAL_ERROR');
                }
                [$encodedRow, $streams] = $this->encodeRow($row, $clientId);
                $this->queueFrame($clientId, [
                    'type' => 'row',
                    'id' => $requestId,
                    'row' => $encodedRow,
                ], $buffer, $bufferedFrames);
                foreach ($streams as $stream) {
                    $this->flushFrameBuffer($clientId, $buffer, $bufferedFrames);
                    $this->sendDownload($clientId, $requestId, $stream);
                }
                $rowCount++;
            }
            $this->queueFrame($clientId, [
                'type' => 'result_end',
                'id' => $requestId,
                'ok' => true,
                'row_count' => $rowCount,
            ], $buffer, $bufferedFrames);
            $this->flushFrameBuffer($clientId, $buffer, $bufferedFrames);
            return null;
        } catch (FoxyException $exception) {
            $this->queueFrame($clientId, [
                'type' => 'result_end',
                'id' => $requestId,
                'ok' => false,
                'row_count' => $rowCount,
                'error' => $exception->toArray(),
            ], $buffer, $bufferedFrames);
            $this->flushFrameBuffer($clientId, $buffer, $bufferedFrames);
            return $exception;
        }
    }

    private function encodeRow(array $row, int $clientId): array
    {
        $encoded = [];
        $streams = [];
        $candidates = [];
        $threshold = min($this->config->inlineValueBytes, 32_768);
        foreach ($row as $column => $value) {
            if ($value instanceof ChunkedValue) {
                $id = bin2hex(random_bytes(12));
                $encoded[$column] = ['$chunk' => $id, 'format' => $value->format, 'bytes' => $value->bytes];
                $streams[] = [
                    'id' => $id,
                    'format' => $value->format,
                    'bytes' => $value->bytes,
                    'parts' => static fn(): \Generator => $value->parts(),
                ];
            } elseif ($value instanceof BinaryValue && strlen($value->bytes) > $threshold) {
                $id = bin2hex(random_bytes(12));
                $bytes = $value->bytes;
                $chunkBytes = $this->outboundChunkPayloadLimit($clientId);
                $encoded[$column] = ['$chunk' => $id, 'format' => 'binary', 'bytes' => strlen($bytes)];
                $streams[] = [
                    'id' => $id,
                    'format' => 'binary',
                    'bytes' => strlen($bytes),
                    'parts' => static function () use ($bytes, $chunkBytes): \Generator {
                        for ($offset = 0; $offset < strlen($bytes); $offset += $chunkBytes) {
                            yield substr($bytes, $offset, $chunkBytes);
                        }
                    },
                ];
            } elseif ($value instanceof BinaryValue) {
                $encoded[$column] = $value;
                $candidates[$column] = ['format' => 'binary', 'value' => $value->bytes];
            } elseif (is_string($value) && strlen($value) > $threshold) {
                $id = bin2hex(random_bytes(12));
                $bytes = $value;
                $chunkBytes = $this->outboundChunkPayloadLimit($clientId);
                $encoded[$column] = ['$chunk' => $id, 'format' => 'utf8', 'bytes' => strlen($bytes)];
                $streams[] = [
                    'id' => $id,
                    'format' => 'utf8',
                    'bytes' => strlen($bytes),
                    'parts' => static function () use ($bytes, $chunkBytes): \Generator {
                        for ($offset = 0; $offset < strlen($bytes); $offset += $chunkBytes) {
                            yield substr($bytes, $offset, $chunkBytes);
                        }
                    },
                ];
            } else {
                $encoded[$column] = $value;
                if (is_string($value) && $value !== '') {
                    $candidates[$column] = ['format' => 'utf8', 'value' => $value];
                }
            }
        }
        $budget = max(128, $this->outboundPacketLimit($clientId) - 1_024);
        if (FrameCodec::encodedValueBytes($encoded) > $budget) {
            uasort(
                $candidates,
                static fn(array $left, array $right): int => strlen($right['value']) <=> strlen($left['value']),
            );
            foreach ($candidates as $column => $candidate) {
                $id = bin2hex(random_bytes(12));
                $bytes = $candidate['value'];
                $chunkBytes = $this->outboundChunkPayloadLimit($clientId);
                $encoded[$column] = [
                    '$chunk' => $id,
                    'format' => $candidate['format'],
                    'bytes' => strlen($bytes),
                ];
                $streams[] = [
                    'id' => $id,
                    'format' => $candidate['format'],
                    'bytes' => strlen($bytes),
                    'parts' => static function () use ($bytes, $chunkBytes): \Generator {
                        for ($offset = 0; $offset < strlen($bytes); $offset += $chunkBytes) {
                            yield substr($bytes, $offset, $chunkBytes);
                        }
                    },
                ];
                if (FrameCodec::encodedValueBytes($encoded) <= $budget) {
                    break;
                }
            }
        }
        if (FrameCodec::encodedValueBytes($encoded) > $budget) {
            throw new FoxyException('Result row cannot fit in a protocol frame.', 'FRAME_TOO_LARGE');
        }
        return [$encoded, $streams];
    }

    private function sendDownload(int $clientId, mixed $requestId, array $download): void
    {
        $this->send($clientId, [
            'type' => 'chunk_start',
            'id' => $requestId,
            'transfer_id' => $download['id'],
            'direction' => 'download',
            'format' => $download['format'],
            'bytes' => $download['bytes'],
        ]);
        $sent = 0;
        $chunkBytes = $this->outboundChunkPayloadLimit($clientId);
        foreach (($download['parts'])() as $part) {
            $sent += strlen($part);
            for ($offset = 0; $offset < strlen($part); $offset += $chunkBytes) {
                $this->send($clientId, [
                    'type' => 'chunk_data',
                    'id' => $requestId,
                    'transfer_id' => $download['id'],
                    'data' => new BinaryValue(substr($part, $offset, $chunkBytes)),
                ]);
            }
        }
        if ($sent !== $download['bytes']) {
            throw new FoxyException('Downloaded chunk length mismatch.', 'STORAGE_CORRUPT');
        }
        $this->send($clientId, [
            'type' => 'chunk_end',
            'id' => $requestId,
            'transfer_id' => $download['id'],
            'bytes' => $sent,
        ]);
    }

    private function startUpload(int $clientId, array $request, mixed $requestId): void
    {
        $transferId = $this->transferId($request);
        $transferKey = $this->transferKey($transferId);
        $format = $request['format'] ?? null;
        $declared = $request['bytes'] ?? null;
        if (!in_array($format, ['binary', 'utf8'], true)
            || !is_int($declared) || $declared < 0 || $declared > $this->config->maxUploadBytes) {
            throw new FoxyException('Invalid chunk upload declaration.', 'PROTOCOL_ERROR');
        }
        if (isset($this->clients[$clientId]['transfers'][$transferKey])) {
            throw new FoxyException('Transfer identifier is already in use.', 'TRANSFER_EXISTS');
        }
        if (count($this->clients[$clientId]['transfers']) >= $this->config->maxTransfersPerClient) {
            throw new FoxyException('The active transfer limit has been reached.', 'RESOURCE_LIMIT');
        }
        if ($this->activeTransfers >= $this->config->maxGlobalTransfers) {
            throw new FoxyException('The server transfer limit has been reached.', 'RESOURCE_LIMIT');
        }
        $reserved = $declared;
        foreach ($this->clients[$clientId]['transfers'] as $existing) {
            $reserved += (int) ($existing['declared'] ?? $existing['received']);
        }
        if ($reserved > $this->config->maxUploadBytes) {
            throw new FoxyException('The client upload quota has been reached.', 'RESOURCE_LIMIT');
        }
        if ($this->reservedUploadBytes + $declared > $this->config->maxUploadBytes) {
            throw new FoxyException('The server upload quota has been reached.', 'RESOURCE_LIMIT');
        }
        $freeBytes = disk_free_space($this->transferDirectory);
        if ($freeBytes !== false && $declared > max(0, $freeBytes - 16_777_216)) {
            throw new FoxyException('Insufficient disk space for upload.', 'RESOURCE_LIMIT');
        }
        $path = $this->transferDirectory . DIRECTORY_SEPARATOR . bin2hex(random_bytes(16)) . '.upload';
        $stream = @fopen($path, 'xb');
        if ($stream === false) {
            throw new FoxyException('Unable to create upload file.', 'STORAGE_IO');
        }
        $this->clients[$clientId]['transfers'][$transferKey] = [
            'id' => $transferId,
            'state' => 'uploading',
            'path' => $path,
            'stream' => $stream,
            'format' => $format,
            'declared' => $declared,
            'received' => 0,
            'reserved' => $declared,
        ];
        $this->activeTransfers++;
        $this->reservedUploadBytes += $declared;
        $this->send($clientId, [
            'type' => 'chunk_start',
            'id' => $requestId,
            'ok' => true,
            'transfer_id' => $transferId,
            'chunk_bytes' => $this->chunkPayloadLimit($clientId),
        ]);
    }

    private function appendUpload(int $clientId, array $request, mixed $requestId): void
    {
        $transferId = $this->transferId($request);
        $transferKey = $this->transferKey($transferId);
        if (!isset($this->clients[$clientId]['transfers'][$transferKey])) {
            throw new FoxyException('Upload transfer is not active.', 'TRANSFER_NOT_FOUND');
        }
        $transfer = &$this->clients[$clientId]['transfers'][$transferKey];
        if ($transfer['state'] !== 'uploading') {
            throw new FoxyException('Upload transfer is not active.', 'TRANSFER_NOT_FOUND');
        }
        $data = $request['data'] ?? null;
        if (!($data instanceof BinaryValue) || strlen($data->bytes) > $this->chunkPayloadLimit($clientId)) {
            throw new FoxyException('Chunk data is invalid or too large.', 'PROTOCOL_ERROR');
        }
        $decoded = $data->bytes;
        $newSize = $transfer['received'] + strlen($decoded);
        $limit = $transfer['declared'] ?? 4_294_967_295;
        if ($newSize > $limit) {
            throw new FoxyException('Upload exceeds its declared length.', 'INVALID_VALUE');
        }
        FileSystem::writeAll($transfer['stream'], $decoded);
        $transfer['received'] = $newSize;
        unset($transfer);
        $this->send($clientId, [
            'type' => 'chunk_data',
            'id' => $requestId,
            'ok' => true,
            'transfer_id' => $transferId,
            'received' => $newSize,
        ]);
    }

    private function finishUpload(int $clientId, array $request, mixed $requestId): void
    {
        $transferId = $this->transferId($request);
        $transferKey = $this->transferKey($transferId);
        if (!isset($this->clients[$clientId]['transfers'][$transferKey])) {
            throw new FoxyException('Upload transfer is not active.', 'TRANSFER_NOT_FOUND');
        }
        $transfer = &$this->clients[$clientId]['transfers'][$transferKey];
        if ($transfer['state'] !== 'uploading') {
            throw new FoxyException('Upload transfer is not active.', 'TRANSFER_NOT_FOUND');
        }
        if ($transfer['declared'] !== null && $transfer['declared'] !== $transfer['received']) {
            throw new FoxyException('Upload length does not match its declaration.', 'INVALID_VALUE');
        }
        try {
            FileSystem::flush($transfer['stream'], $this->config->syncWrites);
            fclose($transfer['stream']);
            unset($transfer['stream']);
            if ($transfer['format'] === 'utf8') {
                $this->validateUtf8File($transfer['path']);
            }
        } catch (\Throwable $exception) {
            unset($transfer);
            $this->removeTransfer($clientId, $transferId);
            throw $exception;
        }
        $transfer['state'] = 'ready';
        $bytes = $transfer['received'];
        unset($transfer);
        $this->send($clientId, [
            'type' => 'chunk_end',
            'id' => $requestId,
            'ok' => true,
            'transfer_id' => $transferId,
            'bytes' => $bytes,
        ]);
    }

    private function abortUpload(int $clientId, array $request, mixed $requestId): void
    {
        $transferId = $this->transferId($request);
        $this->removeTransfer($clientId, $transferId);
        $this->send($clientId, [
            'type' => 'chunk_abort',
            'id' => $requestId,
            'ok' => true,
            'transfer_id' => $transferId,
        ]);
    }

    private function resolveTransfer(int $clientId, mixed $value, array &$usedTransfers): mixed
    {
        if (!is_array($value) || count($value) !== 1 || !isset($value['$transfer'])) {
            return $value;
        }
        $transferId = $value['$transfer'];
        if (!is_string($transferId) || preg_match('/^[A-Za-z0-9_-]{1,128}$/', $transferId) !== 1) {
            throw new FoxyException('Referenced transfer identifier is invalid.', 'PROTOCOL_ERROR');
        }
        $transferKey = $this->transferKey($transferId);
        $transfer = $this->clients[$clientId]['transfers'][$transferKey] ?? null;
        if ($transfer === null || $transfer['state'] !== 'ready') {
            throw new FoxyException('Referenced transfer is not ready.', 'TRANSFER_NOT_FOUND');
        }
        $usedTransfers[$transferKey] = $transferId;
        return new StreamValue($transfer['path'], $transfer['format'], $transfer['received']);
    }

    private function removeTransfer(int $clientId, string $transferId): void
    {
        $transferKey = $this->transferKey($transferId);
        if (!isset($this->clients[$clientId]['transfers'][$transferKey])) {
            return;
        }
        $transfer = $this->clients[$clientId]['transfers'][$transferKey];
        if (isset($transfer['stream']) && is_resource($transfer['stream'])) {
            fclose($transfer['stream']);
        }
        if (is_file($transfer['path'])) {
            @unlink($transfer['path']);
        }
        $this->activeTransfers = max(0, $this->activeTransfers - 1);
        $this->reservedUploadBytes = max(0, $this->reservedUploadBytes - (int) ($transfer['reserved'] ?? 0));
        unset($this->clients[$clientId]['transfers'][$transferKey]);
    }

    private function validateUtf8File(string $path): void
    {
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to validate uploaded text.', 'STORAGE_IO');
        }
        $carry = '';
        try {
            while (!feof($stream)) {
                $chunk = fread($stream, 65_536);
                if ($chunk === false) {
                    throw new FoxyException('Unable to validate uploaded text.', 'STORAGE_IO');
                }
                if ($chunk === '') {
                    break;
                }
                $data = $carry . $chunk;
                [$complete, $carry] = $this->splitCompleteUtf8($data);
                if ($complete !== '' && !mb_check_encoding($complete, 'UTF-8')) {
                    throw new FoxyException('Uploaded text is not valid UTF-8.', 'INVALID_VALUE');
                }
            }
            if ($carry !== '' && !mb_check_encoding($carry, 'UTF-8')) {
                throw new FoxyException('Uploaded text is not valid UTF-8.', 'INVALID_VALUE');
            }
        } finally {
            fclose($stream);
        }
    }

    private function splitCompleteUtf8(string $data): array
    {
        $length = strlen($data);
        if ($length === 0) {
            return ['', ''];
        }
        $start = $length - 1;
        while ($start >= 0 && (ord($data[$start]) & 0xc0) === 0x80) {
            $start--;
        }
        if ($start < 0) {
            return [$data, ''];
        }
        $lead = ord($data[$start]);
        $expected = match (true) {
            $lead < 0x80 => 1,
            ($lead & 0xe0) === 0xc0 => 2,
            ($lead & 0xf0) === 0xe0 => 3,
            ($lead & 0xf8) === 0xf0 => 4,
            default => 1,
        };
        if ($length - $start < $expected) {
            return [substr($data, 0, $start), substr($data, $start)];
        }
        return [$data, ''];
    }

    private function transferId(array $request): string
    {
        $transferId = $request['transfer_id'] ?? null;
        if (!is_string($transferId) || preg_match('/^[A-Za-z0-9_-]{1,128}$/', $transferId) !== 1) {
            throw new FoxyException('A valid transfer identifier is required.', 'PROTOCOL_ERROR');
        }
        return $transferId;
    }

    private function transferKey(string $transferId): string
    {
        return "\0{$transferId}";
    }

    private function send(int $clientId, array $payload): void
    {
        $this->queueOutput($clientId, FrameCodec::encode($payload, $this->outboundPacketLimit($clientId)));
    }

    private function queueFrame(int $clientId, array $payload, string &$buffer, int &$frames): void
    {
        $encoded = FrameCodec::encode($payload, $this->outboundPacketLimit($clientId));
        if ($buffer !== '' && (strlen($buffer) + strlen($encoded) > 65_536 || $frames >= 16)) {
            $this->flushFrameBuffer($clientId, $buffer, $frames);
        }
        $buffer .= $encoded;
        $frames++;
    }

    private function flushFrameBuffer(int $clientId, string &$buffer, int &$frames): void
    {
        if ($buffer === '') {
            return;
        }
        if (!isset($this->clients[$clientId])) {
            throw new FoxyException('Client is no longer connected.', 'CONNECTION_CLOSED');
        }
        $data = $buffer;
        $buffer = '';
        $frames = 0;
        $this->queueOutput($clientId, $data);
    }

    private function queueOutput(int $clientId, string $data): void
    {
        if ($data === '') {
            return;
        }
        if (!isset($this->clients[$clientId])) {
            throw new FoxyException('Client is no longer connected.', 'CONNECTION_CLOSED');
        }
        if (!$this->flushClientOutput($clientId, false) || !isset($this->clients[$clientId])) {
            throw new FoxyException('Unable to write to the client.', 'CONNECTION_IO');
        }

        $clientBytes = strlen($this->clients[$clientId]['output_buffer']);
        $dataBytes = strlen($data);
        if ($dataBytes > $this->clientOutputLimit($clientId) - $clientBytes
            || $dataBytes > $this->outputBufferLimit() - $this->queuedOutputBytes) {
            $this->disconnect($clientId, 'output_backpressure');
            throw new FoxyException('Client output buffer exceeds its limit.', 'CONNECTION_IO');
        }
        if ($clientBytes === 0) {
            $this->clients[$clientId]['output_since'] = time();
        }
        $this->clients[$clientId]['output_buffer'] .= $data;
        $this->queuedOutputBytes += $dataBytes;
        if (!$this->flushClientOutput($clientId)) {
            throw new FoxyException('Unable to write to the client.', 'CONNECTION_IO');
        }
    }

    private function flushClientOutput(int $clientId, bool $closeWhenDrained = true): bool
    {
        if (!isset($this->clients[$clientId])) {
            return false;
        }
        $buffer = $this->clients[$clientId]['output_buffer'];
        if ($buffer === '') {
            return true;
        }
        $stream = $this->clients[$clientId]['stream'];
        $written = @fwrite($stream, substr($buffer, 0, self::OUTPUT_WRITE_BYTES));
        if ($written === false) {
            $this->disconnect($clientId, 'write_failed');
            return false;
        }
        if ($written === 0) {
            if (feof($stream)) {
                $this->disconnect($clientId, 'write_failed');
                return false;
            }
            return true;
        }

        $this->clients[$clientId]['output_buffer'] = substr($buffer, $written);
        $this->queuedOutputBytes = max(0, $this->queuedOutputBytes - $written);
        $this->clients[$clientId]['last_activity'] = time();
        if ($this->clients[$clientId]['output_buffer'] !== '') {
            $this->clients[$clientId]['output_since'] = time();
            return true;
        }
        $this->clients[$clientId]['output_since'] = null;
        if ($closeWhenDrained && $this->clients[$clientId]['close_after_write']) {
            $reason = $this->clients[$clientId]['close_reason'] ?? 'closed_after_write';
            $this->disconnect($clientId, $reason);
        }
        return true;
    }

    private function scheduleDisconnect(int $clientId, string $reason): void
    {
        if (!isset($this->clients[$clientId])) {
            return;
        }
        $this->clients[$clientId]['close_after_write'] = true;
        $this->clients[$clientId]['close_reason'] = $reason;
    }

    private function sendError(int $clientId, mixed $requestId, FoxyException $exception): void
    {
        try {
            $this->send($clientId, [
                'type' => 'error',
                'id' => $requestId,
                'ok' => false,
                'error' => $exception->toArray(),
                'limits' => $this->protocolLimits($clientId),
            ]);
        } catch (\Throwable) {
            $this->disconnect($clientId, 'error_response_failed');
        }
    }

    private function disconnectIdleClients(): void
    {
        foreach ($this->clients as $id => $client) {
            $connectTimeout = (int) $this->systemVariables->get('connect_timeout');
            $idleTimeout = $client['interactive']
                ? (int) ($client['session']?->variable('interactive_timeout', 300) ?? 300)
                : (int) ($client['session']?->variable('wait_timeout', 300) ?? 300);
            if ($client['output_buffer'] !== '' && $client['output_since'] !== null
                && $client['output_since'] <= time() - self::OUTPUT_STALL_TIMEOUT_SECONDS) {
                $this->disconnect($id, 'write_timeout');
            } elseif ((!$client['tls_ready'] && $client['connected_at'] < time() - $connectTimeout)
                || ($client['tls_ready'] && !$client['authenticated']
                    && $client['connected_at'] < time() - $connectTimeout)
                || $client['last_activity'] < time() - $idleTimeout) {
                $this->disconnect($id, 'timeout');
            }
        }
    }

    private function disconnect(int $clientId, string $reason = 'closed'): void
    {
        if (!isset($this->clients[$clientId])) {
            return;
        }
        $context = $this->clientContext($clientId) + ['reason' => $reason];
        $this->logger->general('connection.closed', $context);
        $this->logger->audit('connection.closed', $context);
        foreach ($this->clients[$clientId]['transfers'] as $transfer) {
            $this->removeTransfer($clientId, $transfer['id']);
        }
        $session = $this->clients[$clientId]['session'];
        if ($session instanceof Session) {
            $session->resetAuthentication();
            if (count($this->sessionCache) < (int) $this->systemVariables->get('thread_cache_size')) {
                $this->sessionCache[] = $session;
            }
        }
        $stream = $this->clients[$clientId]['stream'];
        $this->bufferedInputBytes = max(
            0,
            $this->bufferedInputBytes - strlen($this->clients[$clientId]['buffer']),
        );
        $this->queuedOutputBytes = max(
            0,
            $this->queuedOutputBytes - strlen($this->clients[$clientId]['output_buffer']),
        );
        unset($this->clients[$clientId]);
        if (is_resource($stream)) {
            fclose($stream);
        }
    }

    private function clientContext(int $clientId): array
    {
        $client = $this->clients[$clientId] ?? null;
        if (!is_array($client)) {
            return ['connection_id' => $clientId];
        }
        return [
            'connection_id' => $clientId,
            'peer' => $client['peer'],
            'peer_address' => $client['peer_address'],
            'peer_name' => $client['peer_name'],
            'username' => $client['username'],
            'tls_ready' => $client['tls_ready'],
            'authenticated' => $client['authenticated'],
            'interactive' => $client['interactive'],
        ];
    }

    private function globalPacketLimit(): int
    {
        return min($this->config->maxFrameBytes, (int) $this->systemVariables->get('max_allowed_packet'));
    }

    private function packetLimit(int $clientId): int
    {
        $global = $this->globalPacketLimit();
        $session = $this->clients[$clientId]['session'] ?? null;
        return $session instanceof Session
            ? min($global, (int) $session->variable('max_allowed_packet', $global))
            : $global;
    }

    private function chunkPayloadLimit(?int $clientId = null): int
    {
        $packet = $clientId === null ? $this->globalPacketLimit() : $this->packetLimit($clientId);
        return max(256, min($this->config->chunkBytes, max(256, $packet - 1_024)));
    }

    private function outboundPacketLimit(int $clientId): int
    {
        $packet = $this->packetLimit($clientId);
        $peer = $this->clients[$clientId]['peer_frame_bytes'] ?? null;
        return is_int($peer) ? min($packet, $peer) : $packet;
    }

    private function outboundChunkPayloadLimit(int $clientId): int
    {
        $packet = max(1, $this->outboundPacketLimit($clientId) - 1_024);
        $peer = $this->clients[$clientId]['peer_chunk_bytes'] ?? null;
        $peerLimit = is_int($peer) ? $peer : $packet;
        return max(1, min($this->config->chunkBytes, $packet, $peerLimit));
    }

    private function protocolLimits(int $clientId): array
    {
        return [
            'frame_payload_bytes' => $this->packetLimit($clientId),
            'chunk_payload_bytes' => $this->chunkPayloadLimit($clientId),
        ];
    }

    private function inputBufferLimit(): int
    {
        return max(self::BUFFER_POOL_BYTES, $this->globalPacketLimit() + FrameCodec::HEADER_BYTES);
    }

    private function clientOutputLimit(int $clientId): int
    {
        return max(
            self::MINIMUM_CLIENT_OUTPUT_BYTES,
            $this->outboundPacketLimit($clientId) + FrameCodec::HEADER_BYTES,
        );
    }

    private function outputBufferLimit(): int
    {
        return max(self::BUFFER_POOL_BYTES, $this->globalPacketLimit() + FrameCodec::HEADER_BYTES);
    }

    private function peerAddress(string $peer): string
    {
        if (preg_match('/^\[([^]]+)](?::[0-9]+)?$/', $peer, $match) === 1) {
            return $match[1];
        }
        $separator = strrpos($peer, ':');
        if ($separator !== false) {
            $candidate = substr($peer, 0, $separator);
            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                return $candidate;
            }
        }
        return $peer;
    }

    private function recordConnectError(string $address): void
    {
        if (!isset($this->connectErrors[$address]) && count($this->connectErrors) >= 10_000) {
            unset($this->connectErrors[array_key_first($this->connectErrors)]);
        }
        $count = $this->connectErrorCount($address);
        $this->connectErrors[$address] = ['count' => $count + 1, 'last_failure' => time()];
    }

    private function connectErrorCount(string $address): int
    {
        $entry = $this->connectErrors[$address] ?? null;
        if (!is_array($entry)) {
            return 0;
        }
        if (($entry['last_failure'] ?? 0) < time() - self::CONNECT_ERROR_WINDOW_SECONDS) {
            unset($this->connectErrors[$address]);
            return 0;
        }
        return (int) ($entry['count'] ?? 0);
    }

    private function removeAbandonedTransfers(): void
    {
        $entries = scandir($this->transferDirectory);
        if ($entries === false) {
            throw new FoxyException('Unable to scan transfer directory.', 'STORAGE_IO');
        }
        foreach ($entries as $entry) {
            if (str_ends_with($entry, '.upload')) {
                @unlink($this->transferDirectory . DIRECTORY_SEPARATOR . $entry);
            }
        }
    }
}
