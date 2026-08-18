<?php

declare(strict_types=1);

require __DIR__ . '/../src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Support\FileSystem;

/**
 * Crash-consistency for multi-row commits.
 *
 * A server is told to commit a very large multi-row INSERT (which takes long
 * enough to observe mid-flight) and is then killed at several points: before
 * the batch journal appears, while the batch journal and partially written
 * slots are on disk, and after the commit has fully flushed. On restart the
 * row count must be exactly the seed count or the seed count plus the full
 * batch size - never a committed prefix.
 */

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-crash-' . bin2hex(random_bytes(6));
$serverLog = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-crash-server-' . bin2hex(random_bytes(6)) . '.log';
$databaseName = 'crash';
$tableName = 'atomic_test';
$batchRows = 18_000;
$seedRows = 1;

$listener = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
if ($listener === false) {
    throw new RuntimeException("Unable to reserve a port: {$errorMessage}");
}
$name = stream_socket_get_name($listener, false);
fclose($listener);
$port = (int) substr(strrchr($name, ':'), 1);

$failures = [];
$process = null;
$pipes = [];

$startServer = static function () use (&$process, &$pipes, $port, $directory, $serverLog): void {
    $process = proc_open(
        [
            PHP_BINARY, '-d', 'memory_limit=1G',
            __DIR__ . '/../bin/foxydb.php',
            "--host=127.0.0.1",
            "--port={$port}",
            "--data-dir={$directory}",
        ],
        [0 => ['pipe', 'r'], 1 => ['file', $serverLog, 'a'], 2 => ['file', $serverLog, 'a']],
        $pipes,
        dirname(__DIR__),
        null,
        ['bypass_shell' => true],
    );
    fclose($pipes[0]);
};

$stopServer = static function () use (&$process, &$pipes): void {
    if ($process === null) {
        $pipes = [];
        return;
    }
    @proc_terminate($process);
    for ($i = 0; $i < 100; $i++) {
        $status = proc_get_status($process);
        if ($status['running'] === false) {
            break;
        }
        usleep(50_000);
    }
    if (($status['running'] ?? false) === true) {
        @proc_terminate($process, 9);
        usleep(100_000);
    }
    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    $process = null;
    $pipes = [];
};

$connectClient = static function (float $timeout) use ($port): mixed {
    $socket = false;
    $lastError = '';
    for ($attempt = 0; $attempt < 100 && $socket === false; $attempt++) {
        $socket = @stream_socket_client(
            "tcp://127.0.0.1:{$port}",
            $errorCodeA,
            $errorMessageA,
            $timeout,
            STREAM_CLIENT_CONNECT,
        );
        if ($socket === false) {
            $lastError = $errorMessageA;
            usleep(100_000);
        }
    }
    if ($socket === false) {
        throw new RuntimeException(
            "Unable to connect to the server on port {$port}: {$lastError}",
        );
    }
    stream_set_timeout($socket, (int) $timeout);
    $hello = FrameCodec::read($socket, 8_388_608);
    if (($hello['type'] ?? null) !== 'hello') {
        fclose($socket);
        throw new RuntimeException('Server did not send the protocol greeting.');
    }
    FrameCodec::write($socket, [
        'type' => 'auth',
        'id' => 1,
        'username' => 'root',
        'password' => 'root',
        'interactive' => false,
        'limits' => ['frame_payload_bytes' => 8_388_608, 'chunk_payload_bytes' => 1_048_576],
    ], 8_388_608);
    $auth = FrameCodec::read($socket, 8_388_608);
    if (($auth['type'] ?? null) !== 'auth' || ($auth['ok'] ?? false) !== true) {
        fclose($socket);
        throw new RuntimeException('Authentication failed on the crash test connection.');
    }
    return $socket;
};

$query = static function ($socket, int $id, string $sql, array $params = []): void {
    FrameCodec::write($socket, ['type' => 'query', 'id' => $id, 'sql' => $sql, 'params' => $params], 8_388_608);
    for (;;) {
        $frame = FrameCodec::read($socket, 8_388_608);
        $type = $frame['type'] ?? null;
        if ($type === 'error') {
            throw new FoxyException('Crash test query failed: ' . json_encode($frame));
        }
        if ($type === 'result' || $type === 'result_start' || $type === 'result_end') {
            break;
        }
    }
};

$countRows = static function ($socket, string $sql): int {
    FrameCodec::write($socket, ['type' => 'query', 'id' => 999, 'sql' => $sql, 'params' => []], 8_388_608);
    $total = null;
    for (;;) {
        $frame = FrameCodec::read($socket, 8_388_608);
        $type = $frame['type'] ?? null;
        if ($type === 'row') {
            $row = $frame['row'] ?? [];
            $total = (int) ($row['total'] ?? 0);
        }
        if ($type === 'error') {
            throw new FoxyException('Crash test count query failed: ' . json_encode($frame));
        }
        if ($type === 'result_end') {
            break;
        }
    }
    if ($total === null) {
        throw new RuntimeException('Crash test count query returned no row.');
    }
    return $total;
};

$placeholders = [];
$parameters = [];
for ($i = 0; $i < $batchRows; $i++) {
    $placeholders[] = '(?, ?)';
    $parameters[] = 'v' . $i;
    $parameters[] = 'b' . $i;
}
$insertSql = 'INSERT INTO atomic_test (value, note) VALUES ' . implode(', ', $placeholders);

$tableDir = $directory . DIRECTORY_SEPARATOR . 'databases' . DIRECTORY_SEPARATOR
    . $databaseName . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $tableName;
$batchJournalPath = $tableDir . DIRECTORY_SEPARATOR . 'row.batch.fdb';

$readResult = static function ($socket): void {
    for (;;) {
        try {
            $frame = FrameCodec::read($socket, 8_388_608);
        } catch (\Throwable $throwable) {
            throw new RuntimeException('Insert response not received: ' . $throwable->getMessage());
        }
        $type = $frame['type'] ?? null;
        if ($type === 'error') {
            throw new FoxyException('Insert response reported an error: ' . json_encode($frame));
        }
        if ($type === 'result' || $type === 'result_end') {
            return;
        }
    }
};

$killStrategies = [
    'before-commit' => static function (): void {
        usleep(350_000);
    },
    'mid-commit' => static function () use ($batchJournalPath): void {
        $start = microtime(true);
        while (microtime(true) - $start < 25) {
            if (is_file($batchJournalPath)) {
                fwrite(STDERR, "  [mid-commit] batch journal observed, killing now\n");
                usleep(80_000);
                return;
            }
            usleep(10_000);
        }
        fwrite(STDERR, "  [mid-commit] batch journal never appeared; killing anyway\n");
    },
    'after-commit' => static function () use ($batchJournalPath, &$insertSocket, $readResult): void {
        // Wait for the batch journal to appear, then keep reading the insert
        // response so the server can finish flushing every slot and index
        // entry. Reading the response confirms the commit fully completed.
        $start = microtime(true);
        while (microtime(true) - $start < 120) {
            if (is_file($batchJournalPath)) {
                break;
            }
            usleep(20_000);
        }
        $readResult($insertSocket);
    },
];

try {
    foreach ($killStrategies as $strategyName => $strategy) {
        FileSystem::removeTree($directory);
        $process = null;
        $pipes = [];
        $insertSocket = null;
        $startServer();

        $insertSocket = $connectClient(8.0);
        $query($insertSocket, 10, "CREATE DATABASE {$databaseName}");
        $query($insertSocket, 11, "USE {$databaseName}");
        $query($insertSocket, 12, "CREATE TABLE {$tableName} (id INT PRIMARY KEY AUTO_INCREMENT, value VARCHAR(10), note VARCHAR(40))");
        $query($insertSocket, 13, "INSERT INTO {$tableName} (value, note) VALUES ('seed', 'baseline')");

        // Fire the large insert without waiting for its response. Keep the socket
        // open so the server can consume the full frame and start the commit.
        FrameCodec::write($insertSocket, ['type' => 'query', 'id' => 200, 'sql' => $insertSql, 'params' => $parameters], 8_388_608);

        fwrite(STDERR, "  [{$strategyName}] waiting for the crash point...\n");
        $strategy();

        $status = proc_get_status($process);
        if ($status['running'] === false) {
            $failures[] = "The server exited before it could be killed during {$strategyName}.";
            $stopServer();
            continue;
        }
        proc_terminate($process, 9);
        for ($i = 0; $i < 100 && proc_get_status($process)['running']; $i++) {
            usleep(50_000);
        }
        fwrite(STDERR, "  killed for {$strategyName}\n");
        if (is_resource($insertSocket)) {
            fclose($insertSocket);
        }
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        $process = null;
        $pipes = [];
        usleep(200_000);

        // Restart on the same data directory and count.
        $startServer();
        $socket = $connectClient(120.0);
        $query($socket, 20, "USE {$databaseName}");
        $total = $countRows($socket, "SELECT COUNT(*) AS total FROM {$tableName}");
        fclose($socket);
        $stopServer();
        fwrite(STDERR, "  [{$strategyName}] rows after restart: {$total}\n");

        $expected = [$seedRows, $seedRows + $batchRows];
        if (!in_array($total, $expected, true)) {
            $failures[] = sprintf(
                "After %s the table held %d rows; expected all-or-nothing in {%s}.",
                $strategyName,
                $total,
                implode(', ', $expected),
            );
        }
    }
} catch (\Throwable $throwable) {
    $failures[] = 'uncaught: ' . $throwable->getMessage();
} finally {
    $stopServer();
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
    if (file_exists($serverLog) && $failures !== []) {
        fwrite(STDERR, "SERVER LOG:\n" . file_get_contents($serverLog) . "\n");
    }
    @unlink($serverLog);
}

if ($failures !== []) {
    fwrite(STDERR, "crash consistency:\n  - " . implode("\n  - ", $failures) . "\n");
    if (isset($throwable)) {
        throw $throwable;
    }
    exit(1);
}
echo "crash consistency: ok\n";
