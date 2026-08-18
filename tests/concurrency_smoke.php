<?php

declare(strict_types=1);

require __DIR__ . '/../src/Autoloader.php';

use FoxyDB\Client;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Support\FileSystem;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-concurrent-' . bin2hex(random_bytes(6));
$serverLog = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-concurrent-server-' . bin2hex(random_bytes(6)) . '.log';

$listener = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
if ($listener === false) {
    throw new RuntimeException("Unable to reserve a port: {$errorMessage}");
}
$name = stream_socket_get_name($listener, false);
fclose($listener);
$port = (int) substr(strrchr($name, ':'), 1);

$process = null;
$pipes = [];
$slow = null;
$failures = [];
try {
    $process = proc_open(
        [PHP_BINARY, __DIR__ . '/../bin/foxydb.php', "--host=127.0.0.1", "--port={$port}", "--data-dir={$directory}", '--no-sync'],
        [0 => ['pipe', 'r'], 1 => ['file', $serverLog, 'a'], 2 => ['file', $serverLog, 'a']],
        $pipes,
        dirname(__DIR__),
        null,
        ['bypass_shell' => true],
    );
    fclose($pipes[0]);

    $client = null;
    for ($attempt = 0; $attempt < 100 && $client === null; $attempt++) {
        try {
            $client = Client::connect('127.0.0.1', $port, 'root', 'root', 60.0);
        } catch (FoxyException) {
            usleep(100_000);
        }
    }
    if ($client === null) {
        throw new RuntimeException('Server did not come up; log: ' . @file_get_contents($serverLog));
    }
    $client->query('CREATE DATABASE concurrent');
    $client->query('USE concurrent');
    $client->query('CREATE TABLE load_test (id INT PRIMARY KEY AUTO_INCREMENT, value INT, note VARCHAR(20))');

    $insertStarted = microtime(true);
    for ($batch = 0; $batch < 40; $batch++) {
        $placeholders = [];
        $parameters = [];
        for ($i = 0; $i < 100; $i++) {
            $placeholders[] = '(?, ?)';
            $parameters[] = $batch * 100 + $i;
            $parameters[] = 'row' . ($batch * 100 + $i);
        }
        $client->query('INSERT INTO load_test (value, note) VALUES ' . implode(', ', $placeholders), $parameters);
    }
    $insertMs = (int) ((microtime(true) - $insertStarted) * 1000);

    $slow = stream_socket_client("tcp://127.0.0.1:{$port}", $socketErrorCode, $socketErrorMessage, 3.0);
    if ($slow === false) {
        throw new RuntimeException("Unable to open the slow query connection: {$socketErrorMessage}");
    }
    stream_set_timeout($slow, 5);
    $hello = FrameCodec::read($slow, 8_388_608);
    if (($hello['type'] ?? null) !== 'hello') {
        throw new RuntimeException('Slow connection did not receive a greeting.');
    }
    FrameCodec::write($slow, [
        'type' => 'auth',
        'id' => 1,
        'username' => 'root',
        'password' => 'root',
        'interactive' => false,
        'limits' => ['frame_payload_bytes' => 8_388_608, 'chunk_payload_bytes' => 1_048_576],
    ], 8_388_608);
    $auth = FrameCodec::read($slow, 8_388_608);
    if (($auth['type'] ?? null) !== 'auth' || ($auth['ok'] ?? false) !== true) {
        throw new RuntimeException('Slow connection authentication failed: ' . json_encode($auth));
    }
    FrameCodec::write($slow, ['type' => 'query', 'id' => 2, 'sql' => 'USE concurrent', 'params' => []], 8_388_608);
    $useResponse = FrameCodec::read($slow, 8_388_608);
    if (($useResponse['ok'] ?? false) !== true) {
        throw new RuntimeException('USE failed on the slow connection: ' . json_encode($useResponse));
    }

    $queryStarted = microtime(true);
    FrameCodec::write($slow, ['type' => 'query', 'id' => 3, 'sql' => 'SELECT id, value, note FROM load_test', 'params' => []], 8_388_608);

    $fast = Client::connect('127.0.0.1', $port, 'root', 'root', 60.0);
    $pingStarted = microtime(true);
    $fast->ping();
    $pingMicroseconds = (int) ((microtime(true) - $pingStarted) * 1_000_000);
    $fast->close();

    $drained = 0;
    $sawRows = false;
    $sawEnd = false;
    while ($drained < 320 && $sawEnd === false) {
        try {
            $frame = FrameCodec::read($slow, 8_388_608);
        } catch (FoxyException $exception) {
            break;
        }
        $drained++;
        if (($frame['type'] ?? null) === 'result_end') {
            $sawEnd = true;
        }
        if (($frame['type'] ?? null) === 'row') {
            $sawRows = true;
        }
    }
    $fullMs = (int) ((microtime(true) - $queryStarted) * 1000);
    fclose($slow);
    $slow = null;

    if ($drained < 2) {
        $failures[] = "The slow query connection drained only {$drained} frames: insert {$insertMs} ms; full-scan {$fullMs} ms.";
    }
    if ($sawRows === false) {
        $failures[] = "The slow query streamed no row frames ({$drained} frames total).";
    }
    if ($pingMicroseconds > $fullMs * 250) {
        $failures[] = sprintf(
            'A short ping was not interleaved while a long query ran: ping %d us, full scan %d ms.',
            $pingMicroseconds,
            $fullMs,
        );
    }
    if ($fullMs > 0 && $insertMs < 0) {
        $failures[] = 'Gate failed; check the stopwatch.';
    }
} finally {
    if ($slow !== null) {
        fclose($slow);
    }
    if ($process !== null) {
        proc_terminate($process);
        for ($i = 0; $i < 50; $i++) {
            $status = proc_get_status($process);
            if ($status['running'] === false) {
                break;
            }
            usleep(100_000);
        }
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        proc_close($process);
    }
    if (isset($client)) {
        $client->close();
    }
    FileSystem::removeTree($directory);
    @unlink($serverLog);
}

if ($failures !== []) {
    fwrite(STDERR, "concurrency smoke:\n  - " . implode("\n  - ", $failures) . "\n");
    exit(1);
}
echo 'concurrency smoke: ok' . PHP_EOL;