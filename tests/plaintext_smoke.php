<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Client;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;
use FoxyDB\TlsOptions;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-plain-' . bin2hex(random_bytes(6));
$probe = stream_socket_server('tcp://127.0.0.1:0', $probeCode, $probeError);
if ($probe === false) {
    throw new RuntimeException("Unable to reserve a test port: {$probeError}");
}
$probeAddress = stream_socket_get_name($probe, false);
fclose($probe);
$port = (int) substr(strrchr($probeAddress, ':'), 1);
$command = [
    PHP_BINARY,
    dirname(__DIR__) . '/bin/foxydb.php',
    '--host=127.0.0.1',
    '--port=' . $port,
    '--data-dir=' . $directory,
    '--no-sync',
    '--plaintext',
];
$process = proc_open($command, [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
], $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
if (!is_resource($process)) {
    throw new RuntimeException('Unable to launch the plaintext FoxyDB test server.');
}
fclose($pipes[0]);
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

try {
    $client = null;
    $deadline = microtime(true) + 10;
    while (microtime(true) < $deadline) {
        try {
            $client = Client::connect(
                host: '127.0.0.1',
                port: $port,
                username: 'root',
                password: 'root',
                timeoutSeconds: 1.0,
                tlsOptions: new TlsOptions(mode: 'DISABLED'),
            );
            break;
        } catch (FoxyException) {
            usleep(100_000);
        }
    }
    if (!$client instanceof Client) {
        throw new RuntimeException(
            'Plaintext server did not start: ' . stream_get_contents($pipes[1]) . ' ' . stream_get_contents($pipes[2]),
        );
    }
    if ($client->tlsInfo() !== [] || !$client->ping()) {
        throw new RuntimeException('Plaintext client transport was not established correctly.');
    }
    $rows = $client->query('SELECT * FROM config_schema ORDER BY config_key ASC LIMIT 50')->rows;
    if ($rows === []) {
        throw new RuntimeException('Plaintext query returned no configuration rows.');
    }
    $client->close();

    $preferred = Client::connect(
        host: '127.0.0.1',
        port: $port,
        username: 'root',
        password: 'root',
        timeoutSeconds: 1.0,
        tlsOptions: new TlsOptions(mode: 'PREFERRED'),
    );
    if ($preferred->tlsInfo() !== [] || !$preferred->ping()) {
        throw new RuntimeException('Preferred mode did not fall back to plaintext.');
    }
    $preferred->close();

    $default = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
    if ($default->tlsInfo() !== [] || !$default->ping()) {
        throw new RuntimeException('Default client did not connect over plaintext.');
    }
    $default->close();
    if (is_file($directory . '/tls/server.crt')) {
        throw new RuntimeException('Plaintext mode generated an unnecessary TLS certificate.');
    }
    echo "plaintext smoke: ok\n";
} finally {
    proc_terminate($process);
    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    proc_close($process);
    FileSystem::removeTree($directory);
}
