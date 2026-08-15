<?php

declare(strict_types=1);

$tests = [
    'metadata.php',
    'protocol.php',
    'storage_smoke.php',
    'sql_smoke.php',
    'regression.php',
    'authentication.php',
    'identifiers.php',
    'ordered_indexes.php',
    'system_variables.php',
    'logging.php',
    'secure_options.php',
    'tcp_smoke.php',
    'concurrency_smoke.php',
    'replication.php',
    'ordered_indexes_disk.php',
    'crash_consistency.php',
];

foreach ($tests as $test) {
    $command = [PHP_BINARY, __DIR__ . DIRECTORY_SEPARATOR . $test];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
    if (!is_resource($process)) {
        fwrite(STDERR, "Unable to launch {$test}.\n");
        exit(1);
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    echo $stdout;
    if ($stderr !== '') {
        fwrite(STDERR, $stderr);
    }
    if ($exitCode !== 0) {
        fwrite(STDERR, "{$test} failed with exit code {$exitCode}.\n");
        exit($exitCode);
    }
}

echo "all tests: ok\n";
