<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Client;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;

function launchServer(string $tag, int $port, string $directory, array $extraEnv = []): array
{
    $command = [
        PHP_BINARY,
        dirname(__DIR__) . '/bin/foxydb.php',
        '--host=127.0.0.1',
        '--port=' . $port,
        '--data-dir=' . $directory,
        '--no-sync',
    ];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $environment = getenv();
    if (!is_array($environment)) {
        $environment = [];
    }
    foreach ($extraEnv as $name => $value) {
        $environment[$name] = (string) $value;
    }
    $process = proc_open($command, $descriptors, $pipes, dirname(__DIR__), $environment, ['bypass_shell' => true]);
    if (!is_resource($process)) {
        throw new RuntimeException("Unable to launch the {$tag} server.");
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    return ['process' => $process, 'pipes' => $pipes];
}

function awaitReady(int $port, array $server): Client
{
    $deadline = microtime(true) + 20;
    while (microtime(true) < $deadline) {
        try {
            return Client::connect('127.0.0.1', $port, 'root', 'root', 2.0);
        } catch (FoxyException) {
            usleep(100_000);
        }
    }
    $stdout = stream_get_contents($server['pipes'][1]);
    $stderr = stream_get_contents($server['pipes'][2]);
    throw new RuntimeException("server did not start. stdout={$stdout} stderr={$stderr}");
}

function stopServer(array $server): void
{
    proc_terminate($server['process']);
    $deadline = microtime(true) + 5;
    do {
        $status = proc_get_status($server['process']);
        if (!$status['running']) {
            break;
        }
        usleep(100_000);
    } while (microtime(true) < $deadline);
    if (($status['running'] ?? false) === true) {
        proc_terminate($server['process'], 9);
    }
    foreach ($server['pipes'] as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    proc_close($server['process']);
}

function reservePort(): int
{
    $probe = stream_socket_server('tcp://127.0.0.1:0', $probeCode, $probeError);
    if ($probe === false) {
        throw new RuntimeException("Unable to reserve a test port: {$probeError}");
    }
    $probeAddress = stream_socket_get_name($probe, false);
    fclose($probe);
    return (int) substr(strrchr($probeAddress, ':'), 1);
}

function replicateOnce(int $sourcePort, int $targetPort): array
{
    $command = [
        PHP_BINARY,
        dirname(__DIR__) . '/bin/foxydb-replicate.php',
        '--source-host=127.0.0.1',
        '--source-port=' . $sourcePort,
        '--target-host=127.0.0.1',
        '--target-port=' . $targetPort,
        '--connect-timeout=10',
        '--once',
    ];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes, dirname(__DIR__), null, ['bypass_shell' => true]);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to launch the relay process.');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    if ($exitCode !== 0) {
        throw new RuntimeException("relay failed code={$exitCode} stdout={$stdout} stderr={$stderr}");
    }
    return ['stdout' => $stdout, 'stderr' => $stderr];
}

function fetchRows(Client $client, string $sql, array $parameters = []): array
{
    return iterator_to_array($client->query($sql, $parameters)->rows, false);
}

$sourceDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-repl-src-' . bin2hex(random_bytes(6));
$targetDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-repl-tgt-' . bin2hex(random_bytes(6));

$sourcePort = reservePort();
$targetPort = reservePort();
$sourceServer = launchServer('source', $sourcePort, $sourceDirectory, [
    'FOXYDB_REPLICATION' => '1',
    'FOXYDB_REPLICATION_RETENTION_HOURS' => '0',
]);
$targetServer = launchServer('follower', $targetPort, $targetDirectory);

try {
    $source = awaitReady($sourcePort, $sourceServer);
    $target = awaitReady($targetPort, $targetServer);

    $source->query('CREATE DATABASE ledger');
    $source->query('USE ledger');
    $source->query(
        'CREATE TABLE accounts (id INT PRIMARY KEY AUTO_INCREMENT, '
        . 'owner VARCHAR(80) NOT NULL, balance INT NOT NULL DEFAULT 0)',
    );
    replicateOnce($sourcePort, $targetPort);

    $target->query('USE ledger');
    $targetTables = fetchRows($target, 'SHOW TABLES');
    if (!in_array('accounts', array_column($targetTables, 'table'), true)) {
        throw new RuntimeException('replicated CREATE TABLE did not land on the follower.');
    }

    $source->query("INSERT INTO accounts (owner, balance) VALUES ('alice', 100)");
    $source->query("INSERT INTO accounts (owner, balance) VALUES ('bob', 0), ('carol', 50)");
    replicateOnce($sourcePort, $targetPort);
    $sourceAccounts = fetchRows($source, 'SELECT id, owner, balance FROM accounts ORDER BY id');
    $targetAccounts = fetchRows($target, 'SELECT id, owner, balance FROM accounts ORDER BY id');
    if ($sourceAccounts !== $targetAccounts) {
        throw new RuntimeException('replicated INSERT diverged the follower.');
    }

    $source->query("UPDATE accounts SET balance = 300 WHERE owner = 'alice'");
    $source->query("DELETE FROM accounts WHERE owner = 'bob'");
    replicateOnce($sourcePort, $targetPort);
    if (fetchRows($source, 'SELECT id, owner, balance FROM accounts ORDER BY id')
        !== fetchRows($target, 'SELECT id, owner, balance FROM accounts ORDER BY id')) {
        throw new RuntimeException('UPDATE/DELETE did not replicate consistently.');
    }

    $source->query('TRUNCATE TABLE accounts');
    replicateOnce($sourcePort, $targetPort);
    if (count(fetchRows($target, 'SELECT id FROM accounts')) !== 0) {
        throw new RuntimeException('TRUNCATE did not clear the follower.');
    }

    $source->query(
        "INSERT INTO accounts (owner, balance) VALUES "
        . "('dave', 12), ('erin', 7), ('frank', 40), ('gina', 91), ('hugo', 33)",
    );
    replicateOnce($sourcePort, $targetPort);
    $source->query("DELETE FROM accounts WHERE balance >= 40");
    replicateOnce($sourcePort, $targetPort);
    if (fetchRows($source, 'SELECT id, owner, balance FROM accounts ORDER BY id')
        !== fetchRows($target, 'SELECT id, owner, balance FROM accounts ORDER BY id')) {
        throw new RuntimeException('bulk DELETE diverged the follower.');
    }

    if (preg_match('/replication.pass applied=(\d+)/', replicateOnce($sourcePort, $targetPort)['stdout'], $match) !== 1
        || (int) $match[1] !== 0) {
        throw new RuntimeException('relay did not remain idle after the previous drain.');
    }
    $pending = fetchRows($source, "SELECT log_id FROM `foxydb`.`replication_log` WHERE applied = FALSE");
    if ($pending !== []) {
        throw new RuntimeException('relay left unapplied journal entries.');
    }

    try {
        $source->query('BEGIN');
        $source->query("INSERT INTO accounts (owner, balance) VALUES ('rollback-target', 9999)");
        $source->query('ROLLBACK');
        replicateOnce($sourcePort, $targetPort);
        if (fetchRows($source, "SELECT id FROM accounts WHERE owner = 'rollback-target'") !== []) {
            throw new RuntimeException('source kept the rolled-back row.');
        }
        if (fetchRows($target, "SELECT id FROM accounts WHERE owner = 'rollback-target'") !== []) {
            throw new RuntimeException('follower received rolled-back transaction work.');
        }
    } catch (FoxyException $exception) {
        throw new RuntimeException('transaction rollback path failed: ' . $exception->getMessage());
    }

    $source->query('BEGIN');
    $source->query("INSERT INTO accounts (owner, balance) VALUES ('commit-target', 10000)");
    $source->query('COMMIT');
    replicateOnce($sourcePort, $targetPort);
    $sb = fetchRows($source, "SELECT id, owner, balance FROM accounts WHERE owner = 'commit-target'");
    $tb = fetchRows($target, "SELECT id, owner, balance FROM accounts WHERE owner = 'commit-target'");
    if ($sb
        !== $tb) {
        throw new RuntimeException('committed transaction work did not replicate cleanly.');
    }

    $source->query("INSERT INTO accounts (owner, balance) VALUES ('jane', 88)");
    replicateOnce($sourcePort, $targetPort);
    $changedTarget = fetchRows($target, "SELECT id, owner, balance FROM accounts WHERE owner = 'jane'");
    if ($changedTarget === []
        || $changedTarget[0]['balance'] !== 88) {
        throw new RuntimeException('default-source INSERT row did not arrive on the follower.');
    }

    $sourceSource = fetchRows($source, 'SELECT id, owner, balance FROM accounts ORDER BY id');
    $sourceTarget = fetchRows($target, 'SELECT id, owner, balance FROM accounts ORDER BY id');
    if ($sourceSource !== $sourceTarget) {
        throw new RuntimeException('final source/target diverged.');
    }

    $source->close();
    $target->close();
    echo "replication: ok\n";
} finally {
    stopServer($sourceServer);
    stopServer($targetServer);
    if (is_dir($sourceDirectory)) {
        FileSystem::removeTree($sourceDirectory);
    }
    if (is_dir($targetDirectory)) {
        FileSystem::removeTree($targetDirectory);
    }
}
