<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Client;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Replication;

$options = getopt('', [
    'source-host:',
    'source-port::',
    'source-user::',
    'source-password::',
    'target-host:',
    'target-port::',
    'target-user::',
    'target-password::',
    'batch::',
    'interval-seconds::',
    'max-batches::',
    'connect-timeout::',
    'once',
    'help',
]);

if (isset($options['help']) || !isset($options['source-host'], $options['target-host'])) {
    echo <<<'HELP'
FoxyDB replication relay

Ships changelog entries from a FoxyDB source (FOXYDB_REPLICATION=1) to a
follower. Replayed statements are idempotent so multiple relays or restarts
are safe; the source marks every applied entry AFTER it lands.

Usage:
  php bin/foxydb-replicate.php
      --source-host=127.0.0.1 [--source-port=2002]
      [--source-user=root] [--source-password=root]
      --target-host=127.0.0.1 [--target-port=2003]
      [--target-user=root] [--target-password=root]
      [--batch=500]            entries per polling pass
      [--interval-seconds=1]  poll pacing in stream mode (0 = once)
      [--max-batches=0]       0 = unlimited, otherwise stop after N passes
      [--connect-timeout=60]  seconds spent on each TLS connect/auth
      [--once]                drain pending entries once then exit

The follower credentials need privileges on every database that the source
records; WITHOUT GRANT OPTION when row-level policies are enforced.

HELP;
    exit(0);
}

$sourceHost = (string) $options['source-host'];
$sourcePort = isset($options['source-port']) ? (int) $options['source-port'] : 2002;
$sourceUser = $options['source-user'] ?? 'root';
$sourcePassword = $options['source-password'] ?? 'root';
$targetHost = (string) $options['target-host'];
$targetPort = isset($options['target-port']) ? (int) $options['target-port'] : 2002;
$targetUser = $options['target-user'] ?? 'root';
$targetPassword = $options['target-password'] ?? 'root';
$batch = isset($options['batch']) ? max(1, (int) $options['batch']) : 500;
$intervalSeconds = isset($options['interval-seconds']) ? max(0, (int) $options['interval-seconds']) : 1;
$maxBatches = isset($options['max-batches']) ? max(0, (int) $options['max-batches']) : 0;
$connectTimeout = isset($options['connect-timeout']) ? max(1.0, (float) $options['connect-timeout']) : 60.0;
$once = isset($options['once']);

$upsertPath = static function () use (
    $sourceHost, $sourcePort, $sourceUser, $sourcePassword, $connectTimeout
): Client {
    return Client::connect($sourceHost, $sourcePort, $sourceUser, $sourcePassword, $connectTimeout);
};
$targetFactory = static function () use (
    $targetHost, $targetPort, $targetUser, $targetPassword, $connectTimeout
): Client {
    return Client::connect($targetHost, $targetPort, $targetUser, $targetPassword, $connectTimeout);
};

$selectPending = sprintf(
    'SELECT log_id, change_sql FROM `%s`.`%s` WHERE applied = FALSE ORDER BY log_id LIMIT ?',
    'foxydb',
    Replication::LOG_TABLE,
);

$markSql = sprintf(
    'UPDATE `%s`.`%s` SET applied = TRUE WHERE log_id IN (%s)',
    'foxydb',
    Replication::LOG_TABLE,
    implode(', ', array_fill(0, 100, '?')),
);

try {
    while (true) {
        $source = $upsertPath();
        $target = $targetFactory();
        $appliedCount = 0;
        $markIds = [];
        $result = $source->query($selectPending, [$batch]);
        foreach ($result->rows as $row) {
            $logId = (int) $row['log_id'];
            $sql = (string) $row['change_sql'];
            if ($sql === '') {
                $markIds[] = $logId;
                continue;
            }
            try {
                $target->query($sql);
            } catch (FoxyException $exception) {
                fwrite(STDERR, sprintf(
                    'replication.apply_failed log_id=%d code=%s message=%s sql=%s' . PHP_EOL,
                    $logId,
                    $exception->errorCode,
                    $exception->getMessage(),
                    PHP_EOL . substr($sql, 0, 512),
                ));
                throw $exception;
            }
            $markIds[] = $logId;
            $appliedCount++;
            if (count($markIds) >= 100) {
                $source->query($markSql, $markIds);
                $markIds = [];
            }
        }
        if ($markIds !== []) {
            $remainingSql = sprintf(
                'UPDATE `%s`.`%s` SET applied = TRUE WHERE log_id IN (%s)',
                'foxydb',
                Replication::LOG_TABLE,
                implode(', ', array_fill(0, count($markIds), '?')),
            );
            $source->query($remainingSql, $markIds);
        }
        $source->close();
        $target->close();
        fwrite(STDOUT, sprintf('replication.pass applied=%d' . PHP_EOL, $appliedCount));
        if ($once) {
            exit(0);
        }
        if ($maxBatches > 0) {
            $maxBatches--;
            if ($maxBatches <= 0) {
                exit(0);
            }
        }
        if ($intervalSeconds > 0) {
            sleep($intervalSeconds);
        }
    }
} catch (FoxyException $exception) {
    fwrite(STDERR, sprintf(
        'replication.fatal code=%s message=%s' . PHP_EOL,
        $exception->errorCode,
        $exception->getMessage(),
    ));
    exit(2);
} catch (\Throwable $exception) {
    fwrite(STDERR, sprintf(
        'replication.unhandled exception=%s message=%s' . PHP_EOL,
        $exception::class,
        $exception->getMessage(),
    ));
    exit(2);
}
