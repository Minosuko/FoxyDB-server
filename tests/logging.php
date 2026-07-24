<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Support\FileSystem;
use FoxyDB\Support\StructuredLogger;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-logs-' . bin2hex(random_bytes(6));

try {
    $logger = new StructuredLogger($directory, 1_024, 2);
    foreach (['general.log', 'error.log', 'audit.log', 'slow.log'] as $file) {
        $path = $directory . DIRECTORY_SEPARATOR . $file;
        if (!is_file($path)) {
            throw new RuntimeException("Logger did not initialize {$file}.");
        }
        if (DIRECTORY_SEPARATOR === '/') {
            $permissions = fileperms($path);
            if ($permissions === false || ($permissions & 0777) !== 0600) {
                throw new RuntimeException("Logger did not secure {$file} permissions.");
            }
        }
    }

    $sql = "UPDATE users_schema SET password_hash = 'plain-secret', token = raw-secret "
        . "WHERE username = \"private-user\" -- hidden-comment";
    $redactedSql = StructuredLogger::redactSql($sql);
    foreach (['plain-secret', 'raw-secret', 'private-user', 'hidden-comment'] as $secret) {
        if (str_contains($redactedSql, $secret)) {
            throw new RuntimeException('SQL credential redaction leaked sensitive input.');
        }
    }

    $logger->audit('authentication.test', [
        'username' => 'visible-user',
        'password' => 'context-secret',
        'nested' => ['access_token' => 'nested-secret'],
        'sql' => $sql,
    ]);
    $audit = file_get_contents($directory . DIRECTORY_SEPARATOR . 'audit.log');
    if ($audit === false || !str_contains($audit, 'authentication.test')
        || !str_contains($audit, 'visible-user') || !str_contains($audit, '[REDACTED]')) {
        throw new RuntimeException('Structured audit event was not written.');
    }
    foreach (['context-secret', 'nested-secret', 'plain-secret', 'raw-secret', 'private-user', 'hidden-comment'] as $secret) {
        if (str_contains($audit, $secret)) {
            throw new RuntimeException('Structured logging leaked sensitive context.');
        }
    }
    $entry = json_decode(trim($audit), true, 32, JSON_THROW_ON_ERROR);
    foreach (['timestamp', 'channel', 'level', 'event', 'pid', 'context'] as $field) {
        if (!array_key_exists($field, $entry)) {
            throw new RuntimeException("Structured log entry is missing {$field}.");
        }
    }

    for ($index = 0; $index < 10; $index++) {
        $logger->general('rotation.test', ['index' => $index, 'message' => str_repeat('x', 700)]);
    }
    if (!is_file($directory . DIRECTORY_SEPARATOR . 'general.log.1')
        || !is_file($directory . DIRECTORY_SEPARATOR . 'general.log.2')
        || is_file($directory . DIRECTORY_SEPARATOR . 'general.log.3')) {
        throw new RuntimeException('Log rotation did not enforce the archive limit.');
    }

    echo "logging: ok\n";
} finally {
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
