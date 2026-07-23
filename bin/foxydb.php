<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Server;

$options = getopt('', ['host:', 'port:', 'data-dir:', 'no-sync', 'help']);
if (isset($options['help'])) {
    echo <<<'HELP'
FoxyDB server

Usage:
  php bin/foxydb.php [--host=127.0.0.1] [--port=2002] [--data-dir=path]
                         [--no-sync]

Environment variables:
  FOXYDB_HOST, FOXYDB_PORT, FOXYDB_DATA_DIR
  FOXYDB_MAX_FRAME_BYTES, FOXYDB_CHUNK_BYTES, FOXYDB_INLINE_VALUE_BYTES
  FOXYDB_MAX_MATERIALIZED_BYTES, FOXYDB_MAX_RESULT_ROWS, FOXYDB_IDLE_TIMEOUT
  FOXYDB_MAX_CONNECTIONS, FOXYDB_MAX_TRANSFERS, FOXYDB_MAX_GLOBAL_TRANSFERS
  FOXYDB_MAX_UPLOAD_BYTES, FOXYDB_SYNC_WRITES
  FOXYDB_LOG_DIR, FOXYDB_LOG_MAX_BYTES, FOXYDB_LOG_MAX_FILES
  FOXYDB_SLOW_QUERY_MS

HELP;
    exit(0);
}

try {
    if (PHP_VERSION_ID < 80200) {
        throw new FoxyException('FoxyDB requires PHP 8.2 or newer.', 'INVALID_CONFIG');
    }
    if (PHP_INT_SIZE < 8) {
        throw new FoxyException('FoxyDB binary protocol requires 64-bit PHP.', 'INVALID_CONFIG');
    }
    foreach (['json', 'mbstring', 'zlib', 'openssl'] as $extension) {
        if (!extension_loaded($extension)) {
            throw new FoxyException("Required PHP extension is missing: {$extension}", 'INVALID_CONFIG');
        }
    }
    $config = Config::fromEnvironment(dirname(__DIR__));
    $overrides = [];
    if (isset($options['host'])) {
        $overrides['host'] = $options['host'];
    }
    if (isset($options['port'])) {
        if (filter_var($options['port'], FILTER_VALIDATE_INT) === false) {
            throw new FoxyException('The port option must be an integer.', 'INVALID_CONFIG');
        }
        $overrides['port'] = (int) $options['port'];
    }
    if (isset($options['data-dir'])) {
        $overrides['dataDirectory'] = (string) $options['data-dir'];
    }
    if (isset($options['no-sync'])) {
        $overrides['syncWrites'] = false;
    }
    $config = $config->withOverrides($overrides);
    $server = new Server($config);

    if (function_exists('pcntl_async_signals') && function_exists('pcntl_signal')) {
        pcntl_async_signals(true);
        pcntl_signal(SIGINT, static fn() => $server->stop());
        pcntl_signal(SIGTERM, static fn() => $server->stop());
    } elseif (function_exists('sapi_windows_set_ctrl_handler')) {
        sapi_windows_set_ctrl_handler(static function (int $event) use ($server): bool {
            if ($event === PHP_WINDOWS_EVENT_CTRL_C || $event === PHP_WINDOWS_EVENT_CTRL_BREAK) {
                $server->stop();
                return true;
            }
            return false;
        });
    }

    $server->run(static function (string $address): void {
        echo "FoxyDB listening on {$address}\n";
    });
} catch (FoxyException $exception) {
    fwrite(STDERR, "FoxyDB error [{$exception->errorCode}]: {$exception->getMessage()}\n");
    exit(1);
} catch (Throwable $exception) {
    fwrite(STDERR, 'FoxyDB fatal error: ' . $exception->getMessage() . "\n");
    exit(1);
}
