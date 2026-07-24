<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Authentication;
use FoxyDB\Config;
use FoxyDB\Session;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\SystemVariables;

$iterations = isset($argv[1]) ? max(100, (int) $argv[1]) : 1_000;
$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-benchmark-' . bin2hex(random_bytes(6));
$config = new Config(
    host: '127.0.0.1',
    port: 2002,
    dataDirectory: $directory,
    chunkBytes: 4_096,
    syncWrites: false,
);

$measure = static function (int $count, callable $operation): float {
    $started = hrtime(true);
    for ($index = 0; $index < $count; $index++) {
        $operation($index);
    }
    return (hrtime(true) - $started) / 1_000 / $count;
};

try {
    $storage = new StorageEngine($config);
    $authentication = new Authentication($storage, $config);
    $variables = new SystemVariables($storage, $config);
    $identity = $authentication->authenticateIdentity('root', 'root');
    if ($identity === null) {
        throw new RuntimeException('Unable to authenticate benchmark session.');
    }
    $session = new Session($storage, $config, $authentication, $variables);
    $session->authenticateAs($identity['username'], $identity['account_id']);
    $session->execute('CREATE DATABASE benchmark');
    $session->execute('USE benchmark');
    $session->execute(
        'CREATE TABLE items ('
        . 'id INT PRIMARY KEY AUTO_INCREMENT, '
        . 'value VARCHAR(30), '
        . 'category INT, '
        . 'INDEX idx_category (category)'
        . ')',
    );
    $values = [];
    $parameters = [];
    for ($index = 0; $index < 100; $index++) {
        $values[] = '(?, ?)';
        $parameters[] = 'value-' . $index;
        $parameters[] = $index % 10;
    }
    $session->execute(
        'INSERT INTO items (value, category) VALUES ' . implode(', ', $values),
        $parameters,
    );

    $session->execute('SET GLOBAL query_cache_size = 0');
    $indexed = $measure($iterations, static function (int $index) use ($session): void {
        iterator_to_array(
            $session->execute('SELECT value FROM items WHERE id = ?', [($index % 100) + 1])->rows,
            false,
        );
    });
    $like = $measure(max(100, intdiv($iterations, 10)), static function (int $index) use ($session): void {
        iterator_to_array(
            $session->execute('SELECT value FROM items WHERE value LIKE ?', ['%value-' . ($index % 10) . '%'])->rows,
            false,
        );
    });

    $session->execute('SET GLOBAL query_cache_size = 16777216');
    iterator_to_array($session->execute('SELECT value FROM items WHERE id = ?', [1])->rows, false);
    $cached = $measure($iterations, static function (int $_index) use ($session): void {
        iterator_to_array($session->execute('SELECT value FROM items WHERE id = ?', [1])->rows, false);
    });

    echo json_encode([
        'iterations' => $iterations,
        'microseconds_per_query' => [
            'indexed_select_result_cache_disabled' => round($indexed, 2),
            'like_scan_result_cache_disabled' => round($like, 2),
            'result_cache_hit' => round($cached, 2),
        ],
        'cache_statistics' => $storage->cacheStatistics(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
} finally {
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
