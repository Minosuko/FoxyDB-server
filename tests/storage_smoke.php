<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\TypeSystem;
use FoxyDB\Value\ChunkedValue;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-storage-' . bin2hex(random_bytes(6));
$config = new Config(
    host: '127.0.0.1',
    port: 2002,
    dataDirectory: $directory,
    chunkBytes: 4_096,
    inlineValueBytes: 32,
);

try {
    $storage = new StorageEngine($config);
    try {
        new StorageEngine($config);
        throw new RuntimeException('A second engine opened the same data directory.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'STORAGE_IN_USE') {
            throw $exception;
        }
    }
    $storage->createDatabase('test');
    $types = new TypeSystem($config);
    $schema = $types->compileSchema('items', [
        'columns' => [
            [
                'name' => 'id',
                'type' => 'INT',
                'nullable' => false,
                'auto_increment' => true,
                'primary' => true,
            ],
            ['name' => 'name', 'type' => 'VARCHAR', 'length' => 50, 'nullable' => false, 'unique' => true],
            ['name' => 'body', 'type' => 'LONGTEXT', 'nullable' => true],
        ],
        'constraints' => [],
    ]);
    $storage->createTable('test', 'items', $schema);
    $metadataPath = $directory . '/databases/test/tables/items/meta.fdb';
    if (!is_file($metadataPath) || substr((string) file_get_contents($metadataPath), 0, 4) !== 'FXMD'
        || is_file($directory . '/databases/test/tables/items/meta.json')) {
        throw new RuntimeException('Table metadata is not stored in the binary FXMD format.');
    }
    $table = $storage->table('test', 'items');
    $inserted = $table->insert(['name' => 'alpha', 'body' => str_repeat('x', 10_000)]);
    if ($inserted['last_insert_id'] !== 1) {
        throw new RuntimeException('AUTO_INCREMENT did not start at 1.');
    }
    $rows = iterator_to_array($table->rows(), false);
    if (count($rows) !== 1 || !$rows[0]['values']['body'] instanceof ChunkedValue) {
        throw new RuntimeException('Large text was not stored as chunks.');
    }
    if ($rows[0]['values']['body']->materialize(20_000) !== str_repeat('x', 10_000)) {
        throw new RuntimeException('Chunked text did not round trip.');
    }
    try {
        $table->insert(['name' => 'alpha']);
        throw new RuntimeException('Duplicate unique value was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'UNIQUE_VIOLATION') {
            throw $exception;
        }
    }
    $updated = $table->update(['name' => 'beta'], static fn(array $row): bool => $row['id'] === 1);
    if ($updated !== 1) {
        throw new RuntimeException('Expected one updated row.');
    }
    $compacted = $table->compact();
    if ($compacted['rows'] !== 1) {
        throw new RuntimeException('Compaction lost a row.');
    }
    $reopened = $storage->table('test', 'items');
    $rows = iterator_to_array($reopened->rows(), false);
    if ($rows[0]['values']['name'] !== 'beta') {
        throw new RuntimeException('Persisted row did not round trip.');
    }
    echo "storage smoke: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
