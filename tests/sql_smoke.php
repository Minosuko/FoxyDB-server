<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Session;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-sql-' . bin2hex(random_bytes(6));
$config = new Config(
    host: '127.0.0.1',
    port: 2002,
    dataDirectory: $directory,
    chunkBytes: 4_096,
    inlineValueBytes: 64,
);

try {
    $storage = new StorageEngine($config);
    $session = new Session($storage, $config);
    $session->execute('CREATE DATABASE app');
    $session->execute('USE app');
    $session->execute(<<<'SQL'
        CREATE TABLE records (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            code VARCHAR(36) NOT NULL UNIQUE,
            small TINYINT,
            amount DOUBLE,
            ratio FLOAT,
            estimate REAL,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            event_time DATETIME,
            uid UUID NOT NULL DEFAULT UUID(),
            note TEXT,
            detail LONGTEXT,
            payload BLOB,
            fixed BINARY(4),
            INDEX idx_active (active)
        )
        SQL);

    $first = $session->execute(
        'INSERT INTO records (code, small, amount, ratio, estimate, event_time, note, detail, payload, fixed) '
        . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, X\'6162\')',
        [
            'alpha',
            7,
            12.5,
            0.25,
            99.125,
            '2026-07-22 12:30:00',
            str_repeat('n', 500),
            str_repeat('d', 10_000),
            new BinaryValue(str_repeat("\xff", 5_000)),
        ],
    );
    if ($first->affectedRows !== 1 || $first->lastInsertId !== 1) {
        throw new RuntimeException('INSERT result metadata is incorrect.');
    }
    $session->execute(
        'INSERT INTO records (code, small, amount, ratio, estimate, event_time, fixed) VALUES (:code, 3, 2, 1, 5, NULL, X\'01020304\')',
        ['code' => 'beta'],
    );

    $selected = $session->execute(
        'SELECT id, code, detail, payload, fixed FROM records WHERE code = ? AND active = TRUE LIMIT 5',
        ['alpha'],
    );
    $rows = iterator_to_array($selected->rows, false);
    if (count($rows) !== 1 || $rows[0]['code'] !== 'alpha') {
        throw new RuntimeException('Indexed SELECT returned the wrong rows.');
    }
    if (!$rows[0]['detail'] instanceof ChunkedValue || !$rows[0]['payload'] instanceof ChunkedValue) {
        throw new RuntimeException('Large values were not returned as chunked values.');
    }
    if (!$rows[0]['fixed'] instanceof BinaryValue || $rows[0]['fixed']->bytes !== "ab\0\0") {
        throw new RuntimeException('BINARY padding did not round trip.');
    }

    $updated = $session->execute('UPDATE records SET amount = ?, active = FALSE WHERE code = ?', [42.75, 'alpha']);
    if ($updated->affectedRows !== 1) {
        throw new RuntimeException('UPDATE affected row count is incorrect.');
    }
    $count = $session->execute('SELECT COUNT(*) AS total FROM records WHERE amount >= 2 AND code IN (?, ?)', ['alpha', 'beta']);
    $countRows = iterator_to_array($count->rows, false);
    if ($countRows[0]['total'] !== 2) {
        throw new RuntimeException('COUNT or IN filtering is incorrect.');
    }
    $ordered = $session->execute('SELECT code, amount FROM records ORDER BY amount DESC LIMIT 1');
    $orderedRows = iterator_to_array($ordered->rows, false);
    if ($orderedRows[0]['code'] !== 'alpha') {
        throw new RuntimeException('ORDER BY returned the wrong row.');
    }
    try {
        $session->execute('INSERT INTO records (code, fixed) VALUES (?, X\'00000000\')', ['alpha']);
        throw new RuntimeException('Duplicate unique value was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'UNIQUE_VIOLATION') {
            throw $exception;
        }
    }
    $session->execute('CREATE INDEX idx_amount ON records (amount)');
    $deleted = $session->execute("DELETE FROM records WHERE code LIKE 'b%'");
    if ($deleted->affectedRows !== 1) {
        throw new RuntimeException('DELETE or LIKE filtering is incorrect.');
    }
    $compacted = $session->execute('COMPACT TABLE records');
    if (($compacted->metadata['rows'] ?? null) !== 1) {
        throw new RuntimeException('SQL compaction result is incorrect.');
    }

    $session->execute('OPTIMIZE TABLE records');
    $session->execute('ANALYZE TABLE records');

    $check = $session->execute('CHECK TABLE records');
    if (($check->metadata['status'] ?? null) !== 'ok') {
        throw new RuntimeException('CHECK TABLE did not report ok.');
    }

    $checksum = $session->execute('CHECKSUM TABLE records');
    if (!is_string($checksum->metadata['checksum'] ?? null)) {
        throw new RuntimeException('CHECKSUM TABLE did not produce a checksum.');
    }

    $session->execute('FLUSH TABLE records');

    $session->execute('ALTER TABLE records AUTO_INCREMENT = 5000');
    $inserted = $session->execute('INSERT INTO records (code) VALUES (?)', ['auto_test']);
    if ($inserted->lastInsertId !== 5000) {
        throw new RuntimeException('SET AUTO_INCREMENT did not take effect.');
    }

    $session->execute('CREATE TABLE rename_src (id BIGINT PRIMARY KEY AUTO_INCREMENT, v INT)');
    $session->execute('INSERT INTO rename_src (v) VALUES (1), (2)');
    $session->execute('RENAME TABLE rename_src TO rename_dst');
    $dstRows = iterator_to_array($session->execute('SELECT v FROM rename_dst ORDER BY v')->rows, false);
    if ($dstRows !== [['v' => 1], ['v' => 2]]) {
        throw new RuntimeException('RENAME TABLE lost data.');
    }

    $session->execute('CREATE TABLE copy_src (id BIGINT PRIMARY KEY AUTO_INCREMENT, label VARCHAR(20))');
    $session->execute('INSERT INTO copy_src (label) VALUES (\'a\'), (\'b\'), (\'c\')');
    $session->execute('COPY TABLE copy_src TO app.copy_dst');
    $copiedRows = iterator_to_array($session->execute('SELECT label FROM copy_dst ORDER BY label')->rows, false);
    if ($copiedRows !== [['label' => 'a'], ['label' => 'b'], ['label' => 'c']]) {
        throw new RuntimeException('COPY TABLE lost data.');
    }

    $session->execute('CREATE TABLE move_src (id BIGINT PRIMARY KEY AUTO_INCREMENT, v INT)');
    $session->execute('INSERT INTO move_src (v) VALUES (100)');
    $session->execute('MOVE TABLE move_src TO app.move_dst');
    $movedRows = iterator_to_array($session->execute('SELECT v FROM move_dst')->rows, false);
    if ($movedRows !== [['v' => 100]]) {
        throw new RuntimeException('MOVE TABLE lost data.');
    }

    $session->execute('ALTER TABLE records COLLATE utf8mb4_general_ci');

    $session->execute('CREATE TABLE json_docs (id INT PRIMARY KEY AUTO_INCREMENT, payload JSON NOT NULL)');
    $session->execute(
        'INSERT INTO json_docs (payload) VALUES (?)',
        ['{"name":"alpha","status":"active","meta":{"rating":5,"tags":["x","y"]},"items":[10,20,30]}'],
    );
    $session->execute(
        'INSERT INTO json_docs (payload) VALUES (?)',
        [json_encode(['name' => 'beta', 'status' => 'inactive', 'meta' => ['rating' => 3]], JSON_THROW_ON_ERROR)],
    );
    try {
        $session->execute('INSERT INTO json_docs (payload) VALUES (?)', ['{"broken"']);
        throw new RuntimeException('Invalid JSON input was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'INVALID_VALUE') {
            throw $exception;
        }
    }
    $jsonMatches = $session->execute(
        "SELECT id FROM json_docs WHERE JSON_EXTRACT(payload, '$.status') = 'active'",
    );
    if (array_column(iterator_to_array($jsonMatches->rows, false), 'id') !== [1]) {
        throw new RuntimeException('JSON_EXTRACT equality did not match.');
    }
    $jsonNested = $session->execute(
        "SELECT JSON_EXTRACT(payload, '$.meta.tags') AS tags FROM json_docs WHERE id = 1"
    );
    $jsonNestedRow = iterator_to_array($jsonNested->rows, false)[0];
    if ($jsonNestedRow['tags'] !== '["x","y"]') {
        throw new RuntimeException('JSON_EXTRACT did not return a nested array.');
    }
    $jsonIndex = $session->execute(
        "SELECT id FROM json_docs WHERE JSON_EXTRACT(payload, '$.items[2]') = 30"
    );
    if (array_column(iterator_to_array($jsonIndex->rows, false), 'id') !== [1]) {
        throw new RuntimeException('JSON_EXTRACT array index did not match.');
    }
    $jsonMissing = $session->execute(
        "SELECT id FROM json_docs WHERE JSON_EXTRACT(payload, '$.missing') IS NULL"
    );
    if (count(iterator_to_array($jsonMissing->rows, false)) !== 2) {
        throw new RuntimeException('JSON_EXTRACT missing key did not yield NULL.');
    }
    try {
        $session->execute("SELECT id FROM json_docs WHERE JSON_EXTRACT(payload, 'status') = 'active'");
        throw new RuntimeException('A JSON path without $ was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'SQL_SEMANTIC') {
            throw $exception;
        }
    }
    $largeDoc = json_encode(['big' => str_repeat('k', 200_000), 'status' => 'active'], JSON_THROW_ON_ERROR);
    $session->execute('INSERT INTO json_docs (payload) VALUES (?)', [$largeDoc]);
    $largeRow = iterator_to_array(
        $session->execute('SELECT payload FROM json_docs WHERE id = 3')->rows,
        false,
    )[0]['payload'];
    if ($largeRow instanceof ChunkedValue) {
        $largeRow = $largeRow->materialize(PHP_INT_MAX);
    }
    if ($largeRow !== $largeDoc) {
        throw new RuntimeException('A large JSON document did not round trip.');
    }
    $largeExtract = $session->execute(
        "SELECT id FROM json_docs WHERE JSON_EXTRACT(payload, '$.status') = 'active' AND id > 2"
    );
    if (array_column(iterator_to_array($largeExtract->rows, false), 'id') !== [3]) {
        throw new RuntimeException('JSON_EXTRACT failed on a large chunked document.');
    }

    echo "sql smoke: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
