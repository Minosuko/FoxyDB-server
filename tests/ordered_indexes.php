<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Authentication;
use FoxyDB\Config;
use FoxyDB\Session;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\SystemVariables;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-range-' . bin2hex(random_bytes(6));
$config = new Config('127.0.0.1', 2002, $directory);

function rangeColumns(array $rows, string $column): array
{
    $values = array_column($rows, $column);
    sort($values, SORT_NUMERIC);
    return $values;
}

function rangeStrings(array $rows, string $column): array
{
    $values = array_column($rows, $column);
    sort($values);
    return $values;
}

$storage = null;
try {
    $storage = new StorageEngine($config);
    $authentication = new Authentication($storage, $config);
    $session = new Session($storage, $config, $authentication, new SystemVariables($storage, $config));
    $session->authenticateAs('root', (string) ($authentication->authenticateIdentity('root', 'root')['account_id'] ?? ''));
    $session->execute('CREATE DATABASE app');
    $session->execute('USE app');
    $session->execute(
        'CREATE TABLE items ('
        . 'id INT PRIMARY KEY AUTO_INCREMENT, price INT, tag VARCHAR(20), score DOUBLE, note VARCHAR(20))'
    );
    $prices = [3, 17, 17, 50, 50, 51, 88, 100, 100, 101, 250, 999];
    $tags = ['apple', 'banana', 'cherry', 'date', 'elderberry', 'fig', 'grape', 'honeydew'];
    $index = 0;
    foreach ($prices as $price) {
        $session->execute(
            'INSERT INTO items (price, tag, score, note) VALUES (?, ?, ?, ?)',
            [$price, $tags[$index % count($tags)], $price / 10, $index % 2 === 0 ? 'even' : 'odd'],
        );
        $index++;
    }
    $session->execute(
        'CREATE TABLE plain ('
        . 'id INT PRIMARY KEY AUTO_INCREMENT, price INT, tag VARCHAR(20), score DOUBLE, note VARCHAR(20))'
    );
    foreach ($prices as $price) {
        $session->execute(
            'INSERT INTO plain (price, tag, score, note) VALUES (?, ?, ?, ?)',
            [$price, $tags[$index % count($tags)], $price / 10, $index % 2 === 0 ? 'even' : 'odd'],
        );
        $index++;
    }

    $session->execute('CREATE INDEX price_range ON items (price) ORDERED');
    $session->execute('CREATE INDEX tag_range ON items (tag) ORDERED');
    $session->execute('CREATE INDEX tag_price ON items (tag, price) ORDERED');

    $session->execute('CREATE TABLE wide_keys (value VARCHAR(5000), INDEX value_hash (value), INDEX value_ordered (value) ORDERED)');
    $wideValue = str_repeat('wide', 1_250);
    $session->execute('INSERT INTO wide_keys (value) VALUES (?)', [$wideValue]);
    $wideMatches = iterator_to_array(
        $session->execute('SELECT value FROM wide_keys WHERE value >= ?', [$wideValue])->rows,
        false,
    );
    if (count($wideMatches) !== 1 || $wideMatches[0]['value'] !== $wideValue) {
        throw new RuntimeException('Index keys beyond the former 4096-byte ceiling failed.');
    }

    $indexes = array_column(
        iterator_to_array($session->execute('SHOW INDEXES FROM items')->rows, false),
        'ordered',
    );
    foreach (array_slice($indexes, 2) as $ordered) {
        if ($ordered !== true) {
            throw new RuntimeException('SHOW INDEXES did not report ORDERED indexes.');
        }
    }
    if ($indexes[0] !== false) {
        throw new RuntimeException('The primary key was incorrectly marked ordered.');
    }

    $queries = [
        'SELECT price FROM items WHERE price > 100',
        'SELECT price FROM items WHERE price >= 100',
        'SELECT price FROM items WHERE price < 50',
        'SELECT price FROM items WHERE price <= 50',
        'SELECT price FROM items WHERE price > 50 AND price <= 250',
        'SELECT price FROM items WHERE price >= 17 AND price < 88',
        'SELECT price FROM items WHERE price >= 60 AND price >= 50',
        'SELECT price FROM items WHERE price < 17 AND price < 50',
        'SELECT price FROM items WHERE 100 < price',
        'SELECT price FROM items WHERE 100 <= price',
        'SELECT price FROM items WHERE price > 50 AND price < 50',
        'SELECT tag FROM items WHERE tag >= \'f\'',
        'SELECT tag FROM items WHERE tag <= \'c\'',
        'SELECT tag FROM items WHERE tag > \'grape\'',
        'SELECT price FROM items WHERE price > 17 AND note = \'even\'',
    ];
    foreach ($queries as $sql) {
        $expectedSql = str_replace('items', 'plain', $sql);
        $expected = array_column(
            iterator_to_array($session->execute($expectedSql)->rows, false),
            'price',
            'tag',
        );
        $expected = array_values($expected);
        $actual = array_values(array_column(
            iterator_to_array($session->execute($sql)->rows, false),
            'price',
            'tag',
        ));
        if ($actual !== $expected) {
            throw new RuntimeException(
                "Range query mismatch for: {$sql}\nExpected: " . json_encode($expected)
                . "\nActual: " . json_encode($actual),
            );
        }
    }

    $equality = array_column(
        iterator_to_array($session->execute('SELECT price FROM items WHERE price = 100')->rows, false),
        'price',
    );
    sort($equality);
    if ($equality !== [100, 100]) {
        throw new RuntimeException('Equality lookup on an ordered index returned the wrong rows.');
    }
    $prefixed = array_column(
        iterator_to_array($session->execute("SELECT price FROM items WHERE tag = 'fig'")->rows, false),
        'price',
    );
    sort($prefixed, SORT_NUMERIC);
    if ($prefixed !== [51]) {
        throw new RuntimeException('Equality lookup on the prefix of a multi-column ordered index failed.');
    }

    $mirror = [];
    foreach ($prices as $position => $price) {
        $mirror[] = ['price' => $price, 'tag' => $tags[$position % count($tags)], 'note' => $position % 2 === 0 ? 'even' : 'odd'];
    }
    $session->execute("UPDATE items SET price = 151 WHERE tag = 'fig'");
    foreach ($mirror as &$entry) {
        if ($entry['tag'] === 'fig') {
            $entry['price'] = 151;
        }
    }
    unset($entry);
    $moved = array_values(array_filter($mirror, static fn(array $entry): bool => $entry['price'] > 140));
    $moved = array_column($moved, 'price');
    sort($moved);
    if ($moved !== [151, 250, 999]) {
        throw new RuntimeException('UPDATE did not maintain the ordered index correctly.');
    }

    $session->execute('DELETE FROM items WHERE tag = \'apple\'');
    $mirror = array_values(array_filter($mirror, static fn(array $entry): bool => $entry['tag'] !== 'apple'));
    $remaining = array_values(array_filter($mirror, static fn(array $entry): bool => $entry['price'] <= 20));
    $remaining = array_column($remaining, 'price');
    sort($remaining);
    if ($remaining !== [17, 17]) {
        throw new RuntimeException('DELETE did not maintain the ordered index correctly.');
    }
    $expectedLarge = array_values(array_filter($mirror, static fn(array $entry): bool => $entry['price'] >= 100));
    $expectedLarge = array_column($expectedLarge, 'price');
    sort($expectedLarge);

    $session->execute('OPTIMIZE TABLE items');
    $afterCompact = rangeColumns(
        iterator_to_array($session->execute('SELECT price FROM items WHERE price >= 100')->rows, false),
        'price',
    );
    if ($afterCompact !== $expectedLarge) {
        throw new RuntimeException('Compact lost range-index rows.');
    }

    $session->execute('CREATE TABLE inline (a INT, b VARCHAR(10), INDEX ab_range (a) ORDERED)');
    $session->execute("INSERT INTO inline (a, b) VALUES (1, 'x'), (5, 'y'), (9, 'z')");
    $inline = rangeColumns(
        iterator_to_array($session->execute('SELECT a FROM inline WHERE a >= 5')->rows, false),
        'a',
    );
    if ($inline !== [5, 9]) {
        throw new RuntimeException('CREATE TABLE with an inline ORDERED index failed.');
    }

    $session->execute('ALTER TABLE inline ADD INDEX b_range (b) ORDERED');
    $altered = rangeStrings(
        iterator_to_array($session->execute('SELECT b FROM inline WHERE b >= \'y\'')->rows, false),
        'b',
    );
    if ($altered !== ['y', 'z']) {
        throw new RuntimeException('ALTER TABLE ADD INDEX ... ORDERED failed.');
    }

    $session->execute(
        'CREATE TABLE domains ('
        . 'id INT PRIMARY KEY AUTO_INCREMENT, n BIGINT, f DOUBLE, s VARCHAR(20), '
        . 'INDEX n_range (n) ORDERED, INDEX f_range (f) ORDERED, INDEX s_range (s) ORDERED)'
    );
    $session->execute('CREATE TABLE domains_plain (id INT PRIMARY KEY AUTO_INCREMENT, n BIGINT, f DOUBLE, s VARCHAR(20))');
    $domainRows = [
        [-100, -10.5, 'a'],
        [-1, -0.25, 'aa'],
        [0, 0.0, 'b'],
        [1, 0.25, 'ba'],
        [100, 10.5, 'z'],
    ];
    foreach ($domainRows as $row) {
        $session->execute('INSERT INTO domains (n, f, s) VALUES (?, ?, ?)', $row);
        $session->execute('INSERT INTO domains_plain (n, f, s) VALUES (?, ?, ?)', $row);
    }
    foreach ([
        'SELECT id FROM domains WHERE n < 0',
        'SELECT id FROM domains WHERE n >= -1',
        'SELECT id FROM domains WHERE f < 0',
        'SELECT id FROM domains WHERE f >= -0.25 AND f < 10.5',
        "SELECT id FROM domains WHERE s < 'b'",
        "SELECT id FROM domains WHERE s >= 'aa' AND s < 'z'",
    ] as $sql) {
        $expected = array_column(iterator_to_array(
            $session->execute(str_replace('domains', 'domains_plain', $sql))->rows,
            false,
        ), 'id');
        $actual = array_column(iterator_to_array($session->execute($sql)->rows, false), 'id');
        if ($actual !== $expected) {
            throw new RuntimeException("Ordered index domain mismatch for: {$sql}");
        }
    }

    $session->execute('DROP INDEX price_range ON items');
    $afterDrop = rangeColumns(
        iterator_to_array($session->execute('SELECT price FROM items WHERE price >= 100')->rows, false),
        'price',
    );
    if ($afterCompact !== $afterDrop) {
        throw new RuntimeException('Dropping the ordered index changed query results.');
    }

    $storage->close();
    $storage = new StorageEngine($config);
    $reopenedAuth = new Authentication($storage, $config);
    $session = new Session(
        $storage,
        $config,
        $reopenedAuth,
        new SystemVariables($storage, $config),
    );
    $session->authenticateAs('root', (string) ($reopenedAuth->authenticateIdentity('root', 'root')['account_id'] ?? ''));
    $session->execute('USE app');
    $persisted = rangeColumns(
        iterator_to_array($session->execute('SELECT price FROM items WHERE price >= 100')->rows, false),
        'price',
    );
    if ($afterCompact !== $persisted) {
        throw new RuntimeException('Ordered index results changed after restart.');
    }

    echo "ordered indexes: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
