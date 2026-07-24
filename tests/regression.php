<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Session;
use FoxyDB\Sql\Parser;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\BinaryCodec;
use FoxyDB\Support\FileSystem;
use FoxyDB\Value\StreamValue;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-regression-' . bin2hex(random_bytes(6));
$fixtures = [];
$config = new Config(
    host: '127.0.0.1',
    port: 2002,
    dataDirectory: $directory,
    chunkBytes: 4_096,
    inlineValueBytes: 32,
);

$expectError = static function (string $code, callable $operation): void {
    try {
        $operation();
    } catch (FoxyException $exception) {
        if ($exception->errorCode === $code) {
            return;
        }
        throw $exception;
    }
    throw new RuntimeException("Expected error {$code} was not raised.");
};

try {
    $parser = new Parser();
    $parsed = $parser->parse("SELECT value FROM cached_parse WHERE value LIKE '%test%'");
    if ($parser->parse("SELECT value FROM cached_parse WHERE value LIKE '%test%'") !== $parsed
        || $parser->cacheStatistics()['hits'] < 1) {
        throw new RuntimeException('Repeated SQL text did not use the parsed-statement cache.');
    }
    $session = new Session(new StorageEngine($config), $config);
    $session->execute('CREATE DATABASE app');
    $session->execute('USE app');

    $session->execute('CREATE TABLE quoted ("primary" INT, "null" VARCHAR(10), code VARCHAR(10))');
    $session->execute("INSERT INTO quoted (\"primary\", \"null\", code) VALUES (1, NULL, 'a'), (2, 'x', 'b')");
    $quoted = $session->execute('SELECT code FROM quoted WHERE ("null") IS NULL');
    $quotedRows = iterator_to_array($quoted->rows, false);
    if (array_column($quotedRows, 'code') !== ['a']) {
        throw new RuntimeException('Quoted identifiers or parenthesized operands are incorrect.');
    }

    $session->execute('CREATE TABLE strings (value VARCHAR(10) UNIQUE)');
    $session->execute("INSERT INTO strings VALUES ('01'), ('1')");
    $exact = $session->execute("SELECT value FROM strings WHERE value = '1'");
    if (array_column(iterator_to_array($exact->rows, false), 'value') !== ['1']) {
        throw new RuntimeException('String comparison and index key semantics disagree.');
    }

    $session->execute('CREATE TABLE recreated_index_cache (value VARCHAR(10) UNIQUE)');
    iterator_to_array(
        $session->execute("SELECT value FROM recreated_index_cache WHERE value = 'same'")->rows,
        false,
    );
    $session->execute('DROP TABLE recreated_index_cache');
    $session->execute('CREATE TABLE recreated_index_cache (value VARCHAR(10) UNIQUE)');
    $session->execute("INSERT INTO recreated_index_cache VALUES ('same')");
    $expectError('UNIQUE_VIOLATION', static fn() => $session->execute(
        "INSERT INTO recreated_index_cache VALUES ('same')",
    ));

    $session->execute('CREATE TABLE like_patterns (value VARCHAR(20) UNIQUE)');
    $session->execute("INSERT INTO like_patterns VALUES ('alpha'), ('alphabet'), ('beta'), ('100%'), ('_literal')");
    $allLike = $session->execute("SELECT value FROM like_patterns WHERE value LIKE '%' ORDER BY value");
    if (array_column(iterator_to_array($allLike->rows, false), 'value')
        !== ['100%', '_literal', 'alpha', 'alphabet', 'beta']) {
        throw new RuntimeException('LIKE percent wildcard did not match every text value.');
    }
    $contains = $session->execute("SELECT value FROM like_patterns WHERE value LIKE '%pha%' ORDER BY value");
    if (array_column(iterator_to_array($contains->rows, false), 'value') !== ['alpha', 'alphabet']) {
        throw new RuntimeException('LIKE percent wildcard did not match an embedded fragment.');
    }
    $parameterized = $session->execute(
        'SELECT value FROM like_patterns WHERE value LIKE ? ORDER BY value',
        ['%ta'],
    );
    if (array_column(iterator_to_array($parameterized->rows, false), 'value') !== ['beta']) {
        throw new RuntimeException('Parameterized LIKE pattern was not applied.');
    }
    $escapedPercent = $session->execute("SELECT value FROM like_patterns WHERE value LIKE '100\\%'");
    if (array_column(iterator_to_array($escapedPercent->rows, false), 'value') !== ['100%']) {
        throw new RuntimeException('LIKE could not escape a literal percent character.');
    }
    $escapedUnderscore = $session->execute("SELECT value FROM like_patterns WHERE value LIKE '\\_literal'");
    if (array_column(iterator_to_array($escapedUnderscore->rows, false), 'value') !== ['_literal']) {
        throw new RuntimeException('LIKE could not escape a literal underscore character.');
    }
    $notLike = $session->execute("SELECT value FROM like_patterns WHERE value NOT LIKE 'a%' ORDER BY value");
    if (array_column(iterator_to_array($notLike->rows, false), 'value') !== ['100%', '_literal', 'beta']) {
        throw new RuntimeException('NOT LIKE percent wildcard returned the wrong rows.');
    }

    $session->execute('CREATE TABLE batch_insert (code VARCHAR(10) UNIQUE)');
    $expectError('UNIQUE_VIOLATION', static fn() => $session->execute(
        "INSERT INTO batch_insert VALUES ('same'), ('same')",
    ));
    $count = $session->execute('SELECT COUNT(*) AS total FROM batch_insert');
    if (iterator_to_array($count->rows, false)[0]['total'] !== 0) {
        throw new RuntimeException('A failed batch INSERT committed a prefix.');
    }

    $session->execute('CREATE TABLE batch_update (code VARCHAR(10) UNIQUE)');
    $session->execute("INSERT INTO batch_update VALUES ('a'), ('b')");
    $expectError('UNIQUE_VIOLATION', static fn() => $session->execute("UPDATE batch_update SET code = 'same'"));
    $unchanged = $session->execute('SELECT code FROM batch_update ORDER BY code');
    if (array_column(iterator_to_array($unchanged->rows, false), 'code') !== ['a', 'b']) {
        throw new RuntimeException('A failed batch UPDATE committed a prefix.');
    }

    $session->execute('CREATE TABLE streams (body LONGTEXT)');
    $text = str_repeat('streamed text ', 2_000);
    $textPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-text-' . bin2hex(random_bytes(5));
    $fixtures[] = $textPath;
    file_put_contents($textPath, $text);
    $textStream = new StreamValue($textPath, 'utf8', strlen($text));
    $session->execute('INSERT INTO streams VALUES (?)', [$textStream]);
    $streamMatch = $session->execute('SELECT COUNT(*) AS total FROM streams WHERE body = ?', [$textStream]);
    if (iterator_to_array($streamMatch->rows, false)[0]['total'] !== 1) {
        throw new RuntimeException('Streamed predicate did not match its stored text.');
    }
    $emptyPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-empty-' . bin2hex(random_bytes(5));
    $fixtures[] = $emptyPath;
    file_put_contents($emptyPath, '');
    $falsey = $session->execute(
        'SELECT COUNT(*) AS total FROM streams WHERE ?',
        [new StreamValue($emptyPath, 'utf8', 0)],
    );
    if (iterator_to_array($falsey->rows, false)[0]['total'] !== 0) {
        throw new RuntimeException('An empty streamed predicate was treated as true.');
    }
    $invalidPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-invalid-' . bin2hex(random_bytes(5));
    $fixtures[] = $invalidPath;
    file_put_contents($invalidPath, "\xff");
    $expectError('INVALID_VALUE', static fn() => $session->execute(
        'INSERT INTO streams VALUES (?)',
        [new StreamValue($invalidPath, 'utf8', 1)],
    ));
    $count = $session->execute('SELECT COUNT(*) AS total FROM streams');
    if (iterator_to_array($count->rows, false)[0]['total'] !== 1) {
        throw new RuntimeException('Invalid streamed text partially committed.');
    }

    $session->execute('CREATE TABLE wide_index (value VARCHAR(2000))');
    $expectError('SCHEMA_ERROR', static fn() => $session->execute(
        'CREATE INDEX idx_wide ON wide_index (value)',
    ));

    $session->execute('CREATE TABLE sequence_items (id INT PRIMARY KEY AUTO_INCREMENT, value VARCHAR(10))');
    $session->execute("INSERT INTO sequence_items (value) VALUES ('a'), ('b')");
    $sequencePath = $directory . '/databases/app/tables/sequence_items/sequence.fdb';
    $body = 'FXSQ' . BinaryCodec::uint32(1) . BinaryCodec::uint64(1) . BinaryCodec::uint64(1);
    FileSystem::atomicWrite(
        $sequencePath,
        $body . BinaryCodec::uint32(BinaryCodec::crc32($body)) . "\0\0\0\0",
    );
    $recoveredInsert = $session->execute("INSERT INTO sequence_items (value) VALUES ('c')");
    if ($recoveredInsert->lastInsertId !== 3) {
        throw new RuntimeException('A stale sequence was not recovered safely.');
    }

    $session->execute('CREATE TABLE journal_items (id INT PRIMARY KEY AUTO_INCREMENT, value VARCHAR(10))');
    $session->execute("INSERT INTO journal_items (value) VALUES ('old')");
    $journalTable = $directory . '/databases/app/tables/journal_items';
    $slot = substr((string) file_get_contents($journalTable . '/g000001/rows.fdx'), 0, 24);
    $session->execute("UPDATE journal_items SET value = 'new' WHERE id = 1");
    FileSystem::writeMetadata($journalTable . '/row.journal.fdb', [
        'generation' => 1,
        'row_id' => 1,
        'slot' => $slot,
    ]);
    $journalResult = $session->execute('SELECT value FROM journal_items WHERE id = 1');
    if (iterator_to_array($journalResult->rows, false)[0]['value'] !== 'new') {
        throw new RuntimeException('A stale journal rolled back a newer row.');
    }

    $session->execute('COMPACT TABLE journal_items');
    FileSystem::removeTree($journalTable . '/g000002');
    $fallback = $session->execute('SELECT value FROM journal_items WHERE id = 1');
    if (iterator_to_array($fallback->rows, false)[0]['value'] !== 'new') {
        throw new RuntimeException('Previous generation fallback failed.');
    }

    $session->execute('CREATE TABLE index_repair (id INT PRIMARY KEY AUTO_INCREMENT, code VARCHAR(10), INDEX idx_code (code))');
    $session->execute("INSERT INTO index_repair (code) VALUES ('old')");
    $indexData = $directory . '/databases/app/tables/index_repair/g000001/indexes/idx_code/data.fxi';
    unlink($indexData);
    $session->execute("INSERT INTO index_repair (code) VALUES ('new')");
    $repaired = $session->execute("SELECT code FROM index_repair WHERE code = 'old'");
    if (array_column(iterator_to_array($repaired->rows, false), 'code') !== ['old']) {
        throw new RuntimeException('Index repair produced a partial index.');
    }

    $session->execute('CREATE TABLE binary_keys (value BINARY(4) UNIQUE)');
    $binaryPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-binary-' . bin2hex(random_bytes(5));
    $fixtures[] = $binaryPath;
    file_put_contents($binaryPath, "\x01\x02\x03\x04");
    $binaryStream = new StreamValue($binaryPath, 'binary', 4);
    $session->execute('INSERT INTO binary_keys VALUES (?)', [$binaryStream]);
    $binaryMatch = $session->execute('SELECT COUNT(*) AS total FROM binary_keys WHERE value = ?', [$binaryStream]);
    if (iterator_to_array($binaryMatch->rows, false)[0]['total'] !== 1) {
        throw new RuntimeException('Streamed indexed BINARY did not round trip.');
    }

    $cursor = $session->execute('SELECT code FROM batch_update');
    foreach ($cursor->rows as $_row) {
        break;
    }
    if ($session->execute("UPDATE batch_update SET code = 'c' WHERE code = 'a'")->affectedRows !== 1) {
        throw new RuntimeException('An abandoned result cursor retained a table lock.');
    }

    $session->execute('CREATE TABLE journal_bounds (id INT PRIMARY KEY AUTO_INCREMENT)');
    $session->execute('INSERT INTO journal_bounds DEFAULT VALUES');
    $boundsTable = $directory . '/databases/app/tables/journal_bounds';
    $slotBody = BinaryCodec::uint64(0) . BinaryCodec::uint32(0) . BinaryCodec::uint32(2)
        . chr(2) . "\0\0\0";
    $deletedSlot = $slotBody . BinaryCodec::uint32(BinaryCodec::crc32($slotBody));
    FileSystem::writeMetadata($boundsTable . '/row.journal.fdb', [
        'generation' => 1,
        'row_id' => 2_000_000,
        'slot' => $deletedSlot,
    ]);
    $expectError('STORAGE_CORRUPT', static fn() => $session->execute('SELECT * FROM journal_bounds'));
    if (filesize($boundsTable . '/g000001/rows.fdx') !== 24) {
        throw new RuntimeException('Malformed journal expanded the row slot file.');
    }

    echo "regression: ok\n";
} finally {
    foreach ($fixtures as $fixture) {
        if (is_file($fixture)) {
            unlink($fixture);
        }
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
