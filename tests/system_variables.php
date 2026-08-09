<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Authentication;
use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Session;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\SystemVariables;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-variables-' . bin2hex(random_bytes(6));
$config = new Config(
    host: '127.0.0.1',
    port: 2002,
    dataDirectory: $directory,
    maxFrameBytes: 65_536,
    chunkBytes: 4_096,
    maxMaterializedBytes: 2_097_152,
    idleTimeoutSeconds: 17,
    syncWrites: false,
);

try {
    $storage = new StorageEngine($config);
    $authentication = new Authentication($storage, $config);
    $variables = new SystemVariables($storage, $config);
    $root = $authentication->authenticateIdentity('root', 'root');
    if ($root === null) {
        throw new RuntimeException('Unable to authenticate the variable test session.');
    }
    $session = new Session($storage, $config, $authentication, $variables);
    $session->authenticateAs($root['username'], $root['account_id']);

    $globalRows = iterator_to_array($session->execute('SHOW GLOBAL VARIABLES')->rows, false);
    $global = array_column($globalRows, 'value', 'variable_name');
    if (($global['max_allowed_packet'] ?? null) !== '65536'
        || ($global['max_heap_table_size'] ?? null) !== '2097152'
        || ($global['wait_timeout'] ?? null) !== '17') {
        throw new RuntimeException('Runtime variables did not inherit initial configuration limits.');
    }

    $session->execute("SET SESSION sort_buffer_size = '64K'");
    $sessionRows = iterator_to_array(
        $session->execute("SHOW SESSION VARIABLES LIKE 'sort_buffer%'")->rows,
        false,
    );
    if (count($sessionRows) !== 1 || $sessionRows[0]['value'] !== '65536') {
        throw new RuntimeException('Session variable override was not applied.');
    }
    $globalSortRows = iterator_to_array(
        $session->execute("SHOW GLOBAL VARIABLES LIKE 'sort_buffer%'")->rows,
        false,
    );
    if ($globalSortRows[0]['value'] === '65536') {
        throw new RuntimeException('Session variable override changed the global value.');
    }

    $epoch = $storage->cacheStatistics()['mutation_epoch'];
    $session->execute('SET GLOBAL max_allowed_packet = 131072');
    if ($storage->cacheStatistics()['mutation_epoch'] <= $epoch) {
        throw new RuntimeException('Global variable change did not invalidate the query cache.');
    }
    $reloaded = new SystemVariables($storage, $config);
    if ($reloaded->get('max_allowed_packet') !== 131_072) {
        throw new RuntimeException('Global variable change was not persisted.');
    }
    foreach ([
        "UPDATE sys_config SET variable_value = '999' WHERE variable_name = 'wait_timeout'",
        "DELETE FROM sys_config WHERE variable_name = 'wait_timeout'",
        "INSERT INTO sys_config (variable_name, variable_value) VALUES ('wait_timeout', '999')",
    ] as $directMutation) {
        try {
            $session->execute($directMutation);
            throw new RuntimeException('Direct DML changed a managed system variable.');
        } catch (FoxyException $exception) {
            if ($exception->errorCode !== 'SYSTEM_VARIABLE_PROTECTED') {
                throw $exception;
            }
        }
    }

    try {
        $session->execute('SET GLOBAL thread_stack = 2097152');
        throw new RuntimeException('A read-only variable was changed at runtime.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'READ_ONLY_VARIABLE') {
            throw $exception;
        }
    }
    try {
        $session->execute('SET SESSION query_cache_size = 0');
        throw new RuntimeException('A global-only variable was changed in session scope.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'INVALID_VARIABLE_SCOPE') {
            throw $exception;
        }
    }

    $session->execute('CREATE DATABASE app');
    $session->execute('USE app');
    $session->execute('CREATE TABLE cache_probe (id INT PRIMARY KEY AUTO_INCREMENT, value VARCHAR(20))');
    $session->execute("INSERT INTO cache_probe (value) VALUES ('one')");
    iterator_to_array($session->execute('SELECT value FROM cache_probe')->rows, false);
    iterator_to_array($session->execute('SELECT value FROM cache_probe')->rows, false);
    if ($storage->cacheStatistics()['query_cache']['hits'] < 1) {
        throw new RuntimeException('Repeated SELECT did not use the configured query cache.');
    }
    $session->execute('CREATE TABLE unrelated_cache_probe (id INT PRIMARY KEY AUTO_INCREMENT)');
    $cacheHits = $storage->cacheStatistics()['query_cache']['hits'];
    $storage->table('app', 'unrelated_cache_probe')->insert([]);
    iterator_to_array($session->execute('SELECT value FROM cache_probe')->rows, false);
    if ($storage->cacheStatistics()['query_cache']['hits'] <= $cacheHits) {
        throw new RuntimeException('An unrelated table mutation evicted a valid cached query.');
    }
    $session->execute(
        'CREATE TABLE volatile_cache_probe ('
        . 'id INT PRIMARY KEY AUTO_INCREMENT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'
    );
    $session->execute('INSERT INTO volatile_cache_probe DEFAULT VALUES');
    $cacheHits = $storage->cacheStatistics()['query_cache']['hits'];
    for ($index = 0; $index < 2; $index++) {
        iterator_to_array(
            $session->execute(
                'SELECT id FROM volatile_cache_probe WHERE created_at <= CURRENT_TIMESTAMP',
            )->rows,
            false,
        );
    }
    if ($storage->cacheStatistics()['query_cache']['hits'] !== $cacheHits) {
        throw new RuntimeException('A volatile CURRENT_TIMESTAMP query was result-cached.');
    }
    $mutationEpoch = $storage->cacheStatistics()['mutation_epoch'];
    $storage->table('app', 'cache_probe')->insert(['value' => 'two']);
    if ($storage->cacheStatistics()['mutation_epoch'] <= $mutationEpoch) {
        throw new RuntimeException('A direct committed table mutation did not invalidate caches.');
    }
    $probeRows = iterator_to_array($session->execute('SELECT value FROM cache_probe')->rows, false);
    if (array_column($probeRows, 'value') !== ['one', 'two']) {
        throw new RuntimeException('A stale query-cache entry survived a table mutation.');
    }
    $session->execute('USE foxydb');
    $hash = password_hash('operator-pass', PASSWORD_DEFAULT);
    $session->execute(
        'INSERT INTO users_schema (username, password_hash, enabled) VALUES (?, ?, TRUE)',
        ['operator', $hash],
    );
    $operatorRow = iterator_to_array(
        $session->execute("SELECT account_id FROM users_schema WHERE username = 'operator'")->rows,
        false,
    )[0];
    $session->execute(
        'INSERT INTO privileges (username, account_id, database_name, table_name, privilege) '
        . "VALUES ('operator', ?, 'app', '*', 'CONNECT'), ('operator', ?, 'app', '*', 'ALTER')",
        [$operatorRow['account_id'], $operatorRow['account_id']],
    );
    $operatorIdentity = $authentication->authenticateIdentity('operator', 'operator-pass');
    if ($operatorIdentity === null) {
        throw new RuntimeException('Unable to authenticate the restricted variable test session.');
    }
    $operator = new Session($storage, $config, $authentication, $variables);
    $operator->authenticateAs($operatorIdentity['username'], $operatorIdentity['account_id']);
    $operator->execute('USE app');
    $operator->execute('SET SESSION wait_timeout = 30');
    try {
        $operator->execute('SET GLOBAL wait_timeout = 30');
        throw new RuntimeException('Application ALTER privilege changed a global server variable.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'ACCESS_DENIED') {
            throw $exception;
        }
    }

    echo "system variables: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
