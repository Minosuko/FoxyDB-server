<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Authentication;
use FoxyDB\Config;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-auth-' . bin2hex(random_bytes(6));
$config = new Config('127.0.0.1', 2002, $directory);

try {
    $storage = new StorageEngine($config);
    $authentication = new Authentication($storage, $config);
    $tables = $storage->listTables(Authentication::SYSTEM_DATABASE);
    foreach (['users_schema', 'privileges', 'config_schema', 'performance_schema', 'sys_config'] as $table) {
        if (!in_array($table, $tables, true)) {
            throw new RuntimeException("Missing bootstrapped table: {$table}");
        }
    }
    if ($authentication->authenticate('root', 'root') !== 'root'
        || !$authentication->hasPrivilege('root', 'SELECT', 'anything', 'anything')) {
        throw new RuntimeException('Default root login or privilege is missing.');
    }
    $authentication->hasPrivilege('root', 'SELECT', 'anything', 'anything');
    $cacheStatistics = $authentication->cacheStatistics();
    if ($cacheStatistics['users']['hits'] < 1 || $cacheStatistics['privileges']['hits'] < 1) {
        throw new RuntimeException('Repeated authorization did not use the bounded authorization cache.');
    }

    $privileges = $storage->table(Authentication::SYSTEM_DATABASE, 'privileges');
    $privileges->delete(static fn(array $row): bool => $row['username'] === 'root');
    if ($authentication->hasPrivilege('root', 'SELECT', 'anything', 'anything')) {
        throw new RuntimeException('Privilege cache survived a committed privilege revocation.');
    }
    $authentication = new Authentication($storage, $config);
    if ($authentication->hasPrivilege('root', 'SELECT', 'anything', 'anything')) {
        throw new RuntimeException('Restart restored a deliberately removed root privilege.');
    }

    $users = $storage->table(Authentication::SYSTEM_DATABASE, 'users_schema');
    $newHash = password_hash('changed-password', PASSWORD_DEFAULT);
    $users->update(
        ['password_hash' => $newHash],
        static fn(array $row): bool => $row['username'] === 'root',
        $users->lookupForEqualities(['username' => 'root']),
    );
    $authentication = new Authentication($storage, $config);
    if ($authentication->authenticate('root', 'root') !== null
        || $authentication->authenticate('root', 'changed-password') !== 'root') {
        throw new RuntimeException('Login did not use the password stored in users_schema.');
    }

    $users->delete(static fn(array $row): bool => $row['username'] === 'root');
    $authentication = new Authentication($storage, $config);
    if ($authentication->authenticate('root', 'root') !== null) {
        throw new RuntimeException('Restart recreated a deliberately removed root account.');
    }

    echo "authentication: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
