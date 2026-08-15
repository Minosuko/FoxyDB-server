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

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-identifiers-' . bin2hex(random_bytes(6));
$config = new Config('127.0.0.1', 2002, $directory);

try {
    $storage = new StorageEngine($config);
    $authentication = new Authentication($storage, $config);
    $admin = new Session($storage, $config, $authentication, new SystemVariables($storage, $config));
    $admin->authenticateAs('root', (string) ($authentication->authenticateIdentity('root', 'root')['account_id'] ?? ''));

    $admin->execute('CREATE DATABASE `Данные`');
    $admin->execute('CREATE DATABASE `Büro`');
    $admin->execute('USE `данные`');
    $admin->execute(
        'CREATE TABLE `Tabél` ('
        . 'id BIGINT PRIMARY KEY AUTO_INCREMENT, '
        . '`Nom` VARCHAR(40) NOT NULL UNIQUE, '
        . '`Émise` BOOLEAN NOT NULL DEFAULT TRUE'
        . ')',
    );
    $admin->execute("INSERT INTO `tabél` (`nom`) VALUES ('alpha'), ('beta')");
    $admin->execute('INSERT INTO `Tabél` (`NOM`, `émise`) VALUES (?, FALSE)', ['gamma']);
    $admin->execute('INSERT INTO Tabél (Nom) VALUES (?)', ['delta']);
    $rows = iterator_to_array(
        $admin->execute('SELECT id, nom FROM TABÉL WHERE NOM = ?', ['alpha'])->rows,
        false,
    );
    if (count($rows) !== 1 || $rows[0]['nom'] !== 'alpha') {
        throw new RuntimeException('Case-insensitive UTF-8 lookup failed.');
    }
    $all = iterator_to_array($admin->execute('SELECT nom, émise FROM Tabél ORDER BY id')->rows, false);
    if (count($all) !== 4) {
        throw new RuntimeException('UTF-8 table did not retain every row.');
    }
    try {
        $admin->execute("INSERT INTO Tabél (Nom) VALUES ('alpha')");
        throw new RuntimeException('A UTF-8 UNIQUE index did not reject a duplicate.');
    } catch (FoxyException $e) {
        if ($e->errorCode !== 'UNIQUE_VIOLATION') {
            throw $e;
        }
    }
    $admin->execute('CREATE INDEX `Índice` ON `Tabél` (`émise`)');
    $admin->execute('DROP INDEX `índice` ON `Tabél`');
    $indexed = iterator_to_array(
        $admin->execute('SELECT nom FROM tabél WHERE nom = ?', ['delta'])->rows,
        false,
    );
    if (count($indexed) !== 1 || $indexed[0]['nom'] !== 'delta') {
        throw new RuntimeException('Indexed lookup on a UTF-8 index failed.');
    }

    $admin->execute('USE `Büro`');
    $admin->execute('CREATE TABLE `Kündigungen` (id BIGINT PRIMARY KEY AUTO_INCREMENT, `Grund` VARCHAR(80))');
    $admin->execute("INSERT INTO `kündigungen` (`grund`) VALUES ('umzug')");
    $admin->execute('USE `данные`');
    $qualified = iterator_to_array($admin->execute('SELECT grund FROM Büro.Kündigungen')->rows, false);
    if (count($qualified) !== 1 || $qualified[0]['grund'] !== 'umzug') {
        throw new RuntimeException('Qualified UTF-8 names did not resolve.');
    }
    if (!in_array('tabél', $storage->listTables('данные'), true)) {
        throw new RuntimeException('UTF-8 table name was not stored canonically.');
    }

    try {
        $admin->execute('CREATE TABLE `bad' . "\xff" . '` (id BIGINT PRIMARY KEY)');
        throw new RuntimeException('An identifier with invalid UTF-8 was accepted.');
    } catch (FoxyException $e) {
        if ($e->errorCode !== 'SQL_SYNTAX') {
            throw $e;
        }
    }

    $admin->execute('USE `Büro`');
    $admin->execute('DROP TABLE `KÜNDIGUNGEN`');
    $admin->execute('USE `данные`');
    $admin->execute('DROP TABLE `Tabél`');
    $admin->execute('DROP DATABASE `ДАННЫЕ`');
    $admin->execute('DROP DATABASE büro');

    $users = $storage->table(Authentication::SYSTEM_DATABASE, 'users_schema');
    $users->insert(['username' => 'carol', 'password_hash' => password_hash('carol-pass', PASSWORD_DEFAULT)]);
    $users->insert(['username' => 'dave', 'password_hash' => password_hash('dave-pass', PASSWORD_DEFAULT)]);
    $carolAccount = '';
    $daveAccount = '';
    foreach ($users->rows($users->lookupForEqualities(['username' => 'carol'])) as $entry) {
        $carolAccount = $entry['values']['account_id'];
    }
    foreach ($users->rows($users->lookupForEqualities(['username' => 'dave'])) as $entry) {
        $daveAccount = $entry['values']['account_id'];
    }

    $admin->execute('CREATE DATABASE app2');
    $admin->execute('USE app2');
    $admin->execute('CREATE TABLE sales_orders (id INT PRIMARY KEY AUTO_INCREMENT, note VARCHAR(20))');
    $admin->execute('CREATE TABLE sales_items (id INT PRIMARY KEY AUTO_INCREMENT, note VARCHAR(20))');
    $admin->execute('CREATE TABLE other (id INT PRIMARY KEY AUTO_INCREMENT, note VARCHAR(20))');
    $admin->execute("INSERT INTO sales_orders (note) VALUES ('a'), ('b')");
    $admin->execute("INSERT INTO sales_items (note) VALUES ('c')");
    $admin->execute("INSERT INTO other (note) VALUES ('x')");

    $admin->execute('GRANT CONNECT ON app2.* TO carol');
    $admin->execute('GRANT SELECT ON sales% TO carol');
    $admin->execute('GRANT INSERT ON app%.% TO carol');
    $admin->execute('GRANT UPDATE ON app2.sales_% TO dave');
    $admin->execute('GRANT DELETE ON % TO dave');

    if (!$authentication->hasPrivilege('carol', 'SELECT', 'app2', 'sales_orders')
        || !$authentication->hasPrivilege('carol', 'SELECT', 'app2', 'sales_drafts')
        || !$authentication->hasPrivilege('carol', 'SELECT', 'otherdb', 'sales_orders')) {
        throw new RuntimeException('A prefix table pattern did not match.');
    }
    if ($authentication->hasPrivilege('carol', 'SELECT', 'app2', 'other')
        || $authentication->hasPrivilege('carol', 'SELECT', 'otherdb', 'other')) {
        throw new RuntimeException('A prefix table pattern matched a non-matching name.');
    }
    if (!$authentication->hasPrivilege('carol', 'INSERT', 'app2', 'sales_orders')
        || !$authentication->hasPrivilege('carol', 'INSERT', 'appx', 'anything')) {
        throw new RuntimeException('A database prefix pattern did not match.');
    }
    if ($authentication->hasPrivilege('carol', 'INSERT', 'web', 't')) {
        throw new RuntimeException('A database prefix pattern matched a non-matching database.');
    }
    if (!$authentication->hasPrivilege('dave', 'UPDATE', 'app2', 'sales_orders')
        || !$authentication->hasPrivilege('dave', 'UPDATE', 'app2', 'sales_items')) {
        throw new RuntimeException('A qualified table prefix pattern did not match.');
    }
    if ($authentication->hasPrivilege('dave', 'UPDATE', 'app2', 'order_flow')) {
        throw new RuntimeException('A qualified table prefix pattern matched a non-matching table.');
    }
    if (!$authentication->hasPrivilege('dave', 'DELETE', 'whatever', 'whatever')) {
        throw new RuntimeException('A bare % grant did not cover every name.');
    }
    if (!$authentication->hasPrivilege('carol', 'CONNECT', 'app2', '*')) {
        throw new RuntimeException('The * wildcard grant no longer matches.');
    }

    $carol = new Session($storage, $config, $authentication);
    $carol->authenticateAs('carol', $carolAccount);
    $carol->execute('USE app2');
    $orderRows = iterator_to_array($carol->execute('SELECT note FROM sales_orders')->rows, false);
    if (count($orderRows) !== 2) {
        throw new RuntimeException('A patterned grant was not enforced over the wire path.');
    }
    try {
        $carol->execute('SELECT note FROM other');
        throw new RuntimeException('A patterned grant authorized a non-matching table.');
    } catch (FoxyException $e) {
        if ($e->errorCode !== 'ACCESS_DENIED') {
            throw $e;
        }
    }

    $admin->execute('REVOKE SELECT ON sales% FROM carol');
    if ($authentication->hasPrivilege('carol', 'SELECT', 'app2', 'sales_orders')) {
        throw new RuntimeException('REVOKE with a pattern did not remove the grant.');
    }
    $admin->execute("REVOKE INSERT ON app%.% FROM carol");
    if ($authentication->hasPrivilege('carol', 'INSERT', 'app2', 'anything')) {
        throw new RuntimeException('REVOKE with a database pattern did not remove the grant.');
    }

    echo "identifiers: ok\n";
} finally {
    if (isset($storage)) {
        $storage->close();
    }
    FileSystem::removeTree($directory);
}