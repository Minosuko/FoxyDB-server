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
    $configuration = [];
    foreach ($storage->table(Authentication::SYSTEM_DATABASE, 'config_schema')->rows() as $entry) {
        $configuration[$entry['values']['config_key']] = $entry['values']['config_value'];
    }
    if (($configuration['default_host'] ?? null) !== '127.0.0.1') {
        throw new RuntimeException('The default host was not seeded in config_schema.');
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

    $admin = new Session($storage, $config, $authentication, new SystemVariables($storage, $config));
    $admin->authenticateAs('root', (string) ($authentication->authenticateIdentity('root', 'root')['account_id'] ?? ''));
    $admin->execute('CREATE DATABASE app');
    $admin->execute('USE app');
    $admin->execute('CREATE TABLE guard (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(20))');
    $admin->execute("INSERT INTO guard (name) VALUES ('open'), ('secret')");
    $admin->execute('CREATE ROLE analyst');
    $admin->execute("CREATE POLICY secret_rows ON guard FOR SELECT TO analyst USING (name = 'secret')");
    $admin->execute("CREATE POLICY open_rows ON guard FOR SELECT USING (name = 'open')");
    $admin->execute("GRANT SELECT ON app.guard TO analyst");
    $admin->execute("GRANT CONNECT ON app.* TO analyst");
    $users = $storage->table(Authentication::SYSTEM_DATABASE, 'users_schema');
    $users->insert([
        'username' => 'alice',
        'password_hash' => password_hash('alice-pass', PASSWORD_DEFAULT),
    ]);
    $users->insert([
        'username' => 'bob',
        'password_hash' => password_hash('bob-pass', PASSWORD_DEFAULT),
    ]);
    $aliceAccount = '';
    foreach ($users->rows($users->lookupForEqualities(['username' => 'alice'])) as $entry) {
        $aliceAccount = $entry['values']['account_id'];
    }
    $bobAccount = '';
    foreach ($users->rows($users->lookupForEqualities(['username' => 'bob'])) as $entry) {
        $bobAccount = $entry['values']['account_id'];
    }
    $admin->execute("GRANT analyst TO alice");
    $admin->execute("GRANT CONNECT ON app.* TO bob");
    $admin->execute("GRANT SELECT ON app.guard TO bob");
    $alice = new Session($storage, $config, $authentication);
    $alice->authenticateAs('alice', $aliceAccount);
    $alice->execute('USE app');
    $aliceRows = array_column(iterator_to_array($alice->execute('SELECT name FROM guard')->rows, false), 'name');
    sort($aliceRows);
    if ($aliceRows !== ['open', 'secret']) {
        throw new RuntimeException('Role privileges were not aggregated for a role member.');
    }
    $bob = new Session($storage, $config, $authentication);
    $bob->authenticateAs('bob', $bobAccount);
    $bob->execute('USE app');
    if (array_column(iterator_to_array($bob->execute('SELECT name FROM guard')->rows, false), 'name') !== ['open']) {
        throw new RuntimeException('The unscoped policy did not apply or a role policy leaked.');
    }
    if (array_column(iterator_to_array($bob->execute('SELECT name FROM app.guard')->rows, false), 'name') !== ['open']) {
        throw new RuntimeException('A qualified table name did not match an exact grant.');
    }
    $admin->execute('GRANT CREATE ON app.* TO bob');
    try {
        $bob->execute('CREATE ROLE unauthorized_admin');
        throw new RuntimeException('Application CREATE privilege administered global roles.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'ACCESS_DENIED') {
            throw $exception;
        }
    }
    $adminRows = array_column(iterator_to_array($admin->execute('SELECT name FROM guard')->rows, false), 'name');
    if ($adminRows !== ['open']) {
        throw new RuntimeException('A role-scoped policy applied to an account without the role.');
    }
    $admin->execute("GRANT analyst TO root");
    if (count(iterator_to_array($admin->execute('SELECT name FROM guard')->rows, false)) !== 2) {
        throw new RuntimeException('A role-scoped policy was not applied after role assignment.');
    }

    // Write-side policies: INSERT must satisfy the applicable policies, and an
    // UPDATE whose resulting row leaves the policy is rejected.
    $admin->execute("CREATE POLICY insert_open ON guard FOR INSERT USING (name = 'open')");
    $admin->execute("CREATE POLICY update_open ON guard FOR UPDATE USING (name = 'open')");
    $admin->execute("CREATE POLICY delete_open ON guard FOR DELETE USING (name = 'open')");
    $admin->execute("GRANT INSERT ON app.guard TO bob");
    $admin->execute("GRANT UPDATE ON app.guard TO bob");
    $admin->execute("GRANT DELETE ON app.guard TO bob");
    $bob->execute('USE app');
    $bob->execute("INSERT INTO guard (name) VALUES ('open')");
    $bobPolicyFails = false;
    try {
        $bob->execute("INSERT INTO guard (name) VALUES ('secret')");
    } catch (FoxyException $exception) {
        $bobPolicyFails = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$bobPolicyFails) {
        throw new RuntimeException('An INSERT that violates a policy was not rejected.');
    }
    $bobUpdatePolicyFails = false;
    try {
        $bob->execute("UPDATE guard SET name = 'secret' WHERE name = 'open'");
    } catch (FoxyException $exception) {
        $bobUpdatePolicyFails = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$bobUpdatePolicyFails) {
        throw new RuntimeException('An UPDATE that produces a row outside the policy was not rejected.');
    }
    $bobDelete = $bob->execute("DELETE FROM guard WHERE name = 'open'");
    if ($bobDelete->affectedRows !== 2) {
        throw new RuntimeException('DELETE did not honor the delete policy scope.');
    }
    $bobVisible = $bob->execute('SELECT name FROM guard');
    $bobNames = array_column(iterator_to_array($bobVisible->rows, false), 'name');
    if ($bobNames !== []) {
        throw new RuntimeException('Write-side policies left rows visible after DELETE.');
    }
    $adminAfter = $admin->execute('SELECT name FROM guard');
    $adminNames = array_column(iterator_to_array($adminAfter->rows, false), 'name');
    sort($adminNames);
    if ($adminNames !== ['secret']) {
        throw new RuntimeException('Write-side policies corrupted the underlying table.');
    }
    $adminInsertViolation = false;
    try {
        $admin->execute("INSERT INTO guard (name) VALUES ('other')");
    } catch (FoxyException $exception) {
        $adminInsertViolation = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$adminInsertViolation) {
        throw new RuntimeException('An unscoped insert policy did not bind the table owner.');
    }

    // Role-scoped write policies compose the same way reads do: a member of the
    // role may write rows any of their applicable policies allow, and a
    // non-member is not granted the role policy.
    $admin->execute("CREATE POLICY analyst_insert ON guard FOR INSERT TO analyst USING (name = 'secret')");
    $admin->execute("GRANT INSERT ON app.guard TO analyst");
    $alice->execute('USE app');
    $alice->execute("INSERT INTO guard (name) VALUES ('secret')");
    $alice->execute("INSERT INTO guard (name) VALUES ('open')");
    $aliceInsertViolation = false;
    try {
        $alice->execute("INSERT INTO guard (name) VALUES ('other')");
    } catch (FoxyException $exception) {
        $aliceInsertViolation = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$aliceInsertViolation) {
        throw new RuntimeException('A role-scoped insert policy did not bind a role member.');
    }
    $bobRolePolicyLeak = false;
    try {
        $bob->execute("INSERT INTO guard (name) VALUES ('secret')");
    } catch (FoxyException $exception) {
        $bobRolePolicyLeak = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$bobRolePolicyLeak) {
        throw new RuntimeException('A role-scoped insert policy leaked to a non-member.');
    }

    $admin->execute('CREATE TABLE join_left (id INT PRIMARY KEY, value VARCHAR(20))');
    $admin->execute('CREATE TABLE join_right (id INT PRIMARY KEY, value VARCHAR(20))');
    $admin->execute("INSERT INTO join_left (id, value) VALUES (1, 'left-one'), (2, 'left-two')");
    $admin->execute("INSERT INTO join_right (id, value) VALUES (1, 'allowed'), (2, 'hidden')");
    $admin->execute('GRANT SELECT ON app.join_left TO bob');
    $joinDenied = false;
    try {
        $bob->execute('SELECT join_left.id FROM join_left INNER JOIN join_right ON join_left.id = join_right.id');
    } catch (FoxyException $exception) {
        $joinDenied = $exception->errorCode === 'ACCESS_DENIED';
    }
    if (!$joinDenied) {
        throw new RuntimeException('A joined table bypassed SELECT authorization.');
    }
    $admin->execute('CREATE TABLE private_rows (id INT PRIMARY KEY)');
    $admin->execute('INSERT INTO private_rows (id) VALUES (1)');
    $subqueryDenied = false;
    try {
        iterator_to_array($bob->execute(
            'SELECT id FROM join_left WHERE id IN (SELECT id FROM private_rows)'
        )->rows, false);
    } catch (FoxyException $exception) {
        $subqueryDenied = $exception->errorCode === 'ACCESS_DENIED';
    }
    if (!$subqueryDenied) {
        throw new RuntimeException('A subquery table bypassed SELECT authorization.');
    }
    $admin->execute('GRANT SELECT ON app.join_right TO bob');
    $admin->execute('CREATE POLICY joined_rows ON join_right FOR SELECT USING (id = 1)');
    $admin->execute('CREATE POLICY joined_delete ON join_right FOR DELETE USING (id = 1)');
    $joined = iterator_to_array(
        $bob->execute('SELECT join_right.value FROM join_left INNER JOIN join_right ON join_left.id = join_right.id')->rows,
        false,
    );
    if (array_column($joined, 'join_right.value') !== ['allowed']) {
        throw new RuntimeException('A joined table bypassed its row-level policy.');
    }
    $admin->execute('RENAME TABLE join_right TO join_right_renamed');
    $renamedPolicyRows = iterator_to_array(
        $admin->execute('SELECT value FROM join_right_renamed')->rows,
        false,
    );
    if (array_column($renamedPolicyRows, 'value') !== ['allowed']) {
        throw new RuntimeException('Table rename detached its row-level policies.');
    }
    $admin->execute('RENAME TABLE join_right_renamed TO join_right');
    $truncateDenied = false;
    try {
        $admin->execute('TRUNCATE TABLE join_right');
    } catch (FoxyException $exception) {
        $truncateDenied = $exception->errorCode === 'POLICY_VIOLATION';
    }
    if (!$truncateDenied) {
        throw new RuntimeException('TRUNCATE bypassed a row-level DELETE policy.');
    }

    $admin->execute('CREATE TABLE identity_rows (id INT PRIMARY KEY, value VARCHAR(20))');
    $admin->execute("INSERT INTO identity_rows (id, value) VALUES (1, 'owned'), (2, 'other')");
    $admin->execute('CREATE POLICY alice_identity ON identity_rows FOR SELECT TO alice USING (id = 1)');
    $admin->execute('GRANT SELECT ON app.identity_rows TO alice');
    if (array_column(iterator_to_array($alice->execute('SELECT value FROM identity_rows')->rows, false), 'value') !== ['owned']) {
        throw new RuntimeException('User-bound policy did not apply to its account identity.');
    }

    $users->delete(static fn(array $row): bool => $row['username'] === 'alice');
    $users->insert([
        'username' => 'alice',
        'password_hash' => password_hash('new-alice-pass', PASSWORD_DEFAULT),
    ]);
    $newAlice = $authentication->authenticateIdentity('alice', 'new-alice-pass');
    if ($newAlice === null || $authentication->hasPrivilege(
        'alice', 'SELECT', 'app', 'guard', $newAlice['account_id'],
    )) {
        throw new RuntimeException('A recreated username inherited a stale role assignment.');
    }
    $admin->execute('GRANT analyst TO alice');
    if (!$authentication->hasPrivilege('alice', 'SELECT', 'app', 'guard', $newAlice['account_id'])) {
        throw new RuntimeException('A recreated account could not receive a fresh role assignment.');
    }
    $admin->execute('GRANT SELECT ON app.identity_rows TO alice');
    $recreatedAlice = new Session($storage, $config, $authentication);
    $recreatedAlice->authenticateAs('alice', $newAlice['account_id']);
    $recreatedAlice->execute('USE app');
    $identityRows = array_column(iterator_to_array(
        $recreatedAlice->execute('SELECT value FROM identity_rows')->rows,
        false,
    ), 'value');
    sort($identityRows);
    if ($identityRows !== ['other', 'owned']) {
        throw new RuntimeException('A recreated username inherited a stale user-scoped policy.');
    }
    $unknownRoleGranteeRejected = false;
    try {
        $admin->execute('GRANT analyst TO missing_user');
    } catch (FoxyException $exception) {
        $unknownRoleGranteeRejected = $exception->errorCode === 'UNKNOWN_GRANTEE';
    }
    if (!$unknownRoleGranteeRejected) {
        throw new RuntimeException('A role was granted to a nonexistent account.');
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
    if ($authentication->authenticate('carol', 'carol-pass') !== null
        || $authentication->hasPrivilege('carol', 'SELECT', 'anything', 'anything')) {
        throw new RuntimeException('An unknown user was able to authenticate.');
    }
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
