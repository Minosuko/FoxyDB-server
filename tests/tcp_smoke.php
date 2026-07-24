<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Client;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Support\FileSystem;
use FoxyDB\TlsOptions;
use FoxyDB\Value\BinaryValue;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-tcp-' . bin2hex(random_bytes(6));
$uploadPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-upload-' . bin2hex(random_bytes(6));
$probe = stream_socket_server('tcp://127.0.0.1:0', $probeCode, $probeError);
if ($probe === false) {
    throw new RuntimeException("Unable to reserve a test port: {$probeError}");
}
$probeAddress = stream_socket_get_name($probe, false);
fclose($probe);
$port = (int) substr(strrchr($probeAddress, ':'), 1);
$command = [
    PHP_BINARY,
    dirname(__DIR__) . '/bin/foxydb.php',
    '--host=127.0.0.1',
    '--port=' . $port,
    '--data-dir=' . $directory,
    '--no-sync',
];
$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];
$serverEnvironment = getenv();
if (!is_array($serverEnvironment)) {
    $serverEnvironment = [];
}
$serverEnvironment['FOXYDB_MAX_RESULT_ROWS'] = '10';
$process = proc_open(
    $command,
    $descriptors,
    $pipes,
    dirname(__DIR__),
    $serverEnvironment,
    ['bypass_shell' => true],
);
if (!is_resource($process)) {
    throw new RuntimeException('Unable to launch the FoxyDB test server.');
}
fclose($pipes[0]);
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

try {
    $client = null;
    $deadline = microtime(true) + 10;
    while (microtime(true) < $deadline) {
        try {
            $client = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
            break;
        } catch (FoxyException) {
            usleep(100_000);
        }
    }
    if (!$client instanceof Client) {
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        throw new RuntimeException("Server did not start. Output: {$stdout} {$stderr}");
    }
    if (($client->tlsInfo()['protocol'] ?? '') === '' || !is_file($directory . '/tls/server.crt')) {
        throw new RuntimeException('Client connection did not negotiate TLS.');
    }
    $plain = @stream_socket_client("tcp://127.0.0.1:{$port}", $plainCode, $plainError, 1.0);
    if ($plain === false) {
        throw new RuntimeException("Unable to test plaintext rejection: {$plainError}");
    }
    stream_set_timeout($plain, 2);
    fwrite($plain, FrameCodec::encode(['type' => 'ping', 'id' => 1], 1_024));
    $plainResponse = @fread($plain, 1);
    fclose($plain);
    if ($plainResponse !== '' && $plainResponse !== false) {
        throw new RuntimeException('TLS daemon returned application data to a plaintext connection.');
    }
    $verifiedClient = Client::connect(
        host: '127.0.0.1',
        port: $port,
        username: 'root',
        password: 'root',
        timeoutSeconds: 2.0,
        tlsOptions: new TlsOptions(mode: 'VERIFY_IDENTITY', caFile: $directory . '/tls/server.crt'),
    );
    $verifiedClient->close();
    $tls12Client = Client::connect(
        host: '127.0.0.1',
        port: $port,
        username: 'root',
        password: 'root',
        timeoutSeconds: 2.0,
        tlsOptions: new TlsOptions(tlsVersions: ['TLSv1.2']),
    );
    if (($tls12Client->tlsInfo()['protocol'] ?? null) !== 'TLSv1.2') {
        throw new RuntimeException('TLS version policy was not enforced.');
    }
    $tls12Client->close();
    $sessionDataPath = $directory . '/client-session.fdb';
    $sessionClient = Client::connect(
        host: '127.0.0.1',
        port: $port,
        username: 'root',
        password: 'root',
        timeoutSeconds: 2.0,
        tlsOptions: new TlsOptions(sessionDataFile: $sessionDataPath),
    );
    $sessionClient->close();
    $sessionData = FileSystem::readMetadata($sessionDataPath);
    $sessionData['certificate_sha256'] = str_repeat('0', 64);
    FileSystem::writeMetadata($sessionDataPath, $sessionData);
    try {
        Client::connect(
            host: '127.0.0.1',
            port: $port,
            username: 'root',
            password: 'root',
            timeoutSeconds: 2.0,
            tlsOptions: new TlsOptions(sessionDataFile: $sessionDataPath),
        );
        throw new RuntimeException('Mismatched TLS session peer data was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'TLS_SESSION_REUSE_FAILED') {
            throw $exception;
        }
    }
    try {
        Client::connect('127.0.0.1', $port, 'root', 'wrong-password', 1.0);
        throw new RuntimeException('Invalid credentials were accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'AUTH_FAILED') {
            throw $exception;
        }
    }
    $authenticationContext = stream_context_create(['ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
    ]]);
    $authenticationStream = @stream_socket_client(
        "tls://127.0.0.1:{$port}",
        $authenticationCode,
        $authenticationError,
        2.0,
        STREAM_CLIENT_CONNECT,
        $authenticationContext,
    );
    if ($authenticationStream === false) {
        throw new RuntimeException("Unable to test authentication closure: {$authenticationError}");
    }
    stream_set_timeout($authenticationStream, 2);
    $authenticationHello = FrameCodec::read($authenticationStream, 8_388_608);
    FrameCodec::write($authenticationStream, [
        'type' => 'auth',
        'id' => 1,
        'username' => 'root',
        'password' => 'wrong-password',
        'interactive' => false,
    ], 8_388_608);
    $authenticationFailure = FrameCodec::read($authenticationStream, 8_388_608);
    if (($authenticationHello['type'] ?? null) !== 'hello'
        || ($authenticationFailure['error']['code'] ?? null) !== 'AUTH_FAILED') {
        fclose($authenticationStream);
        throw new RuntimeException('Failed authentication did not return the expected protocol response.');
    }
    try {
        FrameCodec::read($authenticationStream, 8_388_608);
        fclose($authenticationStream);
        throw new RuntimeException('Server allowed authentication retries on one connection.');
    } catch (FoxyException $exception) {
        fclose($authenticationStream);
        if ($exception->errorCode !== 'CONNECTION_CLOSED') {
            throw $exception;
        }
    }
    if (!$client->ping()) {
        throw new RuntimeException('TCP ping failed.');
    }
    $packetClient = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
    $packetClient->query('SET SESSION max_allowed_packet = 1024');
    try {
        $packetClient->query('SELECT username FROM users_schema WHERE username = ?', [str_repeat('p', 2_000)]);
        throw new RuntimeException('Live session packet limit was not enforced.');
    } catch (FoxyException $exception) {
        if (!in_array($exception->errorCode, [
            'FRAME_TOO_LARGE', 'PROTOCOL_ERROR', 'CONNECTION_CLOSED', 'CONNECTION_IO',
        ], true)) {
            throw $exception;
        }
    }
    $timeoutClient = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
    $timeoutClient->query('SET SESSION wait_timeout = 1');
    sleep(3);
    try {
        $timeoutClient->ping();
        throw new RuntimeException('Live session idle timeout was not enforced.');
    } catch (FoxyException) {
    }
    $systemTables = $client->query('SHOW TABLES');
    $systemTableNames = array_column(iterator_to_array($systemTables->rows, false), 'table');
    foreach (['users_schema', 'privileges', 'config_schema', 'performance_schema', 'sys_config'] as $tableName) {
        if (!in_array($tableName, $systemTableNames, true)) {
            throw new RuntimeException("Missing system table: {$tableName}");
        }
    }
    $rootUser = $client->query("SELECT username, password_hash FROM users_schema WHERE username = 'root'");
    $rootRows = iterator_to_array($rootUser->rows, false);
    if (count($rootRows) !== 1 || $rootRows[0]['password_hash'] === 'root'
        || !password_verify('root', $rootRows[0]['password_hash'])) {
        throw new RuntimeException('Default root credentials were not securely bootstrapped.');
    }
    try {
        $client->query(
            "UPDATE users_schema SET account_id = '00000000-0000-4000-8000-000000000001' WHERE username = 'root'",
        );
        throw new RuntimeException('A client changed a server-generated account identifier.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'SYSTEM_COLUMN_PROTECTED') {
            throw $exception;
        }
    }
    $client->query('CREATE DATABASE network');
    $client->query('USE network');
    $client->query('CREATE TABLE files (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50) UNIQUE, body BLOB)');

    $adaptiveUpload = random_bytes(8_192);
    if (file_put_contents($uploadPath, $adaptiveUpload) !== strlen($adaptiveUpload)) {
        throw new RuntimeException('Unable to prepare adaptive upload fixture.');
    }
    $adaptiveClient = Client::connect(
        host: '127.0.0.1',
        port: $port,
        username: 'root',
        password: 'root',
        timeoutSeconds: 2.0,
        uploadChunkBytes: 65_536,
    );
    $adaptiveClient->query('SET SESSION max_allowed_packet = 1024');
    $adaptiveClient->uploadFile($uploadPath, 'binary');
    $adaptiveClient->close();

    $upload = random_bytes(300_000);
    if (file_put_contents($uploadPath, $upload) !== strlen($upload)) {
        throw new RuntimeException('Unable to prepare upload fixture.');
    }
    $reference = $client->uploadFile($uploadPath, 'binary');
    $inserted = $client->query('INSERT INTO files (name, body) VALUES (?, ?)', ['payload', $reference]);
    if ($inserted->lastInsertId !== 1) {
        throw new RuntimeException('TCP INSERT did not return its identifier.');
    }
    $numericReference = $client->uploadFile($uploadPath, 'binary', '0');
    $numericInsert = $client->query(
        'INSERT INTO files (name, body) VALUES (?, ?)',
        ['numeric-transfer', $numericReference],
    );
    if ($numericInsert->lastInsertId !== 2 || !$client->ping()) {
        throw new RuntimeException('Numeric transfer identifier cleanup damaged the connection.');
    }
    $orphanClient = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
    $orphanClient->uploadFile($uploadPath, 'binary', '-1');
    $orphanClient->close();
    usleep(100_000);
    if (!$client->ping()) {
        throw new RuntimeException('Numeric transfer identifier disconnect cleanup stopped the server.');
    }
    $result = $client->query('SELECT id, name, body FROM files WHERE name = ?', ['payload']);
    $rows = iterator_to_array($result->rows, false);
    if (count($rows) !== 1 || !$rows[0]['body'] instanceof BinaryValue || $rows[0]['body']->bytes !== $upload) {
        throw new RuntimeException('TCP chunked value did not round trip.');
    }
    $inlineBinary = random_bytes(257);
    $client->query(
        'INSERT INTO files (name, body) VALUES (?, ?)',
        ['inline', new BinaryValue($inlineBinary)],
    );
    $inlineRows = iterator_to_array(
        $client->query("SELECT body FROM files WHERE name = 'inline'")->rows,
        false,
    );
    if (count($inlineRows) !== 1 || !($inlineRows[0]['body'] instanceof BinaryValue)
        || $inlineRows[0]['body']->bytes !== $inlineBinary) {
        throw new RuntimeException('TCP inline binary value did not round trip without Base64.');
    }
    $client->query('CREATE TABLE overflow_rows (id INT PRIMARY KEY AUTO_INCREMENT, value VARCHAR(20))');
    $values = [];
    $overflowParameters = [];
    for ($index = 0; $index < 11; $index++) {
        $values[] = '(?)';
        $overflowParameters[] = 'value-' . $index;
    }
    $client->query(
        'INSERT INTO overflow_rows (value) VALUES ' . implode(', ', $values),
        $overflowParameters,
    );
    $limitClient = Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
    $limitClient->query('USE network');
    try {
        $limitClient->query('SELECT id, value FROM overflow_rows');
        throw new RuntimeException('Streamed result row limit was not enforced.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'RESOURCE_LIMIT') {
            throw $exception;
        }
    }
    $client->query('USE foxydb');
    $readerHash = password_hash('reader-pass', PASSWORD_DEFAULT);
    $client->query(
        'INSERT INTO users_schema (username, password_hash, enabled) VALUES (?, ?, TRUE)',
        ['reader', $readerHash],
    );
    $readerAccount = iterator_to_array(
        $client->query("SELECT account_id FROM users_schema WHERE username = 'reader'")->rows,
        false,
    )[0]['account_id'];
    $client->query(
        'INSERT INTO privileges (username, account_id, database_name, table_name, privilege) '
        . "VALUES ('reader', ?, 'network', '*', 'CONNECT'), ('reader', ?, 'network', 'files', 'SELECT')",
        [$readerAccount, $readerAccount],
    );
    $reader = Client::connect('127.0.0.1', $port, 'reader', 'reader-pass', 1.0);
    $reader->query('USE network');
    $readerRows = iterator_to_array($reader->query('SELECT name FROM files')->rows, false);
    if (array_column($readerRows, 'name') !== ['payload', 'numeric-transfer', 'inline']) {
        throw new RuntimeException('Granted reader privilege did not permit SELECT.');
    }
    try {
        $reader->query("INSERT INTO files (name) VALUES ('denied')");
        throw new RuntimeException('Unprivileged INSERT was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'ACCESS_DENIED') {
            throw $exception;
        }
    }
    $client->query("DELETE FROM users_schema WHERE username = 'reader'");
    $client->query(
        'INSERT INTO users_schema (username, password_hash, enabled) VALUES (?, ?, TRUE)',
        ['reader', $readerHash],
    );
    try {
        $reader->query('SELECT name FROM files');
        throw new RuntimeException('A recreated username revived an old authenticated session.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'ACCESS_DENIED') {
            throw $exception;
        }
    }
    $reader->close();

    $installerCommand = [
        PHP_BINARY,
        dirname(__DIR__) . '/bin/foxydb_secure_installation.php',
        '--no-defaults',
        '--host=127.0.0.1',
        '--port=' . $port,
        '--user=root',
        '--password=root',
        '--ssl-mode=VERIFY_IDENTITY',
        '--ssl-ca=' . $directory . '/tls/server.crt',
        '--use-default',
    ];
    $installer = proc_open($installerCommand, $descriptors, $installerPipes, dirname(__DIR__), null, [
        'bypass_shell' => true,
    ]);
    if (!is_resource($installer)) {
        throw new RuntimeException('Unable to launch secure installation test.');
    }
    fclose($installerPipes[0]);
    $installerOutput = stream_get_contents($installerPipes[1]);
    $installerError = stream_get_contents($installerPipes[2]);
    fclose($installerPipes[1]);
    fclose($installerPipes[2]);
    $installerExit = proc_close($installer);
    if ($installerExit !== 0 || preg_match('/Generated password for root: (\S+)/', $installerOutput, $match) !== 1) {
        throw new RuntimeException("Secure installation failed: {$installerOutput} {$installerError}");
    }
    $generatedRootPassword = $match[1];
    $client->close();
    try {
        Client::connect('127.0.0.1', $port, 'root', 'root', 1.0);
        throw new RuntimeException('Secure installation left the default root password active.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'AUTH_FAILED') {
            throw $exception;
        }
    }
    $securedClient = Client::connect('127.0.0.1', $port, 'root', $generatedRootPassword, 2.0);
    $secureMarker = $securedClient->query(
        "SELECT variable_value FROM sys_config WHERE variable_name = 'secure_installation_completed'",
    );
    if (count(iterator_to_array($secureMarker->rows, false)) !== 1) {
        throw new RuntimeException('Secure installation did not persist its completion marker.');
    }
    $securedClient->close();
    $generalLog = file_get_contents($directory . '/logs/general.log');
    $auditLog = file_get_contents($directory . '/logs/audit.log');
    if ($generalLog === false || $auditLog === false
        || !str_contains($generalLog, 'query.executed')
        || !str_contains($auditLog, 'authentication.succeeded')
        || !str_contains($auditLog, 'authentication.failed')
        || !str_contains($auditLog, '"status":"failed"')
        || !str_contains($auditLog, '"error_code":"RESOURCE_LIMIT"')) {
        throw new RuntimeException('TCP server did not emit the required structured log events.');
    }
    foreach (['wrong-password', 'reader-pass', $generatedRootPassword] as $secret) {
        if (str_contains($generalLog, $secret) || str_contains($auditLog, $secret)) {
            throw new RuntimeException('TCP server logs exposed a credential.');
        }
    }
    echo "tcp smoke: ok\n";
} finally {
    proc_terminate($process);
    $deadline = microtime(true) + 5;
    do {
        $status = proc_get_status($process);
        if (!$status['running']) {
            break;
        }
        usleep(100_000);
    } while (microtime(true) < $deadline);
    if (($status['running'] ?? false) === true) {
        proc_terminate($process, 9);
    }
    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }
    proc_close($process);
    if (is_file($uploadPath)) {
        unlink($uploadPath);
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
