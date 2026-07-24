<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\SecureInstallationOptions;

$path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-options-' . bin2hex(random_bytes(5)) . '.ini';
$configuration = <<<'INI'
[client]
host = defaults.test
port = 2200
ssl_mode = VERIFY_CA

[foxydb_secure_installation_prod]
user = administrator
tls_version = TLSv1.3
use_default
INI;

try {
    file_put_contents($path, $configuration);
    $options = SecureInstallationOptions::parse([
        'foxydb_secure_installation.php',
        '--defaults-file=' . $path,
        '--defaults-group-suffix=_prod',
        '--host=override.test',
        '--password=secret',
    ], dirname(__DIR__));
    if ($options->get('host') !== 'override.test' || $options->get('port') !== 2200
        || $options->get('user') !== 'administrator' || $options->get('ssl-mode') !== 'VERIFY_CA'
        || $options->get('tls-version') !== 'TLSv1.3' || $options->get('use-default') !== true) {
        throw new RuntimeException('Defaults files, suffix groups, or CLI precedence are incorrect.');
    }
    $printable = implode(' ', $options->printableArguments());
    if (!str_contains($printable, '--password=*****') || str_contains($printable, 'secret')) {
        throw new RuntimeException('Printable defaults exposed a password.');
    }

    $withoutDefaults = SecureInstallationOptions::parse([
        'foxydb_secure_installation.php',
        '--defaults-file=' . $path,
        '--no-defaults',
    ], dirname(__DIR__));
    if ($withoutDefaults->get('host') !== '127.0.0.1' || $withoutDefaults->get('port') !== 2002) {
        throw new RuntimeException('--no-defaults did not suppress defaults files.');
    }

    try {
        SecureInstallationOptions::parse(['tool', '--unknown-option'], dirname(__DIR__));
        throw new RuntimeException('Unknown secure installation option was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'INVALID_CONFIG') {
            throw $exception;
        }
    }
    echo "secure options: ok\n";
} finally {
    if (is_file($path)) {
        unlink($path);
    }
}
