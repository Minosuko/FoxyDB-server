<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\SecureInstallation;
use FoxyDB\SecureInstallationOptions;

const HELP = <<<'TEXT'
FoxyDB secure installation

Usage:
  php bin/foxydb_secure_installation.php [OPTIONS]

Options:
  --defaults-extra-file=FILE  Read this file after normal defaults files
  --defaults-file=FILE        Read only this defaults file
  --defaults-group-suffix=S   Also read option groups with this suffix
  --help                      Display this help
  --host=HOST                 FoxyDB host, default 127.0.0.1
  --no-defaults               Do not read defaults files
  --password[=PASSWORD]       Current password, prompts when omitted
  --port=PORT                 FoxyDB port, default 2002
  --print-defaults            Print resolved options and exit
  --protocol=PROTOCOL         TCP, TLS, or SOCKET
  --socket=PATH               Local socket path, reserved for socket daemons
  --ssl-ca=FILE               Certificate authority file
  --ssl-capath=DIR            Certificate authority directory
  --ssl-cert=FILE             Client certificate file
  --ssl-cipher=LIST           TLS 1.2 cipher list
  --ssl-crl=FILE              Certificate revocation list file
  --ssl-crlpath=DIR           Certificate revocation list directory
  --ssl-fips-mode=MODE        OFF, ON, or STRICT
  --ssl-key=FILE              Client private key file
  --ssl-mode=MODE             DISABLED, PREFERRED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY
  --ssl-session-data=FILE     Binary peer certificate session pin data
  --ssl-session-data-continue-on-failed-reuse[=BOOL]
                              Continue when saved peer session data differs
  --tls-ciphersuites=LIST     TLS 1.3 cipher suites
  --tls-version=LIST          TLSv1.2,TLSv1.3 by default
  --use-default               Apply recommended defaults without prompts
  --user=USER                 Login user, default root

The tool never writes a plaintext password to defaults files or environment variables.
TEXT;

try {
    $options = SecureInstallationOptions::parse($argv, dirname(__DIR__));
    if ($options->get('help')) {
        echo HELP . "\n";
        exit(0);
    }
    if ($options->get('print-defaults')) {
        echo 'foxydb_secure_installation ' . implode(' ', $options->printableArguments()) . "\n";
        exit(0);
    }
    (new SecureInstallation($options))->run();
} catch (FoxyException $exception) {
    fwrite(STDERR, "FoxyDB secure installation error [{$exception->errorCode}]: {$exception->getMessage()}\n");
    exit(1);
} catch (Throwable $exception) {
    fwrite(STDERR, 'FoxyDB secure installation fatal error: ' . $exception->getMessage() . "\n");
    exit(1);
}
