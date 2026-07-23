<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;

final readonly class TlsCertificate
{
    private function __construct(
        public string $certificatePath,
        public string $privateKeyPath,
        public string $fingerprint,
    ) {
    }

    public static function ensure(Config $config): self
    {
        if (!extension_loaded('openssl')) {
            throw new FoxyException('The OpenSSL extension is required for TLS.', 'TLS_CONFIG');
        }
        $directory = $config->dataDirectory . DIRECTORY_SEPARATOR . 'tls';
        FileSystem::ensureDirectory($directory);
        if (DIRECTORY_SEPARATOR === '/') {
            @chmod($directory, 0700);
        }
        $lockPath = $directory . DIRECTORY_SEPARATOR . 'certificate.lock';
        $lock = @fopen($lockPath, 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new FoxyException('Unable to acquire TLS certificate lock.', 'STORAGE_LOCK');
        }
        try {
        $certificatePath = $directory . DIRECTORY_SEPARATOR . 'server.crt';
        $privateKeyPath = $directory . DIRECTORY_SEPARATOR . 'server.key';
        $generationState = $directory . DIRECTORY_SEPARATOR . '.certificate-generation';

        if (is_file($generationState) && (!is_file($certificatePath) || !is_file($privateKeyPath))) {
            @unlink($certificatePath);
            @unlink($privateKeyPath);
        }

        if (!is_file($certificatePath) && !is_file($privateKeyPath)) {
            FileSystem::atomicWrite($generationState, "generating\n", $config->syncWrites);
            $generated = false;
            try {
                self::generate($config->host, $certificatePath, $privateKeyPath, $config->syncWrites);
                $generated = true;
            } finally {
                if ($generated) {
                    @unlink($generationState);
                }
            }
        } elseif (!is_file($certificatePath) || !is_file($privateKeyPath)) {
            throw new FoxyException('TLS certificate or private key is missing.', 'TLS_CONFIG');
        }

        $certificatePem = @file_get_contents($certificatePath);
        $privateKeyPem = @file_get_contents($privateKeyPath);
        if ($certificatePem === false || $privateKeyPem === false) {
            throw new FoxyException('Unable to read TLS certificate files.', 'TLS_CONFIG');
        }
        $certificate = @openssl_x509_read($certificatePem);
        $privateKey = @openssl_pkey_get_private($privateKeyPem);
        if ($certificate === false || $privateKey === false
            || !openssl_x509_check_private_key($certificate, $privateKey)) {
            throw new FoxyException('TLS certificate and private key are invalid or do not match.', 'TLS_CONFIG');
        }
        $details = openssl_x509_parse($certificate);
        if ($details === false || (int) ($details['validTo_time_t'] ?? 0) <= time()) {
            throw new FoxyException('TLS certificate is expired or cannot be parsed.', 'TLS_CONFIG');
        }
        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
        if (!is_string($fingerprint)) {
            throw new FoxyException('Unable to calculate TLS certificate fingerprint.', 'TLS_CONFIG');
        }
        @chmod($privateKeyPath, 0600);
        return new self($certificatePath, $privateKeyPath, strtolower($fingerprint));
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function serverContextOptions(): array
    {
        return [
            'local_cert' => $this->certificatePath,
            'local_pk' => $this->privateKeyPath,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'disable_compression' => true,
            'honor_cipher_order' => true,
            'ciphers' => 'ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS',
            'crypto_method' => self::serverCryptoMethod(),
        ];
    }

    private static function generate(string $host, string $certificatePath, string $privateKeyPath, bool $sync): void
    {
        $directory = dirname($certificatePath);
        $configurationPath = $directory . DIRECTORY_SEPARATOR . '.openssl-' . bin2hex(random_bytes(5)) . '.cnf';
        $alternativeNames = "DNS.1 = localhost\nIP.1 = 127.0.0.1\nIP.2 = ::1\n";
        if (filter_var($host, FILTER_VALIDATE_IP) !== false && !in_array($host, ['127.0.0.1', '::1'], true)) {
            $alternativeNames .= "IP.3 = {$host}\n";
        } elseif (preg_match('/^[A-Za-z0-9.-]{1,253}$/', $host) === 1 && strtolower($host) !== 'localhost') {
            $alternativeNames .= "DNS.2 = {$host}\n";
        }
        $configuration = "[ req ]\n"
            . "distinguished_name = req_dn\n"
            . "prompt = no\n"
            . "x509_extensions = v3_server\n"
            . "[ req_dn ]\n"
            . "CN = FoxyDB\n"
            . "O = FoxyDB\n"
            . "[ v3_server ]\n"
            . "basicConstraints = critical, CA:FALSE\n"
            . "keyUsage = critical, digitalSignature, keyEncipherment\n"
            . "extendedKeyUsage = serverAuth\n"
            . "subjectAltName = @alt_names\n"
            . "[ alt_names ]\n"
            . $alternativeNames;
        FileSystem::atomicWrite($configurationPath, $configuration, $sync);

        try {
            $options = [
                'config' => $configurationPath,
                'digest_alg' => 'sha256',
                'private_key_bits' => 3072,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'x509_extensions' => 'v3_server',
            ];
            $privateKey = @openssl_pkey_new($options);
            if ($privateKey === false) {
                throw new FoxyException('Unable to generate TLS private key.', 'TLS_CONFIG');
            }
            $request = @openssl_csr_new(
                ['commonName' => 'FoxyDB', 'organizationName' => 'FoxyDB'],
                $privateKey,
                $options,
            );
            if ($request === false) {
                throw new FoxyException('Unable to generate TLS certificate request.', 'TLS_CONFIG');
            }
            $certificate = @openssl_csr_sign($request, null, $privateKey, 3_650, $options);
            if ($certificate === false) {
                throw new FoxyException('Unable to self-sign TLS certificate.', 'TLS_CONFIG');
            }
            if (!openssl_pkey_export($privateKey, $privateKeyPem, null, $options)
                || !openssl_x509_export($certificate, $certificatePem)) {
                throw new FoxyException('Unable to export generated TLS certificate.', 'TLS_CONFIG');
            }
            FileSystem::atomicWrite($privateKeyPath, $privateKeyPem, $sync, 0600);
            @chmod($privateKeyPath, 0600);
            FileSystem::atomicWrite($certificatePath, $certificatePem, $sync);
        } finally {
            @unlink($configurationPath);
        }
    }

    private static function serverCryptoMethod(): int
    {
        $method = 0;
        foreach (['STREAM_CRYPTO_METHOD_TLSv1_2_SERVER', 'STREAM_CRYPTO_METHOD_TLSv1_3_SERVER'] as $constant) {
            if (defined($constant)) {
                $method |= constant($constant);
            }
        }
        return $method !== 0 ? $method : STREAM_CRYPTO_METHOD_TLS_SERVER;
    }
}
