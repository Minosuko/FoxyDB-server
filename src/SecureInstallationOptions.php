<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;

final readonly class SecureInstallationOptions
{
    private const VALUE_OPTIONS = [
        'defaults-extra-file', 'defaults-file', 'defaults-group-suffix', 'host', 'password', 'port',
        'protocol', 'socket', 'ssl-ca', 'ssl-capath', 'ssl-cert', 'ssl-cipher', 'ssl-crl',
        'ssl-crlpath', 'ssl-fips-mode', 'ssl-key', 'ssl-mode', 'ssl-session-data',
        'tls-ciphersuites', 'tls-version', 'user',
    ];
    private const FLAG_OPTIONS = [
        'help', 'no-defaults', 'print-defaults', 'ssl-session-data-continue-on-failed-reuse',
        'use-default',
    ];

    private function __construct(public array $values)
    {
    }

    public static function parse(array $arguments, string $baseDirectory): self
    {
        $commandLine = self::parseCommandLine(array_slice($arguments, 1));
        $values = [
            'host' => '127.0.0.1',
            'port' => 2002,
            'protocol' => 'TCP',
            'user' => 'root',
            'ssl-mode' => 'REQUIRED',
            'ssl-fips-mode' => 'OFF',
            'tls-version' => 'TLSv1.2,TLSv1.3',
            'no-defaults' => false,
            'help' => false,
            'print-defaults' => false,
            'ssl-session-data-continue-on-failed-reuse' => false,
            'use-default' => false,
        ];

        if (!self::boolean($commandLine['no-defaults'] ?? false)) {
            $defaultsFile = self::nullable($commandLine['defaults-file'] ?? null);
            if ($defaultsFile !== null) {
                $values = array_replace($values, self::readDefaultsFile(
                    $defaultsFile,
                    (string) ($commandLine['defaults-group-suffix'] ?? ''),
                    true,
                ));
            } else {
                foreach (self::standardDefaultsFiles($baseDirectory) as $path) {
                    if (is_file($path)) {
                        $values = array_replace($values, self::readDefaultsFile(
                            $path,
                            (string) ($commandLine['defaults-group-suffix'] ?? ''),
                            false,
                        ));
                    }
                }
            }
            $extraFile = self::nullable($commandLine['defaults-extra-file'] ?? null);
            if ($extraFile !== null) {
                $values = array_replace($values, self::readDefaultsFile(
                    $extraFile,
                    (string) ($commandLine['defaults-group-suffix'] ?? ''),
                    true,
                ));
            }
        }
        $values = array_replace($values, $commandLine);
        $values['port'] = filter_var($values['port'], FILTER_VALIDATE_INT);
        if ($values['port'] === false || $values['port'] < 1 || $values['port'] > 65_535) {
            throw new FoxyException('Secure installation port must be from 1 to 65535.', 'INVALID_CONFIG');
        }
        foreach (self::FLAG_OPTIONS as $name) {
            $values[$name] = self::boolean($values[$name] ?? false);
        }
        $values['protocol'] = strtoupper((string) $values['protocol']);
        if (!in_array($values['protocol'], ['TCP', 'TLS', 'SOCKET'], true)) {
            throw new FoxyException('Protocol must be TCP, TLS, or SOCKET.', 'INVALID_CONFIG');
        }
        $values['ssl-mode'] = strtoupper((string) $values['ssl-mode']);
        $values['ssl-fips-mode'] = strtoupper((string) $values['ssl-fips-mode']);
        return new self($values);
    }

    public function get(string $name, mixed $default = null): mixed
    {
        return $this->values[$name] ?? $default;
    }

    public function tlsOptions(): TlsOptions
    {
        return TlsOptions::fromArray($this->values);
    }

    public function printableArguments(): array
    {
        $arguments = [];
        foreach ($this->values as $name => $value) {
            if ($value === null || $value === false || in_array($name, [
                'help', 'print-defaults', 'defaults-file', 'defaults-extra-file', 'defaults-group-suffix',
                'password-prompt',
            ], true)) {
                continue;
            }
            if ($name === 'password') {
                $arguments[] = '--password=*****';
            } elseif ($value === true) {
                $arguments[] = '--' . $name;
            } else {
                $arguments[] = '--' . $name . '=' . $value;
            }
        }
        return $arguments;
    }

    private static function parseCommandLine(array $arguments): array
    {
        $values = [];
        for ($position = 0; $position < count($arguments); $position++) {
            $argument = $arguments[$position];
            if (!str_starts_with($argument, '--')) {
                throw new FoxyException("Unexpected argument: {$argument}", 'INVALID_CONFIG');
            }
            $option = substr($argument, 2);
            $inlineValue = null;
            if (str_contains($option, '=')) {
                [$option, $inlineValue] = explode('=', $option, 2);
            }
            if (in_array($option, self::FLAG_OPTIONS, true)) {
                $values[$option] = $inlineValue === null ? true : self::boolean($inlineValue);
                continue;
            }
            if (!in_array($option, self::VALUE_OPTIONS, true)) {
                throw new FoxyException("Unknown option: --{$option}", 'INVALID_CONFIG');
            }
            if ($inlineValue === null && isset($arguments[$position + 1])
                && !str_starts_with($arguments[$position + 1], '--')) {
                $inlineValue = $arguments[++$position];
            }
            if ($inlineValue === null && $option !== 'password') {
                throw new FoxyException("Option --{$option} requires a value.", 'INVALID_CONFIG');
            }
            if ($option === 'password' && $inlineValue === null) {
                $values['password-prompt'] = true;
            }
            $values[$option] = $inlineValue;
        }
        return $values;
    }

    private static function readDefaultsFile(string $path, string $suffix, bool $required): array
    {
        if (!is_file($path)) {
            if ($required) {
                throw new FoxyException("Defaults file does not exist: {$path}", 'INVALID_CONFIG');
            }
            return [];
        }
        $lines = @file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new FoxyException("Unable to read defaults file: {$path}", 'INVALID_CONFIG');
        }
        $sections = [];
        $section = '';
        foreach ($lines as $number => $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                continue;
            }
            if (preg_match('/^\[([^]]+)]$/', $line, $match) === 1) {
                $section = strtolower(trim($match[1]));
                continue;
            }
            if ($section === '') {
                throw new FoxyException("Option outside a group in {$path} at line " . ($number + 1), 'INVALID_CONFIG');
            }
            $bare = !str_contains($line, '=');
            if (!$bare) {
                [$name, $value] = array_map('trim', explode('=', $line, 2));
                if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"'))
                    || ($value[0] === "'" && str_ends_with($value, "'")))) {
                    $value = substr($value, 1, -1);
                }
            } else {
                $name = $line;
                $value = true;
            }
            $name = str_replace('_', '-', strtolower($name));
            $known = in_array($name, self::VALUE_OPTIONS, true) || in_array($name, self::FLAG_OPTIONS, true);
            if ($bare && in_array($name, self::VALUE_OPTIONS, true)) {
                throw new FoxyException("Option {$name} requires a value in defaults file {$path}.", 'INVALID_CONFIG');
            }
            if (!$known && str_starts_with($section, 'foxydb_secure_installation')) {
                throw new FoxyException("Unknown option {$name} in defaults file {$path}.", 'INVALID_CONFIG');
            }
            if ($known) {
                $sections[$section][$name] = $value;
            }
        }

        $values = [];
        foreach (['client', 'foxydb_secure_installation'] as $group) {
            $names = $suffix === '' ? [$group] : [$group, $group . strtolower($suffix)];
            foreach ($names as $name) {
                if (isset($sections[$name])) {
                    $values = array_replace($values, $sections[$name]);
                }
            }
        }
        return $values;
    }

    private static function standardDefaultsFiles(string $baseDirectory): array
    {
        $paths = [$baseDirectory . DIRECTORY_SEPARATOR . 'foxydb.ini'];
        $home = getenv(PHP_OS_FAMILY === 'Windows' ? 'USERPROFILE' : 'HOME');
        if (is_string($home) && $home !== '') {
            $paths[] = $home . DIRECTORY_SEPARATOR . '.foxydb.cnf';
        }
        if (PHP_OS_FAMILY === 'Windows') {
            $appData = getenv('APPDATA');
            if (is_string($appData) && $appData !== '') {
                $paths[] = $appData . DIRECTORY_SEPARATOR . 'FoxyDB' . DIRECTORY_SEPARATOR . 'foxydb.ini';
            }
        }
        return $paths;
    }

    private static function nullable(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }

    private static function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        $parsed = filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        if ($parsed === null) {
            throw new FoxyException("Invalid boolean option value: {$value}", 'INVALID_CONFIG');
        }
        return $parsed;
    }
}
