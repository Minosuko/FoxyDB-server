<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;

final class SecureInstallation
{
    public function __construct(private readonly SecureInstallationOptions $options)
    {
    }

    public function run(): void
    {
        $protocol = $this->options->get('protocol');
        if ($protocol === 'SOCKET') {
            throw new FoxyException(
                'SOCKET protocol is not available for this TCP daemon. Use TCP or TLS.',
                'UNSUPPORTED_PROTOCOL',
            );
        }
        $tlsOptions = $this->options->tlsOptions();
        if (in_array(strtoupper($tlsOptions->mode), ['DISABLED', 'PREFERRED'], true)) {
            throw new FoxyException('Secure installation requires ssl-mode REQUIRED or stronger.', 'TLS_REQUIRED');
        }
        $password = $this->options->get('password');
        if ($password === null) {
            $password = $this->options->get('use-default') && !$this->options->get('password-prompt', false)
                ? 'root'
                : $this->promptSecret('Enter current FoxyDB password: ');
        }
        $host = (string) $this->options->get('host');
        $port = (int) $this->options->get('port');
        $username = Authentication::normalizeUsername((string) $this->options->get('user'));
        $client = Client::connect(
            host: $host,
            port: $port,
            username: $username,
            password: (string) $password,
            tlsOptions: $tlsOptions,
            interactive: true,
        );

        try {
            $tls = $client->tlsInfo();
            if ($tls === []) {
                throw new FoxyException('Secure installation requires a TLS connection.', 'TLS_REQUIRED');
            }
            echo 'Connected with ' . ($tls['protocol'] ?? 'TLS') . ' using '
                . ($tls['cipher_name'] ?? 'unknown cipher') . ".\n";
            $client->query('USE foxydb');
            $generatedPassword = null;
            $pendingPassword = null;
            if ($this->options->get('use-default')) {
                $generatedPassword = self::generatePassword();
                $pendingPassword = $generatedPassword;
                $this->removeOrphanPrivileges($client);
                $this->removeTestDatabase($client);
            } else {
                if ($this->confirm('Change the password for this account?', true)) {
                    $pendingPassword = $this->promptNewPassword();
                }
                if ($this->confirm('Remove privileges for deleted accounts?', true)) {
                    $this->removeOrphanPrivileges($client);
                }
                if ($this->confirm('Remove the test database?', true)) {
                    $this->removeTestDatabase($client);
                }
            }

            $this->setSystemValue($client, 'tls_required', 'true', 'All FoxyDB network sessions require TLS.');
            $this->setSystemValue(
                $client,
                'tls_certificate_sha256',
                (string) ($tls['certificate_sha256'] ?? ''),
                'SHA-256 fingerprint seen during secure installation.',
            );
            if ($generatedPassword !== null) {
                $secretOutput = "Generated password for {$username}: {$generatedPassword}\n"
                    . "Store this password securely. FoxyDB does not write it to configuration or environment variables.\n";
                $written = fwrite(STDOUT, $secretOutput);
                if ($written !== strlen($secretOutput) || !fflush(STDOUT)) {
                    throw new FoxyException('Unable to deliver the generated password safely.', 'CONSOLE_IO');
                }
            }
            if ($pendingPassword !== null) {
                $this->setPassword($client, $username, $pendingPassword);
            }
            $this->setSystemValue(
                $client,
                'secure_installation_completed',
                (new \DateTimeImmutable('now'))->format(DATE_ATOM),
                'Last successful secure installation timestamp.',
            );
            echo "Applied FoxyDB secure installation settings.\n";
            echo "FoxyDB secure installation completed successfully.\n";
        } finally {
            $client->close();
        }
    }

    private function setPassword(Client $client, string $username, string $password): void
    {
        if (strlen($password) < 12 || strlen($password) > 72) {
            throw new FoxyException('New password must contain from 12 to 72 bytes.', 'INVALID_PASSWORD');
        }
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        if ($hash === false) {
            throw new FoxyException('Unable to hash the new password.', 'AUTH_CONFIG');
        }
        $result = $client->query(
            'UPDATE users_schema SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
            [$hash, $username],
        );
        if ($result->affectedRows !== 1) {
            throw new FoxyException('Authenticated account was not found in users_schema.', 'AUTH_FAILED');
        }
    }

    private function removeOrphanPrivileges(Client $client): void
    {
        $users = $client->query('SELECT account_id FROM users_schema');
        $accounts = [];
        foreach ($users->rows as $row) {
            $accounts[$row['account_id']] = true;
        }
        $privileges = $client->query('SELECT id, account_id FROM privileges');
        foreach ($privileges->rows as $row) {
            if (!isset($accounts[$row['account_id']])) {
                $client->query('DELETE FROM privileges WHERE id = ?', [$row['id']]);
            }
        }
    }

    private function removeTestDatabase(Client $client): void
    {
        $privileges = $client->query("SELECT id FROM privileges WHERE database_name = 'test'");
        foreach ($privileges->rows as $row) {
            $client->query('DELETE FROM privileges WHERE id = ?', [$row['id']]);
        }
        $client->query('DROP DATABASE IF EXISTS test');
    }

    private function setSystemValue(Client $client, string $name, string $value, string $description): void
    {
        $existing = $client->query('SELECT variable_name FROM sys_config WHERE variable_name = ?', [$name]);
        $found = false;
        foreach ($existing->rows as $_row) {
            $found = true;
            break;
        }
        if ($found) {
            $client->query(
                'UPDATE sys_config SET variable_value = ?, description = ?, updated_at = CURRENT_TIMESTAMP '
                . 'WHERE variable_name = ?',
                [$value, $description, $name],
            );
            return;
        }
        $client->query(
            'INSERT INTO sys_config (variable_name, variable_value, description) VALUES (?, ?, ?)',
            [$name, $value, $description],
        );
    }

    private function promptNewPassword(): string
    {
        while (true) {
            $password = $this->promptSecret('Enter new password: ');
            if (strlen($password) < 12 || strlen($password) > 72) {
                echo "Password must contain from 12 to 72 bytes.\n";
                continue;
            }
            $confirmation = $this->promptSecret('Repeat new password: ');
            if (!hash_equals($password, $confirmation)) {
                echo "Passwords do not match.\n";
                continue;
            }
            return $password;
        }
    }

    private function promptSecret(string $prompt): string
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return $this->promptSecretWindows($prompt);
        }
        fwrite(STDOUT, $prompt);
        if (!function_exists('shell_exec')) {
            throw new FoxyException('Cannot disable terminal echo for password input.', 'CONSOLE_IO');
        }
        $stty = trim((string) @shell_exec('stty -g'));
        if ($stty === '') {
            throw new FoxyException('Cannot disable terminal echo for password input.', 'CONSOLE_IO');
        }
        @shell_exec('stty -echo');
        try {
            $value = fgets(STDIN);
        } finally {
            @shell_exec('stty ' . escapeshellarg($stty));
            fwrite(STDOUT, "\n");
        }
        if ($value === false) {
            throw new FoxyException('Unable to read password from the terminal.', 'CONSOLE_IO');
        }
        return rtrim($value, "\r\n");
    }

    private function promptSecretWindows(string $prompt): string
    {
        $escapedPrompt = str_replace("'", "''", $prompt);
        $script = '$secure = Read-Host -AsSecureString -Prompt \'' . $escapedPrompt . '\'; '
            . '$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure); '
            . 'try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) } '
            . 'finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }';
        $process = proc_open(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-Command', $script],
            [0 => STDIN, 1 => ['pipe', 'w'], 2 => STDERR],
            $pipes,
            null,
            null,
            ['bypass_shell' => true],
        );
        if (!is_resource($process)) {
            throw new FoxyException('Unable to launch hidden password prompt.', 'CONSOLE_IO');
        }
        $value = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $exitCode = proc_close($process);
        if ($exitCode !== 0 || $value === false) {
            throw new FoxyException('Unable to read hidden password.', 'CONSOLE_IO');
        }
        return rtrim($value, "\r\n");
    }

    private function confirm(string $question, bool $default): bool
    {
        $suffix = $default ? ' [Y/n] ' : ' [y/N] ';
        fwrite(STDOUT, $question . $suffix);
        $answer = fgets(STDIN);
        if ($answer === false) {
            throw new FoxyException('Unable to read terminal response.', 'CONSOLE_IO');
        }
        $answer = strtolower(trim($answer));
        if ($answer === '') {
            return $default;
        }
        return in_array($answer, ['y', 'yes'], true);
    }

    private static function generatePassword(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    }
}
