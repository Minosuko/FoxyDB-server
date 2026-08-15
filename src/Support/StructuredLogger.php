<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

final class StructuredLogger
{
    private const CHANNEL_FILES = [
        'general' => 'general.log',
        'error' => 'error.log',
        'audit' => 'audit.log',
        'slow' => 'slow.log',
    ];
    private const MAX_CONTEXT_STRING_BYTES = 16_384;

    public function __construct(
        private readonly string $directory,
        private readonly int $maximumBytes,
        private readonly int $maximumArchives,
        private bool $enabled = true,
    ) {
        if ($directory === '' || $maximumBytes < 1_024 || $maximumArchives < 1) {
            throw new FoxyException('Invalid structured logging configuration.', 'INVALID_CONFIG');
        }
        FileSystem::ensureDirectory($directory);
        foreach (self::CHANNEL_FILES as $file) {
            $path = $directory . DIRECTORY_SEPARATOR . $file;
            self::assertRegularPath($path);
            $stream = @fopen($path, 'ab');
            if ($stream === false) {
                throw new FoxyException("Unable to initialize log file {$file}.", 'LOG_IO');
            }
            fclose($stream);
            self::secureFile($path);
        }
    }

    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }

    public function general(string $event, array $context = [], string $level = 'INFO'): void
    {
        $this->write('general', $level, $event, $context);
    }

    public function error(string $event, array $context = []): void
    {
        $this->write('error', 'ERROR', $event, $context);
    }

    public function audit(string $event, array $context = [], string $level = 'INFO'): void
    {
        $this->write('audit', $level, $event, $context);
    }

    public function slow(string $event, array $context = []): void
    {
        $this->write('slow', 'WARNING', $event, $context);
    }

    public function query(array $context, bool $succeeded, bool $slow): void
    {
        $sanitized = self::redactContext($context);
        $level = $succeeded ? 'INFO' : 'WARNING';
        $this->writeSanitized('general', $level, 'query.executed', $sanitized);
        $this->writeSanitized('audit', $level, 'query.executed', $sanitized);
        if ($slow) {
            $this->writeSanitized('slow', 'WARNING', 'query.slow', $sanitized);
        }
    }

    public static function redactSql(string $sql): string
    {
        $sql = substr($sql, 0, 65_536);
        $length = strlen($sql);
        $redacted = '';
        for ($index = 0; $index < $length;) {
            $character = $sql[$index];
            $next = $index + 1 < $length ? $sql[$index + 1] : '';
            if (($character === '-' && $next === '-') || $character === '#') {
                $end = strcspn($sql, "\r\n", $index);
                $redacted .= '/* comment redacted */';
                $index += $end;
                continue;
            }
            if ($character === '/' && $next === '*') {
                $end = strpos($sql, '*/', $index + 2);
                $redacted .= '/* comment redacted */';
                $index = $end === false ? $length : $end + 2;
                continue;
            }
            if ($character === "'" || $character === '"') {
                $quote = $character;
                $redacted .= $quote . '[REDACTED]' . $quote;
                $index++;
                while ($index < $length) {
                    if ($sql[$index] === '\\') {
                        $index = min($length, $index + 2);
                        continue;
                    }
                    if ($sql[$index] === $quote) {
                        if ($index + 1 < $length && $sql[$index + 1] === $quote) {
                            $index += 2;
                            continue;
                        }
                        $index++;
                        break;
                    }
                    $index++;
                }
                continue;
            }
            $redacted .= $character;
            $index++;
        }
        $redacted = preg_replace(
            '/\b(password(?:_hash)?|secret|token|credential|authorization)\b(\s*=\s*)[^\s,;)]+/i',
            '$1$2[REDACTED]',
            $redacted,
        ) ?? $redacted;
        return self::truncate(trim($redacted));
    }

    private function write(string $channel, string $level, string $event, array $context): void
    {
        $this->writeSanitized($channel, $level, $event, self::redactContext($context));
    }

    private function writeSanitized(string $channel, string $level, string $event, array $context): void
    {
        if (!$this->enabled) {
            return;
        }
        try {
            $entry = [
                'timestamp' => (new \DateTimeImmutable('now'))->format('Y-m-d\TH:i:s.uP'),
                'channel' => $channel,
                'level' => strtoupper($level),
                'event' => $event,
                'pid' => getmypid(),
                'context' => $context,
            ];
            $line = json_encode(
                $entry,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
            ) . "\n";
            if (strlen($line) > $this->maximumBytes) {
                $entry['context'] = ['truncated' => true];
                $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
            }
            $this->append($channel, $line);
        } catch (\Throwable $exception) {
            error_log('FoxyDB logging failure: ' . $exception->getMessage());
        }
    }

    private function append(string $channel, string $line): void
    {
        $path = $this->directory . DIRECTORY_SEPARATOR . self::CHANNEL_FILES[$channel];
        $lockPath = $path . '.lock';
        self::assertRegularPath($path);
        self::assertRegularPath($lockPath);
        $lock = @fopen($lockPath, 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new FoxyException('Unable to acquire the log lock.', 'LOG_IO');
        }
        try {
            self::secureFile($lockPath);
            clearstatcache(true, $path);
            $size = is_file($path) ? filesize($path) : 0;
            if ($size === false) {
                throw new FoxyException('Unable to inspect the log file.', 'LOG_IO');
            }
            if ($size > 0 && $size + strlen($line) > $this->maximumBytes) {
                $this->rotate($path);
            }
            $stream = @fopen($path, 'ab');
            if ($stream === false) {
                throw new FoxyException('Unable to open the log file.', 'LOG_IO');
            }
            try {
                self::secureFile($path);
                FileSystem::writeAll($stream, $line);
                if (!fflush($stream)) {
                    throw new FoxyException('Unable to flush the log file.', 'LOG_IO');
                }
            } finally {
                fclose($stream);
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function rotate(string $path): void
    {
        $oldest = $path . '.' . $this->maximumArchives;
        if (is_file($oldest) && !@unlink($oldest)) {
            throw new FoxyException('Unable to remove the oldest rotated log.', 'LOG_IO');
        }
        for ($index = $this->maximumArchives - 1; $index >= 1; $index--) {
            $source = $path . '.' . $index;
            if (is_file($source) && !@rename($source, $path . '.' . ($index + 1))) {
                throw new FoxyException('Unable to rotate a log archive.', 'LOG_IO');
            }
        }
        if (is_file($path) && !@rename($path, $path . '.1')) {
            throw new FoxyException('Unable to rotate the active log.', 'LOG_IO');
        }
    }

    private static function redactContext(mixed $value, ?string $key = null, int $depth = 0): mixed
    {
        if ($key !== null && preg_match(
            '/password|passwd|secret|token|credential|authorization|cookie|private[_-]?key/i',
            $key,
        ) === 1) {
            return '[REDACTED]';
        }
        if ($depth > 16) {
            return '[TRUNCATED]';
        }
        if (is_array($value)) {
            $redacted = [];
            $count = 0;
            foreach ($value as $itemKey => $item) {
                if ($count++ >= 256) {
                    $redacted['truncated'] = true;
                    break;
                }
                $redacted[$itemKey] = self::redactContext($item, (string) $itemKey, $depth + 1);
            }
            return $redacted;
        }
        if (is_string($value)) {
            return $key !== null && in_array(strtolower($key), ['sql', 'query'], true)
                ? self::redactSql($value)
                : self::truncate($value);
        }
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        return get_debug_type($value);
    }

    private static function truncate(string $value): string
    {
        return strlen($value) <= self::MAX_CONTEXT_STRING_BYTES
            ? $value
            : substr($value, 0, self::MAX_CONTEXT_STRING_BYTES) . '...[truncated]';
    }

    private static function assertRegularPath(string $path): void
    {
        if (is_link($path) || (file_exists($path) && !is_file($path))) {
            throw new FoxyException('Log paths must be regular files.', 'LOG_IO');
        }
    }

    private static function secureFile(string $path): void
    {
        if (DIRECTORY_SEPARATOR !== '/') {
            return;
        }
        if (!@chmod($path, 0600)) {
            throw new FoxyException('Unable to secure log file permissions.', 'LOG_IO');
        }
        clearstatcache(true, $path);
        $permissions = fileperms($path);
        if ($permissions === false || ($permissions & 0777) !== 0600) {
            throw new FoxyException('Log file permissions are not owner-only.', 'LOG_IO');
        }
    }
}
