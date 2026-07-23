<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Storage\StorageEngine;

final class SystemVariables
{
    private const DEFINITIONS = [
        'foxydb_buffer_pool_size' => [
            'type' => 'bytes', 'default' => 67_108_864, 'min' => 0, 'max' => 17_179_869_184,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Maximum bytes retained by the decoded row buffer pool.',
        ],
        'max_heap_table_size' => [
            'type' => 'bytes', 'default' => 67_108_864, 'min' => 1_048_576, 'max' => 4_294_967_296,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Maximum bytes staged by an in-memory query operation.',
        ],
        'sort_buffer_size' => [
            'type' => 'bytes', 'default' => 2_097_152, 'min' => 32_768, 'max' => 1_073_741_824,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Per-session memory limit for ORDER BY sorting.',
        ],
        'join_buffer_size' => [
            'type' => 'bytes', 'default' => 2_097_152, 'min' => 32_768, 'max' => 1_073_741_824,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Reserved per-session memory limit for join execution.',
        ],
        'query_cache_size' => [
            'type' => 'bytes', 'default' => 16_777_216, 'min' => 0, 'max' => 4_294_967_296,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Maximum bytes retained by the process-wide SELECT result cache.',
        ],
        'tmp_table_size' => [
            'type' => 'bytes', 'default' => 67_108_864, 'min' => 1_048_576, 'max' => 4_294_967_296,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Maximum bytes allowed for an in-memory temporary result.',
        ],
        'max_allowed_packet' => [
            'type' => 'bytes', 'default' => 8_388_608, 'min' => 1_024, 'max' => FrameCodec::MAXIMUM_FRAME_BYTES,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Maximum bytes in one framed protocol packet.',
        ],
        'connect_timeout' => [
            'type' => 'integer', 'default' => 10, 'min' => 1, 'max' => 3_600,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Seconds allowed for TLS negotiation and authentication.',
        ],
        'wait_timeout' => [
            'type' => 'integer', 'default' => 300, 'min' => 1, 'max' => 31_536_000,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Idle timeout in seconds for non-interactive sessions.',
        ],
        'interactive_timeout' => [
            'type' => 'integer', 'default' => 300, 'min' => 1, 'max' => 31_536_000,
            'scope' => 'BOTH', 'dynamic' => true,
            'description' => 'Idle timeout in seconds for interactive sessions.',
        ],
        'max_connect_errors' => [
            'type' => 'integer', 'default' => 100, 'min' => 1, 'max' => 1_000_000,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Connection errors allowed per address within the blocking window.',
        ],
        'skip_name_resolve' => [
            'type' => 'boolean', 'default' => true,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Skip reverse DNS resolution for incoming peers.',
        ],
        'thread_cache_size' => [
            'type' => 'integer', 'default' => 16, 'min' => 0, 'max' => 1_024,
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Maximum reset Session objects retained by the event loop.',
        ],
        'thread_stack' => [
            'type' => 'bytes', 'default' => 1_048_576, 'min' => 131_072, 'max' => 16_777_216,
            'scope' => 'GLOBAL', 'dynamic' => false,
            'description' => 'Compatibility value for worker stack sizing; PHP owns the actual stack.',
        ],
        'thread_handling' => [
            'type' => 'enum', 'default' => 'event-loop', 'values' => ['event-loop'],
            'scope' => 'GLOBAL', 'dynamic' => false,
            'description' => 'Connection scheduling model used by this PHP server.',
        ],
        'system_time_zone' => [
            'type' => 'timezone', 'default' => 'UTC',
            'scope' => 'GLOBAL', 'dynamic' => true,
            'description' => 'Timezone used by server-side date and log formatting.',
        ],
    ];

    private array $values = [];
    private array $listeners = [];

    public function __construct(
        private readonly StorageEngine $storage,
        private readonly ?Config $config = null,
    )
    {
        $table = $storage->table(Authentication::SYSTEM_DATABASE, 'sys_config');
        foreach (self::DEFINITIONS as $name => $definition) {
            $lookup = $table->lookupForEqualities(['variable_name' => $name]);
            $stored = null;
            foreach ($table->rows($lookup) as $entry) {
                $stored = $entry['values']['variable_value'];
                break;
            }
            if ($stored === null) {
                $value = $this->normalize($name, $this->defaultValue($name, $definition['default']));
                $table->insert([
                    'variable_name' => $name,
                    'variable_value' => self::displayValue($value),
                    'description' => $definition['description'],
                ]);
            } else {
                $value = $this->normalize($name, $stored);
            }
            $this->values[$name] = $value;
        }
        date_default_timezone_set((string) $this->values['system_time_zone']);
        $this->applyCacheLimits();
        $this->onChange(function (string $name, mixed $_value): void {
            if (in_array($name, ['foxydb_buffer_pool_size', 'query_cache_size'], true)) {
                $this->applyCacheLimits();
            }
        });
    }

    public function get(string $name, array $sessionOverrides = []): int|string|bool
    {
        $name = strtolower($name);
        if (!isset(self::DEFINITIONS[$name])) {
            throw new FoxyException("Unknown system variable: {$name}", 'UNKNOWN_SYSTEM_VARIABLE');
        }
        return $sessionOverrides[$name] ?? $this->values[$name];
    }

    public static function isManaged(string $name): bool
    {
        return isset(self::DEFINITIONS[strtolower($name)]);
    }

    public function setGlobal(string $name, mixed $value): int|string|bool
    {
        $name = strtolower($name);
        $definition = self::DEFINITIONS[$name] ?? null;
        if ($definition === null) {
            throw new FoxyException("Unknown system variable: {$name}", 'UNKNOWN_SYSTEM_VARIABLE');
        }
        if (!$definition['dynamic']) {
            throw new FoxyException("System variable {$name} is read-only at runtime.", 'READ_ONLY_VARIABLE');
        }
        $normalized = $this->normalize($name, $value);
        $table = $this->storage->table(Authentication::SYSTEM_DATABASE, 'sys_config');
        $updated = $table->update(
            ['variable_value' => self::displayValue($normalized), 'updated_at' => new \DateTimeImmutable('now')],
            static fn(array $row): bool => $row['variable_name'] === $name,
            $table->lookupForEqualities(['variable_name' => $name]),
        );
        if ($updated === 0) {
            $table->insert([
                'variable_name' => $name,
                'variable_value' => self::displayValue($normalized),
                'description' => $definition['description'],
            ]);
        }
        $this->values[$name] = $normalized;
        $this->storage->invalidateQueryCache();
        if ($name === 'system_time_zone') {
            date_default_timezone_set((string) $normalized);
        }
        foreach ($this->listeners as $listener) {
            $listener($name, $normalized);
        }
        return $normalized;
    }

    public function setSession(string $name, mixed $value, array &$overrides): int|string|bool
    {
        $name = strtolower($name);
        $definition = self::DEFINITIONS[$name] ?? null;
        if ($definition === null) {
            throw new FoxyException("Unknown system variable: {$name}", 'UNKNOWN_SYSTEM_VARIABLE');
        }
        if ($definition['scope'] !== 'BOTH' || !$definition['dynamic']) {
            throw new FoxyException("System variable {$name} has global-only scope.", 'INVALID_VARIABLE_SCOPE');
        }
        return $overrides[$name] = $this->normalize($name, $value);
    }

    public function rows(string $scope, array $sessionOverrides = []): array
    {
        $rows = [];
        foreach (self::DEFINITIONS as $name => $definition) {
            $rows[] = [
                'variable_name' => $name,
                'value' => self::displayValue($scope === 'SESSION'
                    ? ($sessionOverrides[$name] ?? $this->values[$name])
                    : $this->values[$name]),
                'scope' => $definition['scope'],
                'dynamic' => $definition['dynamic'],
                'description' => $definition['description'],
            ];
        }
        return $rows;
    }

    public function onChange(callable $listener): void
    {
        $this->listeners[] = $listener;
    }

    private function normalize(string $name, mixed $value): int|string|bool
    {
        $definition = self::DEFINITIONS[$name];
        return match ($definition['type']) {
            'bytes' => $this->boundedInteger($name, self::parseBytes($value), $definition),
            'integer' => $this->boundedInteger($name, self::parseInteger($value), $definition),
            'boolean' => self::parseBoolean($name, $value),
            'enum' => self::parseEnum($name, $value, $definition['values']),
            'timezone' => self::parseTimezone($value),
            default => throw new FoxyException("Invalid definition for {$name}.", 'INVALID_SYSTEM_VARIABLE'),
        };
    }

    private function boundedInteger(string $name, int $value, array $definition): int
    {
        if ($value < $definition['min'] || $value > $definition['max']) {
            throw new FoxyException(
                "System variable {$name} must be from {$definition['min']} to {$definition['max']}.",
                'INVALID_SYSTEM_VARIABLE',
            );
        }
        return $value;
    }

    private static function parseBytes(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value) || preg_match('/^([0-9]+)\s*([KMGT])?(?:B)?$/i', trim($value), $match) !== 1) {
            throw new FoxyException('Byte-size variable requires an integer or K, M, G, T suffix.', 'INVALID_SYSTEM_VARIABLE');
        }
        $base = filter_var($match[1], FILTER_VALIDATE_INT);
        if ($base === false) {
            throw new FoxyException('Byte-size variable exceeds the integer range.', 'INVALID_SYSTEM_VARIABLE');
        }
        $multiplier = match (strtoupper($match[2] ?? '')) {
            'K' => 1_024,
            'M' => 1_048_576,
            'G' => 1_073_741_824,
            'T' => 1_099_511_627_776,
            default => 1,
        };
        if ($base > intdiv(PHP_INT_MAX, $multiplier)) {
            throw new FoxyException('Byte-size variable exceeds the integer range.', 'INVALID_SYSTEM_VARIABLE');
        }
        return $base * $multiplier;
    }

    private static function parseInteger(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value) || preg_match('/^[0-9]+$/', $value) !== 1) {
            throw new FoxyException('Integer system variable has an invalid value.', 'INVALID_SYSTEM_VARIABLE');
        }
        $parsed = filter_var($value, FILTER_VALIDATE_INT);
        if ($parsed === false) {
            throw new FoxyException('Integer system variable exceeds the platform range.', 'INVALID_SYSTEM_VARIABLE');
        }
        return (int) $parsed;
    }

    private static function parseBoolean(string $name, mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 1 || $value === '1' || (is_string($value) && in_array(strtoupper($value), ['ON', 'TRUE'], true))) {
            return true;
        }
        if ($value === 0 || $value === '0' || (is_string($value) && in_array(strtoupper($value), ['OFF', 'FALSE'], true))) {
            return false;
        }
        throw new FoxyException("Boolean system variable {$name} requires ON or OFF.", 'INVALID_SYSTEM_VARIABLE');
    }

    private static function parseEnum(string $name, mixed $value, array $allowed): string
    {
        $value = strtolower((string) $value);
        if (!in_array($value, $allowed, true)) {
            throw new FoxyException("System variable {$name} does not support value {$value}.", 'INVALID_SYSTEM_VARIABLE');
        }
        return $value;
    }

    private static function parseTimezone(mixed $value): string
    {
        $value = (string) $value;
        if (!in_array($value, timezone_identifiers_list(), true)) {
            throw new FoxyException("Unknown system timezone: {$value}", 'INVALID_SYSTEM_VARIABLE');
        }
        return $value;
    }

    private static function displayValue(int|string|bool $value): string
    {
        return is_bool($value) ? ($value ? 'ON' : 'OFF') : (string) $value;
    }

    private function applyCacheLimits(): void
    {
        $this->storage->configureCaches(
            (int) $this->values['foxydb_buffer_pool_size'],
            (int) $this->values['query_cache_size'],
        );
    }

    private function defaultValue(string $name, int|string|bool $default): int|string|bool
    {
        if ($this->config === null) {
            return $default;
        }
        return match ($name) {
            'max_allowed_packet' => $this->config->maxFrameBytes,
            'max_heap_table_size', 'tmp_table_size' => $this->config->maxMaterializedBytes,
            'wait_timeout', 'interactive_timeout' => $this->config->idleTimeoutSeconds,
            default => $default,
        };
    }
}
