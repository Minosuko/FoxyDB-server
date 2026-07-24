<?php

declare(strict_types=1);

namespace FoxyDB;

use DateTimeImmutable;
use DateTimeZone;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;
use FoxyDB\Value\StreamValue;

final class TypeSystem
{
    private const TYPES = [
        'INT', 'VARCHAR', 'BIGINT', 'LONGTEXT', 'TEXT', 'BINARY', 'BLOB', 'TIMESTAMP',
        'DATETIME', 'FLOAT', 'DOUBLE', 'BOOLEAN', 'REAL', 'TINYINT', 'UUID',
    ];
    private const MAXIMUM_COLUMNS = 1_024;
    private const MAXIMUM_INDEX_KEY_BYTES = 4_096;

    public function __construct(private readonly Config $config)
    {
    }

    public function compileSchema(string $tableName, array $definition): array
    {
        $columns = [];
        foreach ($definition['columns'] ?? [] as $column) {
            $name = self::identifier((string) ($column['name'] ?? ''));
            if (isset($columns[$name])) {
                throw new FoxyException("Duplicate column: {$name}", 'SCHEMA_ERROR');
            }
            $type = strtoupper((string) ($column['type'] ?? ''));
            if (!in_array($type, self::TYPES, true)) {
                throw new FoxyException("Unsupported data type: {$type}", 'SCHEMA_ERROR');
            }
            $length = isset($column['length']) ? (int) $column['length'] : null;
            if (in_array($type, ['VARCHAR', 'BINARY'], true)) {
                $length ??= $type === 'VARCHAR' ? 255 : null;
                if ($length === null || $length < 1 || $length > 65_535) {
                    throw new FoxyException("{$type} requires a length from 1 to 65535.", 'SCHEMA_ERROR');
                }
            } elseif ($length !== null) {
                throw new FoxyException("{$type} does not accept a length.", 'SCHEMA_ERROR');
            }

            $compiled = [
                'name' => $name,
                'type' => $type,
                'length' => $length,
                'nullable' => (bool) ($column['nullable'] ?? true),
                'auto_increment' => (bool) ($column['auto_increment'] ?? false),
            ];
            if (array_key_exists('default', $column)) {
                $compiled['default'] = $this->compileDefault($column['default'], $compiled);
            }
            $columns[$name] = $compiled;
        }
        if ($columns === []) {
            throw new FoxyException('A table requires at least one column.', 'SCHEMA_ERROR');
        }
        if (count($columns) > self::MAXIMUM_COLUMNS) {
            throw new FoxyException('A table cannot have more than 1024 columns.', 'SCHEMA_ERROR');
        }

        $constraints = $definition['constraints'] ?? [];
        foreach ($definition['columns'] as $column) {
            $name = self::identifier($column['name']);
            if (($column['primary'] ?? false) === true) {
                $constraints[] = ['kind' => 'primary', 'columns' => [$name], 'name' => 'primary'];
            }
            if (($column['unique'] ?? false) === true) {
                $constraints[] = ['kind' => 'unique', 'columns' => [$name], 'name' => null];
            }
            if (($column['index'] ?? false) === true) {
                $constraints[] = ['kind' => 'index', 'columns' => [$name], 'name' => null];
            }
        }

        $indexes = [];
        $primaryColumns = [];
        foreach ($constraints as $constraint) {
            $kind = strtolower((string) ($constraint['kind'] ?? ''));
            if (!in_array($kind, ['primary', 'unique', 'index'], true)) {
                throw new FoxyException('Invalid table constraint.', 'SCHEMA_ERROR');
            }
            $indexColumns = array_map([self::class, 'identifier'], $constraint['columns'] ?? []);
            if ($indexColumns === [] || count(array_unique($indexColumns)) !== count($indexColumns)) {
                throw new FoxyException('An index requires distinct columns.', 'SCHEMA_ERROR');
            }
            foreach ($indexColumns as $columnName) {
                if (!isset($columns[$columnName])) {
                    throw new FoxyException("Unknown indexed column: {$columnName}", 'SCHEMA_ERROR');
                }
                if (in_array($columns[$columnName]['type'], ['TEXT', 'LONGTEXT', 'BLOB'], true)) {
                    throw new FoxyException(
                        "Column {$columnName} uses a type that cannot be indexed.",
                        'SCHEMA_ERROR',
                    );
                }
            }
            if ($kind === 'primary') {
                if ($primaryColumns !== []) {
                    throw new FoxyException('Only one primary key is allowed.', 'SCHEMA_ERROR');
                }
                $primaryColumns = $indexColumns;
                foreach ($indexColumns as $columnName) {
                    $columns[$columnName]['nullable'] = false;
                }
                $name = 'primary';
            } else {
                $name = isset($constraint['name']) && $constraint['name'] !== null
                    ? self::identifier((string) $constraint['name'])
                    : $this->generatedIndexName($kind, $indexColumns, $indexes);
            }
            if (isset($indexes[$name])) {
                $existing = $indexes[$name];
                if ($existing['columns'] === $indexColumns
                    && $existing['primary'] === ($kind === 'primary')
                    && $existing['unique'] === ($kind !== 'index')) {
                    continue;
                }
                throw new FoxyException("Duplicate index: {$name}", 'SCHEMA_ERROR');
            }
            $indexes[$name] = [
                'name' => $name,
                'columns' => $indexColumns,
                'unique' => $kind !== 'index',
                'primary' => $kind === 'primary',
            ];
            $this->assertIndexWidth($indexes[$name], $columns);
        }

        $autoColumn = null;
        foreach ($columns as $name => $column) {
            if (!$column['auto_increment']) {
                continue;
            }
            if ($autoColumn !== null) {
                throw new FoxyException('Only one AUTO_INCREMENT column is allowed.', 'SCHEMA_ERROR');
            }
            if (!in_array($column['type'], ['TINYINT', 'INT', 'BIGINT'], true)) {
                throw new FoxyException('AUTO_INCREMENT requires an integer column.', 'SCHEMA_ERROR');
            }
            $isKey = false;
            foreach ($indexes as $index) {
                if ($index['unique'] && $index['columns'] === [$name]) {
                    $isKey = true;
                    break;
                }
            }
            if (!$isKey) {
                throw new FoxyException('AUTO_INCREMENT must be a single-column primary or unique key.', 'SCHEMA_ERROR');
            }
            $columns[$name]['nullable'] = false;
            $autoColumn = $name;
        }

        return [
            'format' => 1,
            'table_id' => bin2hex(random_bytes(16)),
            'name' => self::identifier($tableName),
            'active_generation' => 1,
            'columns' => array_values($columns),
            'primary_key' => $primaryColumns,
            'auto_increment_column' => $autoColumn,
            'indexes' => $indexes,
        ];
    }

    public function compileColumn(array $column, array $existingSchema): void
    {
        $name = self::identifier((string) ($column['name'] ?? ''));
        $type = strtoupper((string) ($column['type'] ?? ''));
        if (!in_array($type, self::TYPES, true)) {
            throw new FoxyException("Unsupported data type: {$type}", 'SCHEMA_ERROR');
        }
        $length = isset($column['length']) ? (int) $column['length'] : null;
        if (in_array($type, ['VARCHAR', 'BINARY'], true)) {
            $length ??= $type === 'VARCHAR' ? 255 : null;
            if ($length === null || $length < 1 || $length > 65_535) {
                throw new FoxyException("{$type} requires a length from 1 to 65535.", 'SCHEMA_ERROR');
            }
        } elseif ($length !== null) {
            throw new FoxyException("{$type} does not accept a length.", 'SCHEMA_ERROR');
        }
        $autoIncrement = (bool) ($column['auto_increment'] ?? false);
        if ($autoIncrement) {
            $hasExistingAuto = false;
            foreach ($existingSchema['columns'] as $existing) {
                if (($existing['auto_increment'] ?? false) === true) {
                    $hasExistingAuto = true;
                    break;
                }
            }
            if ($hasExistingAuto) {
                throw new FoxyException('Only one AUTO_INCREMENT column is allowed.', 'SCHEMA_ERROR');
            }
            if (!in_array($type, ['TINYINT', 'INT', 'BIGINT'], true)) {
                throw new FoxyException('AUTO_INCREMENT requires an integer column.', 'SCHEMA_ERROR');
            }
        }
        if (array_key_exists('default', $column)) {
            $this->compileDefault($column['default'], [
                'name' => $name, 'type' => $type, 'length' => $length, 'nullable' => true,
            ]);
        }
    }

    public function validateIndex(array $index, array $schema): void
    {
        $columns = $index['columns'];
        if ($columns === [] || count(array_unique($columns)) !== count($columns)) {
            throw new FoxyException('An index requires distinct columns.', 'SCHEMA_ERROR');
        }
        $columnMap = [];
        foreach ($schema['columns'] as $column) {
            $columnMap[$column['name']] = $column;
        }
        foreach ($columns as $colName) {
            if (!isset($columnMap[$colName])) {
                throw new FoxyException("Unknown indexed column: {$colName}", 'SCHEMA_ERROR');
            }
            if (in_array($columnMap[$colName]['type'], ['TEXT', 'LONGTEXT', 'BLOB'], true)) {
                throw new FoxyException("Column {$colName} cannot be indexed.", 'SCHEMA_ERROR');
            }
        }
        if (($index['primary'] ?? false) === true) {
            if ($schema['primary_key'] !== [] && $schema['primary_key'] !== $columns) {
                throw new FoxyException('Only one primary key is allowed.', 'SCHEMA_ERROR');
            }
        }
        $this->assertIndexWidth($index, $columnMap);
    }

    public function prepareInsert(array $input, array $schema, int $nextAuto): array
    {
        $input = array_change_key_case($input, CASE_LOWER);
        $known = array_column($schema['columns'], 'name');
        foreach (array_keys($input) as $name) {
            if (!in_array($name, $known, true)) {
                throw new FoxyException("Unknown column: {$name}", 'UNKNOWN_COLUMN');
            }
        }

        $row = [];
        foreach ($schema['columns'] as $column) {
            $name = $column['name'];
            if (array_key_exists($name, $input)) {
                if ($input[$name] !== null) {
                    $row[$name] = $this->coerce($input[$name], $column);
                } elseif ($column['auto_increment']) {
                    $row[$name] = $this->coerce($nextAuto, $column);
                } elseif ($column['nullable']) {
                    $row[$name] = null;
                } else {
                    throw new FoxyException("Column {$name} cannot be null.", 'NOT_NULL_VIOLATION');
                }
            } elseif ($column['auto_increment']) {
                $row[$name] = $this->coerce($nextAuto, $column);
            } elseif (array_key_exists('default', $column)) {
                $row[$name] = $this->evaluateDefault($column['default'], $column);
            } elseif ($column['nullable']) {
                $row[$name] = null;
            } else {
                throw new FoxyException("Column {$name} cannot be null.", 'NOT_NULL_VIOLATION');
            }
        }
        return $row;
    }

    public function prepareUpdate(array $row, array $assignments, array $schema): array
    {
        $columns = [];
        foreach ($schema['columns'] as $column) {
            $columns[$column['name']] = $column;
        }
        foreach ($assignments as $name => $value) {
            $name = self::identifier((string) $name);
            if (!isset($columns[$name])) {
                throw new FoxyException("Unknown column: {$name}", 'UNKNOWN_COLUMN');
            }
            if ($value === null) {
                if (!$columns[$name]['nullable']) {
                    throw new FoxyException("Column {$name} cannot be null.", 'NOT_NULL_VIOLATION');
                }
                $row[$name] = null;
            } else {
                $row[$name] = $this->coerce($value, $columns[$name]);
            }
        }
        return $row;
    }

    public function coerce(mixed $value, array $column): mixed
    {
        if ($value === null) {
            if (!$column['nullable']) {
                throw new FoxyException("Column {$column['name']} cannot be null.", 'NOT_NULL_VIOLATION');
            }
            return null;
        }
        $type = $column['type'];
        return match ($type) {
            'TINYINT' => $this->integer($value, -128, 127, $column['name']),
            'INT' => $this->integer($value, -2_147_483_648, 2_147_483_647, $column['name']),
            'BIGINT' => $this->integer($value, PHP_INT_MIN, PHP_INT_MAX, $column['name']),
            'FLOAT' => $this->floating($value, true, $column['name']),
            'DOUBLE', 'REAL' => $this->floating($value, false, $column['name']),
            'BOOLEAN' => $this->boolean($value, $column['name']),
            'VARCHAR' => $this->varchar($value, $column),
            'TEXT' => $this->text($value, 65_535, $column['name'], true),
            'LONGTEXT' => $this->text($value, 4_294_967_295, $column['name'], true),
            'BINARY' => $this->binary($value, $column['length'], $column['name'], true),
            'BLOB' => $this->binary($value, 4_294_967_295, $column['name'], false),
            'TIMESTAMP' => $this->timestamp($value, true, $column['name']),
            'DATETIME' => $this->timestamp($value, false, $column['name']),
            'UUID' => $this->uuid($value, $column['name']),
            default => throw new FoxyException("Unsupported data type: {$type}", 'SCHEMA_ERROR'),
        };
    }

    public function materialize(mixed $value): mixed
    {
        if ($value instanceof ChunkedValue) {
            $bytes = $value->materialize($this->config->maxMaterializedBytes);
            return $value->format === 'binary' ? new BinaryValue($bytes) : $bytes;
        }
        if ($value instanceof StreamValue) {
            if ($value->bytes > $this->config->maxMaterializedBytes) {
                throw new FoxyException('Stream exceeds the materialization limit.', 'RESOURCE_LIMIT');
            }
            $stream = $value->open();
            try {
                $bytes = \FoxyDB\Support\FileSystem::readExact($stream, $value->bytes) ?? '';
                if (fread($stream, 1) !== '') {
                    throw new FoxyException('Stream contains more bytes than declared.', 'INVALID_VALUE');
                }
            } finally {
                fclose($stream);
            }
            if ($value->format === 'utf8') {
                if (!mb_check_encoding($bytes, 'UTF-8')) {
                    throw new FoxyException('Text stream is not valid UTF-8.', 'INVALID_VALUE');
                }
                return $bytes;
            }
            return new BinaryValue($bytes);
        }
        return $value;
    }

    public function compare(mixed $left, mixed $right): int
    {
        $left = $this->materialize($left);
        $right = $this->materialize($right);
        if ($left instanceof BinaryValue) {
            $left = $left->bytes;
        }
        if ($right instanceof BinaryValue) {
            $right = $right->bytes;
        }
        if (is_string($left) && is_string($right)) {
            return strcmp($left, $right);
        }
        return $left <=> $right;
    }

    public static function identifier(string $name): string
    {
        $name = strtolower($name);
        if (preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $name) !== 1) {
            throw new FoxyException("Invalid identifier: {$name}", 'INVALID_IDENTIFIER');
        }
        return $name;
    }

    private function compileDefault(mixed $default, array $column): array
    {
        if (is_array($default) && isset($default['expression'])) {
            $expression = strtolower((string) $default['expression']);
            if ($expression === 'current_timestamp' && in_array($column['type'], ['TIMESTAMP', 'DATETIME'], true)) {
                return ['kind' => 'current_timestamp'];
            }
            if ($expression === 'uuid' && $column['type'] === 'UUID') {
                return ['kind' => 'uuid'];
            }
            throw new FoxyException('Default expression does not match the column type.', 'SCHEMA_ERROR');
        }
        if ($default === null) {
            if (!$column['nullable']) {
                throw new FoxyException('A non-null column cannot default to null.', 'SCHEMA_ERROR');
            }
            return ['kind' => 'literal', 'value' => null];
        }
        $value = $this->coerce($default, $column);
        if ($value instanceof StreamValue || $value instanceof ChunkedValue) {
            throw new FoxyException('Streamed defaults are not supported.', 'SCHEMA_ERROR');
        }
        if ($value instanceof BinaryValue) {
            return ['kind' => 'binary', 'value' => base64_encode($value->bytes)];
        }
        return ['kind' => 'literal', 'value' => $value];
    }

    private function evaluateDefault(array $default, array $column): mixed
    {
        return match ($default['kind']) {
            'literal' => $default['value'],
            'binary' => $this->binaryDefault($default),
            'current_timestamp' => $this->timestamp('now', $column['type'] === 'TIMESTAMP', $column['name']),
            'uuid' => self::generateUuid(),
            default => throw new FoxyException('Invalid default value metadata.', 'STORAGE_CORRUPT'),
        };
    }

    private function generatedIndexName(string $kind, array $columns, array $existing): string
    {
        $base = ($kind === 'unique' ? 'uq_' : 'idx_') . implode('_', $columns);
        $name = substr($base, 0, 64);
        $counter = 2;
        while (isset($existing[$name])) {
            $suffix = '_' . $counter++;
            $name = substr($base, 0, 64 - strlen($suffix)) . $suffix;
        }
        return $name;
    }

    private function assertIndexWidth(array $index, array $columns): void
    {
        $maximum = 0;
        foreach ($index['columns'] as $name) {
            $column = $columns[$name];
            $valueBytes = match ($column['type']) {
                'TINYINT' => 4,
                'INT' => 11,
                'BIGINT' => 20,
                'FLOAT', 'DOUBLE', 'REAL' => 8,
                'BOOLEAN' => 1,
                'UUID' => 36,
                'TIMESTAMP', 'DATETIME' => 26,
                'BINARY' => $column['length'],
                'VARCHAR' => $column['length'] * 4,
                default => self::MAXIMUM_INDEX_KEY_BYTES + 1,
            };
            $maximum += 5 + $valueBytes;
        }
        if ($maximum > self::MAXIMUM_INDEX_KEY_BYTES) {
            throw new FoxyException(
                "Index {$index['name']} can exceed the 4096-byte key limit.",
                'SCHEMA_ERROR',
            );
        }
    }

    private function binaryDefault(array $default): BinaryValue
    {
        $decoded = base64_decode((string) ($default['value'] ?? ''), true);
        if ($decoded === false) {
            throw new FoxyException('Invalid binary default metadata.', 'STORAGE_CORRUPT');
        }
        return new BinaryValue($decoded);
    }

    private function integer(mixed $value, int $minimum, int $maximum, string $name): int
    {
        if (is_int($value)) {
            $integer = $value;
        } elseif (is_string($value) && preg_match('/^[+-]?\d+$/', $value) === 1) {
            $validated = filter_var($value, FILTER_VALIDATE_INT);
            if ($validated === false) {
                throw new FoxyException("Value for {$name} is outside the integer range.", 'INVALID_VALUE');
            }
            $integer = (int) $validated;
        } else {
            throw new FoxyException("Value for {$name} must be an integer.", 'INVALID_VALUE');
        }
        if ($integer < $minimum || $integer > $maximum) {
            throw new FoxyException("Value for {$name} is outside the allowed range.", 'INVALID_VALUE');
        }
        return $integer;
    }

    private function floating(mixed $value, bool $singlePrecision, string $name): float
    {
        if ((!is_int($value) && !is_float($value) && !is_string($value)) || !is_numeric($value)) {
            throw new FoxyException("Value for {$name} must be numeric.", 'INVALID_VALUE');
        }
        $float = (float) $value;
        if (!is_finite($float)) {
            throw new FoxyException("Value for {$name} must be finite.", 'INVALID_VALUE');
        }
        if ($singlePrecision) {
            $float = unpack('Gvalue', pack('G', $float))['value'];
            if (!is_finite($float)) {
                throw new FoxyException("Value for {$name} exceeds FLOAT range.", 'INVALID_VALUE');
            }
        }
        return $float;
    }

    private function boolean(mixed $value, string $name): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 1 || $value === 0 || $value === '1' || $value === '0') {
            return (bool) $value;
        }
        if (is_string($value) && in_array(strtolower($value), ['true', 'false'], true)) {
            return strtolower($value) === 'true';
        }
        throw new FoxyException("Value for {$name} must be boolean.", 'INVALID_VALUE');
    }

    private function varchar(mixed $value, array $column): string
    {
        if (!is_string($value) || !mb_check_encoding($value, 'UTF-8')) {
            throw new FoxyException("Value for {$column['name']} must be valid UTF-8 text.", 'INVALID_VALUE');
        }
        if (mb_strlen($value, 'UTF-8') > $column['length']) {
            throw new FoxyException("Value for {$column['name']} exceeds VARCHAR length.", 'INVALID_VALUE');
        }
        return $value;
    }

    private function text(mixed $value, int $maximum, string $name, bool $streamAllowed): string|StreamValue
    {
        if ($value instanceof StreamValue && $streamAllowed) {
            if ($value->format !== 'utf8' || $value->bytes > $maximum) {
                throw new FoxyException("Stream for {$name} is invalid or too large.", 'INVALID_VALUE');
            }
            return $value;
        }
        if (!is_string($value) || !mb_check_encoding($value, 'UTF-8')) {
            throw new FoxyException("Value for {$name} must be valid UTF-8 text.", 'INVALID_VALUE');
        }
        if (strlen($value) > $maximum) {
            throw new FoxyException("Value for {$name} is too large.", 'INVALID_VALUE');
        }
        return $value;
    }

    private function binary(mixed $value, int $maximum, string $name, bool $fixed): BinaryValue|StreamValue
    {
        if ($value instanceof StreamValue) {
            if ($value->format !== 'binary' || $value->bytes > $maximum || ($fixed && $value->bytes !== $maximum)) {
                throw new FoxyException("Stream for {$name} is invalid or too large.", 'INVALID_VALUE');
            }
            return $value;
        }
        if (is_string($value)) {
            $value = new BinaryValue($value);
        }
        if (!$value instanceof BinaryValue) {
            throw new FoxyException("Value for {$name} must be binary.", 'INVALID_VALUE');
        }
        $length = strlen($value->bytes);
        if ($length > $maximum) {
            throw new FoxyException("Value for {$name} is too large.", 'INVALID_VALUE');
        }
        if ($fixed && $length < $maximum) {
            return new BinaryValue(str_pad($value->bytes, $maximum, "\0"));
        }
        return $value;
    }

    private function timestamp(mixed $value, bool $withTimezone, string $name): string
    {
        if (!$value instanceof DateTimeImmutable && !is_string($value) && !is_int($value)) {
            throw new FoxyException("Value for {$name} must be a date and time.", 'INVALID_VALUE');
        }
        try {
            if ($value instanceof DateTimeImmutable) {
                $date = $value;
            } elseif (is_int($value)) {
                $date = (new DateTimeImmutable('@' . $value))->setTimezone(new DateTimeZone('UTC'));
            } elseif (!$withTimezone && preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/', $value) === 1) {
                $normalized = str_replace('T', ' ', $value);
                if (!str_contains($normalized, '.')) {
                    $normalized .= '.000000';
                } else {
                    [$whole, $fraction] = explode('.', $normalized, 2);
                    $normalized = $whole . '.' . str_pad($fraction, 6, '0');
                }
                $date = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s.u', $normalized);
                $errors = DateTimeImmutable::getLastErrors();
                if ($date === false || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))) {
                    throw new \RuntimeException('Invalid date');
                }
            } else {
                $date = new DateTimeImmutable((string) $value, new DateTimeZone('UTC'));
            }
        } catch (\Throwable $exception) {
            throw new FoxyException("Value for {$name} is not a valid date and time.", 'INVALID_VALUE', [], $exception);
        }
        if ($withTimezone) {
            $date = $date->setTimezone(new DateTimeZone('UTC'));
        }
        return $date->format('Y-m-d H:i:s.u');
    }

    private function uuid(mixed $value, string $name): string
    {
        if (!is_string($value)
            || preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/', $value) !== 1) {
            throw new FoxyException("Value for {$name} is not a valid UUID.", 'INVALID_VALUE');
        }
        return strtolower($value);
    }

    private static function generateUuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
            . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }
}
