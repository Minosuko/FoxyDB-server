<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Value\BinaryValue;

/**
 * Capture journal and canonical statement builders for replication.
 *
 * The journal is an append-only table in the FoxyDB system schema. Statements
 * are replayed against a follower in log order; every emitted statement is
 * idempotent so that crash recovery or concurrent consumers never diverge the
 * replica.
 */
final class Replication
{
    public const LOG_TABLE = 'replication_log';

    /** Skip journaling for system-internal databases and tables. */
    public static function applicable(string $database, string $table): bool
    {
        if ($database === Authentication::SYSTEM_DATABASE) {
            return false;
        }
        if ($table === self::LOG_TABLE) {
            return false;
        }
        return true;
    }

    /** Column list that identifies a row uniquely; falls back to the whole row. */
    public static function keyColumns(array $schema): array
    {
        foreach ($schema['indexes'] as $index) {
            if (($index['primary'] ?? false) === true) {
                return $index['columns'];
            }
        }
        return array_column($schema['columns'], 'name');
    }

    public static function identifier(string $name): string
    {
        return '`' . str_replace('`', '``', $name) . '`';
    }

    public static function literal(mixed $value): string
    {
        if ($value === null) {
            return 'NULL';
        }
        if (is_bool($value)) {
            return $value ? 'TRUE' : 'FALSE';
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }
        if ($value instanceof BinaryValue) {
            return self::quoteString($value->bytes);
        }
        return self::quoteString((string) $value);
    }

    /** Quote so the SQL lexer restores the exact bytes. */
    public static function quoteString(string $value): string
    {
        return "'" . str_replace(['\\', "'"], ['\\\\', "''"], $value) . "'";
    }

    private static function keyColumnsSql(array $columns): string
    {
        return '(' . implode(', ', array_map([self::class, 'identifier'], $columns)) . ')';
    }

    private static function keyTuplesSql(array $columns, array $keys): string
    {
        $parts = [];
        foreach ($keys as $key) {
            $values = [];
            foreach ($columns as $column) {
                $values[] = self::literal($key[$column] ?? null);
            }
            $parts[] = '(' . implode(', ', $values) . ')';
        }
        return implode(', ', $parts);
    }

    /** Generated a command that inserts the given rows. */
    public static function insertSql(string $database, string $table, array $columns, array $rows): string
    {
        $valueSets = [];
        foreach ($rows as $row) {
            $values = [];
            foreach ($columns as $column) {
                $values[] = self::literal($row[$column] ?? null);
            }
            $valueSets[] = '(' . implode(', ', $values) . ')';
        }
        $columnList = implode(', ', array_map([self::class, 'identifier'], $columns));
        return sprintf(
            'INSERT INTO %s.%s (%s) VALUES %s',
            self::identifier($database),
            self::identifier($table),
            $columnList,
            implode(', ', $valueSets),
        );
    }

    /**
     * One row-bearing change for a table without a primary key; the whole row
     * is matched with equality and IS NULL so a replay is exact.
     */
    public static function updateOneSql(string $database, string $table, array $assignments, array $row): string
    {
        $sets = [];
        foreach ($assignments as $column => $value) {
            $sets[] = self::identifier($column) . ' = ' . self::literal($value);
        }
        return sprintf(
            'UPDATE %s.%s SET %s WHERE %s',
            self::identifier($database),
            self::identifier($table),
            implode(', ', $sets),
            self::rowPredicateSql($row),
        );
    }

    public static function deleteOneSql(string $database, string $table, array $row): string
    {
        return sprintf(
            'DELETE FROM %s.%s WHERE %s',
            self::identifier($database),
            self::identifier($table),
            self::rowPredicateSql($row),
        );
    }

    public static function updateKeysSql(string $database, string $table, array $assignments, array $keyColumns, array $keys): string
    {
        $sets = [];
        foreach ($assignments as $column => $value) {
            $sets[] = self::identifier($column) . ' = ' . self::literal($value);
        }
        $setsSql = implode(', ', $sets);
        $prefix = sprintf('UPDATE %s.%s SET %s WHERE ', self::identifier($database), self::identifier($table), $setsSql);
        if (count($keyColumns) === 1) {
            $column = self::identifier($keyColumns[0]);
            $values = implode(', ', array_map(static fn(array $row): string => self::literal($row[$keyColumns[0]] ?? null), $keys));
            return $prefix . $column . ' IN (' . $values . ')';
        }
        $clauses = [];
        foreach ($keys as $key) {
            $equals = [];
            foreach ($keyColumns as $column) {
                $equals[] = self::identifier($column) . ' = ' . self::literal($key[$column] ?? null);
            }
            $clauses[] = '(' . implode(' AND ', $equals) . ')';
        }
        return $prefix . implode(' OR ', $clauses);
    }

    public static function deleteKeysSql(string $database, string $table, array $keyColumns, array $keys): string
    {
        $prefix = sprintf('DELETE FROM %s.%s WHERE ', self::identifier($database), self::identifier($table));
        if (count($keyColumns) === 1) {
            $column = self::identifier($keyColumns[0]);
            $values = implode(', ', array_map(static fn(array $row): string => self::literal($row[$keyColumns[0]] ?? null), $keys));
            return $prefix . $column . ' IN (' . $values . ')';
        }
        $clauses = [];
        foreach ($keys as $key) {
            $equals = [];
            foreach ($keyColumns as $column) {
                $equals[] = self::identifier($column) . ' = ' . self::literal($key[$column] ?? null);
            }
            $clauses[] = '(' . implode(' AND ', $equals) . ')';
        }
        return $prefix . implode(' OR ', $clauses);
    }

    public static function truncateSql(string $database, string $table): string
    {
        return sprintf(
            'TRUNCATE TABLE %s.%s',
            self::identifier($database),
            self::identifier($table),
        );
    }

    public static function createTableSql(string $database, string $table, array $schema): string
    {
        $parts = [];
        foreach ($schema['columns'] as $column) {
            $part = self::identifier($column['name']) . ' ' . $column['type'];
            if ($column['length'] !== null) {
                $part .= '(' . $column['length'] . ')';
            }
            if (($column['nullable'] ?? true) === false) {
                $part .= ' NOT NULL';
            }
            if (($column['auto_increment'] ?? false) === true) {
                $part .= ' AUTO_INCREMENT';
            }
            if (isset($column['default'])) {
                $part .= ' DEFAULT ' . self::defaultSql($column['default']);
            }
            $parts[] = $part;
        }
        foreach ($schema['indexes'] as $index) {
            $columns = implode(', ', array_map([self::class, 'identifier'], $index['columns']));
            if (($index['primary'] ?? false) === true) {
                $parts[] = 'PRIMARY KEY (' . $columns . ')';
                continue;
            }
            $unique = ($index['unique'] ?? false) === true ? 'UNIQUE ' : '';
            $ordered = ($index['ordered'] ?? false) === true ? ' ORDERED' : '';
            $parts[] = $unique . 'INDEX ' . self::identifier((string) $index['name']) . ' (' . $columns . ')' . $ordered;
        }
        return sprintf(
            'CREATE TABLE IF NOT EXISTS %s (%s)',
            self::identifier($table),
            implode(', ', $parts),
        );
    }

    private static function defaultSql(array $default): string
    {
        return match ($default['kind']) {
            'literal' => self::literal($default['value']),
            'binary' => self::quoteString(
                BinaryValue::fromBase64((string) ($default['value'] ?? ''))->bytes,
            ),
            'current_timestamp' => 'CURRENT_TIMESTAMP',
            'uuid' => 'UUID()',
            default => 'NULL',
        };
    }

    public static function dropTableSql(string $database, string $table): string
    {
        return sprintf(
            'DROP TABLE IF EXISTS %s.%s',
            self::identifier($database),
            self::identifier($table),
        );
    }

    public static function renameTableSql(string $database, string $table, string $newName): string
    {
        return sprintf(
            'RENAME TABLE %s.%s TO %s',
            self::identifier($database),
            self::identifier($table),
            self::identifier($newName),
        );
    }

    public static function moveTableSql(string $database, string $table, string $newDatabase, string $newName): string
    {
        return sprintf(
            'MOVE TABLE %s.%s TO %s.%s',
            self::identifier($database),
            self::identifier($table),
            self::identifier($newDatabase),
            self::identifier($newName),
        );
    }

    public static function copyTableSql(string $database, string $table, string $newDatabase, string $newName): string
    {
        return sprintf(
            'COPY TABLE %s.%s TO %s.%s',
            self::identifier($database),
            self::identifier($table),
            self::identifier($newDatabase),
            self::identifier($newName),
        );
    }

    public static function createIndexSql(string $database, string $table, array $statement): string
    {
        $unique = ($statement['unique'] ?? false) === true ? 'UNIQUE ' : '';
        $ifNotExists = ($statement['if_not_exists'] ?? false) === true ? 'IF NOT EXISTS ' : '';
        $columns = implode(', ', array_map([self::class, 'identifier'], $statement['columns']));
        $ordered = ($statement['ordered'] ?? false) === true ? ' ORDERED' : '';
        return sprintf(
            'CREATE %sINDEX %s%s ON %s (%s)%s',
            $unique,
            $ifNotExists,
            self::identifier((string) $statement['name']),
            self::identifier($table),
            $columns,
            $ordered,
        );
    }

    public static function dropIndexSql(string $database, string $table, array $statement): string
    {
        $ifExists = ($statement['if_exists'] ?? false) === true ? 'IF EXISTS ' : '';
        return sprintf(
            'DROP INDEX %s%s ON %s.%s',
            $ifExists,
            self::identifier((string) $statement['name']),
            self::identifier($database),
            self::identifier($table),
        );
    }

    public static function createDatabaseSql(string $database): string
    {
        return 'CREATE DATABASE IF NOT EXISTS ' . self::identifier($database);
    }

    public static function dropDatabaseSql(string $database): string
    {
        return 'DROP DATABASE IF EXISTS ' . self::identifier($database);
    }

    public static function useSql(string $database): string
    {
        return 'USE ' . self::identifier($database);
    }

    private static function rowPredicateSql(array $row): string
    {
        $parts = [];
        foreach ($row as $column => $value) {
            $parts[] = self::identifier((string) $column) . ($value === null ? ' IS NULL' : ' = ' . self::literal($value));
        }
        return implode(' AND ', $parts);
    }

    /** Append one change entry to the source journal. */
    public static function append(
        StorageEngine $storage,
        string $database,
        string $table,
        string $changeType,
        string $changeSql,
    ): void {
        $log = $storage->table(Authentication::SYSTEM_DATABASE, self::LOG_TABLE);
        try {
            $log->insert([
                'source_database' => $database,
                'source_table' => $table,
                'change_type' => $changeType,
                'change_sql' => $changeSql,
                'applied' => false,
            ]);
        } catch (FoxyException $exception) {
            throw new FoxyException(
                'Unable to record the replication change: ' . $exception->getMessage(),
                'REPLICATION_RECORD_FAILED',
            );
        }
    }

    /** Removes already-applied entries older than the retention window. */
    public static function prune(StorageEngine $storage, Config $config, int $now): int
    {
        if ($config->replicationRetentionHours <= 0) {
            return 0;
        }
        $log = $storage->table(Authentication::SYSTEM_DATABASE, self::LOG_TABLE);
        $threshold = $now - $config->replicationRetentionHours * 3_600;
        $lookup = $log->lookupForEqualities(['applied' => true]);
        $removed = 0;
        $rows = [];
        foreach ($log->rows($lookup) as $entry) {
            $loggedAt = strtotime((string) ($entry['values']['logged_at'] ?? ''));
            if ($loggedAt !== false && $loggedAt < $threshold) {
                $rows[] = $entry['values'];
            }
        }
        if ($rows !== []) {
            foreach (array_chunk($rows, 200) as $chunk) {
                $removed += $log->delete(
                    static fn(array $candidate): bool => in_array($candidate['log_id'], array_column($chunk, 'log_id'), true),
                    null,
                );
            }
        }
        return $removed;
    }

    /**
     * Polled reader used by the shipping CLI: returns unapplied entries in
     * strict log order.
     */
    public static function pending(
        StorageEngine $storage,
        int $maximumEntries,
    ): array {
        $log = $storage->table(Authentication::SYSTEM_DATABASE, self::LOG_TABLE);
        $lookup = $log->lookupForEqualities(['applied' => false]);
        $entries = [];
        foreach ($log->rows($lookup) as $entry) {
            $entries[] = $entry['values'];
            if (count($entries) >= $maximumEntries) {
                break;
            }
        }
        usort($entries, static fn (array $a, array $b): int => (int) $a['log_id'] <=> (int) $b['log_id']);
        return $entries;
    }
}