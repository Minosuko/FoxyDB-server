<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Storage\StorageEngine;

final class InformationSchema
{
    const COLLATION = 'utf8mb4_general_ci';
    const ENGINE = 'foxydb';

    public static function columns(): array
    {
        return [
            ['name' => 'table_catalog', 'type' => 'VARCHAR', 'length' => 64],
            ['name' => 'table_schema', 'type' => 'VARCHAR', 'length' => 64],
            ['name' => 'table_name', 'type' => 'VARCHAR', 'length' => 64],
            ['name' => 'table_type', 'type' => 'VARCHAR', 'length' => 16],
            ['name' => 'engine', 'type' => 'VARCHAR', 'length' => 16],
            ['name' => 'table_collation', 'type' => 'VARCHAR', 'length' => 32],
            ['name' => 'table_rows', 'type' => 'BIGINT'],
            ['name' => 'data_length', 'type' => 'BIGINT'],
            ['name' => 'index_length', 'type' => 'BIGINT'],
            ['name' => 'column_name', 'type' => 'VARCHAR', 'length' => 64],
            ['name' => 'ordinal_position', 'type' => 'INT'],
            ['name' => 'data_type', 'type' => 'VARCHAR', 'length' => 16],
            ['name' => 'is_nullable', 'type' => 'VARCHAR', 'length' => 3],
            ['name' => 'column_default', 'type' => 'VARCHAR', 'length' => 255],
            ['name' => 'character_set_name', 'type' => 'VARCHAR', 'length' => 16],
            ['name' => 'collation_name', 'type' => 'VARCHAR', 'length' => 32],
            ['name' => 'column_key', 'type' => 'VARCHAR', 'length' => 3],
            ['name' => 'extra', 'type' => 'VARCHAR', 'length' => 32],
        ];
    }

    public static function select(StorageEngine $storage): ExecutionResult
    {
        $columns = [
            'table_catalog', 'table_schema', 'table_name', 'table_type',
            'engine', 'table_collation', 'table_rows',
            'data_length', 'index_length',
            'column_name', 'ordinal_position', 'data_type',
            'is_nullable', 'column_default', 'character_set_name',
            'collation_name', 'column_key', 'extra',
        ];
        $rows = [];
        foreach ($storage->listDatabases() as $database) {
            foreach ($storage->listTables($database) as $tableName) {
                $table = $storage->table($database, $tableName);
                $schema = $table->schema();
                $rowCount = $table->countActiveRows();
                $size = $table->estimateSize();
                foreach ($schema['columns'] as $position => $column) {
                    $isPk = in_array($column['name'], $schema['primary_key'] ?? [], true);
                    $default = null;
                    if (isset($column['default'])) {
                        $default = $column['default']['kind'] === 'literal'
                            ? $column['default']['value']
                            : $column['default']['kind'];
                    }
                    $rows[] = [
                        'table_catalog' => 'def',
                        'table_schema' => $database,
                        'table_name' => $tableName,
                        'table_type' => 'BASE TABLE',
                        'engine' => self::ENGINE,
                        'table_collation' => self::COLLATION,
                        'table_rows' => $rowCount,
                        'data_length' => $size['data_length'],
                        'index_length' => $size['index_length'],
                        'column_name' => $column['name'],
                        'ordinal_position' => $position + 1,
                        'data_type' => strtolower($column['type']),
                        'is_nullable' => $column['nullable'] ? 'YES' : 'NO',
                        'column_default' => $default,
                        'character_set_name' => 'utf8mb4',
                        'collation_name' => self::COLLATION,
                        'column_key' => $isPk ? 'PRI' : '',
                        'extra' => ($column['auto_increment'] ?? false) ? 'auto_increment' : '',
                    ];
                }
            }
        }
        return ExecutionResult::rows($columns, $rows);
    }
}
