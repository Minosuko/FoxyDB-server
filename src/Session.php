<?php

declare(strict_types=1);

namespace FoxyDB;

use DateTimeImmutable;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Sql\Parser;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Storage\Table;
use FoxyDB\Support\MemoryCache;
use FoxyDB\Value\BinaryValue;

final class Session
{
    private readonly Parser $parser;
    private readonly TypeSystem $types;
    private ?string $currentDatabase = null;
    private ?string $username = null;
    private ?string $accountId = null;
    private array $sessionVariables = [];
    private bool $inTransaction = false;
    private array $txnUndo = [];

    public function __construct(
        private readonly StorageEngine $storage,
        private readonly Config $config,
        private readonly ?Authentication $authentication = null,
        private readonly ?SystemVariables $systemVariables = null,
    ) {
        $this->parser = new Parser();
        $this->types = new TypeSystem($config);
    }

    public function currentDatabase(): ?string
    {
        return $this->currentDatabase;
    }

    public function variable(string $name, int|string|bool $fallback): int|string|bool
    {
        return $this->systemValue($name, $fallback);
    }

    public function authenticateAs(string $username, string $accountId): void
    {
        $this->username = Authentication::normalizeUsername($username);
        $this->accountId = strtolower($accountId);
        $this->currentDatabase = Authentication::SYSTEM_DATABASE;
    }

    public function execute(string $sql, array $parameters = []): ExecutionResult
    {
        $statement = $this->parser->parse($sql);
        $this->authorize($statement);
        for ($index = 0; $index < $statement['parameter_count']; $index++) {
            if (!array_key_exists($index, $parameters)) {
                throw new FoxyException("Missing positional parameter {$index}.", 'MISSING_PARAMETER');
            }
        }

        $result = $this->handleVirtualTable($statement);
        if ($result !== null) {
            return $result;
        }

        $cacheKey = $statement['type'] === 'select' ? $this->queryCacheKey($statement, $sql, $parameters) : null;
        if ($cacheKey !== null) {
            $cached = $this->storage->queryCacheGet($cacheKey);
            if (is_array($cached)) {
                return ExecutionResult::rows($cached['columns'], $cached['rows'], $cached['metadata']);
            }
        }

        $result = match ($statement['type']) {
            'create_database' => $this->createDatabase($statement),
            'drop_database' => $this->dropDatabase($statement),
            'use' => $this->useDatabase($statement),
            'show_databases' => $this->showDatabases(),
            'show_tables' => $this->showTables($statement),
            'show_variables' => $this->showVariables($statement, $parameters),
            'set_variable' => $this->setVariable($statement, $parameters),
            'create_table' => $this->createTable($statement),
            'drop_table' => $this->dropTable($statement),
            'describe' => $this->describe($statement),
            'show_indexes' => $this->showIndexes($statement),
            'create_index' => $this->createIndex($statement),
            'drop_index' => $this->dropIndex($statement),
            'insert' => $this->insert($statement, $parameters),
            'select' => $this->select($statement, $parameters),
            'update' => $this->update($statement, $parameters),
            'delete' => $this->delete($statement, $parameters),
            'truncate' => $this->truncate($statement),
            'compact' => $this->compact($statement),
            'optimize' => $this->compact($statement),
            'defragment' => $this->compact($statement),
            'alter_table' => $this->alterTable($statement),
            'rename_table' => $this->renameTable($statement),
            'move_table' => $this->moveTable($statement),
            'copy_table' => $this->copyTable($statement),
            'analyze' => $this->analyzeTable($statement),
            'check' => $this->checkTable($statement),
            'checksum' => $this->checksumTable($statement),
            'flush' => $this->flushTable($statement),
            'create_role' => $this->createRole($statement),
            'drop_role' => $this->dropRole($statement),
            'grant' => $this->grantStmt($statement),
            'revoke' => $this->revokeStmt($statement),
            'create_policy' => $this->createPolicy($statement),
            'drop_policy' => $this->dropPolicy($statement),
            'begin' => $this->beginTransaction(),
            'commit' => $this->commitTransaction(),
            'rollback' => $this->rollbackTransaction(),
            default => throw new FoxyException('Unsupported parsed statement.', 'SQL_UNSUPPORTED'),
        };
        return $cacheKey === null ? $result : $this->cacheResult($cacheKey, $result);
    }

    private function createDatabase(array $statement): ExecutionResult
    {
        $this->storage->createDatabase($statement['database'], $statement['if_not_exists']);
        return ExecutionResult::command(metadata: ['database' => $statement['database']]);
    }

    private function dropDatabase(array $statement): ExecutionResult
    {
        $this->storage->dropDatabase($statement['database'], $statement['if_exists']);
        if ($this->currentDatabase === $statement['database']) {
            $this->currentDatabase = null;
        }
        return ExecutionResult::command();
    }

    private function useDatabase(array $statement): ExecutionResult
    {
        if (!$this->storage->databaseExists($statement['database'])) {
            throw new FoxyException("Database {$statement['database']} does not exist.", 'DATABASE_NOT_FOUND');
        }
        $this->currentDatabase = $statement['database'];
        return ExecutionResult::command(metadata: ['database' => $this->currentDatabase]);
    }

    private function showDatabases(): ExecutionResult
    {
        $rows = array_map(static fn(string $name): array => ['database' => $name], $this->storage->listDatabases());
        return ExecutionResult::rows(['database'], $rows);
    }

    private function showTables(array $statement): ExecutionResult
    {
        $database = $statement['database'] ?? $this->requireDatabase();
        $tables = $this->storage->listTables($database);
        if ($database === Authentication::SYSTEM_DATABASE) {
            $virtual = ['information_schema', 'sys'];
            foreach ($virtual as $name) {
                if (!in_array($name, $tables, true)) {
                    $tables[] = $name;
                }
            }
            sort($tables, SORT_STRING);
        }
        $rows = array_map(static fn(string $name): array => ['table' => $name], $tables);
        return ExecutionResult::rows(['table'], $rows, ['database' => $database]);
    }

    private function showVariables(array $statement, array $parameters): ExecutionResult
    {
        if ($this->systemVariables === null) {
            throw new FoxyException('System variables are unavailable in this embedded session.', 'SYSTEM_VARIABLES_UNAVAILABLE');
        }
        $rows = $this->systemVariables->rows($statement['scope'], $this->sessionVariables);
        if ($statement['pattern'] !== null) {
            $pattern = $this->value($statement['pattern'], $parameters);
            if (!is_string($pattern)) {
                throw new FoxyException('SHOW VARIABLES LIKE requires a text pattern.', 'INVALID_VALUE');
            }
            $regex = $this->likePattern($pattern);
            $rows = array_values(array_filter(
                $rows,
                static fn(array $row): bool => preg_match($regex, $row['variable_name']) === 1,
            ));
        }
        return ExecutionResult::rows(
            ['variable_name', 'value', 'scope', 'dynamic', 'description'],
            $rows,
            ['requested_scope' => $statement['scope']],
        );
    }

    private function setVariable(array $statement, array $parameters): ExecutionResult
    {
        if ($this->systemVariables === null) {
            throw new FoxyException('System variables are unavailable in this embedded session.', 'SYSTEM_VARIABLES_UNAVAILABLE');
        }
        $value = $this->value($statement['value'], $parameters);
        $normalized = $statement['scope'] === 'GLOBAL'
            ? $this->systemVariables->setGlobal($statement['name'], $value)
            : $this->systemVariables->setSession($statement['name'], $value, $this->sessionVariables);
        return ExecutionResult::command(metadata: [
            'scope' => $statement['scope'],
            'variable_name' => $statement['name'],
            'value' => is_bool($normalized) ? ($normalized ? 'ON' : 'OFF') : (string) $normalized,
        ]);
    }

    private function createTable(array $statement): ExecutionResult
    {
        $database = $this->requireDatabase();
        $schema = $this->types->compileSchema($statement['table'], $statement['definition']);
        $this->storage->createTable(
            $database,
            $statement['table'],
            $schema,
            $statement['if_not_exists'],
        );
        return ExecutionResult::command(metadata: ['table' => $statement['table']]);
    }

    private function dropTable(array $statement): ExecutionResult
    {
        $this->storage->dropTable(
            $this->requireDatabase(),
            $statement['table'],
            $statement['if_exists'],
        );
        return ExecutionResult::command();
    }

    private function describe(array $statement): ExecutionResult
    {
        $schema = $this->table($statement['table'])->schema();
        $rows = [];
        foreach ($schema['columns'] as $column) {
            $keys = [];
            foreach ($schema['indexes'] as $index) {
                if (!in_array($column['name'], $index['columns'], true)) {
                    continue;
                }
                if ($index['primary']) {
                    $keys[] = 'PRI';
                } elseif ($index['unique']) {
                    $keys[] = 'UNI';
                } else {
                    $keys[] = 'MUL';
                }
            }
            $default = null;
            if (isset($column['default'])) {
                $default = match ($column['default']['kind']) {
                    'literal' => $column['default']['value'],
                    'binary' => BinaryValue::fromBase64($column['default']['value']),
                    'current_timestamp' => 'CURRENT_TIMESTAMP',
                    'uuid' => 'UUID()',
                    default => null,
                };
            }
            $rows[] = [
                'column' => $column['name'],
                'type' => $column['type'] . ($column['length'] === null ? '' : '(' . $column['length'] . ')'),
                'nullable' => $column['nullable'],
                'key' => implode(',', array_unique($keys)),
                'default' => $default,
                'auto_increment' => $column['auto_increment'],
            ];
        }
        return ExecutionResult::rows(
            ['column', 'type', 'nullable', 'key', 'default', 'auto_increment'],
            $rows,
        );
    }

    private function showIndexes(array $statement): ExecutionResult
    {
        $schema = $this->table($statement['table'])->schema();
        $rows = [];
        foreach ($schema['indexes'] as $index) {
            foreach ($index['columns'] as $sequence => $column) {
                $rows[] = [
                    'index' => $index['name'],
                    'column' => $column,
                    'sequence' => $sequence + 1,
                    'unique' => $index['unique'],
                    'primary' => $index['primary'],
                ];
            }
        }
        return ExecutionResult::rows(['index', 'column', 'sequence', 'unique', 'primary'], $rows);
    }

    private function createIndex(array $statement): ExecutionResult
    {
        $this->table($statement['table'])->createIndex(
            $statement['name'],
            $statement['columns'],
            $statement['unique'],
            $statement['if_not_exists'],
        );
        return ExecutionResult::command();
    }

    private function dropIndex(array $statement): ExecutionResult
    {
        $this->table($statement['table'])->dropIndex($statement['name'], $statement['if_exists']);
        return ExecutionResult::command();
    }

    private function insert(array $statement, array $parameters): ExecutionResult
    {
        $table = $this->table($statement['table']);
        $schema = $table->schema();
        $columns = $statement['columns'];
        if ($columns === null) {
            $columns = array_column($schema['columns'], 'name');
        }
        if (count($columns) !== count(array_unique($columns))) {
            throw new FoxyException('An INSERT column is listed more than once.', 'SQL_SEMANTIC');
        }
        $known = array_column($schema['columns'], 'name');
        foreach ($columns as $column) {
            if (!in_array($column, $known, true)) {
                throw new FoxyException("Unknown column: {$column}", 'UNKNOWN_COLUMN');
            }
        }
        foreach ($statement['rows'] as $nodes) {
            if (count($nodes) !== count($columns)) {
                throw new FoxyException('INSERT column and value counts do not match.', 'SQL_SEMANTIC');
            }
        }

        $inputs = [];
        $inputBytes = 0;
        $memoryLimit = $this->mutationMemoryLimit();
        foreach ($statement['rows'] as $nodes) {
            $input = [];
            foreach ($nodes as $position => $node) {
                if ($node['kind'] !== 'default') {
                    $input[$columns[$position]] = $this->value($node, $parameters);
                }
            }
            if ($this->isSystemConfigTable($statement['table'])
                && is_string($input['variable_name'] ?? null)
                && SystemVariables::isManaged($input['variable_name'])) {
                throw new FoxyException(
                    'Managed system variables must be changed with SET GLOBAL.',
                    'SYSTEM_VARIABLE_PROTECTED',
                );
            }
            $inputBytes += MemoryCache::estimateBytes($input);
            if ($inputBytes > $memoryLimit) {
                throw new FoxyException('INSERT exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
            }
            $inputs[] = $input;
        }
        if ($this->inTransaction) {
            $table->setUndoCallback(function (int $rowId, ?string $oldSlotBytes, ?array $oldRow, ?array $newRow) use ($table): void {
                $this->txnUndo[] = [
                    'table' => $table, 'row_id' => $rowId,
                    'old_slot_bytes' => $oldSlotBytes, 'old_row' => $oldRow, 'new_row' => $newRow,
                ];
            });
        }
        try {
            $insertedRows = $table->insertMany($inputs, max(0, $memoryLimit - $inputBytes));
        } finally {
            if ($this->inTransaction) {
                $table->setUndoCallback(null);
            }
        }
        $lastInsertId = null;
        foreach ($insertedRows as $inserted) {
            $lastInsertId = $inserted['last_insert_id'] ?? $lastInsertId;
        }
        return ExecutionResult::command(count($insertedRows), $lastInsertId);
    }

    private function select(array $statement, array $parameters): ExecutionResult
    {
        $this->enforcePolicies('SELECT', $statement);
        $from = $statement['from'] ?? [];
        $hasJoin = count($from) > 1 || (count($from) === 1 && array_key_exists('join', $from[0]));
        if ($hasJoin) {
            return $this->selectJoin($from, $statement, $parameters);
        }
        $table = $this->table($statement['table'] ?? $from[0]['table']);
        $schema = $table->schema();
        $columns = $this->columnMap($schema);
        $predicate = $this->predicate($statement['where'], $columns, $parameters);
        $lookup = $this->lookup($table, $statement['where'], $columns, $parameters, $schema);
        $limit = $this->nonNegativeInteger($statement['limit'], $parameters, 'LIMIT');
        $offset = $this->nonNegativeInteger($statement['offset'], $parameters, 'OFFSET') ?? 0;

        $projections = $statement['projections'];
        if ($projections[0]['kind'] === 'all') {
            $projections = array_map(
                static fn(array $column): array => [
                    'kind' => 'column',
                    'column' => $column['name'],
                    'alias' => $column['name'],
                ],
                $schema['columns'],
            );
        }
$groupColumns = $statement['group'] ?? [];
        $hasGroup = $groupColumns !== [];

        $countProjection = false;
        $aliases = [];
        foreach ($projections as $projection) {
            if ($projection['kind'] === 'column') {
                if ($hasGroup && !in_array($projection['column'], $groupColumns, true)) {
                    throw new FoxyException(
                        "Column {$projection['column']} must appear in GROUP BY.", 'SQL_SEMANTIC',
                    );
                }
                if (!$hasGroup && !isset($columns[$projection['column']])) {
                    throw new FoxyException("Unknown column: {$projection['column']}", 'UNKNOWN_COLUMN');
                }
            } elseif (!$hasGroup && $projection['kind'] === 'count') {
                $countProjection = true;
            }
            if (isset($aliases[$projection['alias']])) {
                throw new FoxyException("Duplicate result column: {$projection['alias']}", 'SQL_SEMANTIC');
            }
            $aliases[$projection['alias']] = true;
        }
        if (!$hasGroup && $countProjection && count($projections) !== 1) {
            throw new FoxyException('COUNT(*) cannot be mixed with non-aggregate columns.', 'SQL_SEMANTIC');
        }
        if (!$hasGroup) {
            foreach ($statement['order'] as $order) {
                if (!isset($columns[$order['column']])) {
                    throw new FoxyException("Unknown ORDER BY column: {$order['column']}", 'UNKNOWN_COLUMN');
                }
            }
        }

        $resultColumns = array_column($projections, 'alias');
        $hasAggregate = !$hasGroup && array_any($projections, static fn(array $p): bool =>
            in_array($p['kind'], ['count', 'sum', 'avg', 'min', 'max'], true)
        );
        if ($hasGroup || $hasAggregate) {
            $rowsIter = (function () use ($table, $lookup, $predicate): \Generator {
                foreach ($table->rows($lookup) as $entry) {
                    $row = $entry['values'];
                    if ($predicate === null || $predicate($row)) {
                        yield $row;
                    }
                }
            })();
            return $this->executeGroupBy(
                $rowsIter, $groupColumns, $projections, $columns,
                $statement['having'] ?? null, $statement['order'], $limit, $offset,
            );
        }

        if ($limit === 0) {
            return ExecutionResult::rows($resultColumns, []);
        }
        if ($countProjection) {
            if ($statement['order'] !== []) {
                throw new FoxyException('ORDER BY is not supported with COUNT(*).', 'SQL_SEMANTIC');
            }
            if ($predicate === null) {
                $count = $table->countActiveRows();
            } else {
                $count = 0;
                foreach ($table->rows($lookup) as $entry) {
                    if ($predicate($entry['values'])) {
                        $count++;
                    }
                }
            }
            $rows = ($offset > 0 || $limit === 0) ? [] : [[$projections[0]['alias'] => $count]];
            return ExecutionResult::rows($resultColumns, $rows);
        }

        if ($statement['order'] !== []) {
            $matching = [];
            $sortBytes = 0;
            $sortLimit = min(
                (int) $this->systemValue('sort_buffer_size', 2_097_152),
                (int) $this->systemValue('max_heap_table_size', 67_108_864),
                (int) $this->systemValue('tmp_table_size', 67_108_864),
            );
            foreach ($table->rows($lookup) as $entry) {
                if ($predicate !== null && !$predicate($entry['values'])) {
                    continue;
                }
                $matching[] = $entry['values'];
                $sortBytes += MemoryCache::estimateBytes($entry['values']);
                if ($sortBytes > $sortLimit) {
                    throw new FoxyException('ORDER BY exceeded the configured sort memory limit.', 'RESOURCE_LIMIT');
                }
                if (count($matching) > $this->config->maxRowsPerResult) {
                    throw new FoxyException('ORDER BY exceeded the configured in-memory row limit.', 'RESOURCE_LIMIT');
                }
            }
            $orders = $statement['order'];
            usort($matching, function (array $left, array $right) use ($orders): int {
                foreach ($orders as $order) {
                    $leftValue = $left[$order['column']];
                    $rightValue = $right[$order['column']];
                    if ($leftValue === null || $rightValue === null) {
                        $comparison = $leftValue === $rightValue ? 0 : ($leftValue === null ? -1 : 1);
                    } else {
                        $comparison = $this->types->compare($leftValue, $rightValue);
                    }
                    if ($comparison !== 0) {
                        return $order['direction'] === 'desc' ? -$comparison : $comparison;
                    }
                }
                return 0;
            });
            $matching = array_slice($matching, $offset, $limit);
            $rows = array_map(fn(array $row): array => $this->project($row, $projections), $matching);
            return ExecutionResult::rows($resultColumns, $rows);
        }

        $maximumRows = $this->config->maxRowsPerResult;
        $rows = (function () use ($table, $lookup, $predicate, $offset, $limit, $projections, $maximumRows): \Generator {
            $skipped = 0;
            $produced = 0;
            foreach ($table->rows($lookup) as $entry) {
                $row = $entry['values'];
                if ($predicate !== null && !$predicate($row)) {
                    continue;
                }
                if ($skipped < $offset) {
                    $skipped++;
                    continue;
                }
                if ($limit !== null && $produced >= $limit) {
                    break;
                }
                if ($produced >= $maximumRows) {
                    throw new FoxyException('Result exceeded the configured row limit.', 'RESOURCE_LIMIT');
                }
                $produced++;
                yield $this->project($row, $projections);
            }
        })();
        return ExecutionResult::rows($resultColumns, $rows);
    }

    private function selectJoin(array $from, array $statement, array $parameters): ExecutionResult
    {
        $tables = [];
        $schemas = [];
        $columnMaps = [];
        $aliases = [];
        foreach ($from as $i => $entry) {
            $table = $this->table($entry['table']);
            $schema = $table->schema();
            $tables[] = $table;
            $schemas[] = $schema;
            $columnMaps[] = $this->columnMap($schema);
            $aliases[$i] = $entry['alias'] ?? $this->tableName($entry['table']);
        }
        $limit = $this->nonNegativeInteger($statement['limit'], $parameters, 'LIMIT');
        $offset = $this->nonNegativeInteger($statement['offset'], $parameters, 'OFFSET') ?? 0;
        $maximumRows = $this->config->maxRowsPerResult;

        $projections = $statement['projections'];
        if ($projections[0]['kind'] === 'all') {
            $projections = [];
            foreach ($from as $i => $entry) {
                $prefix = $entry['alias'] ?? $this->tableName($entry['table']);
                foreach ($schemas[$i]['columns'] as $column) {
                    $projections[] = [
                        'kind' => 'column',
                        'column' => $prefix . '.' . $column['name'],
                        'alias' => $prefix . '.' . $column['name'],
                    ];
                }
            }
        }

        $countProjection = false;
        $projAliasesCheck = [];
        foreach ($projections as $projection) {
            if ($projection['kind'] === 'count') {
                $countProjection = true;
            }
            if (isset($projAliasesCheck[$projection['alias']])) {
                throw new FoxyException("Duplicate result column: {$projection['alias']}", 'SQL_SEMANTIC');
            }
            $projAliasesCheck[$projection['alias']] = true;
        }
        if ($countProjection && count($projections) !== 1) {
            throw new FoxyException('COUNT(*) cannot be mixed with non-aggregate columns.', 'SQL_SEMANTIC');
        }
        $resultColumns = array_column($projections, 'alias');

        if ($limit === 0) {
            return ExecutionResult::rows($resultColumns, []);
        }

        $groupColumns = $statement['group'] ?? [];
        $hasGroup = $groupColumns !== [];
        if ($hasGroup) {
            foreach ($projections as $proj) {
                $aggKinds = ['count', 'sum', 'avg', 'min', 'max'];
                if (!in_array($proj['kind'], $aggKinds, true) && $proj['kind'] !== 'column') {
                    throw new FoxyException('Unsupported projection with GROUP BY.', 'SQL_SEMANTIC');
                }
                if ($proj['kind'] === 'column' && !in_array($proj['column'], $groupColumns, true)) {
                    throw new FoxyException(
                        "Column {$proj['column']} must appear in GROUP BY.", 'SQL_SEMANTIC',
                    );
                }
            }
        }

        $onPredicates = [];
        $joinTypes = [0 => 'inner'];
        foreach ($from as $i => $entry) {
            $joinTypes[$i] = $entry['join'] ?? ($i === 0 ? 'inner' : 'cross');
            if (isset($entry['on'])) {
                $onPredicates[$i] = $this->joinPredicate($entry['on'], $columnMaps, $aliases, $parameters);
            }
        }

        $wherePredicate = $this->joinPredicate($statement['where'] ?? null, $columnMaps, $aliases, $parameters);

        if ($hasGroup) {
            $mergedColumns = [];
            foreach ($columnMaps as $i => $map) {
                $prefix = $aliases[$i];
                foreach ($map as $name => $col) {
                    $mergedColumns[$prefix . '.' . $name] = $col;
                    $mergedColumns[$name] = $col;
                }
            }
            $rowsIter = (function () use ($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, $wherePredicate): \Generator {
                foreach ($this->joinIterator($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, null, null) as $row) {
                    if ($wherePredicate === null || $wherePredicate($row)) {
                        yield $row;
                    }
                }
            })();
            return $this->executeGroupBy(
                $rowsIter, $groupColumns, $projections, $mergedColumns,
                $statement['having'] ?? null, $statement['order'], $limit, $offset,
            );
        }

        $shouldSort = $statement['order'] !== [];
        if ($shouldSort) {
            $sortBytes = 0;
            $sortLimit = min(
                (int) $this->systemValue('sort_buffer_size', 2_097_152),
                (int) $this->systemValue('max_heap_table_size', 67_108_864),
                (int) $this->systemValue('tmp_table_size', 67_108_864),
            );
            $matching = [];
            $iter = $this->joinIterator($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, null, null);
            foreach ($iter as $row) {
                if ($wherePredicate !== null && !$wherePredicate($row)) {
                    continue;
                }
                $matching[] = $row;
                $sortBytes += MemoryCache::estimateBytes($row);
                if ($sortBytes > $sortLimit) {
                    throw new FoxyException('ORDER BY exceeded the configured sort memory limit.', 'RESOURCE_LIMIT');
                }
                if (count($matching) > $maximumRows) {
                    throw new FoxyException('ORDER BY exceeded the configured in-memory row limit.', 'RESOURCE_LIMIT');
                }
            }
            $orders = $statement['order'];
            usort($matching, function (array $left, array $right) use ($orders): int {
                foreach ($orders as $order) {
                    $leftVal = $left[$order['column']] ?? null;
                    $rightVal = $right[$order['column']] ?? null;
                    if ($leftVal === null || $rightVal === null) {
                        $c = $leftVal === $rightVal ? 0 : ($leftVal === null ? -1 : 1);
                    } else {
                        $c = $this->types->compare($leftVal, $rightVal);
                    }
                    if ($c !== 0) {
                        return $order['direction'] === 'desc' ? -$c : $c;
                    }
                }
                return 0;
            });
            $matching = array_slice($matching, $offset, $limit);
            return ExecutionResult::rows($resultColumns, $matching);
        }

        if ($countProjection) {
            $count = 0;
            foreach ($this->joinIterator($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, null, null) as $_row) {
                $count++;
            }
            $count -= $offset;
            if ($count <= 0) {
                return ExecutionResult::rows($resultColumns, []);
            }
            return ExecutionResult::rows($resultColumns, [[$projections[0]['alias'] => $count]]);
        }

        $rows = (function () use ($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, $wherePredicate, $projections, $offset, $limit, $maximumRows): \Generator {
            $skipped = 0;
            $produced = 0;
            foreach ($this->joinIterator($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, null, null) as $row) {
                if ($wherePredicate !== null && !$wherePredicate($row)) {
                    continue;
                }
                if ($skipped < $offset) {
                    $skipped++;
                    continue;
                }
                if ($limit !== null && $produced >= $limit) {
                    break;
                }
                if ($produced >= $maximumRows) {
                    throw new FoxyException('Result exceeded the configured row limit.', 'RESOURCE_LIMIT');
                }
                $produced++;
                $projected = [];
                foreach ($projections as $proj) {
                    if ($proj['kind'] === 'column') {
                        $found = null;
                        if (str_contains($proj['column'], '.')) {
                            $found = $row[$proj['column']] ?? null;
                        } else {
                            foreach ($row as $k => $v) {
                                if (str_ends_with($k, '.' . $proj['column'])) {
                                    $found = $v; break;
                                }
                            }
                        }
                        $projected[$proj['alias']] = $found;
                    }
                }
                yield $projected;
            }
        })();
        return ExecutionResult::rows($resultColumns, $rows);
    }

    private function executeGroupBy(
        iterable $rows, array $groupColumns, array $projections,
        array $columnMap, ?array $having, array $order, ?int $limit, int $offset,
    ): ExecutionResult {
        $groups = [];
        $aggregators = $this->buildAggregators($projections);
        $resultColumns = array_column($projections, 'alias');

        foreach ($rows as $row) {
            $groupKey = $groupColumns === [] ? '' : implode("\0", array_map(
                static fn(string $col): mixed => $row[$col] ?? $row['.'.$col] ?? null,
                $groupColumns,
            ));
            if (!isset($groups[$groupKey])) {
                $groups[$groupKey] = ['row' => [], 'accumulators' => []];
                foreach ($groupColumns as $col) {
                    $groups[$groupKey]['row'][$col] = $row[$col] ?? null;
                }
                foreach ($aggregators as $i => $agg) {
                    $groups[$groupKey]['accumulators'][$i] = $agg['init']();
                }
            }
            foreach ($aggregators as $i => $agg) {
                $value = $agg['extract']($row);
                $groups[$groupKey]['accumulators'][$i] = $agg['accumulate'](
                    $groups[$groupKey]['accumulators'][$i], $value,
                );
            }
        }

        $havPred = $having !== null ? $this->predicate($having, $columnMap, []) : null;
        $limit = $limit ?? PHP_INT_MAX;
        $maxRows = $this->config->maxRowsPerResult;

        $results = [];
        foreach ($groups as $group) {
            $resultRow = [];
            foreach ($projections as $proj) {
                $alias = $proj['alias'];
                if ($proj['kind'] === 'column') {
                    $resultRow[$alias] = $group['row'][$proj['column']] ?? null;
                } elseif (isset($aggregators[$alias])) {
                    $resultRow[$alias] = $aggregators[$alias]['finalize']($group['accumulators'][$alias]);
                }
            }
            if ($havPred !== null && !$havPred($resultRow)) {
                continue;
            }
            $results[] = $resultRow;
            if (count($results) >= $maxRows) {
                throw new FoxyException('Result exceeded the configured row limit.', 'RESOURCE_LIMIT');
            }
        }

        if ($order !== []) {
            usort($results, function (array $left, array $right) use ($order): int {
                foreach ($order as $o) {
                    $l = $left[$o['column']] ?? null;
                    $r = $right[$o['column']] ?? null;
                    if ($l === null || $r === null) {
                        $c = $l === $r ? 0 : ($l === null ? -1 : 1);
                    } else {
                        $c = $this->types->compare($l, $r);
                    }
                    if ($c !== 0) {
                        return $o['direction'] === 'desc' ? -$c : $c;
                    }
                }
                return 0;
            });
        }

        $results = array_slice($results, $offset, $limit);
        return ExecutionResult::rows($resultColumns, $results);
    }

    private function buildAggregators(array $projections): array
    {
        $aggregators = [];
        foreach ($projections as $proj) {
            $kind = $proj['kind'];
            if ($kind === 'column') {
                continue;
            }
            $alias = $proj['alias'];
            $col = $proj['column'];
            if ($col === null) {
                $extract = static fn(array $row): int => 1;
            } else {
                $extract = static function (array $row) use ($col): mixed { return $row[$col] ?? null; };
            }
            switch ($kind) {
                case 'count':
                    $aggregators[$alias] = [
                        'init' => static fn(): int => 0,
                        'accumulate' => static fn(int $acc, mixed $v): int => $v !== null ? $acc + 1 : $acc,
                        'finalize' => static fn(int $acc): int => $acc,
                        'extract' => $extract,
                    ];
                    break;
                case 'sum':
                    $aggregators[$alias] = [
                        'init' => static fn(): float => 0.0,
                        'accumulate' => static fn(float $acc, mixed $v): float =>
                            is_numeric($v) ? $acc + (float) $v : $acc,
                        'finalize' => static fn(float $acc): float => $acc,
                        'extract' => $extract,
                    ];
                    break;
                case 'avg':
                    $aggregators[$alias] = [
                        'init' => static fn(): array => [0.0, 0],
                        'accumulate' => static fn(array $acc, mixed $v): array =>
                            is_numeric($v) ? [$acc[0] + (float) $v, $acc[1] + 1] : $acc,
                        'finalize' => static fn(array $acc): ?float => $acc[1] > 0 ? $acc[0] / $acc[1] : null,
                        'extract' => $extract,
                    ];
                    break;
                case 'min':
                    $types = $this->types;
                    $aggregators[$alias] = [
                        'init' => static fn(): mixed => null,
                        'accumulate' => static fn(mixed $acc, mixed $v): mixed =>
                            $v !== null && ($acc === null || $types->compare($v, $acc) < 0) ? $v : $acc,
                        'finalize' => static fn(mixed $acc): mixed => $acc,
                        'extract' => $extract,
                    ];
                    break;
                case 'max':
                    $types = $this->types;
                    $aggregators[$alias] = [
                        'init' => static fn(): mixed => null,
                        'accumulate' => static fn(mixed $acc, mixed $v): mixed =>
                            $v !== null && ($acc === null || $types->compare($v, $acc) > 0) ? $v : $acc,
                        'finalize' => static fn(mixed $acc): mixed => $acc,
                        'extract' => $extract,
                    ];
                    break;
            }
        }
        return $aggregators;
    }

    private function joinIterator(
        array $tables, array $schemas, array $columnMaps,
        array $onPredicates, array $joinTypes, ?\Closure $wherePredicate, ?array $projections,
    ): \Generator {
        $rowBuffer = [];
        yield from $this->joinNested($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, $rowBuffer, 0, $projections);
    }

    private function joinNested(
        array $tables, array $schemas, array $columnMaps,
        array $onPredicates, array $joinTypes, array &$rowBuffer, int $depth, ?array $projections,
    ): \Generator {
        $maxRows = $this->config->maxRowsPerResult;
        $table = $tables[$depth];
        $schema = $schemas[$depth];
        $prefix = $schema['name'];
        $joinType = $joinTypes[$depth] ?? 'inner';

        $scan = $table->rows(null);
        $anyMatch = false;
        foreach ($scan as $rowEntry) {
            $row = $rowEntry['values'];
            $qualified = [];
            foreach ($row as $col => $val) {
                $qualified[$prefix . '.' . $col] = $val;
            }
            $rowBuffer[$depth] = $qualified;

            if (isset($onPredicates[$depth])) {
                $merged = $this->mergeRowBufferPartial($rowBuffer, $depth);
                if (!$onPredicates[$depth]($merged)) {
                    continue;
                }
            }
            $anyMatch = true;

            if ($depth < count($tables) - 1) {
                yield from $this->joinNested($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, $rowBuffer, $depth + 1, $projections);
            } elseif ($projections === null) {
                yield $this->mergeRowBuffer($rowBuffer, null, $maxRows);
            } else {
                yield $this->mergeRowBuffer($rowBuffer, $projections, $maxRows);
            }
        }

        if (!$anyMatch && $depth > 0 && ($joinType === 'left' || $joinType === 'right')) {
            $nullRow = [];
            foreach ($schemas[$depth]['columns'] as $col) {
                $nullRow[$prefix . '.' . $col['name']] = null;
            }
            $rowBuffer[$depth] = $nullRow;
            if ($depth < count($tables) - 1) {
                yield from $this->joinNested($tables, $schemas, $columnMaps, $onPredicates, $joinTypes, $rowBuffer, $depth + 1, $projections);
            } elseif ($projections === null) {
                yield $this->mergeRowBuffer($rowBuffer, null, $maxRows);
            } else {
                yield $this->mergeRowBuffer($rowBuffer, $projections, $maxRows);
            }
        }
    }

    private function mergeRowBufferPartial(array $rowBuffer, int $upToDepth): array
    {
        $merged = [];
        for ($i = 0; $i <= $upToDepth; $i++) {
            if (isset($rowBuffer[$i])) {
                foreach ($rowBuffer[$i] as $k => $v) {
                    $merged[$k] = $v;
                }
            }
        }
        return $merged;
    }

    private function mergeRowBuffer(array &$rowBuffer, ?array $projections, int $maxRows): array
    {
        $merged = [];
        foreach ($rowBuffer as $buf) {
            foreach ($buf as $k => $v) {
                $merged[$k] = $v;
                $dot = strpos($k, '.');
                if ($dot !== false) {
                    $bare = substr($k, $dot + 1);
                    if (!array_key_exists($bare, $merged)) {
                        $merged[$bare] = $v;
                    }
                }
            }
        }
        if ($projections === null) {
            return $merged;
        }
        $projected = [];
        foreach ($projections as $proj) {
            if ($proj['kind'] === 'all') {
                $projected = $merged;
                break;
            }
            if ($proj['kind'] === 'count') {
                $projected[$proj['alias']] = 1;
                continue;
            }
            $found = null;
            if (str_contains($proj['column'], '.')) {
                $found = $merged[$proj['column']] ?? null;
            } else {
                foreach ($merged as $k => $v) {
                    if (str_ends_with($k, '.' . $proj['column'])) {
                        $found = $v;
                        break;
                    }
                }
            }
            $projected[$proj['alias']] = $found;
        }
        return $projected;
    }

    private function joinPredicate(?array $expression, array $columnMaps, array $aliases, array $parameters): ?\Closure
    {
        if ($expression === null) {
            return null;
        }
        $mergedColumns = [];
        foreach ($columnMaps as $i => $map) {
            $prefix = $aliases[$i];
            foreach ($map as $name => $col) {
                $mergedColumns[$prefix . '.' . $name] = $col;
                $mergedColumns[$name] = $col;
            }
        }
        return $this->predicate($expression, $mergedColumns, $parameters);
    }

    private function update(array $statement, array $parameters): ExecutionResult
    {
        $this->enforcePolicies('UPDATE', $statement);
        $table = $this->table($statement['table']);
        $schema = $table->schema();
        $columns = $this->columnMap($schema);
        $assignments = [];
        foreach ($statement['assignments'] as $name => $node) {
            if (!isset($columns[$name])) {
                throw new FoxyException("Unknown column: {$name}", 'UNKNOWN_COLUMN');
            }
            $value = $this->value($node, $parameters);
            if ($value === null && !$columns[$name]['nullable']) {
                throw new FoxyException("Column {$name} cannot be null.", 'NOT_NULL_VIOLATION');
            }
            $assignments[$name] = $value === null ? null : $this->types->coerce($value, $columns[$name]);
        }
        $predicate = $this->predicate($statement['where'], $columns, $parameters);
        $lookup = $this->lookup($table, $statement['where'], $columns, $parameters, $schema);
        if ($this->isSystemConfigTable($statement['table'])) {
            if (is_string($assignments['variable_name'] ?? null)
                && SystemVariables::isManaged($assignments['variable_name'])) {
                throw new FoxyException(
                    'Managed system variables must be changed with SET GLOBAL.',
                    'SYSTEM_VARIABLE_PROTECTED',
                );
            }
            $predicate = $this->protectManagedVariables($predicate);
        }
        if ($this->inTransaction) {
            $table->setUndoCallback(function (int $rowId, ?string $oldSlotBytes, ?array $oldRow, ?array $newRow) use ($table): void {
                $this->txnUndo[] = [
                    'table' => $table, 'row_id' => $rowId,
                    'old_slot_bytes' => $oldSlotBytes, 'old_row' => $oldRow, 'new_row' => $newRow,
                ];
            });
        }
        try {
            $affected = $table->update($assignments, $predicate, $lookup, $this->mutationMemoryLimit());
        } finally {
            if ($this->inTransaction) {
                $table->setUndoCallback(null);
            }
        }
        return ExecutionResult::command($affected);
    }

    private function delete(array $statement, array $parameters): ExecutionResult
    {
        $this->enforcePolicies('DELETE', $statement);
        $table = $this->table($statement['table']);
        $schema = $table->schema();
        $columns = $this->columnMap($schema);
        $predicate = $this->predicate($statement['where'], $columns, $parameters);
        $lookup = $this->lookup($table, $statement['where'], $columns, $parameters, $schema);
        if ($this->isSystemConfigTable($statement['table'])) {
            $predicate = $this->protectManagedVariables($predicate);
        }
        if ($this->inTransaction) {
            $table->setUndoCallback(function (int $rowId, ?string $oldSlotBytes, ?array $oldRow, ?array $newRow) use ($table): void {
                $this->txnUndo[] = [
                    'table' => $table, 'row_id' => $rowId,
                    'old_slot_bytes' => $oldSlotBytes, 'old_row' => $oldRow, 'new_row' => $newRow,
                ];
            });
        }
        try {
            $result = ExecutionResult::command($table->delete($predicate, $lookup, $this->mutationMemoryLimit()));
        } finally {
            if ($this->inTransaction) {
                $table->setUndoCallback(null);
            }
        }
        return $result;
    }

    private function beginTransaction(): ExecutionResult
    {
        if ($this->inTransaction) {
            throw new FoxyException('Nested transactions are not supported.', 'TRANSACTION_ACTIVE');
        }
        $this->inTransaction = true;
        $this->txnUndo = [];
        return ExecutionResult::command();
    }

    private function commitTransaction(): ExecutionResult
    {
        if (!$this->inTransaction) {
            throw new FoxyException('No active transaction.', 'TRANSACTION_INACTIVE');
        }
        $this->txnUndo = [];
        $this->inTransaction = false;
        return ExecutionResult::command();
    }

    private function rollbackTransaction(): ExecutionResult
    {
        if (!$this->inTransaction) {
            throw new FoxyException('No active transaction.', 'TRANSACTION_INACTIVE');
        }
        if ($this->txnUndo !== []) {
            $tableGroups = [];
            foreach ($this->txnUndo as $entry) {
                $tableKey = spl_object_id($entry['table']);
                $tableGroups[$tableKey]['table'] = $entry['table'];
                $tableGroups[$tableKey]['entries'][] = $entry;
            }
            foreach ($tableGroups as $group) {
                $group['table']->rollbackEntries($group['entries']);
            }
        }
        $this->txnUndo = [];
        $this->inTransaction = false;
        return ExecutionResult::command();
    }

    private function createRole(array $statement): ExecutionResult
    {
        $roleName = $statement['role'];
        $roles = $this->storage->table(Authentication::SYSTEM_DATABASE, 'roles');
        try {
            $roles->insert(['role_name' => $roleName]);
        } catch (FoxyException $e) {
            if ($e->errorCode === 'UNIQUE_VIOLATION') {
                throw new FoxyException("Role {$roleName} already exists.", 'ROLE_EXISTS');
            }
            throw $e;
        }
        return ExecutionResult::command();
    }

    private function dropRole(array $statement): ExecutionResult
    {
        $roleName = $statement['role'];
        $roles = $this->storage->table(Authentication::SYSTEM_DATABASE, 'roles');
        $lookup = $roles->lookupForEqualities(['role_name' => $roleName]);
        $roleId = null;
        foreach ($roles->rows($lookup) as $entry) {
            $roleId = $entry['values']['role_id'];
            break;
        }
        if ($roleId === null) {
            return ExecutionResult::command();
        }
        $assignments = $this->storage->table(Authentication::SYSTEM_DATABASE, 'role_assignments');
        $assignments->delete(null, $assignments->lookupForEqualities(['role_id' => $roleId]));
        $privileges = $this->storage->table(Authentication::SYSTEM_DATABASE, 'privileges');
        $privileges->delete(null, $privileges->lookupForEqualities(['account_id' => $roleId]));
        $roles->delete(null, $lookup);
        return ExecutionResult::command();
    }

    private function grantStmt(array $statement): ExecutionResult
    {
        if ($statement['kind'] === 'privilege') {
            $privileges = $this->storage->table(Authentication::SYSTEM_DATABASE, 'privileges');
            $accountId = $this->resolveAccountId($statement['grantee']);
            if ($accountId === null) {
                throw new FoxyException("User or role {$statement['grantee']} not found.", 'UNKNOWN_GRANTEE');
            }
            try {
                $privileges->insert([
                    'username' => $statement['grantee'],
                    'account_id' => $accountId,
                    'database_name' => $statement['database'],
                    'table_name' => $statement['table'],
                    'privilege' => $statement['privilege'],
                ]);
            } catch (FoxyException $e) {
                if ($e->errorCode === 'UNIQUE_VIOLATION') {
                    throw new FoxyException("Privilege already granted.", 'PRIVILEGE_EXISTS');
                }
                throw $e;
            }
        } else {
            $roleName = $statement['role'];
            $grantee = $statement['grantee'];
            $roles = $this->storage->table(Authentication::SYSTEM_DATABASE, 'roles');
            $lookup = $roles->lookupForEqualities(['role_name' => $roleName]);
            $roleId = null;
            foreach ($roles->rows($lookup) as $entry) {
                $roleId = $entry['values']['role_id'];
                break;
            }
            if ($roleId === null) {
                throw new FoxyException("Role {$roleName} not found.", 'UNKNOWN_ROLE');
            }
            $assignments = $this->storage->table(Authentication::SYSTEM_DATABASE, 'role_assignments');
            try {
                $assignments->insert(['username' => $grantee, 'role_id' => $roleId]);
            } catch (FoxyException $e) {
                if ($e->errorCode === 'UNIQUE_VIOLATION') {
                    throw new FoxyException("User {$grantee} already has role {$roleName}.", 'ROLE_ALREADY_GRANTED');
                }
                throw $e;
            }
        }
        return ExecutionResult::command();
    }

    private function revokeStmt(array $statement): ExecutionResult
    {
        if ($statement['kind'] === 'privilege') {
            $privileges = $this->storage->table(Authentication::SYSTEM_DATABASE, 'privileges');
            $accountId = $this->resolveAccountId($statement['grantee']);
            if ($accountId === null) {
                return ExecutionResult::command();
            }
            $privileges->delete(null, $privileges->lookupForEqualities([
                'account_id' => $accountId,
                'database_name' => $statement['database'],
                'table_name' => $statement['table'],
                'privilege' => $statement['privilege'],
            ]));
        } else {
            $roles = $this->storage->table(Authentication::SYSTEM_DATABASE, 'roles');
            $lookup = $roles->lookupForEqualities(['role_name' => $statement['role']]);
            $roleId = null;
            foreach ($roles->rows($lookup) as $entry) {
                $roleId = $entry['values']['role_id'];
                break;
            }
            if ($roleId === null) {
                return ExecutionResult::command();
            }
            $assignments = $this->storage->table(Authentication::SYSTEM_DATABASE, 'role_assignments');
            $assignments->delete(null, $assignments->lookupForEqualities([
                'username' => $statement['grantee'],
                'role_id' => $roleId,
            ]));
        }
        return ExecutionResult::command();
    }

    private function createPolicy(array $statement): ExecutionResult
    {
        $table = $statement['table'];
        if (str_contains($table, '.')) {
            [$database, $tableName] = explode('.', $table, 2);
        } else {
            $database = $this->requireDatabase();
            $tableName = $table;
        }
        $policies = $this->storage->table(Authentication::SYSTEM_DATABASE, 'policies');
        $json = json_encode($statement['expression'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        try {
            $policies->insert([
                'policy_name' => $statement['name'],
                'database_name' => $database,
                'table_name' => $tableName,
                'operation' => $statement['operation'],
                'expression_sql' => $json === false ? null : $json,
            ]);
        } catch (FoxyException $e) {
            if ($e->errorCode === 'UNIQUE_VIOLATION') {
                throw new FoxyException("Policy {$statement['name']} already exists.", 'POLICY_EXISTS');
            }
            throw $e;
        }
        return ExecutionResult::command();
    }

    private function dropPolicy(array $statement): ExecutionResult
    {
        $table = $statement['table'];
        if (str_contains($table, '.')) {
            [$database, $tableName] = explode('.', $table, 2);
        } else {
            $database = $this->requireDatabase();
            $tableName = $table;
        }
        $policies = $this->storage->table(Authentication::SYSTEM_DATABASE, 'policies');
        $policies->delete(null, $policies->lookupForEqualities([
            'policy_name' => $statement['name'],
            'database_name' => $database,
            'table_name' => $tableName,
        ]));
        return ExecutionResult::command();
    }

    private function resolveAccountId(string $name): ?string
    {
        try {
            $users = $this->storage->table(Authentication::SYSTEM_DATABASE, 'users_schema');
            $lookup = $users->lookupForEqualities(['username' => $name]);
            foreach ($users->rows($lookup) as $entry) {
                return $entry['values']['account_id'];
            }
        } catch (FoxyException) {
        }
        try {
            $roles = $this->storage->table(Authentication::SYSTEM_DATABASE, 'roles');
            $lookup = $roles->lookupForEqualities(['role_name' => $name]);
            foreach ($roles->rows($lookup) as $entry) {
                return $entry['values']['role_id'];
            }
        } catch (FoxyException) {
        }
        return null;
    }

    private function enforcePolicies(string $operation, array &$statement): void
    {
        $table = $statement['table'] ?? null;
        if ($table === null) {
            return;
        }
        if (str_contains($table, '.')) {
            [$database, $tableName] = explode('.', $table, 2);
        } else {
            $database = $this->currentDatabase ?? '';
            if ($database === '') {
                return;
            }
            $tableName = $table;
        }
        try {
            $policies = $this->storage->table(Authentication::SYSTEM_DATABASE, 'policies');
        } catch (FoxyException) {
            return;
        }
        try {
            $lookup = $policies->lookupForEqualities([
                'database_name' => $database,
                'table_name' => $tableName,
            ]);
        } catch (FoxyException) {
            return;
        }
        $policyExprs = [];
        foreach ($policies->rows($lookup) as $entry) {
            $row = $entry['values'];
            if ($row['operation'] !== 'ALL' && $row['operation'] !== $operation) {
                continue;
            }
            if ($row['expression_sql'] !== null) {
                $expr = json_decode($row['expression_sql'], true);
                if (is_array($expr)) {
                    $policyExprs[] = $expr;
                }
            }
        }
        if ($policyExprs === []) {
            return;
        }
        $combined = null;
        foreach ($policyExprs as $expr) {
            if ($combined === null) {
                $combined = $expr;
            } else {
                $combined = ['kind' => 'binary', 'operator' => 'AND', 'left' => $combined, 'right' => $expr];
            }
        }
        $existingWhere = $statement['where'] ?? null;
        if ($existingWhere !== null) {
            $combined = ['kind' => 'binary', 'operator' => 'AND', 'left' => $existingWhere, 'right' => $combined];
        }
        $statement['where'] = $combined;
    }

    private function expressionToSql(?array $node): ?string
    {
        if ($node === null) {
            return null;
        }
        return match ($node['kind']) {
            'column' => $node['column'],
            'value' => $this->valueToSql($node['value']),
            'parameter' => '?',
            'unary' => $node['operator'] . ' ' . $this->expressionToSql($node['operand']),
            'binary' => '(' . $this->expressionToSql($node['left']) . ' ' . $node['operator'] . ' ' . $this->expressionToSql($node['right']) . ')',
            'function' => $node['name'] . '(' . implode(', ', array_map(fn($a) => $this->expressionToSql($a), $node['args'] ?? [])) . ')',
            default => '',
        };
    }

    private function valueToSql(mixed $value): string
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
        return "'" . str_replace("'", "''", (string) $value) . "'";
    }

    private function truncate(array $statement): ExecutionResult
    {
        $this->table($statement['table'])->truncate();
        return ExecutionResult::command();
    }

    private function compact(array $statement): ExecutionResult
    {
        $metadata = $this->table($statement['table'])->compact();
        return ExecutionResult::command(metadata: $metadata);
    }

    private function alterTable(array $statement): ExecutionResult
    {
        $actions = $statement['actions'];
        foreach ($actions as &$action) {
            if ($action['kind'] === 'set_auto_increment') {
                $action['value'] = $this->value($action['value'], []);
            }
        }
        unset($action);
        $result = $this->table($statement['table'])->alterSchema($actions);
        return ExecutionResult::command(metadata: $result);
    }

    private function setCollation(array $statement): ExecutionResult
    {
        $this->table($statement['table'])->setCollation($statement['value']);
        return ExecutionResult::command(metadata: ['collation' => $statement['value']]);
    }

    private function setAutoIncrement(array $statement): ExecutionResult
    {
        $value = $this->value($statement['value'], []);
        $this->table($statement['table'])->setAutoIncrement((int) $value);
        return ExecutionResult::command(metadata: ['value' => (int) $value]);
    }

    private function renameTable(array $statement): ExecutionResult
    {
        $table = $statement['table'];
        if (str_contains($table, '.')) {
            [$database, $name] = explode('.', $table, 2);
        } else {
            $database = $this->requireDatabase();
            $name = $table;
        }
        $this->storage->renameTable($database, $name, $statement['new_name']);
        return ExecutionResult::command(metadata: [
            'old_name' => $name,
            'new_name' => $statement['new_name'],
        ]);
    }

    private function moveTable(array $statement): ExecutionResult
    {
        $table = $statement['table'];
        if (str_contains($table, '.')) {
            [$database, $name] = explode('.', $table, 2);
        } else {
            $database = $this->requireDatabase();
            $name = $table;
        }
        $this->storage->moveTable($database, $name, $statement['target_database'], $statement['target_table']);
        return ExecutionResult::command(metadata: [
            'database' => $database,
            'table' => $name,
            'target_database' => $statement['target_database'],
            'target_table' => $statement['target_table'] ?? $name,
        ]);
    }

    private function copyTable(array $statement): ExecutionResult
    {
        $table = $statement['table'];
        if (str_contains($table, '.')) {
            [$database, $name] = explode('.', $table, 2);
        } else {
            $database = $this->requireDatabase();
            $name = $table;
        }
        $this->storage->copyTable($database, $name, $statement['target_database'], $statement['target_table']);
        return ExecutionResult::command(metadata: [
            'database' => $database,
            'table' => $name,
            'target_database' => $statement['target_database'],
            'target_table' => $statement['target_table'] ?? $name,
        ]);
    }

    private function analyzeTable(array $statement): ExecutionResult
    {
        $metadata = $this->table($statement['table'])->analyze();
        return ExecutionResult::command(metadata: $metadata);
    }

    private function checkTable(array $statement): ExecutionResult
    {
        $result = $this->table($statement['table'])->verify();
        return ExecutionResult::command(metadata: $result);
    }

    private function checksumTable(array $statement): ExecutionResult
    {
        $checksum = $this->table($statement['table'])->checksum();
        return ExecutionResult::command(metadata: ['checksum' => $checksum]);
    }

    private function flushTable(array $statement): ExecutionResult
    {
        if ($statement['table'] !== null) {
            $this->table($statement['table'])->flush();
        } else {
            foreach ($this->storage->listTables($this->requireDatabase()) as $name) {
                $this->table($name)->flush();
            }
        }
        return ExecutionResult::command();
    }

    private function predicate(?array $expression, array $columns, array $parameters): ?\Closure
    {
        if ($expression === null) {
            return null;
        }
        $evaluator = $this->booleanEvaluator($expression, $columns, $parameters);
        return static fn(array $row): bool => $evaluator($row) === true;
    }

    private function executeSelectAllRows(array $statement): array
    {
        $result = $this->select($statement, []);
        if (is_array($result->rows)) {
            return $result->rows;
        }
        return iterator_to_array($result->rows, false);
    }

    private function executeSubqueryValues(array $subquery): array
    {
        $rows = $this->executeSelectAllRows($subquery);
        $values = [];
        foreach ($rows as $row) {
            if (is_array($row)) {
                $values[] = reset($row);
            }
        }
        return $values;
    }

    private function executeScalarSubquery(array $subquery): mixed
    {
        $rows = $this->executeSelectAllRows($subquery);
        foreach ($rows as $row) {
            if (is_array($row)) {
                return reset($row);
            }
        }
        return null;
    }

    private function booleanEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        return match ($expression['kind']) {
            'logical' => $this->logicalEvaluator($expression, $columns, $parameters),
            'not' => $this->notEvaluator($expression, $columns, $parameters),
            'comparison' => $this->comparisonEvaluator($expression, $columns, $parameters),
            'is_null' => $this->isNullEvaluator($expression, $columns, $parameters),
            'in' => $this->inEvaluator($expression, $columns, $parameters),
            'like' => $this->likeEvaluator($expression, $columns, $parameters),
            'truthy' => $this->truthyEvaluator($expression, $columns, $parameters),
            'in_subquery' => $this->inSubqueryEvaluator($expression, $columns, $parameters),
            'exists' => $this->existsEvaluator($expression),
            'subquery' => $this->scalarSubqueryEvaluator($expression),
            default => throw new FoxyException('Unsupported WHERE expression.', 'SQL_SEMANTIC'),
        };
    }

    private function logicalEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $left = $this->booleanEvaluator($expression['left'], $columns, $parameters);
        $right = $this->booleanEvaluator($expression['right'], $columns, $parameters);
        if ($expression['operator'] === 'and') {
            return static function (array $row) use ($left, $right): ?bool {
                $leftValue = $left($row);
                if ($leftValue === false) {
                    return false;
                }
                $rightValue = $right($row);
                if ($rightValue === false) {
                    return false;
                }
                return $leftValue === true && $rightValue === true ? true : null;
            };
        }
        return static function (array $row) use ($left, $right): ?bool {
            $leftValue = $left($row);
            if ($leftValue === true) {
                return true;
            }
            $rightValue = $right($row);
            if ($rightValue === true) {
                return true;
            }
            return $leftValue === false && $rightValue === false ? false : null;
        };
    }

    private function notEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $inner = $this->booleanEvaluator($expression['expression'], $columns, $parameters);
        return static function (array $row) use ($inner): ?bool {
            $value = $inner($row);
            return $value === null ? null : !$value;
        };
    }

    private function comparisonEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        [$left, $right] = $this->operandPair(
            $expression['left'],
            $expression['right'],
            $columns,
            $parameters,
        );
        $operator = $expression['operator'];
        return function (array $row) use ($left, $right, $operator): ?bool {
            $leftValue = ($left['get'])($row);
            $rightValue = ($right['get'])($row);
            if ($leftValue === null || $rightValue === null) {
                return null;
            }
            $comparison = $this->types->compare($leftValue, $rightValue);
            return match ($operator) {
                '=' => $comparison === 0,
                '!=', '<>' => $comparison !== 0,
                '<' => $comparison < 0,
                '<=' => $comparison <= 0,
                '>' => $comparison > 0,
                '>=' => $comparison >= 0,
                default => throw new FoxyException('Unsupported comparison operator.', 'SQL_SEMANTIC'),
            };
        };
    }

    private function isNullEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $operand = $this->operand($expression['operand'], $columns, $parameters);
        $not = $expression['not'];
        return static function (array $row) use ($operand, $not): bool {
            $isNull = ($operand['get'])($row) === null;
            return $not ? !$isNull : $isNull;
        };
    }

    private function inEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $left = $this->operand($expression['operand'], $columns, $parameters);
        $values = [];
        foreach ($expression['values'] as $node) {
            $right = $this->operand($node, $columns, $parameters);
            [$coercedLeft, $coercedRight] = $this->coerceOperands($left, $right, $columns);
            $left = $coercedLeft;
            $values[] = $coercedRight;
        }
        $not = $expression['not'];
        return function (array $row) use ($left, $values, $not): ?bool {
            $needle = ($left['get'])($row);
            if ($needle === null) {
                return null;
            }
            $hasNull = false;
            foreach ($values as $operand) {
                $value = ($operand['get'])($row);
                if ($value === null) {
                    $hasNull = true;
                    continue;
                }
                if ($this->types->compare($needle, $value) === 0) {
                    return !$not;
                }
            }
            if ($hasNull) {
                return null;
            }
            return $not;
        };
    }

    private function likeEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        [$left, $pattern] = $this->operandPair(
            $expression['operand'],
            $expression['pattern'],
            $columns,
            $parameters,
            false,
        );
        $not = $expression['not'];
        $constantPatternReady = false;
        $constantPatternValue = null;
        $constantRegex = null;
        return function (array $row) use (
            $left,
            $pattern,
            $not,
            &$constantPatternReady,
            &$constantPatternValue,
            &$constantRegex,
        ): ?bool {
            $value = $this->types->materialize(($left['get'])($row));
            if ($pattern['constant']) {
                if (!$constantPatternReady) {
                    $constantPatternValue = $this->types->materialize($pattern['value']);
                    if ($constantPatternValue !== null && !is_string($constantPatternValue)) {
                        throw new FoxyException('LIKE requires text operands.', 'INVALID_VALUE');
                    }
                    $constantRegex = $constantPatternValue === null
                        ? null
                        : $this->likePattern($constantPatternValue);
                    $constantPatternReady = true;
                }
                $patternValue = $constantPatternValue;
                $regex = $constantRegex;
            } else {
                $patternValue = $this->types->materialize(($pattern['get'])($row));
                $regex = is_string($patternValue) ? $this->likePattern($patternValue) : null;
            }
            if ($value === null || $patternValue === null) {
                return null;
            }
            if (!is_string($value) || !is_string($patternValue)) {
                throw new FoxyException('LIKE requires text operands.', 'INVALID_VALUE');
            }
            $match = preg_match($regex, $value);
            if ($match === false) {
                throw new FoxyException('LIKE evaluation failed: ' . preg_last_error_msg(), 'INVALID_VALUE');
            }
            $matched = $match === 1;
            return $not ? !$matched : $matched;
        };
    }

    private function truthyEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $operand = $this->operand($expression['operand'], $columns, $parameters);
        return function (array $row) use ($operand): ?bool {
            $value = $this->types->materialize(($operand['get'])($row));
            if ($value instanceof BinaryValue) {
                $value = $value->bytes;
            }
            return $value === null ? null : (bool) $value;
        };
    }

    private function operandPair(
        array $leftNode,
        array $rightNode,
        array $columns,
        array $parameters,
        bool $coerce = true,
    ): array {
        $left = $this->operand($leftNode, $columns, $parameters);
        $right = $this->operand($rightNode, $columns, $parameters);
        return $coerce ? $this->coerceOperands($left, $right, $columns) : [$left, $right];
    }

    private function inSubqueryEvaluator(array $expression, array $columns, array $parameters): \Closure
    {
        $left = $this->operand($expression['operand'], $columns, $parameters);
        $subqueryValues = $this->executeSubqueryValues($expression['subquery']);
        $not = $expression['not'];
        return function (array $row) use ($left, $subqueryValues, $not): ?bool {
            $needle = ($left['get'])($row);
            if ($needle === null) {
                return null;
            }
            foreach ($subqueryValues as $value) {
                if ($value === null) {
                    continue;
                }
                if ($this->types->compare($needle, $value) === 0) {
                    return !$not;
                }
            }
            return $not;
        };
    }

    private function existsEvaluator(array $expression): \Closure
    {
        $hasRows = count($this->executeSelectAllRows($expression['subquery'])) > 0;
        return static fn(array $row): bool => $hasRows;
    }

    private function scalarSubqueryEvaluator(array $expression): \Closure
    {
        $value = $this->executeScalarSubquery($expression['subquery']);
        return static fn(array $row): ?bool => $value === null ? null : (bool) $value;
    }

    private function operand(array $node, array $columns, array $parameters): array
    {
        if ($node['kind'] === 'column') {
            if (!isset($columns[$node['name']])) {
                throw new FoxyException("Unknown column: {$node['name']}", 'UNKNOWN_COLUMN');
            }
            $name = $node['name'];
            return [
                'get' => static fn(array $row): mixed => $row[$name],
                'constant' => false,
                'column' => $name,
                'value' => null,
            ];
        }
        if ($node['kind'] === 'subquery') {
            $value = $this->executeScalarSubquery($node['subquery']);
            return [
                'get' => static fn(array $row): mixed => $value,
                'constant' => true,
                'column' => null,
                'value' => $value,
            ];
        }
        $value = $this->value($node, $parameters);
        return [
            'get' => static fn(array $row): mixed => $value,
            'constant' => true,
            'column' => null,
            'value' => $value,
        ];
    }

    private function coerceOperands(array $left, array $right, array $columns): array
    {
        if ($left['column'] !== null && $right['constant'] && $right['value'] !== null) {
            $right = $this->constantOperand($this->types->materialize(
                $this->types->coerce($right['value'], $columns[$left['column']]),
            ));
        } elseif ($right['column'] !== null && $left['constant'] && $left['value'] !== null) {
            $left = $this->constantOperand($this->types->materialize(
                $this->types->coerce($left['value'], $columns[$right['column']]),
            ));
        }
        return [$left, $right];
    }

    private function constantOperand(mixed $value): array
    {
        return [
            'get' => static fn(array $row): mixed => $value,
            'constant' => true,
            'column' => null,
            'value' => $value,
        ];
    }

    private function lookup(
        Table $table,
        ?array $expression,
        array $columns,
        array $parameters,
        array $schema,
    ): ?array {
        if ($expression === null) {
            return null;
        }
        $equalities = $this->equalities($expression, $columns, $parameters);
        return $equalities === [] ? null : $table->lookupForEqualities($equalities, $schema);
    }

    private function equalities(array $expression, array $columns, array $parameters): array
    {
        if ($expression['kind'] === 'logical' && $expression['operator'] === 'and') {
            return $this->equalities($expression['left'], $columns, $parameters)
                + $this->equalities($expression['right'], $columns, $parameters);
        }
        if ($expression['kind'] !== 'comparison' || $expression['operator'] !== '=') {
            return [];
        }
        $left = $expression['left'];
        $right = $expression['right'];
        if ($left['kind'] === 'column' && in_array($right['kind'], ['literal', 'parameter'], true)) {
            $column = $left['name'];
            $node = $right;
        } elseif ($right['kind'] === 'column' && in_array($left['kind'], ['literal', 'parameter'], true)) {
            $column = $right['name'];
            $node = $left;
        } else {
            return [];
        }
        if (!isset($columns[$column])) {
            throw new FoxyException("Unknown column: {$column}", 'UNKNOWN_COLUMN');
        }
        $value = $this->value($node, $parameters);
        if ($value !== null) {
            $value = $this->types->materialize($this->types->coerce($value, $columns[$column]));
        }
        return [$column => $value];
    }

    private function value(array $node, array $parameters): mixed
    {
        if ($node['kind'] === 'literal') {
            return $node['value'];
        }
        if ($node['kind'] === 'parameter') {
            $key = $node['key'];
            if (!array_key_exists($key, $parameters) && is_string($key) && array_key_exists(':' . $key, $parameters)) {
                $key = ':' . $key;
            }
            if (!array_key_exists($key, $parameters)) {
                throw new FoxyException("Missing parameter {$node['key']}.", 'MISSING_PARAMETER');
            }
            return $this->normalizeParameter($parameters[$key]);
        }
        if ($node['kind'] === 'expression') {
            return match ($node['name']) {
                'current_timestamp' => new DateTimeImmutable('now'),
                'uuid' => self::uuid(),
                default => throw new FoxyException('Unsupported value expression.', 'SQL_SEMANTIC'),
            };
        }
        throw new FoxyException('DEFAULT is not valid in this context.', 'SQL_SEMANTIC');
    }

    private function normalizeParameter(mixed $value): mixed
    {
        return $value;
    }

    private function nonNegativeInteger(?array $node, array $parameters, string $name): ?int
    {
        if ($node === null) {
            return null;
        }
        $value = $this->value($node, $parameters);
        if (is_string($value) && preg_match('/^\d+$/', $value) === 1) {
            $validated = filter_var($value, FILTER_VALIDATE_INT);
            $value = $validated === false ? null : $validated;
        }
        if (!is_int($value) || $value < 0) {
            throw new FoxyException("{$name} must be a non-negative integer.", 'INVALID_VALUE');
        }
        return $value;
    }

    private function tableName(string $qualified): string
    {
        if (str_contains($qualified, '.')) {
            [$db, $tbl] = explode('.', $qualified, 2);
            return $tbl;
        }
        return $qualified;
    }

    private function project(array $row, array $projections): array
    {
        $result = [];
        foreach ($projections as $projection) {
            if ($projection['kind'] === 'value') {
                $result[$projection['alias']] = $projection['value']['value'] ?? null;
            } else {
                $result[$projection['alias']] = $row[$projection['column']];
            }
        }
        return $result;
    }

    private function columnMap(array $schema): array
    {
        $columns = [];
        foreach ($schema['columns'] as $column) {
            $columns[$column['name']] = $column;
        }
        return $columns;
    }

    private function likePattern(string $pattern): string
    {
        $regex = '';
        $length = strlen($pattern);
        for ($index = 0; $index < $length; $index++) {
            $character = $pattern[$index];
            if ($character === '\\' && $index + 1 < $length) {
                $regex .= preg_quote($pattern[++$index], '/');
            } elseif ($character === '%') {
                $regex .= '.*';
            } elseif ($character === '_') {
                $regex .= '.';
            } else {
                $regex .= preg_quote($character, '/');
            }
        }
        return '/\A' . $regex . '\z/us';
    }

    private function requireDatabase(): string
    {
        if ($this->currentDatabase === null) {
            throw new FoxyException('No database is selected. Use USE database first.', 'NO_DATABASE_SELECTED');
        }
        return $this->currentDatabase;
    }

    private function authorize(array $statement): void
    {
        if ($this->authentication === null) {
            return;
        }
        if ($this->username === null) {
            throw new FoxyException('Authentication is required.', 'AUTH_REQUIRED');
        }

        $type = $statement['type'];
        if (in_array($type, ['begin', 'commit', 'rollback'], true)) {
            return;
        }
        $database = match ($type) {
            'create_database', 'drop_database', 'use' => $statement['database'],
            'show_tables' => $statement['database'] ?? $this->currentDatabase ?? '*',
            'show_databases' => '*',
            'set_variable' => $statement['scope'] === 'GLOBAL'
                ? Authentication::SYSTEM_DATABASE
                : $this->currentDatabase ?? '*',
            default => $this->currentDatabase ?? '*',
        };
        $table = $type === 'set_variable' && $statement['scope'] === 'GLOBAL'
            ? 'sys_config'
            : ($statement['table'] ?? '*');
        $privilege = match ($type) {
            'show_databases', 'show_tables', 'show_variables' => 'SHOW',
            'set_variable' => 'ALTER',
            'use' => 'CONNECT',
            'create_database', 'create_table' => 'CREATE',
            'drop_database', 'drop_table' => 'DROP',
            'create_index', 'drop_index' => 'INDEX',
            'describe', 'show_indexes', 'select' => 'SELECT',
            'insert' => 'INSERT',
            'update' => 'UPDATE',
            'delete', 'truncate' => 'DELETE',
            'compact', 'optimize', 'defragment', 'alter_table', 'set_auto_increment', 'set_collation' => 'ALTER',
            'create_role', 'drop_role', 'grant', 'revoke' => 'CREATE',
            'create_policy', 'drop_policy' => 'CREATE',
            'rename_table', 'move_table', 'copy_table' => 'ALTER',
            'analyze' => 'ALTER',
            'check' => 'SELECT',
            'checksum' => 'SELECT',
            'flush' => 'ALTER',
            default => throw new FoxyException('Unsupported authorization target.', 'ACCESS_DENIED'),
        };

        if ($database === Authentication::SYSTEM_DATABASE && in_array($type, [
            'drop_database', 'drop_table', 'truncate', 'create_table',
        ], true)) {
            throw new FoxyException('The FoxyDB system schema is protected.', 'SYSTEM_SCHEMA_PROTECTED');
        }
        if ($database === Authentication::SYSTEM_DATABASE && $table === 'users_schema') {
            if ($type === 'insert'
                && ($statement['columns'] === null || in_array('account_id', $statement['columns'], true))) {
                throw new FoxyException(
                    'users_schema.account_id is generated by the server and cannot be inserted.',
                    'SYSTEM_COLUMN_PROTECTED',
                );
            }
            if ($type === 'update' && array_key_exists('account_id', $statement['assignments'])) {
                throw new FoxyException(
                    'users_schema.account_id is immutable.',
                    'SYSTEM_COLUMN_PROTECTED',
                );
            }
        }
        if ($type === 'set_variable' && $statement['scope'] === 'SESSION') {
            return;
        }
        $this->authentication->assertPrivilege(
            $this->username,
            $privilege,
            $database,
            $table,
            $this->accountId,
        );
    }

    private function handleVirtualTable(array $statement): ?ExecutionResult
    {
        $table = $statement['table'] ?? null;
        if ($table === null) {
            return null;
        }
        if (str_contains($table, '.')) {
            [$database, $name] = explode('.', $table, 2);
        } else {
            $database = $this->currentDatabase ?? '';
            $name = $table;
        }
        if (strtolower($database) !== Authentication::SYSTEM_DATABASE) {
            return null;
        }
        $virtualName = match (strtolower($name)) {
            'information_schema' => 'information_schema',
            'sys' => 'sys',
            default => null,
        };
        if ($virtualName === null) {
            return null;
        }
        return match ($statement['type']) {
            'select' => $virtualName === 'information_schema'
                ? InformationSchema::select($this->storage)
                : SysTable::select($this->config),
            'describe' => $this->describeVirtualTable($virtualName),
            'show_indexes' => ExecutionResult::rows(
                ['column', 'type', 'nullable', 'key', 'default', 'auto_increment'],
                [],
            ),
            'insert', 'update', 'delete', 'drop_table', 'truncate', 'alter_table',
            'create_index', 'drop_index', 'compact', 'optimize', 'defragment',
            'set_auto_increment', 'set_collation', 'rename_table', 'move_table',
            'copy_table', 'analyze', 'check', 'checksum', 'flush',
            'create_policy', 'drop_policy' =>
                throw new Exception\FoxyException(
                    "Virtual table {$virtualName} is read-only.", 'ACCESS_DENIED',
                ),
            default => throw new Exception\FoxyException(
                "Unsupported operation on virtual table {$virtualName}.", 'SQL_UNSUPPORTED',
            ),
        };
    }

    private function describeVirtualTable(string $name): ExecutionResult
    {
        $columns = $name === 'information_schema'
            ? InformationSchema::columns() : SysTable::columns();
        $rows = [];
        foreach ($columns as $column) {
            $rows[] = [
                'column' => $column['name'],
                'type' => $column['type'] . (isset($column['length']) ? '(' . $column['length'] . ')' : ''),
                'nullable' => false,
                'key' => '',
                'default' => null,
                'auto_increment' => false,
            ];
        }
        return ExecutionResult::rows(
            ['column', 'type', 'nullable', 'key', 'default', 'auto_increment'],
            $rows,
        );
    }

    private function table(string $name): Table
    {
        if (str_contains($name, '.')) {
            [$database, $table] = explode('.', $name, 2);
            return $this->storage->table($database, $table);
        }
        return $this->storage->table($this->requireDatabase(), $name);
    }

    public function resetAuthentication(): void
    {
        $this->currentDatabase = null;
        $this->username = null;
        $this->accountId = null;
        $this->sessionVariables = [];
    }

    private function systemValue(string $name, int|string|bool $fallback): int|string|bool
    {
        return $this->systemVariables?->get($name, $this->sessionVariables) ?? $fallback;
    }

    private function mutationMemoryLimit(): int
    {
        return min(
            (int) $this->systemValue('max_heap_table_size', 67_108_864),
            (int) $this->systemValue('tmp_table_size', 67_108_864),
        );
    }

    private function isSystemConfigTable(string $table): bool
    {
        return $this->systemVariables !== null
            && $this->currentDatabase === Authentication::SYSTEM_DATABASE
            && $table === 'sys_config';
    }

    private function protectManagedVariables(?\Closure $predicate): \Closure
    {
        return static function (array $row) use ($predicate): bool {
            $matches = $predicate === null || $predicate($row);
            if ($matches && SystemVariables::isManaged((string) ($row['variable_name'] ?? ''))) {
                throw new FoxyException(
                    'Managed system variables must be changed with SET GLOBAL.',
                    'SYSTEM_VARIABLE_PROTECTED',
                );
            }
            return $matches;
        };
    }

    private function queryCacheKey(array $statement, string $sql, array $parameters): ?string
    {
        if ($this->systemVariables === null || (int) $this->systemValue('query_cache_size', 0) === 0) {
            return null;
        }
        if ($this->containsVolatileExpression($statement)) {
            return null;
        }
        foreach ($parameters as $parameter) {
            if (is_object($parameter) && !$parameter instanceof BinaryValue) {
                return null;
            }
        }
        return hash('sha256', serialize([
            $this->currentDatabase,
            $this->currentDatabase === null
                ? 0
                : $this->storage->tableRevision($this->currentDatabase, $statement['table']),
            $this->accountId,
            $sql,
            $parameters,
            $this->sessionVariables,
        ]));
    }

    private function containsVolatileExpression(array $node): bool
    {
        if (($node['kind'] ?? null) === 'expression'
            && in_array($node['name'] ?? null, ['current_timestamp', 'uuid'], true)) {
            return true;
        }
        foreach ($node as $value) {
            if (is_array($value) && $this->containsVolatileExpression($value)) {
                return true;
            }
        }
        return false;
    }

    private function cacheResult(string $key, ExecutionResult $result): ExecutionResult
    {
        if ($result->kind !== 'rows') {
            return $result;
        }
        $maximum = min(
            (int) $this->systemValue('query_cache_size', 0),
            (int) $this->systemValue('max_heap_table_size', 67_108_864),
        );
        if (is_array($result->rows)) {
            $payload = ['columns' => $result->columns, 'rows' => $result->rows, 'metadata' => $result->metadata];
            $this->storage->queryCachePut($key, $payload, MemoryCache::estimateBytes($payload));
            return $result;
        }
        $rows = (function () use ($result, $key, $maximum): \Generator {
            $captured = [];
            $bytes = 0;
            $cacheable = true;
            foreach ($result->rows as $row) {
                if ($cacheable) {
                    $rowBytes = MemoryCache::estimateBytes($row);
                    if ($bytes + $rowBytes <= $maximum) {
                        $captured[] = $row;
                        $bytes += $rowBytes;
                    } else {
                        $cacheable = false;
                        $captured = [];
                    }
                }
                yield $row;
            }
            if ($cacheable) {
                $payload = ['columns' => $result->columns, 'rows' => $captured, 'metadata' => $result->metadata];
                $this->storage->queryCachePut($key, $payload, MemoryCache::estimateBytes($payload));
            }
        })();
        return ExecutionResult::rows($result->columns, $rows, $result->metadata);
    }

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
            . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }
}
