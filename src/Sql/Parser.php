<?php

declare(strict_types=1);

namespace FoxyDB\Sql;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\MemoryCache;
use FoxyDB\Value\BinaryValue;

final class Parser
{
    private const MAXIMUM_SQL_BYTES = 1_048_576;
    private const STATEMENT_CACHE_BYTES = 4_194_304;

    private array $tokens = [];
    private int $position = 0;
    private int $parameterIndex = 0;
    private int $parameterTotal = 0;
    private int $nestingDepth = 0;
    private int $expressionNodes = 0;
    private readonly MemoryCache $statementCache;
    private static ?MemoryCache $sharedStatementCache = null;

    public function __construct()
    {
        self::$sharedStatementCache ??= new MemoryCache(self::STATEMENT_CACHE_BYTES);
        $this->statementCache = self::$sharedStatementCache;
    }

    public function parse(string $sql): array
    {
        if (strlen($sql) > self::MAXIMUM_SQL_BYTES) {
            throw new FoxyException('SQL text exceeds the 1 MiB limit.', 'SQL_TOO_LARGE');
        }
        $cacheKey = hash('sha256', $sql);
        $cached = $this->statementCache->get($cacheKey);
        if (is_array($cached) && ($cached['sql'] ?? null) === $sql && is_array($cached['statement'] ?? null)) {
            return $cached['statement'];
        }
        $this->tokens = (new Lexer($sql))->tokenize();
        $this->position = 0;
        $this->parameterIndex = 0;
        $this->parameterTotal = 0;
        $this->nestingDepth = 0;
        $this->expressionNodes = 0;
        if ($this->current()->type === 'EOF') {
            throw $this->error('SQL statement is empty.');
        }

        $statement = match (true) {
            $this->matchKeyword('CREATE') => $this->parseCreate(),
            $this->matchKeyword('DROP') => $this->parseDrop(),
            $this->matchKeyword('USE') => ['type' => 'use', 'database' => $this->identifier()],
            $this->matchKeyword('SHOW') => $this->parseShow(),
            $this->matchKeyword('SET') => $this->parseSet(),
            $this->matchKeyword('DESCRIBE') || $this->matchKeyword('DESC') => [
                'type' => 'describe',
                'table' => $this->qualifiedIdentifier(),
            ],
            $this->matchKeyword('INSERT') => $this->parseInsert(),
            $this->matchKeyword('SELECT') => $this->parseSelect(),
            $this->matchKeyword('UPDATE') => $this->parseUpdate(),
            $this->matchKeyword('DELETE') => $this->parseDelete(),
            $this->matchKeyword('TRUNCATE') => $this->parseTruncate(),
            $this->matchKeyword('COMPACT') => $this->parseCompact(),
            $this->matchKeyword('ALTER') => $this->parseAlter(),
            $this->matchKeyword('RENAME') => $this->parseRenameTable(),
            $this->matchKeyword('MOVE') => $this->parseMoveTable(),
            $this->matchKeyword('COPY') => $this->parseCopyTable(),
            $this->matchKeyword('OPTIMIZE') => $this->parseTableMaintenance('optimize'),
            $this->matchKeyword('ANALYZE') => $this->parseTableMaintenance('analyze'),
            $this->matchKeyword('CHECK') => $this->parseCheckTable(),
            $this->matchKeyword('CHECKSUM') => $this->parseCheckTable(),
            $this->matchKeyword('DEFRAGMENT') => $this->parseTableMaintenance('defragment'),
            $this->matchKeyword('FLUSH') => $this->parseFlush(),
            $this->matchKeyword('GRANT') => $this->parseGrant(),
            $this->matchKeyword('REVOKE') => $this->parseRevoke(),
            $this->matchKeyword('BEGIN') => $this->parseBegin(),
            $this->matchKeyword('COMMIT') => $this->parseEndKeyword('commit'),
            $this->matchKeyword('ROLLBACK') => $this->parseEndKeyword('rollback'),
            default => throw $this->error('Unsupported SQL statement.'),
        };

        $this->matchSymbol(';');
        if ($this->current()->type !== 'EOF') {
            throw $this->error('Unexpected token after the SQL statement.');
        }
        $statement['parameter_count'] = $this->parameterIndex;
        $this->statementCache->put($cacheKey, ['sql' => $sql, 'statement' => $statement]);
        return $statement;
    }

    public function cacheStatistics(): array
    {
        return $this->statementCache->statistics();
    }

    private function parseCreate(): array
    {
        if ($this->matchKeyword('DATABASE')) {
            $ifNotExists = $this->parseIfNotExists();
            return [
                'type' => 'create_database',
                'database' => $this->identifier(),
                'if_not_exists' => $ifNotExists,
            ];
        }
        if ($this->matchKeyword('TABLE')) {
            return $this->parseCreateTable();
        }
        if ($this->matchKeyword('ROLE')) {
            return ['type' => 'create_role', 'role' => $this->identifier()];
        }
        if ($this->matchKeyword('POLICY')) {
            return $this->parseCreatePolicy();
        }

        $unique = $this->matchKeyword('UNIQUE');
        if (!$this->matchKeyword('INDEX') && !$this->matchKeyword('KEY')) {
            throw $this->error('Expected DATABASE, TABLE, or INDEX after CREATE.');
        }
        $ifNotExists = $this->parseIfNotExists();
        $name = $this->identifier();
        $this->expectKeyword('ON');
        $table = $this->identifier();
        return [
            'type' => 'create_index',
            'name' => $name,
            'table' => $table,
            'columns' => $this->parseColumnList(),
            'unique' => $unique,
            'if_not_exists' => $ifNotExists,
        ];
    }

    private function parseCreateTable(): array
    {
        $ifNotExists = $this->parseIfNotExists();
        $name = $this->identifier();
        $this->expectSymbol('(');
        $columns = [];
        $constraints = [];
        if (!$this->peekSymbol(')')) {
            do {
                if ($this->isTableConstraint()) {
                    $constraints[] = $this->parseTableConstraint();
                } else {
                    $columns[] = $this->parseColumnDefinition();
                }
            } while ($this->matchSymbol(','));
        }
        $this->expectSymbol(')');
        return [
            'type' => 'create_table',
            'table' => $name,
            'if_not_exists' => $ifNotExists,
            'definition' => ['columns' => $columns, 'constraints' => $constraints],
        ];
    }

    private function parseColumnDefinition(): array
    {
        $name = $this->identifier();
        $typeToken = $this->current();
        $type = strtoupper($this->identifier());
        if ($type === 'DOUBLE') {
            $this->matchKeyword('PRECISION');
        }
        $length = null;
        if ($this->matchSymbol('(')) {
            $lengthToken = $this->current();
            if ($lengthToken->type !== 'NUMBER' || preg_match('/^\d+$/', (string) $lengthToken->value) !== 1) {
                throw $this->error('A column length must be a positive integer.');
            }
            $length = (int) $lengthToken->value;
            $this->advance();
            $this->expectSymbol(')');
        }

        $column = [
            'name' => $name,
            'type' => $type,
            'length' => $length,
            'nullable' => true,
            'auto_increment' => false,
            'primary' => false,
            'unique' => false,
            'index' => false,
        ];
        $nullSpecified = false;
        while (!$this->peekSymbol(',') && !$this->peekSymbol(')') && $this->current()->type !== 'EOF') {
            if ($this->matchKeyword('NOT')) {
                $this->expectKeyword('NULL');
                if ($nullSpecified && $column['nullable']) {
                    throw $this->error('Conflicting NULL modifiers.');
                }
                $column['nullable'] = false;
                $nullSpecified = true;
                continue;
            }
            if ($this->matchKeyword('NULL')) {
                if ($nullSpecified && !$column['nullable']) {
                    throw $this->error('Conflicting NULL modifiers.');
                }
                $column['nullable'] = true;
                $nullSpecified = true;
                continue;
            }
            if ($this->matchKeyword('PRIMARY')) {
                $this->expectKeyword('KEY');
                $column['primary'] = true;
                $column['nullable'] = false;
                continue;
            }
            if ($this->matchKeyword('UNIQUE')) {
                $this->matchKeyword('KEY');
                $column['unique'] = true;
                continue;
            }
            if ($this->matchKeyword('AUTO_INCREMENT')) {
                $column['auto_increment'] = true;
                continue;
            }
            if ($this->matchKeyword('AUTO')) {
                $this->expectKeyword('INCREMENT');
                $column['auto_increment'] = true;
                continue;
            }
            if ($this->matchKeyword('DEFAULT')) {
                if (array_key_exists('default', $column)) {
                    throw $this->error('A column can have only one default.');
                }
                $column['default'] = $this->defaultFromNode($this->parseValueNode(false));
                continue;
            }
            if ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
                $column['index'] = true;
                continue;
            }
            throw $this->error("Unexpected column modifier after {$typeToken->value}.");
        }
        return $column;
    }

    private function parseTableConstraint(): array
    {
        $constraintName = null;
        if ($this->matchKeyword('CONSTRAINT')) {
            $constraintName = $this->identifier();
        }
        if ($this->matchKeyword('PRIMARY')) {
            $this->expectKeyword('KEY');
            return [
                'kind' => 'primary',
                'name' => 'primary',
                'columns' => $this->parseColumnList(),
            ];
        }
        if ($this->matchKeyword('UNIQUE')) {
            $this->matchKeyword('INDEX') || $this->matchKeyword('KEY');
            $name = $constraintName;
            if (!$this->peekSymbol('(')) {
                $name = $this->identifier();
            }
            return ['kind' => 'unique', 'name' => $name, 'columns' => $this->parseColumnList()];
        }
        if ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
            $name = $constraintName;
            if (!$this->peekSymbol('(')) {
                $name = $this->identifier();
            }
            return ['kind' => 'index', 'name' => $name, 'columns' => $this->parseColumnList()];
        }
        throw $this->error('Invalid table constraint.');
    }

    private function parseDrop(): array
    {
        if ($this->matchKeyword('DATABASE')) {
            $ifExists = $this->parseIfExists();
            return ['type' => 'drop_database', 'database' => $this->identifier(), 'if_exists' => $ifExists];
        }
        if ($this->matchKeyword('TABLE')) {
            $ifExists = $this->parseIfExists();
            return ['type' => 'drop_table', 'table' => $this->qualifiedIdentifier(), 'if_exists' => $ifExists];
        }
        if ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
            $ifExists = $this->parseIfExists();
            $name = $this->identifier();
            $this->expectKeyword('ON');
            return [
                'type' => 'drop_index',
                'name' => $name,
                'table' => $this->qualifiedIdentifier(),
                'if_exists' => $ifExists,
            ];
        }
        if ($this->matchKeyword('ROLE')) {
            return ['type' => 'drop_role', 'role' => $this->identifier()];
        }
        if ($this->matchKeyword('POLICY')) {
            return $this->parseDropPolicy();
        }
        throw $this->error('Expected DATABASE, TABLE, INDEX, ROLE, or POLICY after DROP.');
    }

    private function parseShow(): array
    {
        $scope = 'SESSION';
        if ($this->matchKeyword('GLOBAL')) {
            $scope = 'GLOBAL';
        } elseif ($this->matchKeyword('SESSION')) {
            $scope = 'SESSION';
        }
        if ($this->matchKeyword('VARIABLES')) {
            $pattern = null;
            if ($this->matchKeyword('LIKE')) {
                $pattern = $this->parseValueNode(false);
            }
            return ['type' => 'show_variables', 'scope' => $scope, 'pattern' => $pattern];
        }
        if ($this->matchKeyword('DATABASES')) {
            return ['type' => 'show_databases'];
        }
        if ($this->matchKeyword('TABLES')) {
            $database = null;
            if ($this->matchKeyword('FROM') || $this->matchKeyword('IN')) {
                $database = $this->identifier();
            }
            return ['type' => 'show_tables', 'database' => $database];
        }
        if ($this->matchKeyword('INDEX') || $this->matchKeyword('INDEXES') || $this->matchKeyword('KEYS')) {
            $this->expectKeyword('FROM');
            return ['type' => 'show_indexes', 'table' => $this->qualifiedIdentifier()];
        }
        throw $this->error('Expected DATABASES, TABLES, or INDEXES after SHOW.');
    }

    private function parseSet(): array
    {
        $scope = 'SESSION';
        if ($this->matchKeyword('GLOBAL')) {
            $scope = 'GLOBAL';
        } elseif ($this->matchKeyword('SESSION') || $this->matchKeyword('LOCAL')) {
            $scope = 'SESSION';
        }
        $name = $this->identifier();
        $this->expectSymbol('=');
        return [
            'type' => 'set_variable',
            'scope' => $scope,
            'name' => $name,
            'value' => $this->parseValueNode(false),
        ];
    }

    private function parseInsert(): array
    {
        $this->expectKeyword('INTO');
        $table = $this->qualifiedIdentifier();
        $columns = null;
        if ($this->peekSymbol('(')) {
            $columns = $this->parseColumnList();
        }
        if ($this->matchKeyword('DEFAULT')) {
            $this->expectKeyword('VALUES');
            return ['type' => 'insert', 'table' => $table, 'columns' => [], 'rows' => [[]]];
        }
        $this->expectKeyword('VALUES');
        $rows = [];
        do {
            $this->expectSymbol('(');
            $values = [];
            if (!$this->peekSymbol(')')) {
                do {
                    $values[] = $this->parseValueNode(true);
                } while ($this->matchSymbol(','));
            }
            $this->expectSymbol(')');
            $rows[] = $values;
        } while ($this->matchSymbol(','));
        return ['type' => 'insert', 'table' => $table, 'columns' => $columns, 'rows' => $rows];
    }

    private function parseSelect(): array
    {
        $projections = [];
        if ($this->matchSymbol('*')) {
            $projections[] = ['kind' => 'all'];
        } else {
            do {
                $upper = $this->current()->type === 'IDENTIFIER'
                    ? strtoupper((string) $this->current()->value) : '';
                if (in_array($upper, ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX'], true)
                    && $this->isFunctionStart()) {
                    $func = strtolower($this->identifier());
                    $this->expectSymbol('(');
                    $column = $this->matchSymbol('*') ? null : $this->qualifiedIdentifier();
                    $this->expectSymbol(')');
                    $alias = $column !== null ? $func . '_' . $column : $func;
                    $projection = ['kind' => $func, 'column' => $column, 'alias' => $alias];
                } elseif ($this->current()->type === 'NUMBER' || $this->current()->type === 'STRING') {
                    $value = $this->parseValueNode(false);
                    $col = (string)($value['value'] ?? '?');
                    $projection = ['kind' => 'value', 'value' => $value, 'alias' => $col];
                } else {
                    $column = $this->qualifiedIdentifier();
                    $projection = ['kind' => 'column', 'column' => $column, 'alias' => $column];
                }
                if ($this->matchKeyword('AS')) {
                    $projection['alias'] = $this->identifier();
                }
                $projections[] = $projection;
            } while ($this->matchSymbol(','));
        }
        $this->expectKeyword('FROM');
        $joins = [];
        do {
            $table = $this->qualifiedIdentifier();
            $alias = null;
            if ($this->matchKeyword('AS')) {
                $alias = $this->identifier();
            } elseif ($this->current()->type === 'IDENTIFIER'
                && !in_array(strtoupper($this->current()->value), [
                    'WHERE', 'ORDER', 'LIMIT', 'OFFSET', 'GROUP', 'HAVING',
                    'INNER', 'LEFT', 'RIGHT', 'JOIN', 'CROSS', 'OUTER', 'ON',
                    'AND', 'OR', 'NOT', 'IN', 'IS', 'LIKE', 'BETWEEN', 'EXISTS',
                    'GROUP', 'HAVING', 'SUM', 'AVG', 'MIN', 'MAX', 'COUNT',
                ], true)) {
                $alias = $this->identifier();
            }
            $joins[] = ['table' => $table, 'alias' => $alias];
        } while ($this->matchSymbol(','));

        $left = false;
        $right = false;
        while (($this->matchKeyword('INNER') || $this->matchKeyword('CROSS'))
            || ($left = $this->matchKeyword('LEFT'))
            || ($right = $this->matchKeyword('RIGHT'))) {
            if ($left || $right) {
                $this->matchKeyword('OUTER');
            }
            $this->expectKeyword('JOIN');
            $table = $this->qualifiedIdentifier();
            $alias = null;
            if ($this->matchKeyword('AS')) {
                $alias = $this->identifier();
            } elseif ($this->current()->type === 'IDENTIFIER'
                && !in_array(strtoupper($this->current()->value), [
                    'ON', 'INNER', 'LEFT', 'RIGHT', 'JOIN', 'CROSS', 'OUTER',
                    'WHERE', 'ORDER', 'LIMIT', 'OFFSET', 'GROUP', 'HAVING',
                ], true)) {
                $alias = $this->identifier();
            }
            $this->expectKeyword('ON');
            $on = $this->parseExpression();
            $joinType = $right ? 'right' : ($left ? 'left' : 'inner');
            $joins[] = ['table' => $table, 'alias' => $alias, 'join' => $joinType, 'on' => $on];
        }
        $where = $this->matchKeyword('WHERE') ? $this->parseExpression() : null;
        $group = [];
        if ($this->matchKeyword('GROUP')) {
            $this->expectKeyword('BY');
            do {
                $group[] = $this->qualifiedIdentifier();
            } while ($this->matchSymbol(','));
        }
        $having = $this->matchKeyword('HAVING') ? $this->parseExpression() : null;
        $order = [];
        if ($this->matchKeyword('ORDER')) {
            $this->expectKeyword('BY');
            do {
                $column = $this->identifier();
                $direction = 'asc';
                if ($this->matchKeyword('ASC')) {
                    $direction = 'asc';
                } elseif ($this->matchKeyword('DESC')) {
                    $direction = 'desc';
                }
                $order[] = ['column' => $column, 'direction' => $direction];
            } while ($this->matchSymbol(','));
        }
        $limit = null;
        $offset = null;
        if ($this->matchKeyword('LIMIT')) {
            $first = $this->parseValueNode(false);
            if ($this->matchSymbol(',')) {
                $offset = $first;
                $limit = $this->parseValueNode(false);
            } else {
                $limit = $first;
            }
        }
        if ($this->matchKeyword('OFFSET')) {
            if ($offset !== null) {
                throw $this->error('OFFSET was specified more than once.');
            }
            $offset = $this->parseValueNode(false);
        }
        $from = $joins;
        $table = count($from) === 1 && !array_key_exists('join', $from[0]) ? $from[0]['table'] : null;
        return [
            'type' => 'select',
            'table' => $table,
            'from' => $from,
            'projections' => $projections,
            'where' => $where,
            'group' => $group,
            'having' => $having,
            'order' => $order,
            'limit' => $limit,
            'offset' => $offset,
        ];
    }

    private function parseUpdate(): array
    {
        $table = $this->qualifiedIdentifier();
        $this->expectKeyword('SET');
        $assignments = [];
        do {
            $column = $this->identifier();
            if (isset($assignments[$column])) {
                throw $this->error("Column {$column} is assigned more than once.");
            }
            $this->expectSymbol('=');
            $assignments[$column] = $this->parseValueNode(false);
        } while ($this->matchSymbol(','));
        $where = $this->matchKeyword('WHERE') ? $this->parseExpression() : null;
        return ['type' => 'update', 'table' => $table, 'assignments' => $assignments, 'where' => $where];
    }

    private function parseDelete(): array
    {
        $this->expectKeyword('FROM');
        $table = $this->qualifiedIdentifier();
        $where = $this->matchKeyword('WHERE') ? $this->parseExpression() : null;
        return ['type' => 'delete', 'table' => $table, 'where' => $where];
    }

    private function parseTruncate(): array
    {
        $this->matchKeyword('TABLE');
        return ['type' => 'truncate', 'table' => $this->qualifiedIdentifier()];
    }

    private function parseCompact(): array
    {
        $this->expectKeyword('TABLE');
        return ['type' => 'compact', 'table' => $this->qualifiedIdentifier()];
    }

    private function parseAlter(): array
    {
        $this->expectKeyword('TABLE');
        $table = $this->qualifiedIdentifier();
        $actions = [];
        do {
            if ($this->matchKeyword('AUTO_INCREMENT')) {
                $this->expectSymbol('=');
                $actions[] = ['kind' => 'set_auto_increment', 'value' => $this->parseValueNode(false)];
                continue;
            }
            if ($this->matchKeyword('COLLATE') || $this->matchKeyword('COLLATION')) {
                $actions[] = ['kind' => 'set_collation', 'value' => $this->identifier()];
                continue;
            }
            if ($this->matchKeyword('ADD')) {
                $this->matchKeyword('COLUMN');
                if ($this->matchKeyword('CONSTRAINT')) {
                    $constraint = $this->parseTableConstraint();
                    $actions[] = ['kind' => 'add_constraint', 'constraint' => $constraint];
                } elseif ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
                    $name = $this->identifier();
                    $this->expectSymbol('(');
                    $columns = $this->parseColumnList();
                    $actions[] = ['kind' => 'add_index', 'name' => $name, 'columns' => $columns, 'unique' => false];
                } elseif ($this->matchKeyword('UNIQUE')) {
                    $this->matchKeyword('INDEX') || $this->matchKeyword('KEY');
                    $name = $this->identifier();
                    $this->expectSymbol('(');
                    $columns = $this->parseColumnList();
                    $actions[] = ['kind' => 'add_index', 'name' => $name, 'columns' => $columns, 'unique' => true];
                } elseif ($this->matchKeyword('PRIMARY')) {
                    $this->expectKeyword('KEY');
                    $this->expectSymbol('(');
                    $columns = $this->parseColumnList();
                    $actions[] = ['kind' => 'add_primary', 'columns' => $columns];
                } else {
                    $column = $this->parseColumnDefinition();
                    $actions[] = ['kind' => 'add_column', 'column' => $column];
                }
                continue;
            }
            if ($this->matchKeyword('DROP')) {
                $this->matchKeyword('COLUMN');
                if ($this->matchKeyword('PRIMARY')) {
                    $this->expectKeyword('KEY');
                    $actions[] = ['kind' => 'drop_primary'];
                } elseif ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
                    $actions[] = ['kind' => 'drop_index', 'name' => $this->identifier()];
                } elseif ($this->matchKeyword('CONSTRAINT')) {
                    $actions[] = ['kind' => 'drop_constraint', 'name' => $this->identifier()];
                } else {
                    $actions[] = ['kind' => 'drop_column', 'name' => $this->identifier()];
                }
                continue;
            }
            if ($this->matchKeyword('MODIFY')) {
                $this->matchKeyword('COLUMN');
                $column = $this->parseColumnDefinition();
                $actions[] = ['kind' => 'modify_column', 'column' => $column];
                continue;
            }
            if ($this->matchKeyword('CHANGE')) {
                $this->matchKeyword('COLUMN');
                $oldName = $this->identifier();
                $column = $this->parseColumnDefinition();
                $actions[] = ['kind' => 'change_column', 'old_name' => $oldName, 'column' => $column];
                continue;
            }
            if ($this->matchKeyword('RENAME')) {
                if ($this->matchKeyword('TO')) {
                    $actions[] = ['kind' => 'rename_table', 'new_name' => $this->identifier()];
                } elseif ($this->matchKeyword('COLUMN')) {
                    $oldName = $this->identifier();
                    $this->expectKeyword('TO');
                    $newName = $this->identifier();
                    $actions[] = ['kind' => 'rename_column', 'old_name' => $oldName, 'new_name' => $newName];
                } elseif ($this->matchKeyword('INDEX') || $this->matchKeyword('KEY')) {
                    $oldName = $this->identifier();
                    $this->expectKeyword('TO');
                    $newName = $this->identifier();
                    $actions[] = ['kind' => 'rename_index', 'old_name' => $oldName, 'new_name' => $newName];
                } else {
                    throw $this->error('Expected TO, COLUMN, or INDEX after RENAME in ALTER TABLE.');
                }
                continue;
            }
            throw $this->error('Unsupported ALTER TABLE clause.');
        } while ($this->matchSymbol(','));

        return ['type' => 'alter_table', 'table' => $table, 'actions' => $actions];
    }

    private function parseRenameTable(): array
    {
        $this->expectKeyword('TABLE');
        $oldName = $this->qualifiedIdentifier();
        $this->expectKeyword('TO');
        return ['type' => 'rename_table', 'table' => $oldName, 'new_name' => $this->identifier()];
    }

    private function parseMoveTable(): array
    {
        $this->expectKeyword('TABLE');
        $table = $this->qualifiedIdentifier();
        $this->expectKeyword('TO');
        $targetDatabase = $this->identifier();
        $targetTable = null;
        if ($this->matchSymbol('.')) {
            $targetTable = $this->identifier();
        }
        return [
            'type' => 'move_table',
            'table' => $table,
            'target_database' => $targetDatabase,
            'target_table' => $targetTable,
        ];
    }

    private function parseCopyTable(): array
    {
        $this->expectKeyword('TABLE');
        $table = $this->qualifiedIdentifier();
        $this->expectKeyword('TO');
        $targetDatabase = $this->identifier();
        $targetTable = null;
        if ($this->matchSymbol('.')) {
            $targetTable = $this->identifier();
        }
        return [
            'type' => 'copy_table',
            'table' => $table,
            'target_database' => $targetDatabase,
            'target_table' => $targetTable,
        ];
    }

    private function parseTableMaintenance(string $type): array
    {
        $this->matchKeyword('TABLE');
        return ['type' => $type, 'table' => $this->qualifiedIdentifier()];
    }

    private function parseCheckTable(): array
    {
        $type = strtolower((string) $this->tokens[$this->position - 1]->value);
        $this->matchKeyword('TABLE');
        return ['type' => $type, 'table' => $this->qualifiedIdentifier()];
    }

    private function parseFlush(): array
    {
        $this->matchKeyword('TABLE');
        $this->matchKeyword('TABLES');
        $table = null;
        if ($this->current()->type === 'IDENTIFIER') {
            $table = $this->qualifiedIdentifier();
        }
        return ['type' => 'flush', 'table' => $table];
    }

    private function parseExpression(): array
    {
        return $this->parseOr();
    }

    private function parseOr(): array
    {
        $expression = $this->parseAnd();
        while ($this->matchKeyword('OR')) {
            $expression = [
                'kind' => 'logical',
                'operator' => 'or',
                'left' => $expression,
                'right' => $this->parseAnd(),
            ];
        }
        return $expression;
    }

    private function parseAnd(): array
    {
        $expression = $this->parseNot();
        while ($this->matchKeyword('AND')) {
            $expression = [
                'kind' => 'logical',
                'operator' => 'and',
                'left' => $expression,
                'right' => $this->parseNot(),
            ];
        }
        return $expression;
    }

    private function parseNot(): array
    {
        if ($this->matchKeyword('NOT')) {
            $this->enterExpression();
            $this->enterNesting();
            try {
                return ['kind' => 'not', 'expression' => $this->parseNot()];
            } finally {
                $this->nestingDepth--;
            }
        }
        if ($this->peekSymbol('(') && $this->peekKeyword('SELECT', 1)) {
            $this->matchSymbol('(');
            $this->matchKeyword('SELECT');
            $this->enterNesting();
            try {
                $subquery = $this->parseSelect();
                $this->expectSymbol(')');
            } finally {
                $this->nestingDepth--;
            }
            return ['kind' => 'subquery', 'subquery' => $subquery];
        }
        if ($this->matchSymbol('(')) {
            $this->enterNesting();
            try {
                $expression = $this->parseExpression();
                $this->expectSymbol(')');
            } finally {
                $this->nestingDepth--;
            }
            if ($expression['kind'] === 'truthy' && $this->startsPredicateSuffix()) {
                return $this->parsePredicateFrom($expression['operand']);
            }
            return $expression;
        }
        return $this->parsePredicate();
    }

    private function parsePredicate(): array
    {
        $this->enterExpression();
        if ($this->matchKeyword('EXISTS')) {
            $this->expectSymbol('(');
            $this->matchKeyword('SELECT');
            $this->enterNesting();
            try {
                $subquery = $this->parseSelect();
                $this->expectSymbol(')');
            } finally {
                $this->nestingDepth--;
            }
            return ['kind' => 'exists', 'subquery' => $subquery];
        }
        return $this->parsePredicateFrom($this->parseOperand());
    }

    private function parsePredicateFrom(array $left): array
    {
        if ($this->matchKeyword('IS')) {
            $not = $this->matchKeyword('NOT');
            $this->expectKeyword('NULL');
            return ['kind' => 'is_null', 'operand' => $left, 'not' => $not];
        }

        $not = false;
        if ($this->matchKeyword('NOT')) {
            $not = true;
        }
        if ($this->matchKeyword('IN')) {
            $this->expectSymbol('(');
            if ($this->matchKeyword('SELECT')) {
                $subquery = $this->parseSelect();
                $this->expectSymbol(')');
                return ['kind' => 'in_subquery', 'operand' => $left, 'subquery' => $subquery, 'not' => $not];
            }
            $values = [];
            if (!$this->peekSymbol(')')) {
                do {
                    $values[] = $this->parseOperand();
                } while ($this->matchSymbol(','));
            }
            $this->expectSymbol(')');
            if ($values === []) {
                throw $this->error('IN requires at least one value or subquery.');
            }
            return ['kind' => 'in', 'operand' => $left, 'values' => $values, 'not' => $not];
        }
        if ($this->matchKeyword('LIKE')) {
            return ['kind' => 'like', 'operand' => $left, 'pattern' => $this->parseOperand(), 'not' => $not];
        }
        if ($not) {
            throw $this->error('Expected IN or LIKE after NOT.');
        }

        $token = $this->current();
        if ($token->type === 'SYMBOL' && in_array($token->value, ['=', '!=', '<>', '<', '<=', '>', '>='], true)) {
            $this->advance();
            return [
                'kind' => 'comparison',
                'operator' => $token->value,
                'left' => $left,
                'right' => $this->parseOperand(),
            ];
        }
        return ['kind' => 'truthy', 'operand' => $left];
    }

    private function parseOperand(): array
    {
        if ($this->peekSymbol('(') && $this->peekKeyword('SELECT', 1)) {
            $this->matchSymbol('(');
            $this->matchKeyword('SELECT');
            $this->enterNesting();
            try {
                $subquery = $this->parseSelect();
                $this->expectSymbol(')');
            } finally {
                $this->nestingDepth--;
            }
            return ['kind' => 'subquery', 'subquery' => $subquery];
        }
        if ($this->canStartValue()) {
            return $this->parseValueNode(false);
        }
        if ($this->current()->type === 'IDENTIFIER') {
            return ['kind' => 'column', 'name' => $this->qualifiedIdentifier()];
        }
        throw $this->error('Expected a column or value.');
    }

    private function parseValueNode(bool $allowDefault): array
    {
        $sign = 1;
        if ($this->matchSymbol('-')) {
            $sign = -1;
        } elseif ($this->matchSymbol('+')) {
            $sign = 1;
        }
        $token = $this->current();
        if ($token->type === 'NUMBER') {
            $this->advance();
            $number = (string) $token->value;
            if (str_contains($number, '.') || stripos($number, 'e') !== false) {
                $value = (float) $number * $sign;
                if (!is_finite($value)) {
                    throw $this->error('Numeric literal is outside the supported range.', $token);
                }
            } else {
                $signed = $sign < 0 ? '-' . $number : $number;
                $validated = filter_var($signed, FILTER_VALIDATE_INT);
                $value = $validated === false ? $signed : (int) $validated;
            }
            return ['kind' => 'literal', 'value' => $value];
        }
        if ($sign < 0 || $this->previousSymbol('+')) {
            throw $this->error('A sign can only precede a number.', $token);
        }
        if ($token->type === 'STRING') {
            $this->advance();
            return ['kind' => 'literal', 'value' => $token->value];
        }
        if ($token->type === 'BINARY') {
            $this->advance();
            return ['kind' => 'literal', 'value' => new BinaryValue($token->value)];
        }
        if ($token->type === 'PARAMETER') {
            $this->advance();
            if (++$this->parameterTotal > 65_535) {
                throw $this->error('SQL statement contains too many parameters.', $token);
            }
            $key = $token->value ?? $this->parameterIndex++;
            return ['kind' => 'parameter', 'key' => $key];
        }
        if ($this->matchKeyword('NULL')) {
            return ['kind' => 'literal', 'value' => null];
        }
        if ($this->matchKeyword('TRUE')) {
            return ['kind' => 'literal', 'value' => true];
        }
        if ($this->matchKeyword('FALSE')) {
            return ['kind' => 'literal', 'value' => false];
        }
        if ($this->matchKeyword('ON')) {
            return ['kind' => 'literal', 'value' => true];
        }
        if ($this->matchKeyword('OFF')) {
            return ['kind' => 'literal', 'value' => false];
        }
        if ($allowDefault && $this->matchKeyword('DEFAULT')) {
            return ['kind' => 'default'];
        }
        if ($this->matchKeyword('CURRENT_TIMESTAMP')) {
            if ($this->matchSymbol('(')) {
                $this->expectSymbol(')');
            }
            return ['kind' => 'expression', 'name' => 'current_timestamp'];
        }
        if ($this->matchKeyword('UUID')) {
            $this->expectSymbol('(');
            $this->expectSymbol(')');
            return ['kind' => 'expression', 'name' => 'uuid'];
        }
        throw $this->error('Expected a literal value or parameter.');
    }

    private function defaultFromNode(array $node): mixed
    {
        if ($node['kind'] === 'literal') {
            return $node['value'];
        }
        if ($node['kind'] === 'expression') {
            return ['expression' => $node['name']];
        }
        throw $this->error('A default must be a literal or supported expression.');
    }

    private function canStartValue(): bool
    {
        $token = $this->current();
        if (in_array($token->type, ['NUMBER', 'STRING', 'BINARY', 'PARAMETER'], true)) {
            return true;
        }
        if ($token->type === 'SYMBOL' && in_array($token->value, ['+', '-'], true)) {
            return true;
        }
        return $token->type === 'IDENTIFIER'
            && !$token->quoted
            && in_array(
                strtoupper((string) $token->value),
                ['NULL', 'TRUE', 'FALSE', 'ON', 'OFF', 'CURRENT_TIMESTAMP', 'UUID'],
                true,
            );
    }

    private function parseColumnList(): array
    {
        $this->expectSymbol('(');
        $columns = [];
        do {
            $columns[] = $this->identifier();
        } while ($this->matchSymbol(','));
        $this->expectSymbol(')');
        return $columns;
    }

    private function isTableConstraint(): bool
    {
        return $this->peekKeyword('PRIMARY') || $this->peekKeyword('UNIQUE')
            || $this->peekKeyword('INDEX') || $this->peekKeyword('KEY') || $this->peekKeyword('CONSTRAINT');
    }

    private function parseIfNotExists(): bool
    {
        if (!$this->matchKeyword('IF')) {
            return false;
        }
        $this->expectKeyword('NOT');
        $this->expectKeyword('EXISTS');
        return true;
    }

    private function parseIfExists(): bool
    {
        if (!$this->matchKeyword('IF')) {
            return false;
        }
        $this->expectKeyword('EXISTS');
        return true;
    }

    private function identifier(): string
    {
        $token = $this->current();
        if ($token->type !== 'IDENTIFIER') {
            throw $this->error('Expected an identifier.');
        }
        $this->advance();
        return strtolower((string) $token->value);
    }

    private function qualifiedIdentifier(): string
    {
        $name = $this->identifier();
        if ($this->matchSymbol('.')) {
            $name .= '.' . $this->identifier();
        }
        return $name;
    }

    private function expectKeyword(string $keyword): void
    {
        if (!$this->matchKeyword($keyword)) {
            throw $this->error("Expected keyword {$keyword}.");
        }
    }

    private function matchKeyword(string $keyword): bool
    {
        if (!$this->peekKeyword($keyword)) {
            return false;
        }
        $this->advance();
        return true;
    }

    private function peekKeyword(string $keyword, int $distance = 0): bool
    {
        $token = $this->tokens[$this->position + $distance] ?? end($this->tokens);
        return $token->type === 'IDENTIFIER' && !$token->quoted
            && strtoupper((string) $token->value) === $keyword;
    }

    private function expectSymbol(string $symbol): void
    {
        if (!$this->matchSymbol($symbol)) {
            throw $this->error("Expected symbol {$symbol}.");
        }
    }

    private function matchSymbol(string $symbol): bool
    {
        if (!$this->peekSymbol($symbol)) {
            return false;
        }
        $this->advance();
        return true;
    }

    private function peekSymbol(string $symbol, int $distance = 0): bool
    {
        $token = $this->tokens[$this->position + $distance] ?? end($this->tokens);
        return $token->type === 'SYMBOL' && $token->value === $symbol;
    }

    private function previousSymbol(string $symbol): bool
    {
        $token = $this->tokens[$this->position - 1] ?? null;
        return $token instanceof Token && $token->type === 'SYMBOL' && $token->value === $symbol;
    }

    private function current(): Token
    {
        return $this->tokens[$this->position];
    }

    private function advance(): Token
    {
        return $this->tokens[$this->position++];
    }

    private function isFunctionStart(): bool
    {
        return $this->peekSymbol('(', 1);
    }

    private function error(string $message, ?Token $token = null): FoxyException
    {
        $token ??= $this->current();
        return new FoxyException($message, 'SQL_SYNTAX', [
            'offset' => $token->offset,
            'line' => $token->line,
            'column' => $token->column,
        ]);
    }

    private function startsPredicateSuffix(): bool
    {
        $token = $this->current();
        return ($token->type === 'SYMBOL' && in_array($token->value, ['=', '!=', '<>', '<', '<=', '>', '>='], true))
            || $this->peekKeyword('IS') || $this->peekKeyword('NOT')
            || $this->peekKeyword('IN') || $this->peekKeyword('LIKE');
    }

    private function enterNesting(): void
    {
        if (++$this->nestingDepth > 128) {
            throw $this->error('SQL expression nesting exceeds 128 levels.');
        }
    }

    private function enterExpression(): void
    {
        if (++$this->expressionNodes > 4_096) {
            throw $this->error('SQL expression is too complex.');
        }
    }

    private function parseGrant(): array
    {
        $isPrivilege = $this->peekKeyword('ALL') || $this->peekKeyword('SELECT')
            || $this->peekKeyword('INSERT') || $this->peekKeyword('UPDATE')
            || $this->peekKeyword('DELETE') || $this->peekKeyword('CREATE')
            || $this->peekKeyword('DROP') || $this->peekKeyword('ALTER')
            || $this->peekKeyword('INDEX') || $this->peekKeyword('CONNECT')
            || $this->peekKeyword('SHOW') || $this->peekKeyword('TRUNCATE');
        if ($isPrivilege) {
            $privilege = strtoupper($this->identifier());
            $this->expectKeyword('ON');
            $database = $this->identifier();
            $table = '*';
            if ($this->matchSymbol('.')) {
                if ($this->peekSymbol('*')) {
                    $this->matchSymbol('*');
                } else {
                    $table = $this->identifier();
                }
            } else {
                $table = $database;
                $database = '*';
            }
            $this->expectKeyword('TO');
            $grantee = $this->identifier();
            return [
                'type' => 'grant',
                'kind' => 'privilege',
                'privilege' => $privilege,
                'database' => $database,
                'table' => $table,
                'grantee' => $grantee,
            ];
        }
        $role = $this->identifier();
        $this->expectKeyword('TO');
        $grantee = $this->identifier();
        return [
            'type' => 'grant',
            'kind' => 'role',
            'role' => $role,
            'grantee' => $grantee,
        ];
    }

    private function parseRevoke(): array
    {
        $isPrivilege = $this->peekKeyword('ALL') || $this->peekKeyword('SELECT')
            || $this->peekKeyword('INSERT') || $this->peekKeyword('UPDATE')
            || $this->peekKeyword('DELETE') || $this->peekKeyword('CREATE')
            || $this->peekKeyword('DROP') || $this->peekKeyword('ALTER')
            || $this->peekKeyword('INDEX') || $this->peekKeyword('CONNECT')
            || $this->peekKeyword('SHOW') || $this->peekKeyword('TRUNCATE');
        if ($isPrivilege) {
            $privilege = strtoupper($this->identifier());
            $this->expectKeyword('ON');
            $database = $this->identifier();
            $table = '*';
            if ($this->matchSymbol('.')) {
                if ($this->peekSymbol('*')) {
                    $this->matchSymbol('*');
                } else {
                    $table = $this->identifier();
                }
            } else {
                $table = $database;
                $database = '*';
            }
            $this->expectKeyword('FROM');
            $grantee = $this->identifier();
            return [
                'type' => 'revoke',
                'kind' => 'privilege',
                'privilege' => $privilege,
                'database' => $database,
                'table' => $table,
                'grantee' => $grantee,
            ];
        }
        $role = $this->identifier();
        $this->expectKeyword('FROM');
        $grantee = $this->identifier();
        return [
            'type' => 'revoke',
            'kind' => 'role',
            'role' => $role,
            'grantee' => $grantee,
        ];
    }

    private function parseCreatePolicy(): array
    {
        $name = $this->identifier();
        $this->expectKeyword('ON');
        $table = $this->qualifiedIdentifier();
        $this->expectKeyword('FOR');
        $operation = strtoupper($this->identifier());
        if (!in_array($operation, ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ALL'], true)) {
            throw $this->error("Expected SELECT, INSERT, UPDATE, DELETE, or ALL after FOR.");
        }
        $this->expectKeyword('USING');
        $this->expectSymbol('(');
        $expression = $this->parseExpression();
        $this->expectSymbol(')');
        return [
            'type' => 'create_policy',
            'name' => $name,
            'table' => $table,
            'operation' => $operation,
            'expression' => $expression,
        ];
    }

    private function parseDropPolicy(): array
    {
        $name = $this->identifier();
        $ifExists = $this->parseIfExists();
        $this->expectKeyword('ON');
        $table = $this->qualifiedIdentifier();
        return [
            'type' => 'drop_policy',
            'name' => $name,
            'if_exists' => $ifExists,
            'table' => $table,
        ];
    }

    private function parseBegin(): array
    {
        $this->matchKeyword('WORK');
        $this->matchKeyword('TRANSACTION');
        return ['type' => 'begin'];
    }

    private function parseEndKeyword(string $type): array
    {
        $this->matchKeyword('WORK');
        $this->matchKeyword('TRANSACTION');
        return ['type' => $type];
    }
}
