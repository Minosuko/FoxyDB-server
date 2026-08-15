<?php

declare(strict_types=1);

namespace FoxyDB\Sql;

use DateTimeImmutable;
use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\TypeSystem;
use FoxyDB\Value\BinaryValue;

/**
 * Pure row-level evaluation for SELECT scans.
 *
 * This is a faithful, standalone port of the row-evaluation logic that Session
 * uses to filter and project rows. It is deliberately independent of Session
 * and the storage engine so a parallel worker subprocess can rebuild an
 * identical predicate from the serialized WHERE expression, column
 * definitions, and parameter values. Subquery expression kinds (in_subquery,
 * exists, subquery) cannot run without a storage engine and throw; callers
 * must exclude statements containing them before offloading work.
 */
final class RowEvaluator
{
    private readonly TypeSystem $types;

    public function __construct(
        private readonly Config $config,
        private readonly array $columns,
        private readonly array $parameters,
    ) {
        $this->types = new TypeSystem($config);
    }

    public function predicate(?array $expression): ?\Closure
    {
        if ($expression === null) {
            return null;
        }
        $evaluator = $this->booleanEvaluator($expression);
        return static fn(array $row): bool => $evaluator($row) === true;
    }

    private function booleanEvaluator(array $expression): \Closure
    {
        return match ($expression['kind']) {
            'logical' => $this->logicalEvaluator($expression),
            'not' => $this->notEvaluator($expression),
            'comparison' => $this->comparisonEvaluator($expression),
            'is_null' => $this->isNullEvaluator($expression),
            'in' => $this->inEvaluator($expression),
            'like' => $this->likeEvaluator($expression),
            'truthy' => $this->truthyEvaluator($expression),
            'in_subquery', 'exists', 'subquery' => throw new FoxyException(
                'Subqueries cannot be evaluated by a scan worker.',
                'PARALLEL_UNSUPPORTED',
            ),
            default => throw new FoxyException('Unsupported WHERE expression.', 'SQL_SEMANTIC'),
        };
    }

    private function logicalEvaluator(array $expression): \Closure
    {
        $left = $this->booleanEvaluator($expression['left']);
        $right = $this->booleanEvaluator($expression['right']);
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

    private function notEvaluator(array $expression): \Closure
    {
        $inner = $this->booleanEvaluator($expression['expression']);
        return static function (array $row) use ($inner): ?bool {
            $value = $inner($row);
            return $value === null ? null : !$value;
        };
    }

    private function comparisonEvaluator(array $expression): \Closure
    {
        [$left, $right] = $this->operandPair($expression['left'], $expression['right']);
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

    private function isNullEvaluator(array $expression): \Closure
    {
        $operand = $this->operand($expression['operand']);
        $not = $expression['not'];
        return static function (array $row) use ($operand, $not): bool {
            $isNull = ($operand['get'])($row) === null;
            return $not ? !$isNull : $isNull;
        };
    }

    private function inEvaluator(array $expression): \Closure
    {
        $left = $this->operand($expression['operand']);
        $values = [];
        foreach ($expression['values'] as $node) {
            $right = $this->operand($node);
            [$coercedLeft, $coercedRight] = $this->coerceOperands($left, $right);
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

    private function likeEvaluator(array $expression): \Closure
    {
        [$left, $pattern] = $this->operandPair($expression['operand'], $expression['pattern'], false);
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

    private function truthyEvaluator(array $expression): \Closure
    {
        $operand = $this->operand($expression['operand']);
        return function (array $row) use ($operand): ?bool {
            $value = $this->types->materialize(($operand['get'])($row));
            if ($value instanceof BinaryValue) {
                $value = $value->bytes;
            }
            return $value === null ? null : (bool) $value;
        };
    }

    private function operandPair(array $leftNode, array $rightNode, bool $coerce = true): array
    {
        $left = $this->operand($leftNode);
        $right = $this->operand($rightNode);
        return $coerce ? $this->coerceOperands($left, $right) : [$left, $right];
    }

    private function operand(array $node): array
    {
        if ($node['kind'] === 'column') {
            if (!isset($this->columns[$node['name']])) {
                throw new FoxyException("Unknown column: {$node['name']}", 'UNKNOWN_COLUMN');
            }
            $name = $node['name'];
            $parts = explode('.', $name);
            $base = count($parts) === 2 ? $parts[1] : $name;
            return [
                'get' => static fn(array $row): mixed => array_key_exists($base, $row) ? $row[$base] : ($row[$name] ?? null),
                'constant' => false,
                'column' => $base,
                'value' => null,
            ];
        }
        if ($node['kind'] === 'subquery') {
            throw new FoxyException(
                'Subqueries cannot be evaluated by a scan worker.',
                'PARALLEL_UNSUPPORTED',
            );
        }
        if ($node['kind'] === 'call' && $node['name'] === 'json_extract') {
            $operand = $this->operand($node['operand']);
            $pathValue = $node['path']['kind'] === 'parameter'
                ? $this->value($node['path'])
                : $node['path']['value'];
            if (!is_string($pathValue)) {
                throw new FoxyException('JSON_EXTRACT requires a string path.', 'SQL_SEMANTIC');
            }
            $tokens = self::compileJsonPath($pathValue);
            return [
                'get' => function (array $row) use ($operand, $tokens): mixed {
                    $raw = $this->types->materialize(($operand['get'])($row));
                    return self::extractJson($raw, $tokens);
                },
                'constant' => false,
                'column' => null,
                'value' => null,
            ];
        }
        $value = $this->value($node);
        return [
            'get' => static fn(array $row): mixed => $value,
            'constant' => true,
            'column' => null,
            'value' => $value,
        ];
    }

    private function coerceOperands(array $left, array $right): array
    {
        if ($left['column'] !== null && $right['constant'] && $right['value'] !== null) {
            $right = $this->constantOperand($this->types->materialize(
                $this->types->coerce($right['value'], $this->columns[$left['column']]),
            ));
        } elseif ($right['column'] !== null && $left['constant'] && $left['value'] !== null) {
            $left = $this->constantOperand($this->types->materialize(
                $this->types->coerce($left['value'], $this->columns[$right['column']]),
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

    public function value(array $node): mixed
    {
        if ($node['kind'] === 'literal') {
            return $node['value'];
        }
        if ($node['kind'] === 'parameter') {
            $key = $node['key'];
            if (!array_key_exists($key, $this->parameters)
                && is_string($key)
                && array_key_exists(':' . $key, $this->parameters)) {
                $key = ':' . $key;
            }
            if (!array_key_exists($key, $this->parameters)) {
                throw new FoxyException("Missing parameter {$node['key']}.", 'MISSING_PARAMETER');
            }
            return $this->parameters[$key];
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

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
            . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }

    public function project(array $row, array $projections): array
    {
        $result = [];
        foreach ($projections as $projection) {
            if ($projection['kind'] === 'value') {
                $result[$projection['alias']] = $projection['value']['value'] ?? null;
            } elseif ($projection['kind'] === 'json_extract') {
                $column = $projection['column'];
                $parts = explode('.', $column);
                $base = count($parts) === 2 ? $parts[1] : $column;
                $raw = $this->types->materialize(
                    array_key_exists($base, $row) ? $row[$base] : ($row[$column] ?? null),
                );
                $extracted = self::extractJson($raw, $projection['json_tokens']);
                $result[$projection['alias']] = is_array($extracted)
                    ? json_encode($extracted, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                    : $extracted;
            } else {
                $column = $projection['column'];
                $parts = explode('.', $column);
                $base = count($parts) === 2 ? $parts[1] : $column;
                $result[$projection['alias']] = array_key_exists($base, $row) ? $row[$base] : ($row[$column] ?? null);
            }
        }
        return $result;
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

    private static function compileJsonPath(string $path): array
    {
        if (preg_match('/\A\$/', $path) !== 1) {
            throw new FoxyException('JSON path must start with $.', 'SQL_SEMANTIC');
        }
        $tokens = [];
        $length = strlen($path);
        $offset = 1;
        while ($offset < $length) {
            $char = $path[$offset];
            if ($char === '.') {
                $offset++;
                $start = $offset;
                while ($offset < $length && $path[$offset] !== '.' && $path[$offset] !== '[') {
                    $offset++;
                }
                $key = substr($path, $start, $offset - $start);
                if ($key === '') {
                    throw new FoxyException('Invalid JSON path syntax.', 'SQL_SEMANTIC');
                }
                $tokens[] = ['kind' => 'key', 'value' => $key];
            } elseif ($char === '[') {
                $close = strpos($path, ']', $offset);
                if ($close === false || $close === $offset + 1) {
                    throw new FoxyException('Invalid JSON path syntax.', 'SQL_SEMANTIC');
                }
                $inner = substr($path, $offset + 1, $close - $offset - 1);
                if (($inner[0] === "'" || $inner[0] === '"')
                    && strlen($inner) >= 2 && substr($inner, -1) === $inner[0]
                    && !str_contains(substr($inner, 1, -1), $inner[0])) {
                    $tokens[] = ['kind' => 'key', 'value' => substr($inner, 1, -1)];
                } elseif (preg_match('/\A\d+\z/', $inner) === 1) {
                    $tokens[] = ['kind' => 'index', 'value' => (int) $inner];
                } else {
                    throw new FoxyException('Invalid JSON path syntax.', 'SQL_SEMANTIC');
                }
                $offset = $close + 1;
            } else {
                throw new FoxyException('Invalid JSON path syntax.', 'SQL_SEMANTIC');
            }
        }
        if ($tokens === []) {
            throw new FoxyException('Invalid JSON path syntax.', 'SQL_SEMANTIC');
        }
        return $tokens;
    }

    private static function extractJson(mixed $raw, array $tokens): mixed
    {
        if ($raw === null || $raw === '') {
            return null;
        }
        if ($raw instanceof BinaryValue) {
            $raw = $raw->bytes;
        }
        try {
            $decoded = json_decode((string) $raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        $current = $decoded;
        foreach ($tokens as $token) {
            if ($current === null) {
                return null;
            }
            if ($token['kind'] === 'key') {
                if (!is_array($current) || !array_key_exists($token['value'], $current)) {
                    return null;
                }
                $current = $current[$token['value']];
            } else {
                if (!is_array($current) || !array_key_exists($token['value'], $current)) {
                    return null;
                }
                $current = $current[$token['value']];
            }
        }
        return $current;
    }
}
