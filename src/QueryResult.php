<?php

declare(strict_types=1);

namespace FoxyDB;

final readonly class QueryResult implements \Countable, \IteratorAggregate
{
    public function __construct(
        public string $kind,
        public array $columns = [],
        public array $rows = [],
        public int $affectedRows = 0,
        public int|string|null $lastInsertId = null,
        public array $metadata = [],
    ) {
        if (!in_array($kind, ['command', 'rows'], true)) {
            throw new \InvalidArgumentException('Unknown FoxyDB result kind.');
        }
    }

    public static function command(
        int $affectedRows = 0,
        int|string|null $lastInsertId = null,
        array $metadata = [],
    ): self {
        return new self('command', [], [], $affectedRows, $lastInsertId, $metadata);
    }

    public static function rows(array $columns, array $rows, array $metadata = []): self
    {
        return new self('rows', $columns, $rows, 0, null, $metadata);
    }

    public function isRowSet(): bool
    {
        return $this->kind === 'rows';
    }

    public function rowCount(): int
    {
        return $this->kind === 'rows' ? count($this->rows) : $this->affectedRows;
    }

    public function count(): int
    {
        return $this->rowCount();
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->rows);
    }
}
