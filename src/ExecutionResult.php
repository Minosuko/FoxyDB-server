<?php

declare(strict_types=1);

namespace FoxyDB;

final readonly class ExecutionResult
{
    public function __construct(
        public string $kind,
        public array $columns = [],
        public iterable $rows = [],
        public int $affectedRows = 0,
        public int|string|null $lastInsertId = null,
        public array $metadata = [],
    ) {
    }

    public static function command(
        int $affectedRows = 0,
        int|string|null $lastInsertId = null,
        array $metadata = [],
    ): self {
        return new self('command', [], [], $affectedRows, $lastInsertId, $metadata);
    }

    public static function rows(array $columns, iterable $rows, array $metadata = []): self
    {
        return new self('rows', $columns, $rows, 0, null, $metadata);
    }
}
