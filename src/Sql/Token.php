<?php

declare(strict_types=1);

namespace FoxyDB\Sql;

final readonly class Token
{
    public function __construct(
        public string $type,
        public mixed $value,
        public int $offset,
        public int $line,
        public int $column,
        public bool $quoted = false,
    ) {
    }
}
