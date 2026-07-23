<?php

declare(strict_types=1);

namespace FoxyDB\Value;

use FoxyDB\Exception\FoxyException;

final readonly class StreamValue
{
    public function __construct(
        public string $path,
        public string $format,
        public int $bytes,
    ) {
        if (!in_array($format, ['binary', 'utf8'], true) || $bytes < 0 || !is_file($path)) {
            throw new FoxyException('Invalid streamed value.', 'INVALID_VALUE');
        }
    }

    public function open()
    {
        $stream = @fopen($this->path, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open streamed value.', 'STORAGE_IO');
        }
        return $stream;
    }
}
