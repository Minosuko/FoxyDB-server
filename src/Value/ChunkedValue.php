<?php

declare(strict_types=1);

namespace FoxyDB\Value;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;

final readonly class ChunkedValue
{
    public function __construct(
        public string $root,
        public string $format,
        public int $bytes,
        public array $chunks,
    ) {
    }

    public function parts(): \Generator
    {
        $total = 0;
        foreach ($this->chunks as $chunk) {
            $hash = (string) ($chunk['hash'] ?? '');
            $bytes = (int) ($chunk['bytes'] ?? -1);
            if (preg_match('/^[a-f0-9]{64}$/', $hash) !== 1 || $bytes < 0) {
                throw new FoxyException('Invalid chunk manifest.', 'STORAGE_CORRUPT');
            }
            $path = $this->root . DIRECTORY_SEPARATOR . substr($hash, 0, 2) . DIRECTORY_SEPARATOR . $hash . '.chk';
            $stream = @fopen($path, 'rb');
            if ($stream === false) {
                throw new FoxyException("Missing chunk: {$hash}", 'STORAGE_CORRUPT');
            }
            try {
                $data = FileSystem::readExact($stream, $bytes);
                if (hash('sha256', $data) !== $hash) {
                    throw new FoxyException("Chunk checksum mismatch: {$hash}", 'STORAGE_CORRUPT');
                }
                if (fread($stream, 1) !== '') {
                    throw new FoxyException("Chunk length mismatch: {$hash}", 'STORAGE_CORRUPT');
                }
                $total += $bytes;
                yield $data;
            } finally {
                fclose($stream);
            }
        }
        if ($total !== $this->bytes) {
            throw new FoxyException('Chunk manifest length mismatch.', 'STORAGE_CORRUPT');
        }
    }

    public function materialize(int $maximumBytes): string
    {
        if ($this->bytes > $maximumBytes) {
            throw new FoxyException(
                "Value is {$this->bytes} bytes and exceeds the materialization limit.",
                'RESOURCE_LIMIT',
            );
        }
        $value = '';
        foreach ($this->parts() as $part) {
            $value .= $part;
        }
        return $value;
    }
}
