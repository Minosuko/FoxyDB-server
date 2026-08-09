<?php

declare(strict_types=1);

namespace FoxyDB\Storage;

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;
use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;
use FoxyDB\Value\StreamValue;

final class ChunkStore
{
    public function __construct(
        private readonly string $root,
        private readonly Config $config,
    ) {
        FileSystem::ensureDirectory($root);
    }

    public function encode(mixed $value, string $type): mixed
    {
        $binary = in_array($type, ['BINARY', 'BLOB'], true);
        if ($value instanceof ChunkedValue) {
            return [
                '@' => 'chunked',
                'format' => $value->format,
                'bytes' => $value->bytes,
                'chunks' => $value->chunks,
            ];
        }

        if ($value instanceof StreamValue) {
            if (($binary && $value->format !== 'binary') || (!$binary && $value->format !== 'utf8')) {
                throw new FoxyException('Stream format does not match the column type.', 'INVALID_VALUE');
            }
            if ($type === 'BINARY' || $value->bytes <= $this->config->inlineValueBytes) {
                $stream = $value->open();
                try {
                    $contents = FileSystem::readExact($stream, $value->bytes) ?? '';
                    if (fread($stream, 1) !== '') {
                        throw new FoxyException('Stream contains more bytes than declared.', 'INVALID_VALUE');
                    }
                } finally {
                    fclose($stream);
                }
                if ($value->format === 'utf8' && !mb_check_encoding($contents, 'UTF-8')) {
                    throw new FoxyException('Text stream is not valid UTF-8.', 'INVALID_VALUE');
                }
                return $binary
                    ? ['@' => 'binary', 'value' => base64_encode($contents)]
                    : $contents;
            }
            $stream = $value->open();
            try {
                return $this->writeStream($stream, $value->bytes, $value->format);
            } finally {
                fclose($stream);
            }
        }

        if ($value instanceof BinaryValue) {
            if ($type === 'BINARY' || strlen($value->bytes) <= $this->config->inlineValueBytes) {
                return ['@' => 'binary', 'value' => base64_encode($value->bytes)];
            }
            $stream = fopen('php://temp', 'w+b');
            if ($stream === false) {
                throw new FoxyException('Unable to allocate a value stream.', 'STORAGE_IO');
            }
            try {
                FileSystem::writeAll($stream, $value->bytes);
                rewind($stream);
                return $this->writeStream($stream, strlen($value->bytes), 'binary');
            } finally {
                fclose($stream);
            }
        }

        if (is_string($value) && in_array($type, ['TEXT', 'LONGTEXT', 'JSON'], true)
            && strlen($value) > $this->config->inlineValueBytes) {
            $stream = fopen('php://temp', 'w+b');
            if ($stream === false) {
                throw new FoxyException('Unable to allocate a value stream.', 'STORAGE_IO');
            }
            try {
                FileSystem::writeAll($stream, $value);
                rewind($stream);
                return $this->writeStream($stream, strlen($value), 'utf8');
            } finally {
                fclose($stream);
            }
        }

        return $value;
    }

    public function decode(mixed $value): mixed
    {
        if (!is_array($value) || !isset($value['@'])) {
            return $value;
        }
        if ($value['@'] === 'binary') {
            $decoded = base64_decode((string) ($value['value'] ?? ''), true);
            if ($decoded === false) {
                throw new FoxyException('Invalid inline binary value.', 'STORAGE_CORRUPT');
            }
            return new BinaryValue($decoded);
        }
        if ($value['@'] === 'chunked') {
            $format = (string) ($value['format'] ?? '');
            $bytes = (int) ($value['bytes'] ?? -1);
            $chunks = $value['chunks'] ?? null;
            if (!in_array($format, ['binary', 'utf8'], true) || $bytes < 0 || !is_array($chunks)) {
                throw new FoxyException('Invalid chunked value metadata.', 'STORAGE_CORRUPT');
            }
            return new ChunkedValue($this->root, $format, $bytes, $chunks);
        }
        throw new FoxyException('Unknown encoded value.', 'STORAGE_CORRUPT');
    }

    public function recordReferences(mixed $value, string $referenceDirectory): void
    {
        if (!is_array($value)) {
            return;
        }
        if (($value['@'] ?? null) === 'chunked' && is_array($value['chunks'] ?? null)) {
            foreach ($value['chunks'] as $chunk) {
                $hash = (string) ($chunk['hash'] ?? '');
                if (preg_match('/^[a-f0-9]{64}$/', $hash) !== 1) {
                    throw new FoxyException('Invalid chunk reference.', 'STORAGE_CORRUPT');
                }
                FileSystem::ensureDirectory($referenceDirectory);
                $stream = @fopen($referenceDirectory . DIRECTORY_SEPARATOR . substr($hash, 0, 2) . '.refs', 'ab');
                if ($stream === false) {
                    throw new FoxyException('Unable to write chunk references.', 'STORAGE_IO');
                }
                try {
                    FileSystem::writeAll($stream, $hash . "\n");
                } finally {
                    fclose($stream);
                }
            }
            return;
        }
        foreach ($value as $item) {
            $this->recordReferences($item, $referenceDirectory);
        }
    }

    public function garbageCollect(string $referenceDirectory): int
    {
        $removed = 0;
        for ($bucket = 0; $bucket < 256; $bucket++) {
            $prefix = sprintf('%02x', $bucket);
            $references = [];
            $referencePath = $referenceDirectory . DIRECTORY_SEPARATOR . $prefix . '.refs';
            if (is_file($referencePath)) {
                $stream = @fopen($referencePath, 'rb');
                if ($stream === false) {
                    throw new FoxyException('Unable to read chunk references.', 'STORAGE_IO');
                }
                try {
                    while (($line = fgets($stream)) !== false) {
                        $references[rtrim($line, "\r\n")] = true;
                    }
                } finally {
                    fclose($stream);
                }
            }

            $directory = $this->root . DIRECTORY_SEPARATOR . $prefix;
            if (!is_dir($directory)) {
                continue;
            }
            $entries = scandir($directory);
            if ($entries === false) {
                throw new FoxyException('Unable to scan chunk directory.', 'STORAGE_IO');
            }
            foreach ($entries as $entry) {
                if (!str_ends_with($entry, '.chk')) {
                    continue;
                }
                $hash = substr($entry, 0, -4);
                if (!isset($references[$hash])) {
                    if (!@unlink($directory . DIRECTORY_SEPARATOR . $entry)) {
                        throw new FoxyException('Unable to remove unused chunk.', 'STORAGE_IO');
                    }
                    $removed++;
                }
            }
            $remaining = scandir($directory);
            if ($remaining === ['.', '..']) {
                @rmdir($directory);
            }
        }
        return $removed;
    }

    private function writeStream($stream, int $expectedBytes, string $format): array
    {
        $chunks = [];
        $total = 0;
        $utf8Carry = '';
        while (!feof($stream)) {
            $data = fread($stream, $this->config->chunkBytes);
            if ($data === false) {
                throw new FoxyException('Unable to read streamed value.', 'STORAGE_IO');
            }
            if ($data === '') {
                break;
            }
            $total += strlen($data);
            if ($total > $expectedBytes) {
                throw new FoxyException('Stream contains more bytes than declared.', 'INVALID_VALUE');
            }
            if ($format === 'utf8') {
                [$complete, $utf8Carry] = $this->splitCompleteUtf8($utf8Carry . $data);
                if ($complete !== '' && !mb_check_encoding($complete, 'UTF-8')) {
                    throw new FoxyException('Text stream is not valid UTF-8.', 'INVALID_VALUE');
                }
            }
            $hash = hash('sha256', $data);
            $this->writeChunk($hash, $data);
            $chunks[] = ['hash' => $hash, 'bytes' => strlen($data)];
        }
        if ($total !== $expectedBytes) {
            throw new FoxyException('Stream length does not match its declaration.', 'INVALID_VALUE');
        }
        if ($format === 'utf8' && $utf8Carry !== '' && !mb_check_encoding($utf8Carry, 'UTF-8')) {
            throw new FoxyException('Text stream is not valid UTF-8.', 'INVALID_VALUE');
        }
        return [
            '@' => 'chunked',
            'format' => $format,
            'bytes' => $total,
            'chunks' => $chunks,
        ];
    }

    private function writeChunk(string $hash, string $data): void
    {
        $directory = $this->root . DIRECTORY_SEPARATOR . substr($hash, 0, 2);
        FileSystem::ensureDirectory($directory);
        $path = $directory . DIRECTORY_SEPARATOR . $hash . '.chk';
        if (is_file($path)) {
            if (filesize($path) !== strlen($data) || hash_file('sha256', $path) !== $hash) {
                throw new FoxyException('Existing chunk failed integrity validation.', 'STORAGE_CORRUPT');
            }
            return;
        }
        FileSystem::atomicWrite($path, $data, $this->config->syncWrites);
    }

    private function splitCompleteUtf8(string $data): array
    {
        $length = strlen($data);
        if ($length === 0) {
            return ['', ''];
        }
        $start = $length - 1;
        while ($start >= 0 && (ord($data[$start]) & 0xc0) === 0x80) {
            $start--;
        }
        if ($start < 0) {
            return [$data, ''];
        }
        $lead = ord($data[$start]);
        $expected = match (true) {
            $lead < 0x80 => 1,
            ($lead & 0xe0) === 0xc0 => 2,
            ($lead & 0xf0) === 0xe0 => 3,
            ($lead & 0xf8) === 0xf0 => 4,
            default => 1,
        };
        if ($length - $start < $expected) {
            return [substr($data, 0, $start), substr($data, $start)];
        }
        return [$data, ''];
    }
}
