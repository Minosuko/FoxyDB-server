<?php

declare(strict_types=1);

namespace FoxyDB\Storage;

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\BinaryCodec;
use FoxyDB\Support\FileSystem;
use FoxyDB\Support\MemoryCache;
use FoxyDB\Value\BinaryValue;
use FoxyDB\Value\ChunkedValue;
use FoxyDB\Value\StreamValue;

final class IndexStore
{
    private const HEADER_BYTES = 17;
    private const MAXIMUM_KEY_BYTES = 4_096;
    private int $revision = 0;

    public function __construct(
        private readonly string $root,
        private readonly Config $config,
        private readonly ?MemoryCache $cache = null,
        private readonly ?string $cacheNamespace = null,
    ) {
        FileSystem::ensureDirectory($root);
    }

    public static function key(array $values): string
    {
        $key = '';
        foreach ($values as $value) {
            if ($value === null) {
                $part = '';
                $type = 'n';
            } elseif (is_bool($value)) {
                $part = $value ? "\x01" : "\x00";
                $type = 'b';
            } elseif (is_int($value)) {
                $part = (string) $value;
                $type = 'i';
            } elseif (is_float($value)) {
                $part = pack('E', $value === 0.0 ? 0.0 : $value);
                $type = 'f';
            } elseif ($value instanceof BinaryValue) {
                $part = $value->bytes;
                $type = 'x';
            } elseif ($value instanceof ChunkedValue) {
                throw new FoxyException('Chunked values cannot be indexed.', 'INDEX_KEY_TOO_LARGE');
            } elseif ($value instanceof StreamValue) {
                if ($value->format !== 'binary' || $value->bytes > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Streamed index value is invalid or too large.', 'INDEX_KEY_TOO_LARGE');
                }
                $stream = $value->open();
                try {
                    $part = FileSystem::readExact($stream, $value->bytes) ?? '';
                    if (fread($stream, 1) !== '') {
                        throw new FoxyException('Stream contains more bytes than declared.', 'INVALID_VALUE');
                    }
                } finally {
                    fclose($stream);
                }
                $type = 'x';
            } elseif (is_string($value)) {
                $part = $value;
                $type = 's';
            } else {
                throw new FoxyException('Unsupported index value.', 'INVALID_VALUE');
            }
            $key .= $type . BinaryCodec::uint32(strlen($part)) . $part;
            if (strlen($key) > self::MAXIMUM_KEY_BYTES) {
                throw new FoxyException('Index key exceeds 4096 bytes.', 'INDEX_KEY_TOO_LARGE');
            }
        }
        return $key;
    }

    public static function containsNull(array $values): bool
    {
        return in_array(null, $values, true);
    }

    public function append(string $indexName, string $key, int $rowId, bool $put): void
    {
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            throw new FoxyException("Index {$indexName} is missing or incomplete.", 'STORAGE_CORRUPT');
        }
        $operation = $put ? 'P' : 'D';
        $body = $operation . BinaryCodec::uint64($rowId) . BinaryCodec::uint32(strlen($key));
        $record = $body . BinaryCodec::uint32(BinaryCodec::crc32($body . $key)) . $key;
        $stream = @fopen($path, 'ab');
        if ($stream === false) {
            throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
        }
        try {
            FileSystem::writeAll($stream, $record);
            FileSystem::flush($stream, $this->config->syncWrites);
            $this->revision++;
        } finally {
            fclose($stream);
        }
    }

    public function lookup(string $indexName, string $key): array
    {
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            return $this->lookupBucketsLegacy($indexName, $key);
        }
        $cacheKey = hash('sha256', ($this->cacheNamespace ?? $this->root)
            . "\0" . $this->revision . "\0" . $indexName . "\0" . $key);
        if ($this->cache !== null) {
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached) && ($cached['key'] ?? null) === $key && is_array($cached['ids'] ?? null)) {
                return $cached['ids'];
            }
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            $this->cache?->put($cacheKey, ['key' => $key, 'ids' => []]);
            return [];
        }
        $matches = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = BinaryCodec::readUint32($header, 13);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $storedKey = FileSystem::readExact($stream, $keyLength) ?? '';
                if (BinaryCodec::crc32(substr($header, 0, 13) . $storedKey) !== $checksum) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if (hash_equals($key, $storedKey)) {
                    if ($operation === 'P') {
                        $matches[$rowId] = true;
                    } elseif ($operation === 'D') {
                        unset($matches[$rowId]);
                    } else {
                        throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                    }
                    if (count($matches) > $this->config->maxRowsPerResult) {
                        throw new FoxyException('Index lookup exceeded the configured row limit.', 'RESOURCE_LIMIT');
                    }
                }
            }
        } finally {
            fclose($stream);
        }
        $ids = array_map('intval', array_keys($matches));
        sort($ids, SORT_NUMERIC);
        $this->cache?->put($cacheKey, ['key' => $key, 'ids' => $ids]);
        return $ids;
    }

    public function reset(): void
    {
        $this->revision++;
        FileSystem::removeTree($this->root);
        FileSystem::ensureDirectory($this->root);
    }

    public function prepare(array $indexNames): void
    {
        foreach ($indexNames as $indexName) {
            $directory = $this->root . DIRECTORY_SEPARATOR . $indexName;
            FileSystem::ensureDirectory($directory);
            $path = $this->indexPath($indexName);
            if (!is_file($path)) {
                $this->migrateLegacyBuckets($directory);
            }
            if (!is_file($path)) {
                $stream = @fopen($path, 'ab');
                if ($stream === false) {
                    throw new FoxyException('Unable to create index file.', 'STORAGE_IO');
                }
                fclose($stream);
            }
        }
    }

    public function assertUnique(string $indexName): void
    {
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            $this->assertUniqueBucketsLegacy($indexName);
            return;
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            return;
        }
        $keys = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = BinaryCodec::readUint32($header, 13);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (BinaryCodec::crc32(substr($header, 0, 13) . $key) !== $checksum) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                $encoded = base64_encode($key);
                if ($operation === 'D') {
                    unset($keys[$encoded][$rowId]);
                    continue;
                }
                if ($operation !== 'P') {
                    throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                }
                $keys[$encoded][$rowId] = true;
            }
        } finally {
            fclose($stream);
        }
        foreach ($keys as $rows) {
            if (count($rows) > 1) {
                throw new FoxyException('Existing rows violate the requested unique index.', 'UNIQUE_VIOLATION');
            }
        }
    }

    private function indexPath(string $indexName): string
    {
        return $this->root . DIRECTORY_SEPARATOR . $indexName . DIRECTORY_SEPARATOR . 'data.fxi';
    }

    private function readRecordsFromStream($stream): array
    {
        $records = [];
        while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
            $records[] = $header . FileSystem::readExact($stream, BinaryCodec::readUint32($header, 9)) ?? '';
        }
        return $records;
    }

    private function migrateLegacyBuckets(string $directory): void
    {
        $entries = @scandir($directory);
        if ($entries === false) {
            return;
        }
        $bucketFiles = [];
        foreach ($entries as $entry) {
            if (str_ends_with($entry, '.fxi') || $entry === '.manifest') {
                $bucketFiles[] = $entry;
            }
        }
        if ($bucketFiles === []) {
            return;
        }
        $path = $directory . DIRECTORY_SEPARATOR . 'data.fxi';
        $stream = @fopen($path, 'ab');
        if ($stream === false) {
            return;
        }
        try {
            foreach ($bucketFiles as $entry) {
                if ($entry === '.manifest') {
                    @unlink($directory . DIRECTORY_SEPARATOR . $entry);
                    continue;
                }
                $src = @fopen($directory . DIRECTORY_SEPARATOR . $entry, 'rb');
                if ($src === false) {
                    continue;
                }
                try {
                    while (($header = FileSystem::readExact($src, self::HEADER_BYTES, true)) !== null) {
                        $keyLength = BinaryCodec::readUint32($header, 9);
                        if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                            break;
                        }
                        $key = FileSystem::readExact($src, $keyLength);
                        if ($key === null) {
                            break;
                        }
                        FileSystem::writeAll($stream, $header . $key);
                    }
                } finally {
                    fclose($src);
                }
                @unlink($directory . DIRECTORY_SEPARATOR . $entry);
            }
            FileSystem::flush($stream, true);
        } finally {
            fclose($stream);
        }
    }

    private function lookupBucketsLegacy(string $indexName, string $key): array
    {
        $directory = $this->root . DIRECTORY_SEPARATOR . $indexName;
        if (!is_dir($directory)) {
            return [];
        }
        $cacheKey = hash('sha256', ($this->cacheNamespace ?? $this->root)
            . "\0" . $this->revision . "\0" . $indexName . "\0" . $key);
        $bucket = substr(hash('sha256', $key), 0, 2);
        $path = $directory . DIRECTORY_SEPARATOR . $bucket . '.fxi';
        if (!is_file($path)) {
            $this->cache?->put($cacheKey, ['key' => $key, 'ids' => []]);
            return [];
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            $this->cache?->put($cacheKey, ['key' => $key, 'ids' => []]);
            return [];
        }
        $matches = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = BinaryCodec::readUint32($header, 13);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $storedKey = FileSystem::readExact($stream, $keyLength) ?? '';
                if (BinaryCodec::crc32(substr($header, 0, 13) . $storedKey) !== $checksum) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if (hash_equals($key, $storedKey)) {
                    if ($operation === 'P') {
                        $matches[$rowId] = true;
                    } elseif ($operation === 'D') {
                        unset($matches[$rowId]);
                    } else {
                        throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                    }
                    if (count($matches) > $this->config->maxRowsPerResult) {
                        throw new FoxyException('Index lookup exceeded the configured row limit.', 'RESOURCE_LIMIT');
                    }
                }
            }
        } finally {
            fclose($stream);
        }
        return array_map('intval', array_keys($matches));
    }

    private function assertUniqueBucketsLegacy(string $indexName): void
    {
        $directory = $this->root . DIRECTORY_SEPARATOR . $indexName;
        if (!is_dir($directory)) {
            return;
        }
        $entries = @scandir($directory);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if (!str_ends_with($entry, '.fxi')) {
                continue;
            }
            $stream = @fopen($directory . DIRECTORY_SEPARATOR . $entry, 'rb');
            if ($stream === false) {
                continue;
            }
            $keys = [];
            try {
                while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                    $operation = $header[0];
                    $rowId = BinaryCodec::readUint64($header, 1);
                    $keyLength = BinaryCodec::readUint32($header, 9);
                    $checksum = BinaryCodec::readUint32($header, 13);
                    if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                        throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                    }
                    $key = FileSystem::readExact($stream, $keyLength) ?? '';
                    if (BinaryCodec::crc32(substr($header, 0, 13) . $key) !== $checksum) {
                        throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                    }
                    $encoded = base64_encode($key);
                    if ($operation === 'D') {
                        unset($keys[$encoded][$rowId]);
                        continue;
                    }
                    if ($operation !== 'P') {
                        throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                    }
                    $keys[$encoded][$rowId] = true;
                }
            } finally {
                fclose($stream);
            }
            foreach ($keys as $rows) {
                if (count($rows) > 1) {
                    throw new FoxyException('Existing rows violate the requested unique index.', 'UNIQUE_VIOLATION');
                }
            }
        }
    }
}
