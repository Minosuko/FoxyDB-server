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
    private const MAXIMUM_KEY_BYTES = 65_535;
    private const ORDERED_MAP_MAX_BYTES = 33_554_432;
    private const ORDERED_SNAPSHOT_FILE = 'ordered.fxo';
    private const ORDERED_SNAPSHOT_MAGIC = 'FXOS';
    private const ORDERED_SNAPSHOT_VERSION = 2;
    private const ORDERED_SNAPSHOT_HEADER_BYTES = 24;
    private const ORDERED_BLOCK_BYTES = 131_072;
    private const ORDERED_RUN_BYTES = 8_388_608;
    private const ORDERED_SURVIVOR_CHUNK = 512;
    private const ORDERED_RUN_DIR = 'ordered.runs.fxo';
    private int $revision = 0;
    private array $pendingWrites = [];
    private array $orderedMaps = [];

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
                throw new FoxyException('Index key exceeds the 16-bit storage format.', 'INDEX_KEY_TOO_LARGE');
            }
        }
        return $key;
    }

    public static function orderedKey(array $values): string
    {
        $key = '';
        foreach ($values as $value) {
            if ($value === null) {
                $encoded = 'N';
            } elseif (is_bool($value)) {
                $encoded = 'B' . ($value ? "\x01" : "\x00");
            } elseif (is_int($value)) {
                $part = self::signedIntegerBytes($value);
                $part[0] = chr(ord($part[0]) ^ 0x80);
                $encoded = 'I' . $part;
            } elseif (is_float($value)) {
                $part = pack('E', $value === 0.0 ? 0.0 : $value);
                if ((ord($part[0]) & 0x80) !== 0) {
                    $part = ~$part;
                } else {
                    $part[0] = chr(ord($part[0]) ^ 0x80);
                }
                $encoded = 'F' . $part;
            } elseif ($value instanceof BinaryValue) {
                $encoded = 'X' . self::orderedVariablePart($value->bytes);
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
                $encoded = 'X' . self::orderedVariablePart($part);
            } elseif (is_string($value)) {
                $encoded = 'S' . self::orderedVariablePart($value);
            } else {
                throw new FoxyException('Unsupported index value.', 'INVALID_VALUE');
            }
            $key .= $encoded;
            if (strlen($key) > self::MAXIMUM_KEY_BYTES) {
                throw new FoxyException('Index key exceeds the 16-bit storage format.', 'INDEX_KEY_TOO_LARGE');
            }
        }
        return $key;
    }

    private static function orderedVariablePart(string $value): string
    {
        return str_replace("\x00", "\x00\xff", $value) . "\x00\x00";
    }

    private static function signedIntegerBytes(int $value): string
    {
        $words = [0, 0, 0, 0];
        for ($index = 3; $index >= 0; $index--) {
            $words[$index] = $value & 0xffff;
            $value >>= 16;
        }
        return pack('nnnn', ...$words);
    }

    public static function orderedKeyPrefix(array $values, int $count): string
    {
        $values = array_slice($values, 0, $count);
        return self::orderedKey($values);
    }

    public static function containsNull(array $values): bool
    {
        return in_array(null, $values, true);
    }

    public function append(string $indexName, string $key, int $rowId, bool $put): void
    {
        $this->batchAppend($indexName, $key, $rowId, $put);
        $this->flushBatch();
    }

    public function batchAppend(string $indexName, string $key, int $rowId, bool $put): void
    {
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            throw new FoxyException("Index {$indexName} is missing or incomplete.", 'STORAGE_CORRUPT');
        }
        $this->pendingWrites[$indexName][] = [$put ? 'P' : 'D', $rowId, $key];
    }

    public function flushBatch(): void
    {
        if ($this->pendingWrites === []) {
            return;
        }
        try {
            foreach ($this->pendingWrites as $indexName => $records) {
                $path = $this->indexPath($indexName);
                $stream = @fopen($path, 'ab');
                if ($stream === false) {
                    throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
                }
                try {
                    foreach ($records as [$operation, $rowId, $key]) {
                        $body = $operation . BinaryCodec::uint64($rowId) . BinaryCodec::uint32(strlen($key));
                        $record = $body . BinaryCodec::crc32($body . $key) . $key;
                        FileSystem::writeAll($stream, $record);
                    }
                    FileSystem::flush($stream, $this->config->syncWrites);
                    $this->revision++;
                } finally {
                    fclose($stream);
                }
            }
        } finally {
            $this->pendingWrites = [];
        }
    }

    public function discardBatch(): void
    {
        $this->pendingWrites = [];
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
            throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
        }
        $matches = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $storedKey = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $storedKey))) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if ($operation !== 'P' && $operation !== 'D') {
                    throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                }
                if (hash_equals($key, $storedKey)) {
                    if ($operation === 'P') {
                        $matches[$rowId] = true;
                    } else {
                        unset($matches[$rowId]);
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

    public function rangeLookup(
        string $indexName,
        ?string $minimum,
        ?string $maximum,
        bool $minInclusive,
        bool $maxInclusive,
    ): array {
        $map = $this->orderedMap($indexName);
        if ($map === null) {
            return $this->scanRange($indexName, $minimum, $maximum, $minInclusive, $maxInclusive);
        }
        if (($map['snapshot'] ?? false) === true) {
            return $this->rangeLookupOnDisk($map, $minimum, $maximum, $minInclusive, $maxInclusive);
        }
        $keys = $map['keys'];
        $ids = $map['ids'];
        $start = $minimum === null ? 0 : $this->lowerBound($keys, $minimum, $minInclusive);
        $end = $maximum === null ? count($keys) : $this->upperBound($keys, $maximum, $maxInclusive);
        $matches = [];
        for ($index = $start; $index < $end; $index++) {
            foreach ($ids[$index] as $rowId) {
                $matches[] = $rowId;
            }
        }
        sort($matches, SORT_NUMERIC);
        return $matches;
    }

    private function orderedMap(string $indexName): ?array
    {
        $current = $this->orderedMaps[$indexName] ?? null;
        if ($current !== null && $current['revision'] === $this->revision) {
            return $current;
        }
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            return null;
        }
        $size = $this->fileSize($path);
        if ($size > self::ORDERED_MAP_MAX_BYTES) {
            return $this->loadOrderedSnapshot($indexName);
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
        }
        $byKey = [];
        $bytes = 0;
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if ($operation === 'P') {
                    if (!isset($byKey[$key])) {
                        $byKey[$key] = [];
                    }
                    $byKey[$key][$rowId] = true;
                } elseif ($operation === 'D') {
                    unset($byKey[$key][$rowId]);
                } else {
                    throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                }
                $bytes += strlen($key) + 24;
                if ($bytes > self::ORDERED_MAP_MAX_BYTES) {
                    $this->orderedMaps[$indexName] = ['revision' => $this->revision, 'too_big' => true];
                    return null;
                }
            }
        } finally {
            fclose($stream);
        }
        $byKey = array_filter($byKey, static fn(array $ids): bool => $ids !== []);
        ksort($byKey, SORT_STRING);
        $map = [
            'revision' => $this->revision,
            'keys' => array_keys($byKey),
            'ids' => array_map(
                static fn(array $rowIds): array => array_map('intval', array_keys($rowIds)),
                array_values($byKey),
            ),
        ];
        $this->orderedMaps[$indexName] = $map;
        return $map;
    }

    private function loadOrderedSnapshot(string $indexName): ?array
    {
        $snapshotPath = $this->root . DIRECTORY_SEPARATOR . $indexName . DIRECTORY_SEPARATOR . self::ORDERED_SNAPSHOT_FILE;
        try {
            $loaded = $this->readOrderedSnapshot($snapshotPath);
            if ($loaded === null) {
                $loaded = $this->buildOrderedSnapshot($indexName, $snapshotPath);
            }
        } catch (FoxyException) {
            $loaded = null;
        }
        if ($loaded === null || $loaded['directory'] === []) {
            $this->orderedMaps[$indexName] = ['revision' => $this->revision, 'too_big' => true];
            return null;
        }
        $logPath = $this->indexPath($indexName);
        $currentBytes = $this->fileSize($logPath);
        if ($currentBytes < $loaded['logLength']) {
            $loaded = $this->buildOrderedSnapshot($indexName, $snapshotPath);
            if ($loaded === null || $loaded['directory'] === []) {
                $this->orderedMaps[$indexName] = ['revision' => $this->revision, 'too_big' => true];
                return null;
            }
        }
        if ($currentBytes - $loaded['logLength'] > self::ORDERED_MAP_MAX_BYTES) {
            $loaded = $this->buildOrderedSnapshot($indexName, $snapshotPath);
            if ($loaded === null || $loaded['directory'] === []) {
                $this->orderedMaps[$indexName] = ['revision' => $this->revision, 'too_big' => true];
                return null;
            }
        }
        $tail = [];
        if ($currentBytes > $loaded['logLength']) {
            $tail = $this->readIndexTail($logPath, $loaded['logLength'], $currentBytes);
        }
        $map = [
            'revision' => $this->revision,
            'snapshot' => true,
            'path' => $snapshotPath,
            'directory' => $loaded['directory'],
            'tail' => $tail,
        ];
        $this->orderedMaps[$indexName] = $map;
        return $map;
    }

    private function readOrderedSnapshot(string $snapshotPath): ?array
    {
        if (!is_file($snapshotPath)) {
            return null;
        }
        $stream = @fopen($snapshotPath, 'rb');
        if ($stream === false) {
            return null;
        }
        $directory = [];
        try {
            $header = FileSystem::readExact($stream, self::ORDERED_SNAPSHOT_HEADER_BYTES, true);
            if ($header === null || substr($header, 0, 4) !== self::ORDERED_SNAPSHOT_MAGIC) {
                return null;
            }
            if (BinaryCodec::readUint32($header, 4) !== self::ORDERED_SNAPSHOT_VERSION) {
                return null;
            }
            $blockCount = BinaryCodec::readUint64($header, 8);
            $logLength = BinaryCodec::readUint64($header, 16);
            $snapshotBytes = $this->fileSize($snapshotPath);
            if ($blockCount > intdiv(max(0, $snapshotBytes - self::ORDERED_SNAPSHOT_HEADER_BYTES - 4), 10)) {
                return null;
            }
            $protected = $header;
            $previousKey = null;
            $previousOffset = null;
            for ($index = 0; $index < $blockCount; $index++) {
                $offsetField = FileSystem::readExact($stream, 8, true);
                $lengthField = FileSystem::readExact($stream, 2, true);
                if ($offsetField === null || $lengthField === null) {
                    return null;
                }
                $blockOffset = BinaryCodec::readUint64($offsetField, 0);
                $firstKeyLength = unpack('n', $lengthField)[1];
                if ($firstKeyLength < 1 || $firstKeyLength > self::MAXIMUM_KEY_BYTES) {
                    return null;
                }
                $firstKey = FileSystem::readExact($stream, $firstKeyLength, true);
                if ($firstKey === null) {
                    return null;
                }
                if (($previousKey !== null && strcmp($previousKey, $firstKey) >= 0)
                    || ($previousOffset !== null && $blockOffset <= $previousOffset)) {
                    return null;
                }
                $protected .= $offsetField . $lengthField . $firstKey;
                $directory[] = ['key' => $firstKey, 'offset' => $blockOffset];
                $previousKey = $firstKey;
                $previousOffset = $blockOffset;
            }
            $checksum = FileSystem::readExact($stream, 4, true);
            $blocksStart = ftell($stream);
            if ($checksum === null || $blocksStart === false
                || !hash_equals($checksum, BinaryCodec::crc32($protected))) {
                return null;
            }
            foreach ($directory as $entry) {
                if ($entry['offset'] < $blocksStart || $entry['offset'] >= $snapshotBytes) {
                    return null;
                }
            }
        } catch (FoxyException) {
            return null;
        } finally {
            fclose($stream);
        }
        return ['directory' => $directory, 'logLength' => $logLength];
    }

    private function buildOrderedSnapshot(string $indexName, string $snapshotPath): ?array
    {
        $runDir = $this->root . DIRECTORY_SEPARATOR . $indexName . DIRECTORY_SEPARATOR . self::ORDERED_RUN_DIR;
        FileSystem::removeTree($runDir);
        FileSystem::ensureDirectory($runDir);
        $logPath = $this->indexPath($indexName);
        $logLength = $this->fileSize($logPath);
        try {
            $runs = $this->createSortedRuns($logPath, $runDir);
            if ($runs === []) {
                return ['directory' => [], 'logLength' => $logLength];
            }
            $sortedPath = $this->mergeRuns($runDir, $runs);
            return $this->composeSnapshot($runDir, $sortedPath, $snapshotPath, $logLength);
        } finally {
            FileSystem::removeTree($runDir);
        }
    }

    private function createSortedRuns(string $logPath, string $runDir): array
    {
        $stream = @fopen($logPath, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
        }
        $buffer = [];
        $buffered = 0;
        $runs = [];
        $runIndex = 0;
        $sequence = 0;
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES || $keyLength > 65535) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if ($operation !== 'P' && $operation !== 'D') {
                    throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                }
                $tuple = pack('n', $keyLength) . $key
                    . BinaryCodec::uint64($rowId)
                    . BinaryCodec::uint64($sequence++)
                    . ($operation === 'D' ? "\x00" : "\x01");
                $buffer[] = $tuple;
                $buffered += strlen($tuple);
                if ($buffered >= self::ORDERED_RUN_BYTES) {
                    usort($buffer, [self::class, 'compareTuples']);
                    $runs[] = $this->writeRun($runDir, $runIndex++, $buffer);
                    $buffer = [];
                    $buffered = 0;
                }
            }
        } finally {
            fclose($stream);
        }
        if ($buffer !== []) {
            usort($buffer, [self::class, 'compareTuples']);
            $runs[] = $this->writeRun($runDir, $runIndex++, $buffer);
        }
        return $runs;
    }

    private function writeRun(string $runDir, int $index, array $buffer): string
    {
        $path = $runDir . DIRECTORY_SEPARATOR . sprintf('%05d.run', $index);
        $stream = @fopen($path, 'wb');
        if ($stream === false) {
            throw new FoxyException('Unable to create index sort run.', 'STORAGE_IO');
        }
        try {
            FileSystem::writeAll($stream, implode('', $buffer));
            FileSystem::flush($stream, false);
        } finally {
            fclose($stream);
        }
        return $path;
    }

    private function mergeRuns(string $runDir, array $runs): string
    {
        $nextId = count($runs);
        while (count($runs) > 1) {
            $next = [];
            for ($i = 0; $i < count($runs); $i += 2) {
                if ($i + 1 < count($runs)) {
                    $output = $runDir . DIRECTORY_SEPARATOR . sprintf('m%06d.run', $nextId++);
                    $this->mergeTwoRuns($runs[$i], $runs[$i + 1], $output);
                    $next[] = $output;
                } else {
                    $next[] = $runs[$i];
                }
            }
            foreach ($runs as $old) {
                if (!in_array($old, $next, true)) {
                    @unlink($old);
                }
            }
            $runs = $next;
        }
        return $runs[0];
    }

    private function mergeTwoRuns(string $leftPath, string $rightPath, string $outputPath): void
    {
        $left = @fopen($leftPath, 'rb');
        $right = @fopen($rightPath, 'rb');
        if ($left === false || $right === false) {
            if ($left !== false) {
                fclose($left);
            }
            if ($right !== false) {
                fclose($right);
            }
            throw new FoxyException('Unable to open index sort run.', 'STORAGE_IO');
        }
        $out = @fopen($outputPath, 'wb');
        if ($out === false) {
            fclose($left);
            fclose($right);
            throw new FoxyException('Unable to create index sort run.', 'STORAGE_IO');
        }
        $leftTuple = $this->readTuple($left);
        $rightTuple = $this->readTuple($right);
        try {
            while ($leftTuple !== null || $rightTuple !== null) {
                if ($rightTuple === null || ($leftTuple !== null
                    && self::compareTuples($leftTuple, $rightTuple) <= 0)) {
                    FileSystem::writeAll($out, $leftTuple);
                    $leftTuple = $this->readTuple($left);
                } else {
                    FileSystem::writeAll($out, $rightTuple);
                    $rightTuple = $this->readTuple($right);
                }
            }
            FileSystem::flush($out, false);
        } finally {
            fclose($left);
            fclose($right);
            fclose($out);
        }
    }

    private function readTuple($stream): ?string
    {
        $keyLengthField = FileSystem::readExact($stream, 2, true);
        if ($keyLengthField === null) {
            return null;
        }
        $keyLength = unpack('n', $keyLengthField)[1];
        if ($keyLength > 65535) {
            throw new FoxyException('Invalid index sort tuple.', 'STORAGE_CORRUPT');
        }
        $rest = FileSystem::readExact($stream, $keyLength + 17);
        return $keyLengthField . $rest;
    }

    private static function compareTuples(string $left, string $right): int
    {
        $leftLength = unpack('n', substr($left, 0, 2))[1];
        $rightLength = unpack('n', substr($right, 0, 2))[1];
        $comparison = strcmp(substr($left, 2, $leftLength), substr($right, 2, $rightLength));
        if ($comparison !== 0) {
            return $comparison;
        }
        return strcmp(substr($left, 2 + $leftLength), substr($right, 2 + $rightLength));
    }

    private function composeSnapshot(string $runDir, string $sortedPath, string $snapshotPath, int $logLength): array
    {
        $stream = @fopen($sortedPath, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open index sort run.', 'STORAGE_IO');
        }
        $blockFile = @fopen($runDir . DIRECTORY_SEPARATOR . 'blocks.tmp', 'wb');
        if ($blockFile === false) {
            fclose($stream);
            throw new FoxyException('Unable to create index snapshot.', 'STORAGE_IO');
        }
        $directory = [];
        $blockOffsets = [];
        $blockBuffer = '';
        $blockKey = null;
        $blockBytes = 0;
        $currentKey = null;
        $currentIds = null;
        try {
            while (($tuple = $this->readTuple($stream)) !== null) {
                $keyLength = unpack('n', substr($tuple, 0, 2))[1];
                $key = substr($tuple, 2, $keyLength);
                $rowId = BinaryCodec::readUint64($tuple, 2 + $keyLength);
                $op = $tuple[strlen($tuple) - 1];
                if ($currentKey !== null && $key === $currentKey) {
                    if ($op === "\x00") {
                        unset($currentIds[$rowId]);
                    } else {
                        $currentIds[$rowId] = true;
                    }
                    continue;
                }
                $this->flushKeyGroup($currentKey, $currentIds, $blockFile, $blockBuffer, $blockKey, $blockBytes, $blockOffsets, $directory);
                $currentKey = $key;
                $currentIds = $op === "\x01" ? [$rowId => true] : [];
            }
            $this->flushKeyGroup($currentKey, $currentIds, $blockFile, $blockBuffer, $blockKey, $blockBytes, $blockOffsets, $directory);
            if ($blockBuffer !== '') {
                $this->flushOrderedBlock($blockFile, $blockBuffer, $blockKey, $blockOffsets, $directory);
            }
            FileSystem::flush($blockFile, false);
        } finally {
            fclose($stream);
            fclose($blockFile);
        }

        if ($directory === []) {
            @unlink($snapshotPath);
            return ['directory' => [], 'logLength' => $logLength];
        }
        $absolute = $this->assembleOrderedSnapshot($runDir, $snapshotPath, $directory, $blockOffsets, $logLength);
        return ['directory' => $absolute, 'logLength' => $logLength];
    }

    private function flushKeyGroup(
        ?string $key,
        ?array $ids,
        $blockFile,
        string &$blockBuffer,
        ?string &$blockKey,
        int &$blockBytes,
        array &$blockOffsets,
        array &$directory,
    ): void {
        if ($key === null || $ids === null || $ids === []) {
            return;
        }
        $rowIds = array_keys($ids);
        sort($rowIds, SORT_NUMERIC);
        foreach (array_chunk($rowIds, self::ORDERED_SURVIVOR_CHUNK) as $chunk) {
            $entry = pack('n', strlen($key)) . $key . pack('n', count($chunk));
            foreach ($chunk as $id) {
                $entry .= BinaryCodec::uint64((int) $id);
            }
            if ($blockBuffer !== '' && $blockBytes + strlen($entry) > self::ORDERED_BLOCK_BYTES) {
                $this->flushOrderedBlock($blockFile, $blockBuffer, $blockKey, $blockOffsets, $directory);
                $blockBuffer = '';
                $blockKey = null;
                $blockBytes = 0;
            }
            if ($blockBuffer === '') {
                $blockKey = $key;
            }
            $blockBuffer .= $entry;
            $blockBytes += strlen($entry);
        }
    }

    private function flushOrderedBlock($blockFile, string $payload, ?string $firstKey, array &$blockOffsets, array &$directory): void
    {
        $offset = ftell($blockFile);
        $blockOffsets[] = $offset;
        $directory[] = ['key' => $firstKey];
        FileSystem::writeAll(
            $blockFile,
            BinaryCodec::uint32(strlen($payload)) . BinaryCodec::crc32($payload) . $payload,
        );
    }

    private function assembleOrderedSnapshot(string $runDir, string $snapshotPath, array $directory, array $blockOffsets, int $logLength): array
    {
        $blocksStart = self::ORDERED_SNAPSHOT_HEADER_BYTES + 4;
        foreach ($directory as $entry) {
            $blocksStart += 8 + 2 + strlen($entry['key']);
        }
        $absolute = [];
        foreach ($directory as $index => $entry) {
            $absolute[] = [
                'key' => $entry['key'],
                'offset' => $blocksStart + $blockOffsets[$index],
            ];
        }
        $temporary = $snapshotPath . '.tmp.' . bin2hex(random_bytes(8));
        $out = @fopen($temporary, 'wb');
        if ($out === false) {
            throw new FoxyException('Unable to create index snapshot.', 'STORAGE_IO');
        }
        try {
            $protected = self::ORDERED_SNAPSHOT_MAGIC
                . BinaryCodec::uint32(self::ORDERED_SNAPSHOT_VERSION)
                . BinaryCodec::uint64(count($directory))
                . BinaryCodec::uint64($logLength);
            foreach ($directory as $index => $entry) {
                $protected .= BinaryCodec::uint64($absolute[$index]['offset'])
                    . pack('n', strlen($entry['key'])) . $entry['key'];
            }
            FileSystem::writeAll($out, $protected . BinaryCodec::crc32($protected));
            $blocks = @fopen($runDir . DIRECTORY_SEPARATOR . 'blocks.tmp', 'rb');
            if ($blocks === false) {
                throw new FoxyException('Unable to read index snapshot blocks.', 'STORAGE_IO');
            }
            try {
                if (stream_copy_to_stream($blocks, $out) === false) {
                    throw new FoxyException('Unable to copy index snapshot blocks.', 'STORAGE_IO');
                }
            } finally {
                fclose($blocks);
            }
            FileSystem::flush($out, $this->config->syncWrites);
            fclose($out);
            if (!@rename($temporary, $snapshotPath)) {
                @unlink($temporary);
                throw new FoxyException('Unable to publish index snapshot.', 'STORAGE_IO');
            }
        } catch (\Throwable $exception) {
            if (is_resource($out)) {
                fclose($out);
            }
            @unlink($temporary);
            throw $exception;
        }
        return $absolute;
    }

    private function rangeLookupOnDisk(
        array $map,
        ?string $minimum,
        ?string $maximum,
        bool $minInclusive,
        bool $maxInclusive,
    ): array {
        $directory = $map['directory'];
        $count = count($directory);
        if ($count === 0) {
            return [];
        }
        $start = 0;
        if ($minimum !== null) {
            $keys = [];
            foreach ($directory as $entry) {
                $keys[] = $entry['key'];
            }
            $start = max(0, $this->lowerBound($keys, $minimum, $minInclusive) - 1);
        }
        $stream = @fopen($map['path'], 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open ordered index snapshot.', 'STORAGE_IO');
        }
        $byKey = [];
        try {
            for ($index = $start; $index < $count; $index++) {
                $blockKey = $directory[$index]['key'];
                if ($maximum !== null) {
                    $comparison = strcmp($blockKey, $maximum);
                    if ($comparison > 0) {
                        break;
                    }
                    if ($comparison === 0 && !$maxInclusive) {
                        break;
                    }
                }
                $this->readOrderedBlock(
                    $stream,
                    $directory[$index]['offset'],
                    $minimum,
                    $maximum,
                    $minInclusive,
                    $maxInclusive,
                    $byKey,
                );
            }
        } finally {
            fclose($stream);
        }
        if (isset($map['tail']) && $map['tail'] !== []) {
            foreach ($map['tail'] as $record) {
                [$operation, $rowId, $key] = $record;
                $inRange = ($minimum === null || strcmp($key, $minimum) > 0 || ($minInclusive && strcmp($key, $minimum) === 0))
                    && ($maximum === null || strcmp($key, $maximum) < 0 || ($maxInclusive && strcmp($key, $maximum) === 0));
                if (!$inRange) {
                    continue;
                }
                if ($operation === 'P') {
                    if (!isset($byKey[$key])) {
                        $byKey[$key] = [];
                    }
                    $byKey[$key][$rowId] = true;
                } elseif ($operation === 'D') {
                    unset($byKey[$key][$rowId]);
                }
            }
        }
        $matches = [];
        foreach ($byKey as $rowIds) {
            foreach (array_keys($rowIds) as $rowId) {
                $matches[] = $rowId;
            }
        }
        sort($matches, SORT_NUMERIC);
        return $matches;
    }

    private function matchedCount(array $byKey): int
    {
        $count = 0;
        foreach ($byKey as $rowIds) {
            $count += count($rowIds);
        }
        return $count;
    }

    private function readOrderedBlock(
        $stream,
        int $offset,
        ?string $minimum,
        ?string $maximum,
        bool $minInclusive,
        bool $maxInclusive,
        array &$byKey,
    ): void
    {
        if (@fseek($stream, $offset) !== 0) {
            throw new FoxyException('Unable to seek ordered index snapshot.', 'STORAGE_IO');
        }
        $blockHeader = FileSystem::readExact($stream, 8, true);
        if ($blockHeader === null) {
            throw new FoxyException('Ordered index snapshot is truncated.', 'STORAGE_CORRUPT');
        }
        $payloadLength = BinaryCodec::readUint32($blockHeader, 0);
        if ($payloadLength > self::ORDERED_BLOCK_BYTES + self::MAXIMUM_KEY_BYTES + 4_098) {
            throw new FoxyException('Invalid index snapshot block.', 'STORAGE_CORRUPT');
        }
        $payload = FileSystem::readExact($stream, $payloadLength);
        if ($payload === null) {
            throw new FoxyException('Ordered index snapshot block is truncated.', 'STORAGE_CORRUPT');
        }
        if (!hash_equals(substr($blockHeader, 4, 4), BinaryCodec::crc32($payload))) {
            throw new FoxyException('Ordered index snapshot block checksum mismatch.', 'STORAGE_CORRUPT');
        }
        $position = 0;
        $payloadBytes = strlen($payload);
        while ($position < $payloadBytes) {
            if ($position + 2 > $payloadBytes) {
                throw new FoxyException('Ordered index snapshot entry is truncated.', 'STORAGE_CORRUPT');
            }
            $keyLength = unpack('n', substr($payload, $position, 2))[1];
            $position += 2;
            if ($keyLength > self::MAXIMUM_KEY_BYTES || $keyLength > 65535 || $position + $keyLength > $payloadBytes) {
                throw new FoxyException('Ordered index snapshot key is invalid.', 'STORAGE_CORRUPT');
            }
            $key = substr($payload, $position, $keyLength);
            $position += $keyLength;
            if ($position + 2 > $payloadBytes) {
                throw new FoxyException('Ordered index snapshot row count is truncated.', 'STORAGE_CORRUPT');
            }
            $idCount = unpack('n', substr($payload, $position, 2))[1];
            $position += 2;
            if ($position + $idCount * 8 > $payloadBytes) {
                throw new FoxyException('Ordered index snapshot row ids are truncated.', 'STORAGE_CORRUPT');
            }
            if (($minimum === null || strcmp($key, $minimum) > 0 || ($minInclusive && strcmp($key, $minimum) === 0))
                && ($maximum === null || strcmp($key, $maximum) < 0 || ($maxInclusive && strcmp($key, $maximum) === 0))) {
                if (!isset($byKey[$key])) {
                    $byKey[$key] = [];
                }
                for ($j = 0; $j < $idCount; $j++) {
                    $byKey[$key][BinaryCodec::readUint64($payload, $position + $j * 8)] = true;
                }
            }
            $position += $idCount * 8;
        }
    }

    private function readIndexTail(string $logPath, int $fromOffset, int $currentBytes): array
    {
        $records = [];
        $stream = @fopen($logPath, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open ordered index log.', 'STORAGE_IO');
        }
        try {
            if (@fseek($stream, $fromOffset) !== 0) {
                throw new FoxyException('Unable to seek ordered index log.', 'STORAGE_IO');
            }
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid ordered index tail key.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
                    throw new FoxyException('Ordered index tail checksum mismatch.', 'STORAGE_CORRUPT');
                }
                if ($operation !== 'P' && $operation !== 'D') {
                    throw new FoxyException('Invalid ordered index tail operation.', 'STORAGE_CORRUPT');
                }
                $records[] = [$operation, $rowId, $key];
            }
        } finally {
            fclose($stream);
        }
        return $records;
    }

    private function scanRange(
        string $indexName,
        ?string $minimum,
        ?string $maximum,
        bool $minInclusive,
        bool $maxInclusive,
    ): array {
        $path = $this->indexPath($indexName);
        if (!is_file($path)) {
            return [];
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open index file.', 'STORAGE_IO');
        }
        $byKey = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
                    throw new FoxyException('Index record checksum mismatch.', 'STORAGE_CORRUPT');
                }
                $inRange = ($minimum === null || strcmp($key, $minimum) > 0 || ($minInclusive && strcmp($key, $minimum) === 0))
                    && ($maximum === null || strcmp($key, $maximum) < 0 || ($maxInclusive && strcmp($key, $maximum) === 0));
                if (!$inRange) {
                    continue;
                }
                if ($operation === 'P') {
                    if (!isset($byKey[$key])) {
                        $byKey[$key] = [];
                    }
                    $byKey[$key][$rowId] = true;
                } elseif ($operation === 'D') {
                    unset($byKey[$key][$rowId]);
                } else {
                    throw new FoxyException('Invalid index operation.', 'STORAGE_CORRUPT');
                }
            }
        } finally {
            fclose($stream);
        }
        $matches = [];
        foreach ($byKey as $rowIds) {
            foreach ($rowIds as $rowId) {
                $matches[] = $rowId;
            }
        }
        sort($matches, SORT_NUMERIC);
        return $matches;
    }

    private function lowerBound(array $keys, string $needle, bool $inclusive): int
    {
        $low = 0;
        $high = count($keys);
        while ($low < $high) {
            $middle = intdiv($low + $high, 2);
            $comparison = strcmp($keys[$middle], $needle);
            if ($comparison < 0 || ($comparison === 0 && !$inclusive)) {
                $low = $middle + 1;
            } else {
                $high = $middle;
            }
        }
        return $low;
    }

    private function upperBound(array $keys, string $target, bool $inclusive): int
    {
        $low = 0;
        $high = count($keys);
        while ($low < $high) {
            $middle = intdiv($low + $high, 2);
            $comparison = strcmp($keys[$middle], $target);
            $excluded = $inclusive ? $comparison > 0 : $comparison >= 0;
            if (!$excluded) {
                $low = $middle + 1;
            } else {
                $high = $middle;
            }
        }
        return $low;
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
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $key = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
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

    private function fileSize(string $path): int
    {
        $size = @filesize($path);
        if (!is_int($size) || $size < 0) {
            throw new FoxyException('Index file exceeds this platform file-offset limit.', 'PLATFORM_LIMIT');
        }
        return $size;
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
            throw new FoxyException("Index {$indexName} is missing.", 'STORAGE_CORRUPT');
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
            throw new FoxyException('Unable to open legacy index bucket.', 'STORAGE_IO');
        }
        $matches = [];
        try {
            while (($header = FileSystem::readExact($stream, self::HEADER_BYTES, true)) !== null) {
                $operation = $header[0];
                $rowId = BinaryCodec::readUint64($header, 1);
                $keyLength = BinaryCodec::readUint32($header, 9);
                $checksum = substr($header, 13, 4);
                if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                    throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                }
                $storedKey = FileSystem::readExact($stream, $keyLength) ?? '';
                if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $storedKey))) {
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
                    $checksum = substr($header, 13, 4);
                    if ($keyLength > self::MAXIMUM_KEY_BYTES) {
                        throw new FoxyException('Invalid index key length.', 'STORAGE_CORRUPT');
                    }
                    $key = FileSystem::readExact($stream, $keyLength) ?? '';
                    if (!hash_equals($checksum, BinaryCodec::crc32(substr($header, 0, 13) . $key))) {
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
