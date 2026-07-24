<?php

declare(strict_types=1);

namespace FoxyDB\Storage;

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\BinaryCodec;
use FoxyDB\Support\FileSystem;
use FoxyDB\Support\MemoryCache;
use FoxyDB\TypeSystem;

final class Table
{
    private const DATA_HEADER_BYTES = 28;
    private const SLOT_BYTES = 24;
    private const SLOT_ACTIVE = 1;
    private const SLOT_DELETED = 2;
    private const RECORD_COMPRESSED = 1;

    private readonly TypeSystem $types;
    private readonly ChunkStore $chunks;
    private readonly string $lockPath;
    private bool $mutationNotified = false;
    private ?array $metadataCache = null;
    private array $indexStores = [];
    private ?\Closure $undoCallback = null;

    public function __construct(
        private readonly string $path,
        private readonly Config $config,
        ?string $lockPath = null,
        private readonly ?MemoryCache $bufferPool = null,
        private readonly ?MemoryCache $indexCache = null,
        private readonly ?\Closure $onMutation = null,
    ) {
        if ($lockPath === null && (!is_dir($path) || !is_file($this->metadataPath()))) {
            throw new FoxyException('Table does not exist.', 'TABLE_NOT_FOUND');
        }
        $this->lockPath = $lockPath ?? $path . DIRECTORY_SEPARATOR . 'table.lock';
        FileSystem::ensureDirectory(dirname($this->lockPath));
        $lock = $this->acquireLock(LOCK_EX);
        try {
            if (!is_dir($path) || !is_file($this->metadataPath())) {
                throw new FoxyException('Table does not exist.', 'TABLE_NOT_FOUND');
            }
            $this->types = new TypeSystem($config);
            $this->chunks = new ChunkStore($path . DIRECTORY_SEPARATOR . 'chunks', $config);
            $this->recoverLocked();
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function setUndoCallback(?\Closure $callback): void
    {
        $this->undoCallback = $callback;
    }

    public static function create(string $path, array $schema, Config $config): void
    {
        if (file_exists($path)) {
            throw new FoxyException("Table {$schema['name']} already exists.", 'TABLE_EXISTS');
        }
        FileSystem::ensureDirectory(dirname($path));
        $temporary = $path . '.creating.' . bin2hex(random_bytes(6));
        FileSystem::ensureDirectory($temporary);
        try {
            FileSystem::ensureDirectory($temporary . DIRECTORY_SEPARATOR . 'chunks');
            $generation = $temporary . DIRECTORY_SEPARATOR . self::generationName(1);
            $schema['previous_generation'] = null;
            self::initializeGeneration($generation, array_keys($schema['indexes']), $config);
            FileSystem::writeMetadata($temporary . DIRECTORY_SEPARATOR . 'meta.fdb', $schema, $config->syncWrites);
            self::writeSequenceFile(
                $temporary . DIRECTORY_SEPARATOR . 'sequence.fdb',
                1,
                1,
                $config->syncWrites,
            );
            $lock = @fopen($temporary . DIRECTORY_SEPARATOR . 'table.lock', 'c+b');
            if ($lock === false) {
                throw new FoxyException('Unable to create table lock.', 'STORAGE_IO');
            }
            fclose($lock);
            if (!@rename($temporary, $path)) {
                throw new FoxyException('Unable to publish table directory.', 'STORAGE_IO');
            }
        } catch (\Throwable $exception) {
            if (is_dir($temporary)) {
                FileSystem::removeTree($temporary);
            }
            throw $exception;
        }
    }

    public function schema(): array
    {
        $lock = $this->acquireReadyReadLock();
        try {
            return $this->loadMetadata();
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function insert(array $input): array
    {
        return $this->insertMany([$input])[0];
    }

    public function insertMany(array $inputs, ?int $maximumStagingBytes = null): array
    {
        if ($inputs === []) {
            return [];
        }
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            [$nextRowId, $nextAuto] = $this->readSequenceLocked($schema);
            $autoColumn = $schema['auto_increment_column'];
            $prepared = [];
            $pendingUnique = [];
            $stagedBytes = 0;
            foreach ($inputs as $input) {
                if ($nextRowId === PHP_INT_MAX) {
                    throw new FoxyException('The table row identifier space is exhausted.', 'RESOURCE_LIMIT');
                }
                if ($this->readSlotLocked($schema, $nextRowId) !== null) {
                    throw new FoxyException('Row sequence points to an allocated slot.', 'STORAGE_CORRUPT');
                }
                $row = $this->types->prepareInsert($input, $schema, $nextAuto);
                if ($autoColumn !== null) {
                    $autoValue = $row[$autoColumn];
                    if ($autoValue >= PHP_INT_MAX) {
                        throw new FoxyException('The AUTO_INCREMENT sequence is exhausted.', 'RESOURCE_LIMIT');
                    }
                    $nextAuto = max($nextAuto, $autoValue + 1);
                }
                $this->assertUniqueLocked($schema, $row, null);
                foreach ($this->indexEntries($schema, $row) as $name => $entry) {
                    if (!$schema['indexes'][$name]['unique'] || $entry['skip']) {
                        continue;
                    }
                    $encodedKey = base64_encode($entry['key']);
                    if (isset($pendingUnique[$name][$encodedKey])) {
                        throw new FoxyException(
                            "Unique constraint {$name} is violated.",
                            'UNIQUE_VIOLATION',
                            ['index' => $name],
                        );
                    }
                    $pendingUnique[$name][$encodedKey] = true;
                    $stagedBytes += 64 + strlen($encodedKey);
                }
                $stagedBytes += 64 + MemoryCache::estimateBytes($row);
                if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                    throw new FoxyException('INSERT exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
                }
                $prepared[] = [
                    'row_id' => $nextRowId,
                    'row' => $row,
                    'last_insert_id' => $autoColumn === null ? null : $row[$autoColumn],
                ];
                $nextRowId++;
            }
            foreach ($prepared as &$entry) {
                $entry['record'] = $this->encodeRecord($schema, $entry['row_id'], $entry['row']);
                $stagedBytes += strlen($entry['record']);
                if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                    throw new FoxyException('INSERT exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
                }
            }
            unset($entry);
            $this->writeSequence($nextRowId, $nextAuto);
            foreach ($prepared as $entry) {
                $this->storeRowLocked($schema, $entry['row_id'], $entry['row'], null, $entry['record']);
            }
            foreach ($prepared as &$entry) {
                unset($entry['record']);
            }
            unset($entry);
            return $prepared;
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function rows(?array $lookup = null): \Generator
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            $generation = $this->generationPath($schema);
            $lookupIndex = $lookup === null ? null : ($schema['indexes'][$lookup['name']] ?? null);
            $lookupValid = $lookupIndex !== null
                && ($lookup['signature'] ?? null) === [
                    'columns' => $lookupIndex['columns'],
                    'unique' => $lookupIndex['unique'],
                    'primary' => $lookupIndex['primary'],
                ];
            if ($lookupValid) {
                $store = $this->indexStore($schema);
                $rowIds = $store->lookup($lookup['name'], $lookup['key']);
                $maximum = null;
                $prefetched = count($rowIds) <= 256 ? $this->readRowsLocked($schema, $rowIds) : null;
            } else {
                $slotBytes = filesize($generation . DIRECTORY_SEPARATOR . 'rows.fdx');
                if ($slotBytes === false || $slotBytes % self::SLOT_BYTES !== 0) {
                    throw new FoxyException('Row slot file has a truncated tail.', 'STORAGE_CORRUPT');
                }
                $rowIds = null;
                $maximum = intdiv($slotBytes, self::SLOT_BYTES);
                $prefetched = $maximum === 0
                    ? []
                    : $this->readRowsLocked($schema, range(1, min($maximum, 256)));
            }
        } finally {
            $this->releaseLock($lock);
        }

        if ($rowIds !== null) {
            if ($prefetched !== null) {
                yield from $prefetched;
                return;
            }
            foreach (array_chunk($rowIds, 256) as $batch) {
                foreach ($this->readCurrentRows($batch) as $entry) {
                    yield $entry;
                }
            }
            return;
        }
        yield from $prefetched;
        for ($first = 257; $first <= $maximum; $first += 256) {
            $last = min($maximum, $first + 255);
            foreach ($this->readCurrentRows(range($first, $last)) as $entry) {
                yield $entry;
            }
        }
    }

    public function countActiveRows(): int
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            $path = $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx';
            $stream = @fopen($path, 'rb');
            if ($stream === false) {
                throw new FoxyException('Unable to open row slots.', 'STORAGE_IO');
            }
            try {
                $statistics = fstat($stream);
                if ($statistics === false) {
                    throw new FoxyException('Unable to inspect row slots.', 'STORAGE_IO');
                }
                $bytes = (int) ($statistics['size'] ?? -1);
                if ($bytes < 0 || $bytes % self::SLOT_BYTES !== 0) {
                    throw new FoxyException('Row slot file has a truncated tail.', 'STORAGE_CORRUPT');
                }
                $count = 0;
                $emptySlot = str_repeat("\0", self::SLOT_BYTES);
                $remaining = intdiv($bytes, self::SLOT_BYTES);
                while ($remaining > 0) {
                    $slots = min(1_024, $remaining);
                    $block = FileSystem::readExact($stream, $slots * self::SLOT_BYTES) ?? '';
                    for ($index = 0; $index < $slots; $index++) {
                        $encoded = substr($block, $index * self::SLOT_BYTES, self::SLOT_BYTES);
                        if ($encoded === $emptySlot) {
                            continue;
                        }
                        if ($this->decodeSlotBytes($encoded)['status'] === self::SLOT_ACTIVE) {
                            $count++;
                        }
                    }
                    $remaining -= $slots;
                }
                return $count;
            } finally {
                fclose($stream);
            }
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function estimateSize(): array
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            $genPath = $this->generationPath($schema);
            $dataFile = $genPath . DIRECTORY_SEPARATOR . 'rows.fdb';
            $dataLength = @filesize($dataFile) ?: 0;
            $indexLength = 0;
            $indexRoot = $genPath . DIRECTORY_SEPARATOR . 'indexes';
            if (is_dir($indexRoot)) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($indexRoot, \FilesystemIterator::SKIP_DOTS),
                );
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $indexLength += $file->getSize();
                    }
                }
            }
            return ['data_length' => $dataLength, 'index_length' => $indexLength];
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function setAutoIncrement(int $value): void
    {
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $schema = $this->loadMetadata();
            [$nextRow, $nextAuto] = $this->readSequenceLocked($schema);
            $this->writeSequence($nextRow, $value);
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function setCollation(string $collation): void
    {
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $schema = $this->loadMetadata(true);
            $schema['collation'] = $collation;
            $this->storeMetadata($schema);
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function checksum(): string
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            $hash = hash_init('crc32b');
            foreach ($this->iterateRowsLocked($schema, null, true) as $entry) {
                hash_update($hash, $entry['record']);
            }
            return hash_final($hash);
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function check(): array
    {
        return $this->verify();
    }

    public function verify(): array
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            $this->validateMetadata($schema);
            $slotPath = $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx';
            $slotBytes = @filesize($slotPath);
            if ($slotBytes === false || $slotBytes % self::SLOT_BYTES !== 0) {
                throw new FoxyException('Row slot file has an invalid length.', 'STORAGE_CORRUPT');
            }
            $stream = @fopen($slotPath, 'rb');
            if ($stream === false) {
                throw new FoxyException('Unable to open row slot file.', 'STORAGE_IO');
            }
            $count = 0;
            $errors = [];
            $remaining = intdiv($slotBytes, self::SLOT_BYTES);
            while ($remaining > 0) {
                $slots = min(1_024, $remaining);
                $block = FileSystem::readExact($stream, $slots * self::SLOT_BYTES) ?? '';
                for ($i = 0; $i < $slots; $i++) {
                    $slot = substr($block, $i * self::SLOT_BYTES, self::SLOT_BYTES);
                    try {
                        $decoded = $this->decodeSlotBytes($slot);
                        if ($decoded['status'] === self::SLOT_ACTIVE) {
                            $count++;
                        }
                    } catch (\Throwable $e) {
                        $errors[] = 'Slot ' . ($remaining - $remaining + $i) . ': ' . $e->getMessage();
                    }
                }
                $remaining -= $slots;
            }
            fclose($stream);
            if ($errors !== []) {
                return ['status' => 'corrupt', 'rows' => $count, 'errors' => $errors];
            }
            return ['status' => 'ok', 'rows' => $count, 'errors' => []];
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function flush(): void
    {
        $this->metadataCache = null;
    }

    public function update(
        array $assignments,
        ?callable $predicate = null,
        ?array $lookup = null,
        ?int $maximumStagingBytes = null,
    ): int
    {
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            $changes = [];
            $stagedBytes = 0;
            foreach ($this->iterateRowsLocked($schema, $lookup) as $entry) {
                $oldRow = $entry['values'];
                if ($predicate !== null && !$predicate($oldRow)) {
                    continue;
                }
                $newRow = $this->types->prepareUpdate($oldRow, $assignments, $schema);
                $this->indexEntries($schema, $newRow);
                $changes[] = ['id' => $entry['id'], 'old' => $oldRow, 'new' => $newRow];
                $stagedBytes += 64 + MemoryCache::estimateBytes($oldRow) + MemoryCache::estimateBytes($newRow);
                if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                    throw new FoxyException('UPDATE exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
                }
                if (count($changes) > $this->config->maxRowsPerResult) {
                    throw new FoxyException('UPDATE exceeded the configured mutation row limit.', 'RESOURCE_LIMIT');
                }
            }
            $this->assertBatchUpdateUniqueLocked(
                $schema,
                $changes,
                $maximumStagingBytes,
                $stagedBytes,
            );
            foreach ($changes as &$change) {
                if ($change['new'] !== $change['old']) {
                    $change['record'] = $this->encodeRecord($schema, $change['id'], $change['new']);
                    $stagedBytes += strlen($change['record']);
                    if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                        throw new FoxyException(
                            'UPDATE exceeded the configured heap staging limit.',
                            'RESOURCE_LIMIT',
                        );
                    }
                }
            }
            unset($change);
            $autoColumn = $schema['auto_increment_column'];
            if ($autoColumn !== null) {
                [$nextRowId, $nextAuto] = $this->readSequenceLocked($schema);
                foreach ($changes as $change) {
                    if ($change['new'][$autoColumn] >= $nextAuto) {
                        if ($change['new'][$autoColumn] >= PHP_INT_MAX) {
                            throw new FoxyException('The AUTO_INCREMENT sequence is exhausted.', 'RESOURCE_LIMIT');
                        }
                        $nextAuto = $change['new'][$autoColumn] + 1;
                    }
                }
                $this->writeSequence($nextRowId, $nextAuto);
            }
            foreach ($changes as $change) {
                if ($change['new'] !== $change['old']) {
                    $this->storeRowLocked(
                        $schema,
                        $change['id'],
                        $change['new'],
                        $change['old'],
                        $change['record'],
                    );
                }
            }
            return count($changes);
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function delete(
        ?callable $predicate = null,
        ?array $lookup = null,
        ?int $maximumStagingBytes = null,
    ): int
    {
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            $deletions = [];
            foreach ($this->iterateRowsLocked($schema, $lookup) as $entry) {
                if ($predicate !== null && !$predicate($entry['values'])) {
                    continue;
                }
                $deletions[] = $entry;
                $stagedBytes = ($stagedBytes ?? 0) + MemoryCache::estimateBytes($entry);
                if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                    throw new FoxyException('DELETE exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
                }
                if (count($deletions) > $this->config->maxRowsPerResult) {
                    throw new FoxyException('DELETE exceeded the configured mutation row limit.', 'RESOURCE_LIMIT');
                }
            }
            foreach ($deletions as $entry) {
                $this->deleteRowLocked($schema, $entry['id'], $entry['values']);
            }
            return count($deletions);
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function rollbackEntries(array $entries): void
    {
        if ($entries === []) {
            return;
        }
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            FileSystem::atomicWrite($this->dirtyPath(), "dirty\n", $this->config->syncWrites);
            foreach (array_reverse($entries) as $entry) {
                $rowId = $entry['row_id'];
                if ($entry['old_slot_bytes'] === null) {
                    $current = $this->readSlotLocked($schema, $rowId);
                    if ($current !== null) {
                        $delSlot = $this->encodeSlot(0, 0, $current['generation'] + 1, self::SLOT_DELETED);
                        $this->writeSlotLocked($schema, $rowId, $delSlot);
                    }
                } else {
                    $this->writeSlotLocked($schema, $rowId, $entry['old_slot_bytes']);
                }
            }
            $this->rebuildIndexesLocked($schema);
            $this->finishMutationLocked();
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function createIndex(string $name, array $columns, bool $unique, bool $ifNotExists = false): void
    {
        $this->beginMutation();
        $name = TypeSystem::identifier($name);
        $columns = array_map([TypeSystem::class, 'identifier'], $columns);
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            if (isset($schema['indexes'][$name])) {
                if ($ifNotExists) {
                    return;
                }
                throw new FoxyException("Index {$name} already exists.", 'INDEX_EXISTS');
            }
            if ($columns === [] || count($columns) !== count(array_unique($columns))) {
                throw new FoxyException('An index requires distinct columns.', 'SCHEMA_ERROR');
            }
            $columnMap = [];
            foreach ($schema['columns'] as $column) {
                $columnMap[$column['name']] = $column;
            }
            foreach ($columns as $columnName) {
                if (!isset($columnMap[$columnName])) {
                    throw new FoxyException("Unknown column: {$columnName}", 'UNKNOWN_COLUMN');
                }
                if (in_array($columnMap[$columnName]['type'], ['TEXT', 'LONGTEXT', 'BLOB'], true)) {
                    throw new FoxyException("Column {$columnName} cannot be indexed.", 'SCHEMA_ERROR');
                }
            }

            $index = [
                'name' => $name,
                'columns' => $columns,
                'unique' => $unique,
                'primary' => false,
            ];
            $this->types->validateIndex($index, $schema);
            $generation = $this->generationPath($schema);
            $store = $this->indexStore($schema);
            $directory = $generation . DIRECTORY_SEPARATOR . 'indexes' . DIRECTORY_SEPARATOR . $name;
            FileSystem::removeTree($directory);
            try {
                $store->prepare([$name]);
                foreach ($this->iterateRowsLocked($schema, null) as $entry) {
                    $values = $this->indexValues($index, $entry['values']);
                    if ($unique && IndexStore::containsNull($values)) {
                        continue;
                    }
                    $store->append($name, IndexStore::key($values), $entry['id'], true);
                }
                if ($unique) {
                    $store->assertUnique($name);
                }
                $schema['indexes'][$name] = $index;
                $this->storeMetadata($schema);
                $this->notifyMutation();
            } catch (\Throwable $exception) {
                FileSystem::removeTree($directory);
                throw $exception;
            }
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function dropIndex(string $name, bool $ifExists = false): void
    {
        $this->beginMutation();
        $name = TypeSystem::identifier($name);
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            if (!isset($schema['indexes'][$name])) {
                if ($ifExists) {
                    return;
                }
                throw new FoxyException("Index {$name} does not exist.", 'INDEX_NOT_FOUND');
            }
            if (($schema['indexes'][$name]['primary'] ?? false) === true) {
                throw new FoxyException('The primary index cannot be dropped.', 'SCHEMA_ERROR');
            }
            unset($schema['indexes'][$name]);
            $this->storeMetadata($schema);
            $this->notifyMutation();
            FileSystem::removeTree(
                $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'indexes' . DIRECTORY_SEPARATOR . $name,
            );
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function truncate(): void
    {
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            $oldGeneration = $this->generationPath($schema);
            $obsoleteGeneration = $schema['previous_generation'] ?? null;
            $number = $this->nextGenerationNumber();
            $newGeneration = $this->path . DIRECTORY_SEPARATOR . self::generationName($number);
            self::initializeGeneration($newGeneration, array_keys($schema['indexes']), $this->config);
            $references = $this->path . DIRECTORY_SEPARATOR . '.truncate-refs-' . bin2hex(random_bytes(4));
            FileSystem::ensureDirectory($references);
            foreach ($this->iterateRowsLocked($schema, null, true) as $entry) {
                foreach ($entry['encoded'] as $encodedValue) {
                    $this->chunks->recordReferences($encodedValue, $references);
                }
            }
            $schema['previous_generation'] = $schema['active_generation'];
            $schema['active_generation'] = $number;
            $this->storeMetadata($schema);
            $this->notifyMutation();
            $this->writeSequence(1, 1);
            try {
                $this->chunks->garbageCollect($references);
            } finally {
                FileSystem::removeTree($references);
            }
            if ($obsoleteGeneration !== null && (int) $obsoleteGeneration !== (int) $schema['previous_generation']) {
                FileSystem::removeTree($this->path . DIRECTORY_SEPARATOR . self::generationName((int) $obsoleteGeneration));
            }
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function compact(): array
    {
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            $oldGeneration = $this->generationPath($schema);
            $obsoleteGeneration = $schema['previous_generation'] ?? null;
            $number = $this->nextGenerationNumber();
            $temporary = $this->path . DIRECTORY_SEPARATOR . self::generationName($number) . '.compacting';
            $published = $this->path . DIRECTORY_SEPARATOR . self::generationName($number);
            FileSystem::removeTree($temporary);
            self::initializeGeneration($temporary, array_keys($schema['indexes']), $this->config);
            $referenceDirectory = $this->path . DIRECTORY_SEPARATOR . '.chunk-refs-' . bin2hex(random_bytes(5));
            FileSystem::ensureDirectory($referenceDirectory);
            $rowsCopied = 0;
            try {
                $newData = @fopen($temporary . DIRECTORY_SEPARATOR . 'rows.fdb', 'c+b');
                $newSlots = @fopen($temporary . DIRECTORY_SEPARATOR . 'rows.fdx', 'c+b');
                if ($newData === false || $newSlots === false) {
                    if (is_resource($newData)) {
                        fclose($newData);
                    }
                    if (is_resource($newSlots)) {
                        fclose($newSlots);
                    }
                    throw new FoxyException('Unable to create compacted table files.', 'STORAGE_IO');
                }
                $newIndexes = new IndexStore($temporary . DIRECTORY_SEPARATOR . 'indexes', $this->config);
                $newIndexes->prepare(array_keys($schema['indexes']));
                try {
                    foreach ($this->iterateRowsLocked($schema, null, true) as $entry) {
                        $record = $entry['record'];
                        fseek($newData, 0, SEEK_END);
                        $offset = ftell($newData);
                        if ($offset === false) {
                            throw new FoxyException('Unable to locate compacted data offset.', 'STORAGE_IO');
                        }
                        FileSystem::writeAll($newData, $record);
                        $slot = $this->encodeSlot($offset, strlen($record), $entry['generation'], self::SLOT_ACTIVE);
                        $this->writeSlotToStream($newSlots, $entry['id'], $slot);
                        foreach ($entry['encoded'] as $encodedValue) {
                            $this->chunks->recordReferences($encodedValue, $referenceDirectory);
                        }
                        foreach ($this->indexEntries($schema, $entry['values']) as $indexName => $indexEntry) {
                            if ($indexEntry['skip']) {
                                continue;
                            }
                            $newIndexes->append($indexName, $indexEntry['key'], $entry['id'], true);
                        }
                        $rowsCopied++;
                    }
                    FileSystem::flush($newData, $this->config->syncWrites);
                    FileSystem::flush($newSlots, $this->config->syncWrites);
                } finally {
                    fclose($newData);
                    fclose($newSlots);
                }
                if (!@rename($temporary, $published)) {
                    throw new FoxyException('Unable to publish compacted generation.', 'STORAGE_IO');
                }
                $schema['previous_generation'] = $schema['active_generation'];
                $schema['active_generation'] = $number;
                $this->storeMetadata($schema);
                $this->notifyMutation();
                $chunksRemoved = $this->chunks->garbageCollect($referenceDirectory);
                if ($obsoleteGeneration !== null && (int) $obsoleteGeneration !== (int) $schema['previous_generation']) {
                    FileSystem::removeTree(
                        $this->path . DIRECTORY_SEPARATOR . self::generationName((int) $obsoleteGeneration),
                    );
                }
            } catch (\Throwable $exception) {
                if (is_dir($temporary)) {
                    FileSystem::removeTree($temporary);
                }
                throw $exception;
            } finally {
                FileSystem::removeTree($referenceDirectory);
            }
            return ['rows' => $rowsCopied, 'chunks_removed' => $chunksRemoved];
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function alterSchema(array $actions): array
    {
        $this->beginMutation();
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata(true);
            $newSchema = $schema;
            $columnRequiresRebuild = false;

            foreach ($actions as $action) {
                $kind = $action['kind'];
                if ($kind === 'set_auto_increment') {
                    $autoValue = (int) $action['value'];
                    [$nextRow, $nextAuto] = $this->readSequenceLocked($schema);
                    $this->writeSequence($nextRow, $autoValue);
                    continue;
                }
                if ($kind === 'set_collation') {
                    $schema['collation'] = $action['value'];
                    $this->storeMetadata($schema);
                    continue;
                }
                if ($kind === 'rename_column') {
                    $this->validateColumnExists($schema, $action['old_name']);
                    $newName = TypeSystem::identifier($action['new_name']);
                    $this->assertColumnNameUnique($newSchema, $newName, $action['old_name']);
                    foreach ($newSchema['columns'] as $i => $col) {
                        if ($col['name'] === $action['old_name']) {
                            $newSchema['columns'][$i]['name'] = $newName;
                            break;
                        }
                    }
                    if ($newSchema['auto_increment_column'] === $action['old_name']) {
                        $newSchema['auto_increment_column'] = $newName;
                    }
                    $newSchema['primary_key'] = array_map(
                        static fn(string $pk): string => $pk === $action['old_name'] ? $newName : $pk,
                        $newSchema['primary_key'],
                    );
                    foreach ($newSchema['indexes'] as &$index) {
                        $index['columns'] = array_map(
                            static fn(string $col): string => $col === $action['old_name'] ? $newName : $col,
                            $index['columns'],
                        );
                    }
                    unset($index);
                    $schema = $newSchema;
                    $this->storeMetadata($schema);
                    $this->notifyMutation();
                    continue;
                }
                if ($kind === 'rename_table') {
                    $newName = TypeSystem::identifier($action['new_name']);
                    $schema['name'] = $newName;
                    $this->storeMetadata($schema);
                    $this->notifyMutation();
                    continue;
                }
                if ($kind === 'rename_index') {
                    $this->validateIndexExists($schema, $action['old_name']);
                    $newName = TypeSystem::identifier($action['new_name']);
                    if (isset($newSchema['indexes'][$newName]) && $newName !== $action['old_name']) {
                        throw new FoxyException("Index {$newName} already exists.", 'INDEX_EXISTS');
                    }
                    $newSchema['indexes'][$newName] = $newSchema['indexes'][$action['old_name']];
                    $newSchema['indexes'][$newName]['name'] = $newName;
                    unset($newSchema['indexes'][$action['old_name']]);
                    $schema = $newSchema;
                    $this->storeMetadata($schema);
                    $this->notifyMutation();
                    continue;
                }
                if ($kind === 'add_index' || $kind === 'add_primary') {
                    $name = $kind === 'add_primary' ? 'primary' : TypeSystem::identifier($action['name']);
                    $columns = $action['columns'];
                    $unique = $kind === 'add_primary' || ($action['unique'] ?? false);
                    if (isset($newSchema['indexes'][$name])) {
                        throw new FoxyException("Index {$name} already exists.", 'INDEX_EXISTS');
                    }
                    $index = [
                        'name' => $name,
                        'columns' => $columns,
                        'unique' => $unique,
                        'primary' => $kind === 'add_primary',
                    ];
                    $this->types->validateIndex($index, $newSchema);
                    $newSchema['indexes'][$name] = $index;
                    if ($kind === 'add_primary') {
                        $newSchema['primary_key'] = $columns;
                        foreach ($newSchema['columns'] as &$col) {
                            if (in_array($col['name'], $columns, true)) {
                                $col['nullable'] = false;
                            }
                        }
                        unset($col);
                    }
                    $schema = $newSchema;
                    $this->storeMetadata($schema);
                    $store = $this->indexStore($schema);
                    $store->prepare([$name]);
                    foreach ($this->iterateRowsLocked($schema, null) as $entry) {
                        $values = $this->indexValues($index, $entry['values']);
                        if ($unique && IndexStore::containsNull($values)) {
                            continue;
                        }
                        $store->append($name, IndexStore::key($values), $entry['id'], true);
                    }
                    if ($unique) {
                        $store->assertUnique($name);
                    }
                    $this->notifyMutation();
                    continue;
                }
                if ($kind === 'drop_index' || $kind === 'drop_primary' || $kind === 'drop_constraint') {
                    $name = $kind === 'drop_primary' ? 'primary' : TypeSystem::identifier($action['name']);
                    $this->validateIndexExists($schema, $name);
                    if (($newSchema['indexes'][$name]['primary'] ?? false) === true) {
                        $newSchema['primary_key'] = [];
                    }
                    unset($newSchema['indexes'][$name]);
                    $schema = $newSchema;
                    $this->storeMetadata($schema);
                    FileSystem::removeTree(
                        $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'indexes' . DIRECTORY_SEPARATOR . $name,
                    );
                    $this->notifyMutation();
                    continue;
                }
                if ($kind === 'add_column') {
                    $col = $action['column'];
                    $col['name'] = TypeSystem::identifier($col['name']);
                    $this->assertColumnNameUnique($newSchema, $col['name']);
                    $this->types->compileColumn($col, $newSchema);
                    $newSchema['columns'][] = $col;
                    $columnRequiresRebuild = true;
                    continue;
                }
                if ($kind === 'drop_column') {
                    $colName = TypeSystem::identifier($action['name']);
                    $this->validateColumnExists($schema, $colName);
                    if ($schema['auto_increment_column'] === $colName) {
                        throw new FoxyException('An AUTO_INCREMENT column cannot be dropped.', 'SCHEMA_ERROR');
                    }
                    foreach ($newSchema['indexes'] as $indexName => $index) {
                        if (in_array($colName, $index['columns'], true)) {
                            throw new FoxyException(
                                "Column {$colName} is referenced by index {$indexName}.", 'SCHEMA_ERROR',
                            );
                        }
                    }
                    $newSchema['columns'] = array_values(array_filter(
                        $newSchema['columns'],
                        static fn(array $c): bool => $c['name'] !== $colName,
                    ));
                    $newSchema['primary_key'] = array_values(array_filter(
                        $newSchema['primary_key'],
                        static fn(string $pk): bool => $pk !== $colName,
                    ));
                    $columnRequiresRebuild = true;
                    continue;
                }
                if ($kind === 'modify_column' || $kind === 'change_column') {
                    $col = $action['column'];
                    $col['name'] = TypeSystem::identifier($col['name']);
                    $this->validateColumnExists($schema, $col['name']);
                    if (count($newSchema['columns']) > 1024) {
                        throw new FoxyException('The table already has the maximum number of columns.', 'SCHEMA_ERROR');
                    }
                    $this->types->compileColumn($col, $newSchema);
                    if ($newSchema['auto_increment_column'] === $col['name']
                        && !($col['auto_increment'] ?? false)) {
                        throw new FoxyException(
                            'An AUTO_INCREMENT column must retain AUTO_INCREMENT.', 'SCHEMA_ERROR',
                        );
                    }
                    foreach ($newSchema['columns'] as $i => $existing) {
                        if ($existing['name'] === $col['name']) {
                            $col['auto_increment'] = $existing['auto_increment'] ?? $col['auto_increment'] ?? false;
                            $col['primary'] = ($col['auto_increment'] ?? false) || $col['name'] === $newSchema['auto_increment_column'];
                            $newSchema['columns'][$i] = $col;
                            break;
                        }
                    }
                    $columnRequiresRebuild = true;
                    continue;
                }
                throw new FoxyException('Unsupported ALTER TABLE action.', 'SQL_UNSUPPORTED');
            }

            if ($columnRequiresRebuild) {
                $newSchema = $this->types->compileSchema($newSchema['name'], [
                    'columns' => $newSchema['columns'],
                    'constraints' => $this->indexesToConstraints($newSchema),
                ]);
                $newSchema['table_id'] = $schema['table_id'];
                $newSchema['active_generation'] = $schema['active_generation'];
                $newSchema['previous_generation'] = $schema['previous_generation'];
                $newSchema['collation'] = $schema['collation'] ?? null;
                $this->validateMetadata($newSchema);

                $oldGeneration = $this->generationPath($schema);
                $obsoleteGeneration = $schema['previous_generation'] ?? null;
                $number = $this->nextGenerationNumber();
                $temporary = $this->path . DIRECTORY_SEPARATOR . self::generationName($number) . '.compacting';
                $published = $this->path . DIRECTORY_SEPARATOR . self::generationName($number);
                FileSystem::removeTree($temporary);
                self::initializeGeneration($temporary, array_keys($newSchema['indexes']), $this->config);
                $referenceDirectory = $this->path . DIRECTORY_SEPARATOR . '.chunk-refs-' . bin2hex(random_bytes(5));
                FileSystem::ensureDirectory($referenceDirectory);
                $rowsCopied = 0;
                try {
                    $newData = @fopen($temporary . DIRECTORY_SEPARATOR . 'rows.fdb', 'c+b');
                    $newSlots = @fopen($temporary . DIRECTORY_SEPARATOR . 'rows.fdx', 'c+b');
                    if ($newData === false || $newSlots === false) {
                        if (is_resource($newData)) {
                            fclose($newData);
                        }
                        if (is_resource($newSlots)) {
                            fclose($newSlots);
                        }
                        throw new FoxyException('Unable to create migrated table files.', 'STORAGE_IO');
                    }
                    $newIndexes = new IndexStore($temporary . DIRECTORY_SEPARATOR . 'indexes', $this->config);
                    $newIndexes->prepare(array_keys($newSchema['indexes']));
                    try {
                        foreach ($this->iterateRowsLocked($schema, null, true) as $entry) {
                            $migratedRow = [];
                            foreach ($newSchema['columns'] as $newCol) {
                                $newName = $newCol['name'];
                                $oldCol = $this->findColumn($schema, $newName);
                                if ($oldCol !== null && array_key_exists($newName, $entry['values'])) {
                                    $value = $entry['values'][$newName];
                                    $migratedRow[$newName] = $this->types->coerce($value, $newCol);
                                } else {
                                    if ($newCol['nullable']) {
                                        $migratedRow[$newName] = null;
                                    } elseif (array_key_exists('default', $newCol)) {
                                        $migratedRow[$newName] = $newCol['default'];
                                    } else {
                                        throw new FoxyException(
                                            "New column {$newName} requires a default or must be nullable.", 'SCHEMA_ERROR',
                                        );
                                    }
                                }
                            }
                            $encodedRow = $this->encodeRecord($newSchema, $entry['id'], $migratedRow);
                            fseek($newData, 0, SEEK_END);
                            $offset = ftell($newData);
                            if ($offset === false) {
                                throw new FoxyException('Unable to locate migrated data offset.', 'STORAGE_IO');
                            }
                            FileSystem::writeAll($newData, $encodedRow);
                            $slot = $this->encodeSlot($offset, strlen($encodedRow), $entry['generation'], self::SLOT_ACTIVE);
                            $this->writeSlotToStream($newSlots, $entry['id'], $slot);
                            foreach ($entry['encoded'] as $encodedValue) {
                                $this->chunks->recordReferences($encodedValue, $referenceDirectory);
                            }
                            foreach ($this->indexEntries($newSchema, $migratedRow) as $indexName => $indexEntry) {
                                if ($indexEntry['skip']) {
                                    continue;
                                }
                                $newIndexes->append($indexName, $indexEntry['key'], $entry['id'], true);
                            }
                            $rowsCopied++;
                        }
                        FileSystem::flush($newData, $this->config->syncWrites);
                        FileSystem::flush($newSlots, $this->config->syncWrites);
                    } finally {
                        fclose($newData);
                        fclose($newSlots);
                    }
                    if (!@rename($temporary, $published)) {
                        throw new FoxyException('Unable to publish migrated generation.', 'STORAGE_IO');
                    }
                    $newSchema['active_generation'] = $number;
                    $newSchema['previous_generation'] = $schema['active_generation'];
                    $this->storeMetadata($newSchema);
                    $this->notifyMutation();
                    $chunksRemoved = $this->chunks->garbageCollect($referenceDirectory);
                    if ($obsoleteGeneration !== null
                        && (int) $obsoleteGeneration !== (int) $newSchema['previous_generation']) {
                        FileSystem::removeTree(
                            $this->path . DIRECTORY_SEPARATOR . self::generationName((int) $obsoleteGeneration),
                        );
                    }
                } catch (\Throwable $exception) {
                    if (is_dir($temporary)) {
                        FileSystem::removeTree($temporary);
                    }
                    throw $exception;
                } finally {
                    FileSystem::removeTree($referenceDirectory);
                }
                return ['rows_migrated' => $rowsCopied, 'chunks_removed' => $chunksRemoved];
            }

            $this->notifyMutation();
            return ['status' => 'ok'];
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function analyze(): array
    {
        $lock = $this->acquireLock(LOCK_EX);
        try {
            $this->recoverLocked();
            $schema = $this->loadMetadata();
            $this->rebuildIndexesLocked($schema);
            $this->notifyMutation();
            return ['status' => 'ok', 'message' => 'Indexes rebuilt successfully.'];
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function lookupForEqualities(array $values, ?array $schema = null): ?array
    {
        $schema ??= $this->schema();
        $best = null;
        foreach ($schema['indexes'] as $index) {
            $indexValues = [];
            foreach ($index['columns'] as $column) {
                if (!array_key_exists($column, $values)) {
                    continue 2;
                }
                $indexValues[] = $values[$column];
            }
            if ($best === null || count($index['columns']) > $best['columns']) {
                $best = [
                    'name' => $index['name'],
                    'key' => IndexStore::key($indexValues),
                    'columns' => count($index['columns']),
                    'signature' => [
                        'columns' => $index['columns'],
                        'unique' => $index['unique'],
                        'primary' => $index['primary'],
                    ],
                ];
            }
        }
        if ($best === null) {
            return null;
        }
        unset($best['columns']);
        return $best;
    }

    private function recoverLocked(): void
    {
        $schema = $this->loadMetadata(true, false);
        $activePath = $this->generationPath($schema);
        $missingGeneration = null;
        if (!is_dir($activePath)) {
            $missingGeneration = (int) $schema['active_generation'];
            $previous = $schema['previous_generation'] ?? null;
            $previousPath = $previous === null
                ? null
                : $this->path . DIRECTORY_SEPARATOR . self::generationName((int) $previous);
            if ($previousPath === null || !is_dir($previousPath)) {
                throw new FoxyException('The active table generation is missing.', 'STORAGE_CORRUPT');
            }
            $schema['active_generation'] = (int) $previous;
            $schema['previous_generation'] = null;
            $this->storeMetadata($schema);
        }
        $rebuildIndexes = false;
        if (is_file($this->journalPath())) {
            $journal = FileSystem::readMetadata($this->journalPath());
            $generation = $journal['generation'] ?? null;
            $rowId = $journal['row_id'] ?? null;
            $slot = $journal['slot'] ?? null;
            if (!is_int($generation) || !is_int($rowId) || $rowId < 1
                || !is_string($slot) || strlen($slot) !== self::SLOT_BYTES) {
                throw new FoxyException('Invalid row journal.', 'STORAGE_CORRUPT');
            }
            if ($missingGeneration !== null && $generation === $missingGeneration) {
                if (!@unlink($this->journalPath())) {
                    throw new FoxyException('Unable to discard unavailable generation journal.', 'STORAGE_IO');
                }
                $rebuildIndexes = true;
            } elseif ($generation !== (int) $schema['active_generation']) {
                throw new FoxyException('Invalid row journal generation.', 'STORAGE_CORRUPT');
            } else {
                $journalSlot = $this->decodeSlotBytes($slot);
                $slotBytes = filesize($this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx');
                if ($slotBytes === false || $slotBytes % self::SLOT_BYTES !== 0) {
                    throw new FoxyException('Row slot file has an invalid length.', 'STORAGE_CORRUPT');
                }
                $allocatedRows = intdiv($slotBytes, self::SLOT_BYTES);
                $maximumAllowed = $allocatedRows > PHP_INT_MAX - $this->config->maxRowsPerResult - 1
                    ? PHP_INT_MAX
                    : $allocatedRows + $this->config->maxRowsPerResult + 1;
                $currentSlot = $this->readSlotLocked($schema, $rowId);
                if (($journalSlot['status'] === self::SLOT_DELETED && ($rowId > $allocatedRows || $currentSlot === null))
                    || ($journalSlot['status'] === self::SLOT_ACTIVE && $rowId > $maximumAllowed)) {
                    throw new FoxyException('Row journal identifier exceeds its recovery bounds.', 'STORAGE_CORRUPT');
                }
                $currentGeneration = $currentSlot['generation'] ?? 0;
                if ($currentGeneration < $journalSlot['generation']) {
                    $this->validateJournalTarget($schema, $rowId, $journalSlot);
                    $this->writeSlotLocked($schema, $rowId, $slot);
                    $rebuildIndexes = true;
                } elseif ($currentGeneration === $journalSlot['generation']) {
                    $currentEncoded = $currentSlot === null ? null : $this->encodeSlot(
                        $currentSlot['offset'],
                        $currentSlot['length'],
                        $currentSlot['generation'],
                        $currentSlot['status'],
                    );
                    if ($currentEncoded !== $slot) {
                        throw new FoxyException('Row journal conflicts with the current slot.', 'STORAGE_CORRUPT');
                    }
                    $this->validateJournalTarget($schema, $rowId, $journalSlot);
                    $rebuildIndexes = true;
                }
                if (!@unlink($this->journalPath())) {
                    throw new FoxyException('Unable to clear row journal.', 'STORAGE_IO');
                }
            }
        }
        if (is_file($this->dirtyPath()) || $rebuildIndexes || !$this->indexesComplete($schema)) {
            $this->rebuildIndexesLocked($schema);
            if (is_file($this->dirtyPath()) && !@unlink($this->dirtyPath())) {
                throw new FoxyException('Unable to clear dirty marker.', 'STORAGE_IO');
            }
        }
    }

    private function storeRowLocked(
        array $schema,
        int $rowId,
        array $row,
        ?array $oldRow,
        ?string $preparedRecord = null,
    ): void
    {
        $oldSlot = $this->readSlotLocked($schema, $rowId);
        $generation = ($oldSlot['generation'] ?? 0) + 1;
        $undoOldSlotBytes = $this->undoCallback !== null ? $this->readRawSlotBytesLocked($schema, $rowId) : null;
        FileSystem::atomicWrite($this->dirtyPath(), "dirty\n", $this->config->syncWrites);
        $record = $preparedRecord ?? $this->encodeRecord($schema, $rowId, $row);
        $dataPath = $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdb';
        $stream = @fopen($dataPath, 'c+b');
        if ($stream === false) {
            throw new FoxyException('Unable to open row data.', 'STORAGE_IO');
        }
        try {
            if (fseek($stream, 0, SEEK_END) !== 0) {
                throw new FoxyException('Unable to seek row data.', 'STORAGE_IO');
            }
            $offset = ftell($stream);
            if ($offset === false) {
                throw new FoxyException('Unable to determine row data offset.', 'STORAGE_IO');
            }
            FileSystem::writeAll($stream, $record);
            FileSystem::flush($stream, $this->config->syncWrites);
        } finally {
            fclose($stream);
        }
        $slot = $this->encodeSlot($offset, strlen($record), $generation, self::SLOT_ACTIVE);
        $this->commitSlotLocked($schema, $rowId, $slot);
        try {
            $this->applyIndexChangesLocked($schema, $rowId, $oldRow, $row);
        } catch (\Throwable) {
            $this->rebuildIndexesLocked($schema);
        }
        $this->finishMutationLocked();
        if ($this->undoCallback !== null) {
            ($this->undoCallback)($rowId, $undoOldSlotBytes, $oldRow, $row);
        }
    }

    private function deleteRowLocked(array $schema, int $rowId, array $oldRow): void
    {
        $oldSlot = $this->readSlotLocked($schema, $rowId);
        if ($oldSlot === null || $oldSlot['status'] !== self::SLOT_ACTIVE) {
            return;
        }
        $undoOldSlotBytes = $this->undoCallback !== null ? $this->readRawSlotBytesLocked($schema, $rowId) : null;
        FileSystem::atomicWrite($this->dirtyPath(), "dirty\n", $this->config->syncWrites);
        $slot = $this->encodeSlot(0, 0, $oldSlot['generation'] + 1, self::SLOT_DELETED);
        $this->commitSlotLocked($schema, $rowId, $slot);
        try {
            $this->applyIndexChangesLocked($schema, $rowId, $oldRow, null);
        } catch (\Throwable) {
            $this->rebuildIndexesLocked($schema);
        }
        $this->finishMutationLocked();
        if ($this->undoCallback !== null) {
            ($this->undoCallback)($rowId, $undoOldSlotBytes, $oldRow, null);
        }
    }

    private function commitSlotLocked(array $schema, int $rowId, string $slot): void
    {
        FileSystem::writeMetadata($this->journalPath(), [
            'generation' => $schema['active_generation'],
            'row_id' => $rowId,
            'slot' => $slot,
        ], $this->config->syncWrites);
        $this->writeSlotLocked($schema, $rowId, $slot);
        $this->notifyMutation();
        if (!@unlink($this->journalPath())) {
            throw new FoxyException('Unable to clear row journal.', 'STORAGE_IO');
        }
    }

    private function finishMutationLocked(): void
    {
        if (!@unlink($this->dirtyPath())) {
            throw new FoxyException('Unable to clear dirty marker.', 'STORAGE_IO');
        }
    }

    private function beginMutation(): void
    {
        $this->mutationNotified = false;
    }

    private function notifyMutation(): void
    {
        if ($this->mutationNotified) {
            return;
        }
        $this->mutationNotified = true;
        if ($this->onMutation !== null) {
            ($this->onMutation)();
        }
    }

    private function applyIndexChangesLocked(array $schema, int $rowId, ?array $oldRow, ?array $newRow): void
    {
        $store = $this->indexStore($schema);
        $oldEntries = $oldRow === null ? [] : $this->indexEntries($schema, $oldRow);
        $newEntries = $newRow === null ? [] : $this->indexEntries($schema, $newRow);
        foreach ($schema['indexes'] as $name => $index) {
            $old = $oldEntries[$name] ?? null;
            $new = $newEntries[$name] ?? null;
            if ($old !== null && !$old['skip'] && ($new === null || $new['skip'] || $old['key'] !== $new['key'])) {
                $store->append($name, $old['key'], $rowId, false);
            }
            if ($new !== null && !$new['skip'] && ($old === null || $old['skip'] || $old['key'] !== $new['key'])) {
                $store->append($name, $new['key'], $rowId, true);
            }
        }
    }

    private function assertUniqueLocked(array $schema, array $row, ?int $exceptRowId): void
    {
        $store = $this->indexStore($schema);
        foreach ($this->indexEntries($schema, $row) as $name => $entry) {
            $index = $schema['indexes'][$name];
            if (!$index['unique'] || $entry['skip']) {
                continue;
            }
            foreach ($store->lookup($name, $entry['key']) as $rowId) {
                if ($exceptRowId === null || $rowId !== $exceptRowId) {
                    throw new FoxyException(
                        "Unique constraint {$name} is violated.",
                        'UNIQUE_VIOLATION',
                        ['index' => $name],
                    );
                }
            }
        }
    }

    private function assertBatchUpdateUniqueLocked(
        array $schema,
        array $changes,
        ?int $maximumStagingBytes,
        int &$stagedBytes,
    ): void
    {
        if ($changes === []) {
            return;
        }
        $affected = [];
        foreach ($changes as $change) {
            $affected[$change['id']] = true;
            $stagedBytes += 32;
            if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                throw new FoxyException('UPDATE exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
            }
        }
        $pending = [];
        $store = $this->indexStore($schema);
        foreach ($changes as $change) {
            foreach ($this->indexEntries($schema, $change['new']) as $name => $entry) {
                if (!$schema['indexes'][$name]['unique'] || $entry['skip']) {
                    continue;
                }
                $encodedKey = base64_encode($entry['key']);
                if (isset($pending[$name][$encodedKey]) && $pending[$name][$encodedKey] !== $change['id']) {
                    throw new FoxyException(
                        "Unique constraint {$name} is violated.",
                        'UNIQUE_VIOLATION',
                        ['index' => $name],
                    );
                }
                $pending[$name][$encodedKey] = $change['id'];
                $stagedBytes += 64 + strlen($encodedKey);
                if ($maximumStagingBytes !== null && $stagedBytes > $maximumStagingBytes) {
                    throw new FoxyException('UPDATE exceeded the configured heap staging limit.', 'RESOURCE_LIMIT');
                }
                foreach ($store->lookup($name, $entry['key']) as $existingRowId) {
                    if ($existingRowId !== $change['id'] && !isset($affected[$existingRowId])) {
                        throw new FoxyException(
                            "Unique constraint {$name} is violated.",
                            'UNIQUE_VIOLATION',
                            ['index' => $name],
                        );
                    }
                }
            }
        }
    }

    private function indexEntries(array $schema, array $row): array
    {
        $entries = [];
        foreach ($schema['indexes'] as $name => $index) {
            $values = $this->indexValues($index, $row);
            $skip = $index['unique'] && IndexStore::containsNull($values);
            $entries[$name] = [
                'key' => $skip ? '' : IndexStore::key($values),
                'skip' => $skip,
            ];
        }
        return $entries;
    }

    private function indexValues(array $index, array $row): array
    {
        $values = [];
        foreach ($index['columns'] as $column) {
            $values[] = $row[$column];
        }
        return $values;
    }

    private function iterateRowsLocked(array $schema, ?array $lookup, bool $includeRecord = false): \Generator
    {
        $generation = $this->generationPath($schema);
        $slotStream = @fopen($generation . DIRECTORY_SEPARATOR . 'rows.fdx', 'rb');
        $dataStream = @fopen($generation . DIRECTORY_SEPARATOR . 'rows.fdb', 'rb');
        if ($slotStream === false || $dataStream === false) {
            if (is_resource($slotStream)) {
                fclose($slotStream);
            }
            if (is_resource($dataStream)) {
                fclose($dataStream);
            }
            throw new FoxyException('Unable to open table generation.', 'STORAGE_IO');
        }
        try {
            $statistics = fstat($slotStream);
            if ($statistics === false || ((int) $statistics['size']) % self::SLOT_BYTES !== 0) {
                throw new FoxyException('Row slot file has a truncated tail.', 'STORAGE_CORRUPT');
            }
            $slotBytes = (int) $statistics['size'];
            $lookupIndex = $lookup === null ? null : ($schema['indexes'][$lookup['name']] ?? null);
            $lookupValid = $lookupIndex !== null
                && ($lookup['signature'] ?? null) === [
                    'columns' => $lookupIndex['columns'],
                    'unique' => $lookupIndex['unique'],
                    'primary' => $lookupIndex['primary'],
                ];
            if ($lookupValid) {
                $store = $this->indexStore($schema);
                $rowIds = $store->lookup($lookup['name'], $lookup['key']);
            } else {
                $maximum = intdiv($slotBytes, self::SLOT_BYTES);
                $rowIds = null;
            }

            if ($rowIds !== null) {
                $slots = $this->readSlotsFromStream($slotStream, $rowIds, $slotBytes);
                foreach ($rowIds as $rowId) {
                    $slot = $slots[$rowId] ?? null;
                    if ($slot === null || $slot['status'] !== self::SLOT_ACTIVE) {
                        continue;
                    }
                    $decoded = $this->readRecord($dataStream, $schema, $rowId, $slot, $includeRecord);
                    unset($decoded['_estimated_bytes']);
                    yield ['id' => $rowId] + $decoded + ['generation' => $slot['generation']];
                }
                return;
            }

            for ($first = 1; $first <= $maximum; $first += 256) {
                $ids = range($first, min($maximum, $first + 255));
                $slots = $this->readSlotsFromStream($slotStream, $ids, $slotBytes);
                foreach ($ids as $rowId) {
                    $slot = $slots[$rowId] ?? null;
                    if ($slot === null || $slot['status'] !== self::SLOT_ACTIVE) {
                        continue;
                    }
                    $decoded = $this->readRecord($dataStream, $schema, $rowId, $slot, $includeRecord);
                    unset($decoded['_estimated_bytes']);
                    yield ['id' => $rowId] + $decoded + ['generation' => $slot['generation']];
                }
            }
        } finally {
            fclose($slotStream);
            fclose($dataStream);
        }
    }

    private function encodeRecord(array $schema, int $rowId, array $row): string
    {
        $encoded = [];
        foreach ($schema['columns'] as $column) {
            $encoded[] = $this->chunks->encode($row[$column['name']], $column['type']);
        }
        try {
            $raw = json_encode(
                $encoded,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR,
            );
        } catch (\JsonException $exception) {
            throw new FoxyException('Unable to encode row data.', 'STORAGE_IO', [], $exception);
        }
        $flags = 0;
        $stored = $raw;
        if (strlen($raw) >= 1_024) {
            $compressed = gzcompress($raw, 3);
            if ($compressed !== false && strlen($compressed) < (int) (strlen($raw) * 0.9)) {
                $stored = $compressed;
                $flags |= self::RECORD_COMPRESSED;
            }
        }
        if (strlen($stored) > 0xffffffff - self::DATA_HEADER_BYTES || strlen($raw) > 0xffffffff) {
            throw new FoxyException('Row record exceeds the storage limit.', 'RESOURCE_LIMIT');
        }
        return 'FXR1' . BinaryCodec::uint64($rowId) . BinaryCodec::uint32($flags)
            . BinaryCodec::uint32(strlen($stored)) . BinaryCodec::uint32(strlen($raw))
            . BinaryCodec::uint32(BinaryCodec::crc32($raw)) . $stored;
    }

    private function readRecord($stream, array $schema, int $rowId, array $slot, bool $includeRecord): array
    {
        $cacheKey = $schema['table_id'] . ':' . $schema['active_generation'] . ':'
            . $rowId . ':' . $slot['generation'];
        if (!$includeRecord && $this->bufferPool !== null) {
            $cached = $this->bufferPool->get($cacheKey);
            if (is_array($cached) && is_array($cached['row'] ?? null) && is_int($cached['bytes'] ?? null)) {
                return ['values' => $cached['row'], '_estimated_bytes' => $cached['bytes']];
            }
        }
        if (fseek($stream, $slot['offset']) !== 0) {
            throw new FoxyException('Unable to seek row record.', 'STORAGE_IO');
        }
        $header = FileSystem::readExact($stream, self::DATA_HEADER_BYTES) ?? '';
        if (substr($header, 0, 4) !== 'FXR1' || BinaryCodec::readUint64($header, 4) !== $rowId) {
            throw new FoxyException('Invalid row record header.', 'STORAGE_CORRUPT');
        }
        $flags = BinaryCodec::readUint32($header, 12);
        $storedLength = BinaryCodec::readUint32($header, 16);
        $rawLength = BinaryCodec::readUint32($header, 20);
        $checksum = BinaryCodec::readUint32($header, 24);
        if ($slot['length'] !== self::DATA_HEADER_BYTES + $storedLength) {
            throw new FoxyException('Row slot length does not match its record.', 'STORAGE_CORRUPT');
        }
        $stored = FileSystem::readExact($stream, $storedLength) ?? '';
        if (($flags & self::RECORD_COMPRESSED) !== 0) {
            $raw = gzuncompress($stored, $rawLength);
            if ($raw === false) {
                throw new FoxyException('Unable to decompress row record.', 'STORAGE_CORRUPT');
            }
        } else {
            $raw = $stored;
        }
        if (strlen($raw) !== $rawLength || BinaryCodec::crc32($raw) !== $checksum) {
            throw new FoxyException('Row record checksum mismatch.', 'STORAGE_CORRUPT');
        }
        try {
            $encoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new FoxyException('Invalid row record payload.', 'STORAGE_CORRUPT', [], $exception);
        }
        if (!is_array($encoded) || count($encoded) !== count($schema['columns'])) {
            throw new FoxyException('Row does not match its schema.', 'STORAGE_CORRUPT');
        }
        $row = [];
        foreach ($schema['columns'] as $position => $column) {
            $row[$column['name']] = $this->chunks->decode($encoded[$position]);
        }
        $estimatedBytes = MemoryCache::estimateBytes($row);
        if (!$includeRecord && $this->bufferPool !== null) {
            $this->bufferPool->put(
                $cacheKey,
                ['row' => $row, 'bytes' => $estimatedBytes],
                $estimatedBytes + 64,
            );
        }
        $result = ['values' => $row, '_estimated_bytes' => $estimatedBytes];
        if ($includeRecord) {
            $result['record'] = $header . $stored;
            $result['encoded'] = $encoded;
        }
        return $result;
    }

    private function rebuildIndexesLocked(array $schema): void
    {
        $store = $this->indexStore($schema);
        $store->reset();
        $store->prepare(array_keys($schema['indexes']));
        foreach ($this->iterateRowsLocked($schema, null) as $entry) {
            foreach ($this->indexEntries($schema, $entry['values']) as $name => $indexEntry) {
                if (!$indexEntry['skip']) {
                    $store->append($name, $indexEntry['key'], $entry['id'], true);
                }
            }
        }
    }

    private function readSlotLocked(array $schema, int $rowId): ?array
    {
        $stream = @fopen($this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx', 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open row slots.', 'STORAGE_IO');
        }
        try {
            return $this->readSlotFromStream($stream, $rowId);
        } finally {
            fclose($stream);
        }
    }

    private function readRawSlotBytesLocked(array $schema, int $rowId): ?string
    {
        $generation = $this->generationPath($schema);
        $stream = @fopen($generation . DIRECTORY_SEPARATOR . 'rows.fdx', 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to open row slots.', 'STORAGE_IO');
        }
        try {
            $statistics = fstat($stream);
            $streamBytes = (int) ($statistics['size'] ?? 0);
            $offset = ($rowId - 1) * self::SLOT_BYTES;
            if ($offset < 0 || $offset + self::SLOT_BYTES > $streamBytes) {
                return null;
            }
            if (fseek($stream, $offset) !== 0) {
                throw new FoxyException('Unable to seek row slot.', 'STORAGE_IO');
            }
            $slot = FileSystem::readExact($stream, self::SLOT_BYTES) ?? '';
            if ($slot === str_repeat("\0", self::SLOT_BYTES)) {
                return null;
            }
            return $slot;
        } finally {
            fclose($stream);
        }
    }

    private function readCurrentRows(array $rowIds): array
    {
        $lock = $this->acquireReadyReadLock();
        try {
            $schema = $this->loadMetadata();
            return $this->readRowsLocked($schema, $rowIds);
        } finally {
            $this->releaseLock($lock);
        }
    }

    private function readRowsLocked(array $schema, array $rowIds): array
    {
        if ($rowIds === []) {
            return [];
        }
        $generation = $this->generationPath($schema);
        $slotStream = @fopen($generation . DIRECTORY_SEPARATOR . 'rows.fdx', 'rb');
        $dataStream = @fopen($generation . DIRECTORY_SEPARATOR . 'rows.fdb', 'rb');
        if ($slotStream === false || $dataStream === false) {
            if (is_resource($slotStream)) {
                fclose($slotStream);
            }
            if (is_resource($dataStream)) {
                fclose($dataStream);
            }
            throw new FoxyException('Unable to open table generation.', 'STORAGE_IO');
        }
        $rows = [];
        $decodedBytes = 0;
        try {
            $statistics = fstat($slotStream);
            if ($statistics === false || ((int) $statistics['size']) % self::SLOT_BYTES !== 0) {
                throw new FoxyException('Row slot file has a truncated tail.', 'STORAGE_CORRUPT');
            }
            $slots = $this->readSlotsFromStream($slotStream, $rowIds, (int) $statistics['size']);
            foreach ($rowIds as $rowId) {
                $slot = $slots[$rowId] ?? null;
                if ($slot === null || $slot['status'] !== self::SLOT_ACTIVE) {
                    continue;
                }
                $decoded = $this->readRecord($dataStream, $schema, $rowId, $slot, false);
                $decodedBytes += $decoded['_estimated_bytes'];
                if ($decodedBytes > $this->config->maxMaterializedBytes) {
                    throw new FoxyException('Row batch exceeded the configured materialization limit.', 'RESOURCE_LIMIT');
                }
                unset($decoded['_estimated_bytes']);
                $rows[] = ['id' => $rowId] + $decoded + ['generation' => $slot['generation']];
            }
            return $rows;
        } finally {
            fclose($slotStream);
            fclose($dataStream);
        }
    }

    private function readSlotFromStream($stream, int $rowId, ?int $streamBytes = null): ?array
    {
        $offset = ($rowId - 1) * self::SLOT_BYTES;
        if ($streamBytes === null) {
            $statistics = fstat($stream);
            $streamBytes = (int) ($statistics['size'] ?? 0);
        }
        if ($offset < 0 || $offset + self::SLOT_BYTES > $streamBytes) {
            return null;
        }
        if (fseek($stream, $offset) !== 0) {
            throw new FoxyException('Unable to seek row slot.', 'STORAGE_IO');
        }
        $slot = FileSystem::readExact($stream, self::SLOT_BYTES) ?? '';
        if ($slot === str_repeat("\0", self::SLOT_BYTES)) {
            return null;
        }
        return $this->decodeSlotBytes($slot);
    }

    private function readSlotsFromStream($stream, array $rowIds, int $streamBytes): array
    {
        if ($rowIds === []) {
            return [];
        }
        $contiguous = true;
        for ($index = 1, $count = count($rowIds); $index < $count; $index++) {
            if ($rowIds[$index] !== $rowIds[$index - 1] + 1) {
                $contiguous = false;
                break;
            }
        }
        if (!$contiguous) {
            $slots = [];
            foreach ($rowIds as $rowId) {
                $slot = $this->readSlotFromStream($stream, $rowId, $streamBytes);
                if ($slot !== null) {
                    $slots[$rowId] = $slot;
                }
            }
            return $slots;
        }

        $first = $rowIds[0];
        $offset = ($first - 1) * self::SLOT_BYTES;
        $bytes = count($rowIds) * self::SLOT_BYTES;
        if ($offset < 0 || $offset + $bytes > $streamBytes) {
            return [];
        }
        if (fseek($stream, $offset) !== 0) {
            throw new FoxyException('Unable to seek row slots.', 'STORAGE_IO');
        }
        $block = FileSystem::readExact($stream, $bytes) ?? '';
        $slots = [];
        foreach ($rowIds as $index => $rowId) {
            $encoded = substr($block, $index * self::SLOT_BYTES, self::SLOT_BYTES);
            if ($encoded !== str_repeat("\0", self::SLOT_BYTES)) {
                $slots[$rowId] = $this->decodeSlotBytes($encoded);
            }
        }
        return $slots;
    }

    private function encodeSlot(int $offset, int $length, int $generation, int $status): string
    {
        $body = BinaryCodec::uint64($offset) . BinaryCodec::uint32($length)
            . BinaryCodec::uint32($generation) . chr($status) . "\0\0\0";
        return $body . BinaryCodec::uint32(BinaryCodec::crc32($body));
    }

    private function writeSlotLocked(array $schema, int $rowId, string $slot): void
    {
        $stream = @fopen($this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx', 'c+b');
        if ($stream === false) {
            throw new FoxyException('Unable to open row slots.', 'STORAGE_IO');
        }
        try {
            $this->writeSlotToStream($stream, $rowId, $slot);
            FileSystem::flush($stream, $this->config->syncWrites);
        } finally {
            fclose($stream);
        }
    }

    private function writeSlotToStream($stream, int $rowId, string $slot): void
    {
        if (fseek($stream, ($rowId - 1) * self::SLOT_BYTES) !== 0) {
            throw new FoxyException('Unable to seek row slot.', 'STORAGE_IO');
        }
        FileSystem::writeAll($stream, $slot);
    }

    private function indexStore(array $schema): IndexStore
    {
        $generation = (int) $schema['active_generation'];
        if (isset($this->indexStores[$generation])) {
            return $this->indexStores[$generation];
        }
        $store = new IndexStore(
            $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'indexes',
            $this->config,
            $this->indexCache,
            $schema['table_id'] . ':' . $generation,
        );
        $this->indexStores[$generation] = $store;
        if (count($this->indexStores) > 2) {
            unset($this->indexStores[array_key_first($this->indexStores)]);
        }
        return $store;
    }

    private function loadMetadata(bool $refresh = false, bool $requireGeneration = true): array
    {
        if (!$refresh && $this->metadataCache !== null) {
            if ($requireGeneration && !is_dir($this->generationPath($this->metadataCache))) {
                throw new FoxyException('The active table generation is missing.', 'STORAGE_CORRUPT');
            }
            return $this->metadataCache;
        }
        $metadata = FileSystem::readMetadata($this->metadataPath());
        $this->validateMetadata($metadata);
        if ($requireGeneration && !is_dir($this->generationPath($metadata))) {
            throw new FoxyException('The active table generation is missing.', 'STORAGE_CORRUPT');
        }
        return $this->metadataCache = $metadata;
    }

    private function storeMetadata(array $metadata): void
    {
        FileSystem::writeMetadata($this->metadataPath(), $metadata, $this->config->syncWrites);
        $this->metadataCache = $metadata;
    }

    private function readSequenceLocked(array $schema): array
    {
        $path = $this->sequencePath();
        $contents = @file_get_contents($path);
        $slotPath = $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdx';
        $slotBytes = filesize($slotPath);
        if ($slotBytes === false || $slotBytes % self::SLOT_BYTES !== 0) {
            throw new FoxyException('Row slot file has an invalid length.', 'STORAGE_CORRUPT');
        }
        $allocatedRows = intdiv($slotBytes, self::SLOT_BYTES);
        if ($contents !== false && strlen($contents) === 32 && substr($contents, 0, 4) === 'FXSQ'
            && BinaryCodec::readUint32($contents, 4) === 1
            && BinaryCodec::crc32(substr($contents, 0, 24)) === BinaryCodec::readUint32($contents, 24)) {
            $nextRow = BinaryCodec::readUint64($contents, 8);
            $nextAuto = BinaryCodec::readUint64($contents, 16);
            if ($nextRow > $allocatedRows && $nextAuto > 0) {
                return [$nextRow, $nextAuto];
            }
        }

        $nextRow = $allocatedRows + 1;
        $nextAuto = 1;
        $autoColumn = $schema['auto_increment_column'];
        foreach ($this->iterateRowsLocked($schema, null) as $entry) {
            if ($autoColumn !== null) {
                $nextAuto = max($nextAuto, $entry['values'][$autoColumn] + 1);
            }
        }
        $this->writeSequence($nextRow, $nextAuto);
        return [$nextRow, $nextAuto];
    }

    private function writeSequence(int $nextRow, int $nextAuto): void
    {
        self::writeSequenceFile($this->sequencePath(), $nextRow, $nextAuto, $this->config->syncWrites);
    }

    private static function writeSequenceFile(string $path, int $nextRow, int $nextAuto, bool $sync): void
    {
        $body = 'FXSQ' . BinaryCodec::uint32(1) . BinaryCodec::uint64($nextRow) . BinaryCodec::uint64($nextAuto);
        FileSystem::atomicWrite($path, $body . BinaryCodec::uint32(BinaryCodec::crc32($body)) . "\0\0\0\0", $sync);
    }

    private static function initializeGeneration(string $path, array $indexNames, Config $config): void
    {
        FileSystem::ensureDirectory($path . DIRECTORY_SEPARATOR . 'indexes');
        foreach (['rows.fdb', 'rows.fdx'] as $name) {
            $stream = @fopen($path . DIRECTORY_SEPARATOR . $name, 'xb');
            if ($stream === false) {
                throw new FoxyException('Unable to initialize table generation.', 'STORAGE_IO');
            }
            fclose($stream);
        }
        (new IndexStore($path . DIRECTORY_SEPARATOR . 'indexes', $config))->prepare($indexNames);
    }

    private function acquireLock(int $operation)
    {
        $stream = @fopen($this->lockPath, 'c+b');
        if ($stream === false || !flock($stream, $operation)) {
            if (is_resource($stream)) {
                fclose($stream);
            }
            throw new FoxyException('Unable to acquire table lock.', 'STORAGE_LOCK');
        }
        return $stream;
    }

    private function acquireReadyReadLock()
    {
        while (true) {
            $lock = $this->acquireLock(LOCK_SH);
            $activeGenerationAvailable = $this->metadataCache === null
                || is_dir($this->generationPath($this->metadataCache));
            if (!is_file($this->dirtyPath()) && !is_file($this->journalPath()) && $activeGenerationAvailable) {
                return $lock;
            }
            $this->releaseLock($lock);
            $exclusive = $this->acquireLock(LOCK_EX);
            try {
                $this->recoverLocked();
            } finally {
                $this->releaseLock($exclusive);
            }
        }
    }

    private function releaseLock($stream): void
    {
        flock($stream, LOCK_UN);
        fclose($stream);
    }

    private function nextGenerationNumber(): int
    {
        $maximum = 0;
        $entries = scandir($this->path);
        if ($entries === false) {
            throw new FoxyException('Unable to scan table directory.', 'STORAGE_IO');
        }
        foreach ($entries as $entry) {
            if (preg_match('/^g(\d{6})$/', $entry, $match) === 1) {
                $maximum = max($maximum, (int) $match[1]);
            }
        }
        return $maximum + 1;
    }

    private function metadataPath(): string
    {
        return $this->path . DIRECTORY_SEPARATOR . 'meta.fdb';
    }

    private function sequencePath(): string
    {
        return $this->path . DIRECTORY_SEPARATOR . 'sequence.fdb';
    }

    private function journalPath(): string
    {
        return $this->path . DIRECTORY_SEPARATOR . 'row.journal.fdb';
    }

    private function dirtyPath(): string
    {
        return $this->path . DIRECTORY_SEPARATOR . 'dirty';
    }

    private function generationPath(array $schema): string
    {
        return $this->path . DIRECTORY_SEPARATOR . self::generationName((int) $schema['active_generation']);
    }

    private static function generationName(int $generation): string
    {
        return sprintf('g%06d', $generation);
    }

    private function validateMetadata(array $metadata): void
    {
        $invalid = static function (): never {
            throw new FoxyException('Unsupported or invalid table metadata.', 'STORAGE_CORRUPT');
        };
        if (($metadata['format'] ?? null) !== 1
            || !is_string($metadata['table_id'] ?? null)
            || preg_match('/^[a-f0-9]{32}$/', $metadata['table_id']) !== 1
            || !is_string($metadata['name'] ?? null)
            || preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $metadata['name']) !== 1
            || !is_int($metadata['active_generation'] ?? null)
            || $metadata['active_generation'] < 1 || $metadata['active_generation'] > 999_999
            || !is_array($metadata['columns'] ?? null) || !array_is_list($metadata['columns'])
            || $metadata['columns'] === [] || count($metadata['columns']) > 1_024
            || !is_array($metadata['indexes'] ?? null)
            || !is_array($metadata['primary_key'] ?? null) || !array_is_list($metadata['primary_key'])
            || !array_key_exists('auto_increment_column', $metadata)
            || !array_key_exists('previous_generation', $metadata)) {
            $invalid();
        }
        $previous = $metadata['previous_generation'];
        if ($previous !== null && (!is_int($previous) || $previous < 1 || $previous > 999_999
            || $previous === $metadata['active_generation'])) {
            $invalid();
        }

        $types = [
            'INT', 'VARCHAR', 'BIGINT', 'LONGTEXT', 'TEXT', 'BINARY', 'BLOB', 'TIMESTAMP',
            'DATETIME', 'FLOAT', 'DOUBLE', 'BOOLEAN', 'REAL', 'TINYINT', 'UUID',
        ];
        $columnNames = [];
        foreach ($metadata['columns'] as $column) {
            if (!is_array($column)
                || !is_string($column['name'] ?? null)
                || preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $column['name']) !== 1
                || isset($columnNames[$column['name']])
                || !is_string($column['type'] ?? null) || !in_array($column['type'], $types, true)
                || !array_key_exists('length', $column)
                || ($column['length'] !== null && (!is_int($column['length']) || $column['length'] < 1))
                || !is_bool($column['nullable'] ?? null)
                || !is_bool($column['auto_increment'] ?? null)) {
                $invalid();
            }
            if ((in_array($column['type'], ['VARCHAR', 'BINARY'], true)
                    && (!is_int($column['length']) || $column['length'] > 65_535))
                || (!in_array($column['type'], ['VARCHAR', 'BINARY'], true) && $column['length'] !== null)
                || ($column['auto_increment'] && !in_array($column['type'], ['TINYINT', 'INT', 'BIGINT'], true))) {
                $invalid();
            }
            if (array_key_exists('default', $column)) {
                $default = $column['default'];
                if (!is_array($default) || !is_string($default['kind'] ?? null)
                    || !in_array($default['kind'], ['literal', 'binary', 'current_timestamp', 'uuid'], true)
                    || (in_array($default['kind'], ['literal', 'binary'], true)
                        && !array_key_exists('value', $default))
                    || ($default['kind'] === 'binary' && !is_string($default['value'] ?? null))) {
                    $invalid();
                }
            }
            $columnNames[$column['name']] = true;
        }

        foreach ($metadata['primary_key'] as $columnName) {
            if (!is_string($columnName) || !isset($columnNames[$columnName])) {
                $invalid();
            }
        }
        $autoColumn = $metadata['auto_increment_column'];
        if ($autoColumn !== null && (!is_string($autoColumn) || !isset($columnNames[$autoColumn]))) {
            $invalid();
        }
        foreach ($metadata['indexes'] as $indexName => $index) {
            if (!is_string($indexName) || preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $indexName) !== 1
                || !is_array($index) || ($index['name'] ?? null) !== $indexName
                || !is_array($index['columns'] ?? null) || !array_is_list($index['columns'])
                || $index['columns'] === [] || !is_bool($index['unique'] ?? null)
                || !is_bool($index['primary'] ?? null)) {
                $invalid();
            }
            foreach ($index['columns'] as $columnName) {
                if (!is_string($columnName) || !isset($columnNames[$columnName])) {
                    $invalid();
                }
            }
        }
    }

    private function decodeSlotBytes(string $slot): array
    {
        if (strlen($slot) !== self::SLOT_BYTES
            || BinaryCodec::crc32(substr($slot, 0, 20)) !== BinaryCodec::readUint32($slot, 20)) {
            throw new FoxyException('Row slot checksum mismatch.', 'STORAGE_CORRUPT');
        }
        $status = ord($slot[16]);
        if (!in_array($status, [self::SLOT_ACTIVE, self::SLOT_DELETED], true)) {
            throw new FoxyException('Invalid row slot state.', 'STORAGE_CORRUPT');
        }
        $decoded = [
            'offset' => BinaryCodec::readUint64($slot, 0),
            'length' => BinaryCodec::readUint32($slot, 8),
            'generation' => BinaryCodec::readUint32($slot, 12),
            'status' => $status,
        ];
        if ($status === self::SLOT_DELETED && ($decoded['offset'] !== 0 || $decoded['length'] !== 0)) {
            throw new FoxyException('Deleted row slot contains a record reference.', 'STORAGE_CORRUPT');
        }
        return $decoded;
    }

    private function validateJournalTarget(array $schema, int $rowId, array $slot): void
    {
        if ($slot['status'] !== self::SLOT_ACTIVE) {
            return;
        }
        $stream = @fopen($this->generationPath($schema) . DIRECTORY_SEPARATOR . 'rows.fdb', 'rb');
        if ($stream === false) {
            throw new FoxyException('Unable to validate journal row data.', 'STORAGE_IO');
        }
        try {
            $this->readRecord($stream, $schema, $rowId, $slot, false);
        } finally {
            fclose($stream);
        }
    }

    private function findColumn(array $schema, string $name): ?array
    {
        foreach ($schema['columns'] as $column) {
            if ($column['name'] === $name) {
                return $column;
            }
        }
        return null;
    }

    private function validateColumnExists(array $schema, string $name): void
    {
        if ($this->findColumn($schema, $name) === null) {
            throw new FoxyException("Column {$name} does not exist.", 'UNKNOWN_COLUMN');
        }
    }

    private function validateIndexExists(array $schema, string $name): void
    {
        if (!isset($schema['indexes'][$name])) {
            throw new FoxyException("Index {$name} does not exist.", 'INDEX_NOT_FOUND');
        }
    }

    private function assertColumnNameUnique(array $schema, string $name, ?string $skipName = null): void
    {
        foreach ($schema['columns'] as $column) {
            if ($column['name'] === $name && $column['name'] !== $skipName) {
                throw new FoxyException("Column {$name} already exists.", 'SCHEMA_ERROR');
            }
        }
    }

    private function indexesToConstraints(array $schema): array
    {
        $constraints = [];
        foreach ($schema['indexes'] ?? [] as $index) {
            if ($index['primary']) {
                $constraints[] = ['kind' => 'primary', 'name' => 'primary', 'columns' => $index['columns']];
            } elseif ($index['unique']) {
                $constraints[] = ['kind' => 'unique', 'name' => $index['name'], 'columns' => $index['columns']];
            } else {
                $constraints[] = ['kind' => 'index', 'name' => $index['name'], 'columns' => $index['columns']];
            }
        }
        return $constraints;
    }

    private function indexesComplete(array $schema): bool
    {
        $root = $this->generationPath($schema) . DIRECTORY_SEPARATOR . 'indexes';
        foreach (array_keys($schema['indexes']) as $indexName) {
            if (!is_file($root . DIRECTORY_SEPARATOR . $indexName . DIRECTORY_SEPARATOR . 'data.fxi')) {
                return false;
            }
        }
        return true;
    }
}
