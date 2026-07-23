<?php

declare(strict_types=1);

namespace FoxyDB\Storage;

use FoxyDB\Config;
use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;
use FoxyDB\Support\MemoryCache;
use FoxyDB\TypeSystem;

final class StorageEngine
{
    private const MAXIMUM_TABLE_HANDLES = 256;

    private readonly string $databasesPath;
    private readonly string $locksPath;
    private readonly MemoryCache $bufferPool;
    private readonly MemoryCache $indexCache;
    private readonly MemoryCache $queryCache;
    private int $mutationEpoch = 0;
    private int $queryCacheEpoch = 0;
    private array $tableRevisions = [];
    private array $tableHandles = [];
    private $instanceLock;

    public function __construct(private readonly Config $config)
    {
        FileSystem::ensureDirectory($config->dataDirectory);
        $canonicalDirectory = realpath($config->dataDirectory);
        if ($canonicalDirectory === false) {
            throw new FoxyException('Unable to resolve the data directory.', 'STORAGE_IO');
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            $canonicalDirectory = strtolower($canonicalDirectory);
        }
        $instanceLockPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR
            . 'foxydb-instance-' . hash('sha256', $canonicalDirectory) . '.lock';
        $this->instanceLock = @fopen($instanceLockPath, 'c+b');
        if ($this->instanceLock === false || !flock($this->instanceLock, LOCK_EX | LOCK_NB)) {
            if (is_resource($this->instanceLock)) {
                fclose($this->instanceLock);
            }
            throw new FoxyException('The data directory is already open by another FoxyDB engine.', 'STORAGE_IN_USE');
        }
        if (DIRECTORY_SEPARATOR === '/') {
            @chmod($instanceLockPath, 0600);
        }
        $this->databasesPath = $config->dataDirectory . DIRECTORY_SEPARATOR . 'databases';
        $this->locksPath = $config->dataDirectory . DIRECTORY_SEPARATOR . 'locks';
        FileSystem::ensureDirectory($this->databasesPath);
        FileSystem::ensureDirectory($this->locksPath);
        $this->bufferPool = new MemoryCache();
        $this->indexCache = new MemoryCache();
        $this->queryCache = new MemoryCache();
        $lock = @fopen($config->dataDirectory . DIRECTORY_SEPARATOR . 'catalog.lock', 'c+b');
        if ($lock === false) {
            throw new FoxyException('Unable to initialize the database catalog.', 'STORAGE_IO');
        }
        fclose($lock);
    }

    public function shutdown(): void
    {
        $this->tableHandles = [];
        $this->invalidateCaches();
        if (is_resource($this->instanceLock)) {
            flock($this->instanceLock, LOCK_UN);
            fclose($this->instanceLock);
            $this->instanceLock = null;
        }
    }

    public function __destruct()
    {
        $this->shutdown();
    }

    public function createDatabase(string $name, bool $ifNotExists = false): void
    {
        $name = TypeSystem::identifier($name);
        $lock = $this->catalogLock(LOCK_EX);
        try {
            $path = $this->databasePath($name);
            if (is_dir($path)) {
                if ($ifNotExists) {
                    return;
                }
                throw new FoxyException("Database {$name} already exists.", 'DATABASE_EXISTS');
            }
            $temporary = $path . '.creating.' . bin2hex(random_bytes(6));
            FileSystem::ensureDirectory($temporary . DIRECTORY_SEPARATOR . 'tables');
            $databaseLock = @fopen($temporary . DIRECTORY_SEPARATOR . 'database.lock', 'c+b');
            if ($databaseLock === false) {
                FileSystem::removeTree($temporary);
                throw new FoxyException('Unable to initialize database lock.', 'STORAGE_IO');
            }
            fclose($databaseLock);
            if (!@rename($temporary, $path)) {
                FileSystem::removeTree($temporary);
                throw new FoxyException('Unable to publish database directory.', 'STORAGE_IO');
            }
            $this->invalidateCaches();
            FileSystem::ensureDirectory($this->databaseLocksPath($name));
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function dropDatabase(string $name, bool $ifExists = false): void
    {
        $name = TypeSystem::identifier($name);
        $lock = $this->catalogLock(LOCK_EX);
        $databaseLock = null;
        $tableLocks = [];
        try {
            $path = $this->databasePath($name);
            if (!is_dir($path)) {
                if ($ifExists) {
                    return;
                }
                throw new FoxyException("Database {$name} does not exist.", 'DATABASE_NOT_FOUND');
            }
            $databaseLock = $this->databaseLock($name, LOCK_EX);
            $lockDirectory = $this->databaseLocksPath($name);
            if (is_dir($lockDirectory)) {
                $entries = scandir($lockDirectory);
                if ($entries === false) {
                    throw new FoxyException('Unable to scan database locks.', 'STORAGE_IO');
                }
                foreach ($entries as $entry) {
                    if (str_ends_with($entry, '.table.lock')) {
                        $tableLocks[] = $this->lock($lockDirectory . DIRECTORY_SEPARATOR . $entry, LOCK_EX);
                    }
                }
            }
            $tombstone = $path . '.dropping.' . bin2hex(random_bytes(6));
            if (!@rename($path, $tombstone)) {
                throw new FoxyException('Unable to detach database directory.', 'STORAGE_IO');
            }
            foreach (array_keys($this->tableHandles) as $key) {
                if (str_starts_with($key, $name . '.')) {
                    unset($this->tableHandles[$key]);
                }
            }
            $this->invalidateCaches();
            FileSystem::removeTree($tombstone);
        } finally {
            foreach (array_reverse($tableLocks) as $tableLock) {
                $this->releaseLock($tableLock);
            }
            if ($databaseLock !== null) {
                $this->releaseLock($databaseLock);
            }
            $this->releaseLock($lock);
        }
    }

    public function listDatabases(): array
    {
        $lock = $this->catalogLock(LOCK_SH);
        try {
            $entries = scandir($this->databasesPath);
            if ($entries === false) {
                throw new FoxyException('Unable to scan databases.', 'STORAGE_IO');
            }
            $databases = [];
            foreach ($entries as $entry) {
                if (preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $entry) === 1
                    && is_dir($this->databasesPath . DIRECTORY_SEPARATOR . $entry)) {
                    $databases[] = $entry;
                }
            }
            sort($databases, SORT_STRING);
            return $databases;
        } finally {
            $this->releaseLock($lock);
        }
    }

    public function databaseExists(string $name): bool
    {
        $name = TypeSystem::identifier($name);
        $catalogLock = $this->catalogLock(LOCK_SH);
        try {
            return is_dir($this->databasePath($name));
        } finally {
            $this->releaseLock($catalogLock);
        }
    }

    public function createTable(string $database, string $table, array $schema, bool $ifNotExists = false): void
    {
        $database = TypeSystem::identifier($database);
        $table = TypeSystem::identifier($table);
        $catalogLock = $this->catalogLock(LOCK_SH);
        $lock = null;
        $tableLock = null;
        try {
            $databasePath = $this->requireDatabase($database);
            $lock = $this->databaseLock($database, LOCK_EX);
            $tableLock = $this->tableLock($database, $table, LOCK_EX);
            $this->requireDatabase($database);
            $path = $databasePath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $table;
            if (is_dir($path)) {
                if ($ifNotExists) {
                    return;
                }
                throw new FoxyException("Table {$table} already exists.", 'TABLE_EXISTS');
            }
            Table::create($path, $schema, $this->config);
            $this->invalidateTableCaches($database, $table);
        } finally {
            if ($tableLock !== null) {
                $this->releaseLock($tableLock);
            }
            if ($lock !== null) {
                $this->releaseLock($lock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function dropTable(string $database, string $table, bool $ifExists = false): void
    {
        $database = TypeSystem::identifier($database);
        $table = TypeSystem::identifier($table);
        $catalogLock = $this->catalogLock(LOCK_SH);
        $lock = null;
        $tableLock = null;
        try {
            $databasePath = $this->requireDatabase($database);
            $lock = $this->databaseLock($database, LOCK_EX);
            $tableLock = $this->tableLock($database, $table, LOCK_EX);
            $this->requireDatabase($database);
            $path = $databasePath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $table;
            if (!is_dir($path)) {
                if ($ifExists) {
                    return;
                }
                throw new FoxyException("Table {$table} does not exist.", 'TABLE_NOT_FOUND');
            }
            $tombstone = $path . '.dropping.' . bin2hex(random_bytes(6));
            if (!@rename($path, $tombstone)) {
                throw new FoxyException('Unable to detach table directory.', 'STORAGE_IO');
            }
            unset($this->tableHandles[$this->tableKey($database, $table)]);
            $this->indexCache->clear();
            $this->invalidateTableCaches($database, $table);
            FileSystem::removeTree($tombstone);
        } finally {
            if ($tableLock !== null) {
                $this->releaseLock($tableLock);
            }
            if ($lock !== null) {
                $this->releaseLock($lock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function renameTable(string $database, string $oldName, string $newName): void
    {
        $database = TypeSystem::identifier($database);
        $oldName = TypeSystem::identifier($oldName);
        $newName = TypeSystem::identifier($newName);
        $catalogLock = $this->catalogLock(LOCK_SH);
        $lock = null;
        $oldTableLock = null;
        $newTableLock = null;
        try {
            $databasePath = $this->requireDatabase($database);
            $lock = $this->databaseLock($database, LOCK_EX);
            $oldTableLock = $this->tableLock($database, $oldName, LOCK_EX);
            $newTableLock = $this->tableLock($database, $newName, LOCK_EX);
            $this->requireDatabase($database);
            $oldPath = $databasePath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $oldName;
            $newPath = $databasePath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $newName;
            if (!is_dir($oldPath)) {
                throw new FoxyException("Table {$oldName} does not exist.", 'TABLE_NOT_FOUND');
            }
            if (is_dir($newPath)) {
                throw new FoxyException("Table {$newName} already exists.", 'TABLE_EXISTS');
            }
            if (!@rename($oldPath, $newPath)) {
                throw new FoxyException('Unable to rename table directory.', 'STORAGE_IO');
            }
            unset($this->tableHandles[$this->tableKey($database, $oldName)]);
            $this->invalidateTableCaches($database, $oldName);
            $this->invalidateTableCaches($database, $newName);
        } finally {
            if ($newTableLock !== null) {
                $this->releaseLock($newTableLock);
            }
            if ($oldTableLock !== null) {
                $this->releaseLock($oldTableLock);
            }
            if ($lock !== null) {
                $this->releaseLock($lock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function moveTable(string $database, string $table, string $targetDatabase, ?string $targetTable): void
    {
        $database = TypeSystem::identifier($database);
        $table = TypeSystem::identifier($table);
        $targetDatabase = TypeSystem::identifier($targetDatabase);
        $targetTable = $targetTable !== null ? TypeSystem::identifier($targetTable) : $table;
        if ($database === $targetDatabase && $table === $targetTable) {
            return;
        }
        $catalogLock = $this->catalogLock(LOCK_SH);
        $sameDb = $database === $targetDatabase;
        $sameTableLock = $sameDb && $table === $targetTable;
        $srcLock = null;
        $dstLock = null;
        $srcTableLock = null;
        $dstTableLock = null;
        try {
            $srcPath = $this->requireDatabase($database);
            $dstPath = $sameDb ? $srcPath : $this->requireDatabase($targetDatabase);
            $srcLock = $this->databaseLock($database, LOCK_EX);
            $dstLock = $sameDb ? null : $this->databaseLock($targetDatabase, LOCK_EX);
            $srcTableLock = $this->tableLock($database, $table, LOCK_EX);
            $dstTableLock = $sameTableLock ? null : $this->tableLock($targetDatabase, $targetTable, LOCK_EX);
            $this->requireDatabase($database);
            if (!$sameDb) { $this->requireDatabase($targetDatabase); }
            $oldPath = $srcPath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $table;
            $newPath = $dstPath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $targetTable;
            if (!is_dir($oldPath)) {
                throw new FoxyException("Table {$table} does not exist.", 'TABLE_NOT_FOUND');
            }
            if (is_dir($newPath)) {
                throw new FoxyException("Table {$targetTable} already exists in target database.", 'TABLE_EXISTS');
            }
            if (!@rename($oldPath, $newPath)) {
                throw new FoxyException('Unable to move table directory.', 'STORAGE_IO');
            }
            unset($this->tableHandles[$this->tableKey($database, $table)]);
            $this->invalidateTableCaches($database, $table);
            $this->invalidateTableCaches($targetDatabase, $targetTable);
        } finally {
            if ($dstTableLock !== null) {
                $this->releaseLock($dstTableLock);
            }
            if ($srcTableLock !== null) {
                $this->releaseLock($srcTableLock);
            }
            if ($dstLock !== null) {
                $this->releaseLock($dstLock);
            }
            if ($srcLock !== null) {
                $this->releaseLock($srcLock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function copyTable(string $database, string $table, string $targetDatabase, ?string $targetTable): void
    {
        $database = TypeSystem::identifier($database);
        $table = TypeSystem::identifier($table);
        $targetDatabase = TypeSystem::identifier($targetDatabase);
        $targetTable = $targetTable !== null ? TypeSystem::identifier($targetTable) : $table;
        if ($database === $targetDatabase && $table === $targetTable) {
            throw new FoxyException('Source and target are the same table.', 'TABLE_EXISTS');
        }
        $catalogLock = $this->catalogLock(LOCK_SH);
        $sameDb = $database === $targetDatabase;
        $sameTableLock = $sameDb && $table === $targetTable;
        $srcLock = null;
        $dstLock = null;
        $srcTableLock = null;
        $dstTableLock = null;
        try {
            $srcPath = $this->requireDatabase($database) . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $table;
            $dstDbPath = $sameDb ? $this->requireDatabase($database) : $this->requireDatabase($targetDatabase);
            $srcLock = $this->databaseLock($database, LOCK_EX);
            $dstLock = $sameDb ? null : $this->databaseLock($targetDatabase, LOCK_EX);
            $srcTableLock = $this->tableLock($database, $table, LOCK_EX);
            $dstTableLock = $sameTableLock ? null : $this->tableLock($targetDatabase, $targetTable, LOCK_EX);
            $this->requireDatabase($database);
            if (!$sameDb) { $this->requireDatabase($targetDatabase); }
            if (!is_dir($srcPath)) {
                throw new FoxyException("Table {$table} does not exist.", 'TABLE_NOT_FOUND');
            }
            $dstPath = $dstDbPath . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $targetTable;
            if (is_dir($dstPath)) {
                throw new FoxyException("Table {$targetTable} already exists in target database.", 'TABLE_EXISTS');
            }
            FileSystem::copyTree($srcPath, $dstPath);
            $this->invalidateTableCaches($targetDatabase, $targetTable);
        } finally {
            if ($dstTableLock !== null) {
                $this->releaseLock($dstTableLock);
            }
            if ($srcTableLock !== null) {
                $this->releaseLock($srcTableLock);
            }
            if ($dstLock !== null) {
                $this->releaseLock($dstLock);
            }
            if ($srcLock !== null) {
                $this->releaseLock($srcLock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function listTables(string $database): array
    {
        $database = TypeSystem::identifier($database);
        $catalogLock = $this->catalogLock(LOCK_SH);
        $lock = null;
        try {
            $databasePath = $this->requireDatabase($database);
            $lock = $this->databaseLock($database, LOCK_SH);
            $tablesPath = $databasePath . DIRECTORY_SEPARATOR . 'tables';
            $entries = scandir($tablesPath);
            if ($entries === false) {
                throw new FoxyException('Unable to scan tables.', 'STORAGE_IO');
            }
            $tables = [];
            foreach ($entries as $entry) {
                if (preg_match('/^[a-z_][a-z0-9_]{0,63}$/', $entry) === 1
                    && is_dir($tablesPath . DIRECTORY_SEPARATOR . $entry)) {
                    $tables[] = $entry;
                }
            }
            sort($tables, SORT_STRING);
            return $tables;
        } finally {
            if ($lock !== null) {
                $this->releaseLock($lock);
            }
            $this->releaseLock($catalogLock);
        }
    }

    public function table(string $database, string $table): Table
    {
        $database = TypeSystem::identifier($database);
        $table = TypeSystem::identifier($table);
        $key = $this->tableKey($database, $table);
        if (isset($this->tableHandles[$key])) {
            $handle = $this->tableHandles[$key];
            unset($this->tableHandles[$key]);
            $this->tableHandles[$key] = $handle;
            return $handle;
        }
        $catalogLock = $this->catalogLock(LOCK_SH);
        try {
            $path = $this->requireDatabase($database) . DIRECTORY_SEPARATOR . 'tables' . DIRECTORY_SEPARATOR . $table;
            if (!is_dir($path)) {
                throw new FoxyException("Table {$table} does not exist.", 'TABLE_NOT_FOUND');
            }
            $handle = new Table(
                $path,
                $this->config,
                $this->tableLockPath($database, $table),
                $this->bufferPool,
                $this->indexCache,
                function () use ($database, $table): void {
                    $this->invalidateTableCaches($database, $table);
                },
            );
            $this->tableHandles[$key] = $handle;
            if (count($this->tableHandles) > self::MAXIMUM_TABLE_HANDLES) {
                unset($this->tableHandles[array_key_first($this->tableHandles)]);
                $this->indexCache->clear();
            }
            return $handle;
        } finally {
            $this->releaseLock($catalogLock);
        }
    }

    private function requireDatabase(string $name): string
    {
        $path = $this->databasePath($name);
        if (!is_dir($path)) {
            throw new FoxyException("Database {$name} does not exist.", 'DATABASE_NOT_FOUND');
        }
        return $path;
    }

    private function databasePath(string $name): string
    {
        return $this->databasesPath . DIRECTORY_SEPARATOR . $name;
    }

    private function catalogLock(int $operation)
    {
        return $this->lock($this->config->dataDirectory . DIRECTORY_SEPARATOR . 'catalog.lock', $operation);
    }

    private function databaseLock(string $database, int $operation)
    {
        $directory = $this->databaseLocksPath($database);
        FileSystem::ensureDirectory($directory);
        return $this->lock($directory . DIRECTORY_SEPARATOR . 'database.lock', $operation);
    }

    private function tableLock(string $database, string $table, int $operation)
    {
        return $this->lock($this->tableLockPath($database, $table), $operation);
    }

    private function tableLockPath(string $database, string $table): string
    {
        $directory = $this->databaseLocksPath($database);
        FileSystem::ensureDirectory($directory);
        return $directory . DIRECTORY_SEPARATOR . $table . '.table.lock';
    }

    private function databaseLocksPath(string $database): string
    {
        return $this->locksPath . DIRECTORY_SEPARATOR . $database;
    }

    public function configureCaches(int $bufferPoolBytes, int $queryCacheBytes): void
    {
        $this->bufferPool->setMaximumBytes($bufferPoolBytes);
        $this->indexCache->setMaximumBytes(min(16_777_216, intdiv($bufferPoolBytes, 4)));
        $this->queryCache->setMaximumBytes($queryCacheBytes);
    }

    public function queryCacheGet(string $key): mixed
    {
        return $this->queryCache->get($this->queryCacheEpoch . ':' . $key);
    }

    public function queryCachePut(string $key, mixed $value, ?int $bytes = null): bool
    {
        return $this->queryCache->put($this->queryCacheEpoch . ':' . $key, $value, $bytes);
    }

    public function invalidateCaches(): void
    {
        $this->invalidateQueryCache();
        $this->bufferPool->clear();
        $this->indexCache->clear();
    }

    public function tableRevision(string $database, string $table): int
    {
        return $this->tableRevisions[$this->tableKey($database, $table)] ?? 0;
    }

    public function invalidateQueryCache(): void
    {
        $this->mutationEpoch++;
        $this->queryCacheEpoch++;
        $this->queryCache->clear();
    }

    public function cacheStatistics(): array
    {
        return [
            'buffer_pool' => $this->bufferPool->statistics(),
            'index_cache' => $this->indexCache->statistics(),
            'query_cache' => $this->queryCache->statistics(),
            'mutation_epoch' => $this->mutationEpoch,
            'table_handles' => count($this->tableHandles),
        ];
    }

    private function invalidateTableCaches(string $database, string $table): void
    {
        $key = $this->tableKey($database, $table);
        $this->tableRevisions[$key] = ($this->tableRevisions[$key] ?? 0) + 1;
        $this->mutationEpoch++;
    }

    private function tableKey(string $database, string $table): string
    {
        return $database . '.' . $table;
    }

    private function lock(string $path, int $operation)
    {
        $stream = @fopen($path, 'c+b');
        if ($stream === false || !flock($stream, $operation)) {
            if (is_resource($stream)) {
                fclose($stream);
            }
            throw new FoxyException('Unable to acquire catalog lock.', 'STORAGE_LOCK');
        }
        return $stream;
    }

    private function releaseLock($stream): void
    {
        flock($stream, LOCK_UN);
        fclose($stream);
    }
}
