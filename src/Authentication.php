<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Storage\StorageEngine;
use FoxyDB\Support\FileSystem;
use FoxyDB\Support\MemoryCache;

final class Authentication
{
    public const SYSTEM_DATABASE = 'foxydb';
    private const DEFAULT_USERNAME = 'root';
    private const DEFAULT_PASSWORD = 'root';

    private string $dummyPasswordHash;
    private readonly MemoryCache $userCache;
    private readonly MemoryCache $privilegeCache;
    private readonly MemoryCache $roleCache;
    private string $authorizationRevision = '';
    private const PRIVILEGES = [
        'ALL', 'SHOW', 'CONNECT', 'CREATE', 'DROP', 'INDEX', 'SELECT',
        'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'ALTER',
    ];

    public function __construct(
        private readonly StorageEngine $storage,
        private readonly Config $config,
    ) {
        $this->userCache = new MemoryCache(2_097_152);
        $this->privilegeCache = new MemoryCache(4_194_304);
        $this->roleCache = new MemoryCache(2_097_152);
        $this->dummyPasswordHash = $this->hashPassword(bin2hex(random_bytes(32)));
        $this->bootstrapWithLock();
    }

    public function authenticate(string $username, string $password): ?string
    {
        $identity = $this->authenticateIdentity($username, $password);
        return $identity === null ? null : $identity['username'];
    }

    public function authenticateIdentity(string $username, string $password): ?array
    {
        $username = self::normalizeUsername($username);
        if (strlen($password) > 1_024) {
            password_verify($password, $this->dummyPasswordHash);
            return null;
        }

        $user = $this->findUser($username);
        $hash = $user['password_hash'] ?? $this->dummyPasswordHash;
        $valid = password_verify($password, $hash);
        if ($user === null || !$valid || $user['enabled'] !== true) {
            return null;
        }

        if (password_needs_rehash($hash, $this->passwordAlgorithm())) {
            $users = $this->storage->table(self::SYSTEM_DATABASE, 'users_schema');
            $users->update(
                ['password_hash' => $this->hashPassword($password), 'updated_at' => new \DateTimeImmutable('now')],
                static fn(array $row): bool => $row['username'] === $username
                    && $row['password_hash'] === $hash,
                $users->lookupForEqualities(['username' => $username]),
            );
        }
        return ['username' => $username, 'account_id' => $user['account_id']];
    }

    public function assertPrivilege(
        string $username,
        string $privilege,
        string $database = '*',
        string $table = '*',
        ?string $accountId = null,
    ): void {
        if ($this->hasPrivilege($username, $privilege, $database, $table, $accountId)) {
            return;
        }
        throw new FoxyException(
            "User {$username} lacks {$privilege} privilege on {$database}.{$table}.",
            'ACCESS_DENIED',
            ['username' => $username, 'privilege' => $privilege, 'database' => $database, 'table' => $table],
        );
    }

    public function hasPrivilege(
        string $username,
        string $privilege,
        string $database = '*',
        string $table = '*',
        ?string $accountId = null,
    ): bool {
        $username = self::normalizeUsername($username);
        $user = $this->findUser($username);
        if ($user === null || $user['enabled'] !== true
            || ($accountId !== null && !hash_equals($user['account_id'], $accountId))) {
            return false;
        }
        $effectiveAccountId = $accountId ?? $user['account_id'];
        $privilege = strtoupper($privilege);
        $effectiveAccounts = [$effectiveAccountId, ...$this->roleIdsFor($username, $effectiveAccountId)];
        foreach ($effectiveAccounts as $candidateAccountId) {
            foreach ($this->privilegesFor($candidateAccountId) as $row) {
                if (!hash_equals($row['account_id'], $candidateAccountId)) {
                    continue;
                }
                $privilegeMatches = $row['privilege'] === 'ALL' || $row['privilege'] === $privilege;
                $databaseMatches = self::nameMatches((string) $row['database_name'], $database);
                $tableMatches = self::nameMatches((string) $row['table_name'], $table);
                if ($privilegeMatches && $databaseMatches && $tableMatches) {
                    return true;
                }
            }
        }
        return false;
    }

    public function cacheStatistics(): array
    {
        $this->synchronizeAuthorizationCaches();
        return [
            'users' => $this->userCache->statistics(),
            'privileges' => $this->privilegeCache->statistics(),
        ];
    }

    public static function normalizeUsername(string $username): string
    {
        $username = strtolower(trim($username));
        if (preg_match('/^[a-z0-9_.-]{1,64}$/', $username) !== 1) {
            throw new FoxyException('Username is invalid.', 'AUTH_FAILED');
        }
        return $username;
    }

    /**
     * Matches a stored grant name against a requested name.
     *
     * A pattern of '*' or '%' matches every name. A '%' anywhere else in the
     * pattern acts as a LIKE-style multi-character wildcard anchored to the
     * full name; every other byte, including '_', is literal. Both names are
     * already in canonical folded form.
     */
    private static function nameMatches(string $pattern, string $name): bool
    {
        if ($pattern === '*' || $pattern === '%' || $pattern === $name) {
            return true;
        }
        if (!str_contains($pattern, '%')) {
            return false;
        }
        $regex = '~^' . str_replace('%', '.*', preg_quote($pattern, '~')) . '$~';
        return preg_match($regex, $name) === 1;
    }

    private static function validGrantPattern(mixed $pattern): bool
    {
        if (!is_string($pattern)) {
            return false;
        }
        if ($pattern === '*' || $pattern === '%') {
            return true;
        }
        $name = str_ends_with($pattern, '%') ? substr($pattern, 0, -1) : $pattern;
        if ($name === '' || str_contains($name, '%')) {
            return false;
        }
        try {
            return TypeSystem::identifier($name) === $name;
        } catch (FoxyException) {
            return false;
        }
    }

    private function bootstrap(): void
    {
        self::ensureSystemSchema($this->storage, $this->config);

        $markerPath = $this->config->dataDirectory . DIRECTORY_SEPARATOR . 'auth.initialized';
        $statePath = $this->config->dataDirectory . DIRECTORY_SEPARATOR . 'auth.bootstrap.state';
        $authenticationInitialized = is_file($markerPath);
        if (!$authenticationInitialized) {
            $users = $this->storage->table(self::SYSTEM_DATABASE, 'users_schema');
            $hasUsers = false;
            foreach ($users->rows() as $_entry) {
                $hasUsers = true;
                break;
            }
            $completeDefaultBootstrap = !$hasUsers || is_file($statePath);
            if ($completeDefaultBootstrap) {
                if (!is_file($statePath)) {
                    FileSystem::atomicWrite($statePath, "default-root\n", $this->config->syncWrites);
                }
                try {
                    if ($this->findUser(self::DEFAULT_USERNAME) === null) {
                        $users->insert([
                            'username' => self::DEFAULT_USERNAME,
                            'password_hash' => $this->hashPassword(self::DEFAULT_PASSWORD),
                            'enabled' => true,
                        ]);
                    }
                } catch (FoxyException $exception) {
                    if ($exception->errorCode !== 'UNIQUE_VIOLATION') {
                        throw $exception;
                    }
                }
                $root = $this->findUser(self::DEFAULT_USERNAME);
                if ($root !== null) {
                    $this->seedRow('privileges', [
                        'account_id' => $root['account_id'],
                        'database_name' => '*',
                        'table_name' => '*',
                        'privilege' => 'ALL',
                    ], [
                        'username' => self::DEFAULT_USERNAME,
                        'account_id' => $root['account_id'],
                        'database_name' => '*',
                        'table_name' => '*',
                        'privilege' => 'ALL',
                    ]);
                }
            }
            FileSystem::atomicWrite($markerPath, "FXAUTH1\n", $this->config->syncWrites);
            if (is_file($statePath)) {
                @unlink($statePath);
            }
        } elseif (is_file($statePath)) {
            @unlink($statePath);
        }
        $this->seedRow('config_schema', ['config_key' => 'server_version'], [
            'config_key' => 'server_version',
            'config_value' => '1',
        ]);
        $this->seedRow('config_schema', ['config_key' => 'default_port'], [
            'config_key' => 'default_port',
            'config_value' => (string) $this->config->port,
        ]);
        $this->seedRow('config_schema', ['config_key' => 'enable_log'], [
            'config_key' => 'enable_log',
            'config_value' => $this->config->enableLog ? 'true' : 'false',
        ]);
        $this->seedRow('performance_schema', ['metric_name' => 'server_starts'], [
            'metric_name' => 'server_starts',
            'metric_value' => 1.0,
        ]);
        $this->seedRow('sys_config', ['variable_name' => 'chunk_bytes'], [
            'variable_name' => 'chunk_bytes',
            'variable_value' => (string) $this->config->chunkBytes,
            'description' => 'Maximum bytes in each stored chunk.',
        ]);
        $this->seedRow('sys_config', ['variable_name' => 'inline_value_bytes'], [
            'variable_name' => 'inline_value_bytes',
            'variable_value' => (string) $this->config->inlineValueBytes,
            'description' => 'Threshold for moving large values into chunk storage.',
        ]);
    }

    private function findUser(string $username): ?array
    {
        $this->synchronizeAuthorizationCaches();
        $cached = $this->userCache->get($username);
        if (is_array($cached) && array_key_exists('user', $cached)) {
            return $cached['user'];
        }
        $table = $this->storage->table(self::SYSTEM_DATABASE, 'users_schema');
        $lookup = $table->lookupForEqualities(['username' => $username]);
        foreach ($table->rows($lookup) as $entry) {
            if ($entry['values']['username'] === $username) {
                $this->userCache->put($username, ['user' => $entry['values']]);
                return $entry['values'];
            }
        }
        $this->userCache->put($username, ['user' => null]);
        return null;
    }

    private function privilegesFor(string $accountId): array
    {
        $this->synchronizeAuthorizationCaches();
        $cached = $this->privilegeCache->get($accountId);
        if (is_array($cached) && isset($cached['rows']) && is_array($cached['rows'])) {
            return $cached['rows'];
        }
        $rows = [];
        $privileges = $this->storage->table(self::SYSTEM_DATABASE, 'privileges');
        $lookup = $privileges->lookupForEqualities(['account_id' => $accountId]);
        foreach ($privileges->rows($lookup) as $entry) {
            $row = $entry['values'];
            if (!in_array($row['privilege'] ?? null, self::PRIVILEGES, true)
                || !self::validGrantPattern($row['database_name'] ?? null)
                || !self::validGrantPattern($row['table_name'] ?? null)) {
                throw new FoxyException('Stored privilege contains an invalid grant.', 'STORAGE_CORRUPT');
            }
            $rows[] = $row;
        }
        $this->privilegeCache->put($accountId, ['rows' => $rows]);
        return $rows;
    }

    public function roleIdsFor(string $username, ?string $accountId = null): array
    {
        $username = self::normalizeUsername($username);
        $accountId ??= $this->findUser($username)['account_id'] ?? null;
        if ($accountId === null) {
            return [];
        }
        $this->synchronizeAuthorizationCaches();
        $cacheKey = 'ids:' . $username . ':' . $accountId;
        $cached = $this->roleCache->get($cacheKey);
        if (is_array($cached) && isset($cached['ids']) && is_array($cached['ids'])) {
            return $cached['ids'];
        }
        $ids = [];
        try {
            $assignments = $this->storage->table(self::SYSTEM_DATABASE, 'role_assignments');
            $lookup = $assignments->lookupForEqualities(['account_id' => $accountId]);
            foreach ($assignments->rows($lookup) as $entry) {
                if ($entry['values']['username'] !== $username
                    || !hash_equals((string) $entry['values']['account_id'], $accountId)) {
                    continue;
                }
                $ids[] = $entry['values']['role_id'];
            }
        } catch (FoxyException) {
        }
        $this->roleCache->put($cacheKey, ['ids' => $ids]);
        return $ids;
    }

    public function roleNamesFor(string $username, ?string $accountId = null): array
    {
        $username = self::normalizeUsername($username);
        $accountId ??= $this->findUser($username)['account_id'] ?? null;
        if ($accountId === null) {
            return [];
        }
        $this->synchronizeAuthorizationCaches();
        $cacheKey = 'names:' . $username . ':' . $accountId;
        $cached = $this->roleCache->get($cacheKey);
        if (is_array($cached) && isset($cached['roles']) && is_array($cached['roles'])) {
            return $cached['roles'];
        }
        $roles = [];
        try {
            $assignments = $this->storage->table(self::SYSTEM_DATABASE, 'role_assignments');
            $roleTable = $this->storage->table(self::SYSTEM_DATABASE, 'roles');
            $lookup = $assignments->lookupForEqualities(['account_id' => $accountId]);
            foreach ($assignments->rows($lookup) as $entry) {
                if ($entry['values']['username'] !== $username
                    || !hash_equals((string) $entry['values']['account_id'], $accountId)) {
                    continue;
                }
                $roleId = $entry['values']['role_id'];
                $roleLookup = $roleTable->lookupForEqualities(['role_id' => $roleId]);
                foreach ($roleTable->rows($roleLookup) as $roleEntry) {
                    $roles[] = $roleEntry['values']['role_name'];
                }
            }
        } catch (FoxyException) {
        }
        $this->roleCache->put($cacheKey, ['roles' => $roles]);
        return $roles;
    }

    public function synchronizeAuthorizationCaches(): void
    {
        $revision = $this->storage->tableRevision(self::SYSTEM_DATABASE, 'users_schema')
            . ':' . $this->storage->tableRevision(self::SYSTEM_DATABASE, 'privileges')
            . ':' . $this->storage->tableRevision(self::SYSTEM_DATABASE, 'roles')
            . ':' . $this->storage->tableRevision(self::SYSTEM_DATABASE, 'role_assignments');
        if ($revision === $this->authorizationRevision) {
            return;
        }
        $this->authorizationRevision = $revision;
        $this->userCache->clear();
        $this->privilegeCache->clear();
        $this->roleCache->clear();
    }

    public static function ensureSystemSchema(StorageEngine $storage, Config $config): void
    {
        $storage->createDatabase(self::SYSTEM_DATABASE, true);
        $types = new TypeSystem($config);

        $tables = self::systemTableDefinitions();
        foreach ($tables as $name => $definition) {
            $storage->createTable(
                self::SYSTEM_DATABASE,
                $name,
                $types->compileSchema($name, $definition),
                true,
            );
        }
        self::migrateRoleAssignments($storage);
        self::migratePolicyScopes($storage);
    }

    /**
     * @return list<array{name: string, definition: array}>
     */
    public static function systemTableDefinitions(): array
    {
        return [
            'users_schema' => [
                'columns' => [
                    ['name' => 'username', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    [
                        'name' => 'account_id',
                        'type' => 'UUID',
                        'nullable' => false,
                        'unique' => true,
                        'default' => ['expression' => 'uuid'],
                    ],
                    ['name' => 'password_hash', 'type' => 'VARCHAR', 'length' => 255, 'nullable' => false],
                    [
                        'name' => 'enabled',
                        'type' => 'BOOLEAN',
                        'nullable' => false,
                        'default' => true,
                    ],
                    [
                        'name' => 'created_at',
                        'type' => 'TIMESTAMP',
                        'nullable' => false,
                        'default' => ['expression' => 'current_timestamp'],
                    ],
                    ['name' => 'updated_at', 'type' => 'TIMESTAMP', 'nullable' => true],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['username']],
                ],
            ],
            'privileges' => [
                'columns' => [
                    [
                        'name' => 'id',
                        'type' => 'BIGINT',
                        'nullable' => false,
                        'auto_increment' => true,
                    ],
                    ['name' => 'username', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'account_id', 'type' => 'UUID', 'nullable' => false],
                    ['name' => 'database_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'table_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'privilege', 'type' => 'VARCHAR', 'length' => 32, 'nullable' => false],
                    [
                        'name' => 'granted_at',
                        'type' => 'TIMESTAMP',
                        'nullable' => false,
                        'default' => ['expression' => 'current_timestamp'],
                    ],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['id']],
                    [
                        'kind' => 'unique',
                        'name' => 'uq_privilege',
                        'columns' => ['account_id', 'database_name', 'table_name', 'privilege'],
                    ],
                    ['kind' => 'index', 'name' => 'idx_privilege_account', 'columns' => ['account_id']],
                ],
            ],
            'config_schema' => [
                'columns' => [
                    ['name' => 'config_key', 'type' => 'VARCHAR', 'length' => 128, 'nullable' => false],
                    ['name' => 'config_value', 'type' => 'LONGTEXT', 'nullable' => true],
                    [
                        'name' => 'updated_at',
                        'type' => 'TIMESTAMP',
                        'nullable' => false,
                        'default' => ['expression' => 'current_timestamp'],
                    ],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['config_key']],
                ],
            ],
            'performance_schema' => [
                'columns' => [
                    ['name' => 'metric_name', 'type' => 'VARCHAR', 'length' => 128, 'nullable' => false],
                    ['name' => 'metric_value', 'type' => 'DOUBLE', 'nullable' => false, 'default' => 0.0],
                    [
                        'name' => 'updated_at',
                        'type' => 'TIMESTAMP',
                        'nullable' => false,
                        'default' => ['expression' => 'current_timestamp'],
                    ],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['metric_name']],
                ],
            ],
            'roles' => [
                'columns' => [
                    ['name' => 'role_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'role_id', 'type' => 'UUID', 'nullable' => false, 'default' => ['expression' => 'uuid']],
                    ['name' => 'created_at', 'type' => 'TIMESTAMP', 'nullable' => false, 'default' => ['expression' => 'current_timestamp']],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['role_name']],
                    ['kind' => 'unique', 'name' => 'uq_role_id', 'columns' => ['role_id']],
                ],
            ],
            'policies' => [
                'columns' => [
                    ['name' => 'policy_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'database_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'table_name', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'operation', 'type' => 'VARCHAR', 'length' => 16, 'nullable' => false],
                    ['name' => 'username', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => true],
                    ['name' => 'scope_type', 'type' => 'VARCHAR', 'length' => 16, 'nullable' => true],
                    ['name' => 'scope_id', 'type' => 'UUID', 'nullable' => true],
                    ['name' => 'expression_sql', 'type' => 'TEXT', 'nullable' => true],
                    ['name' => 'created_at', 'type' => 'TIMESTAMP', 'nullable' => false, 'default' => ['expression' => 'current_timestamp']],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['policy_name', 'database_name', 'table_name']],
                    ['kind' => 'index', 'name' => 'idx_policy_table', 'columns' => ['database_name', 'table_name']],
                ],
            ],
            'replication_log' => [
                'columns' => [
                    ['name' => 'log_id', 'type' => 'BIGINT', 'nullable' => false, 'auto_increment' => true],
                    ['name' => 'logged_at', 'type' => 'TIMESTAMP', 'nullable' => false, 'default' => ['expression' => 'current_timestamp']],
                    ['name' => 'source_database', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'source_table', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'change_type', 'type' => 'VARCHAR', 'length' => 16, 'nullable' => false],
                    ['name' => 'change_sql', 'type' => 'LONGTEXT', 'nullable' => false],
                    ['name' => 'applied', 'type' => 'BOOLEAN', 'nullable' => false, 'default' => false],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['log_id']],
                ],
            ],
            'role_assignments' => [
                'columns' => [
                    ['name' => 'username', 'type' => 'VARCHAR', 'length' => 64, 'nullable' => false],
                    ['name' => 'account_id', 'type' => 'UUID', 'nullable' => false],
                    ['name' => 'role_id', 'type' => 'UUID', 'nullable' => false],
                    ['name' => 'granted_at', 'type' => 'TIMESTAMP', 'nullable' => false, 'default' => ['expression' => 'current_timestamp']],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['account_id', 'role_id']],
                    ['kind' => 'index', 'name' => 'idx_ra_username', 'columns' => ['username']],
                    ['kind' => 'index', 'name' => 'idx_ra_role', 'columns' => ['role_id']],
                ],
            ],
            'sys_config' => [
                'columns' => [
                    ['name' => 'variable_name', 'type' => 'VARCHAR', 'length' => 128, 'nullable' => false],
                    ['name' => 'variable_value', 'type' => 'LONGTEXT', 'nullable' => true],
                    ['name' => 'description', 'type' => 'TEXT', 'nullable' => true],
                    [
                        'name' => 'updated_at',
                        'type' => 'TIMESTAMP',
                        'nullable' => false,
                        'default' => ['expression' => 'current_timestamp'],
                    ],
                ],
                'constraints' => [
                    ['kind' => 'primary', 'name' => 'primary', 'columns' => ['variable_name']],
                ],
            ],
        ];
    }

    private static function migrateRoleAssignments(StorageEngine $storage): void
    {
        $assignments = $storage->table(self::SYSTEM_DATABASE, 'role_assignments');
        if (!in_array('account_id', array_column($assignments->schema()['columns'], 'name'), true)) {
            $assignments->alterSchema([[
                'kind' => 'add_column',
                'column' => ['name' => 'account_id', 'type' => 'UUID', 'nullable' => true],
            ]]);
        }
        $users = $storage->table(self::SYSTEM_DATABASE, 'users_schema');
        foreach ($assignments->rows() as $entry) {
            $username = (string) $entry['values']['username'];
            $accountId = null;
            $createdAt = null;
            foreach ($users->rows($users->lookupForEqualities(['username' => $username])) as $user) {
                if ($user['values']['username'] === $username) {
                    $accountId = $user['values']['account_id'];
                    $createdAt = $user['values']['created_at'];
                    break;
                }
            }
            $grantedAt = $entry['values']['granted_at'] ?? null;
            if ($accountId === null || ($createdAt instanceof \DateTimeInterface
                && $grantedAt instanceof \DateTimeInterface && $grantedAt < $createdAt)) {
                $assignments->delete(static fn(array $row): bool =>
                    $row['username'] === $username && $row['role_id'] === $entry['values']['role_id']
                );
                continue;
            }
            if (($entry['values']['account_id'] ?? null) !== $accountId) {
                $roleId = $entry['values']['role_id'];
                $assignments->update(
                    ['account_id' => $accountId],
                    static fn(array $row): bool =>
                        $row['username'] === $username && $row['role_id'] === $roleId,
                );
            }
        }
    }

    private static function migratePolicyScopes(StorageEngine $storage): void
    {
        $policies = $storage->table(self::SYSTEM_DATABASE, 'policies');
        $columns = array_column($policies->schema()['columns'], 'name');
        $actions = [];
        if (!in_array('scope_type', $columns, true)) {
            $actions[] = [
                'kind' => 'add_column',
                'column' => ['name' => 'scope_type', 'type' => 'VARCHAR', 'length' => 16, 'nullable' => true],
            ];
        }
        if (!in_array('scope_id', $columns, true)) {
            $actions[] = [
                'kind' => 'add_column',
                'column' => ['name' => 'scope_id', 'type' => 'UUID', 'nullable' => true],
            ];
        }
        if ($actions !== []) {
            $policies->alterSchema($actions);
        }
        $users = $storage->table(self::SYSTEM_DATABASE, 'users_schema');
        $roles = $storage->table(self::SYSTEM_DATABASE, 'roles');
        foreach ($policies->rows() as $entry) {
            $row = $entry['values'];
            $scope = $row['username'] ?? null;
            if ($scope === null || $scope === '' || (($row['scope_type'] ?? null) !== null
                && ($row['scope_id'] ?? null) !== null)) {
                continue;
            }
            $matches = [];
            foreach ($users->rows($users->lookupForEqualities(['username' => $scope])) as $user) {
                if ($user['values']['username'] === $scope) {
                    $matches[] = ['type' => 'user', 'id' => $user['values']['account_id']];
                }
            }
            foreach ($roles->rows($roles->lookupForEqualities(['role_name' => $scope])) as $role) {
                if ($role['values']['role_name'] === $scope) {
                    $matches[] = ['type' => 'role', 'id' => $role['values']['role_id']];
                }
            }
            $identity = [
                'policy_name' => $row['policy_name'],
                'database_name' => $row['database_name'],
                'table_name' => $row['table_name'],
            ];
            if (count($matches) !== 1) {
                $policies->delete(null, $policies->lookupForEqualities($identity));
                continue;
            }
            $policies->update(
                ['scope_type' => $matches[0]['type'], 'scope_id' => $matches[0]['id']],
                static fn(array $candidate): bool =>
                    $candidate['policy_name'] === $identity['policy_name']
                    && $candidate['database_name'] === $identity['database_name']
                    && $candidate['table_name'] === $identity['table_name'],
                $policies->lookupForEqualities($identity),
            );
        }
    }

    private function bootstrapWithLock(): void
    {
        $path = $this->config->dataDirectory . DIRECTORY_SEPARATOR . 'auth.bootstrap.lock';
        FileSystem::ensureDirectory(dirname($path));
        $lock = @fopen($path, 'c+b');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new FoxyException('Unable to acquire authentication bootstrap lock.', 'STORAGE_LOCK');
        }
        try {
            $this->bootstrap();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function seedRow(string $tableName, array $identity, array $row): void
    {
        if ($this->rowExists($tableName, $identity)) {
            return;
        }
        $table = $this->storage->table(self::SYSTEM_DATABASE, $tableName);
        try {
            $table->insert($row);
        } catch (FoxyException $exception) {
            if ($exception->errorCode !== 'UNIQUE_VIOLATION') {
                throw $exception;
            }
        }
    }

    private function rowExists(string $tableName, array $identity): bool
    {
        $table = $this->storage->table(self::SYSTEM_DATABASE, $tableName);
        $lookup = $table->lookupForEqualities($identity);
        foreach ($table->rows($lookup) as $_entry) {
            return true;
        }
        return false;
    }

    private function hashPassword(string $password): string
    {
        $hash = password_hash($password, $this->passwordAlgorithm());
        if ($hash === false) {
            throw new FoxyException('Unable to hash bootstrap password.', 'AUTH_CONFIG');
        }
        return $hash;
    }

    private function passwordAlgorithm(): string|int|null
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    }
}
