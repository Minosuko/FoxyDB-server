# FoxyDB Server

FoxyDB is a dependency-free database server implemented in PHP 8.2 or newer. It listens on TCP port `2002`, accepts SQL through a checksummed typed binary protocol, and uses its own append-oriented storage engine. It does not use SQLite, MySQL, or another database for persistence.

FoxyDB is an early server implementation. Test it with representative workloads and maintain backups before using it for important data.

For SQLite-style deployment without a daemon or network connection, use the [`Minosuko/FoxyDB-serverless`](https://github.com/Minosuko/FoxyDB-serverless/README.md) embedded package. Embedded databases use a distinct marked bundle directory and must not be opened from the daemon's data directory.

## Features

- TCP server on `127.0.0.1:2002` by default
- TLS 1.2 and TLS 1.3 encryption on every network connection
- SQL lexer, parser, typed AST, and execution engine (statements up to 16 MiB and 1,000,000 tokens)
- `INT`, `VARCHAR`, `BIGINT`, `LONGTEXT`, `TEXT`, `BINARY`, `BLOB`, `TIMESTAMP`, `DATETIME`, `FLOAT`, `DOUBLE`, `BOOLEAN`, `REAL`, `TINYINT`, `UUID`, and `JSON`
- Primary, unique, and non-unique hash indexes
- `JSON` columns with `JSON_EXTRACT` predicates and projections
- `AUTO_INCREMENT` integer keys
- Append-only row data with fixed-size row directory slots
- Checksummed records, redo slots, dirty-index recovery, and generation fallback
- Content-addressed, deduplicated chunks for large text and binary values
- Bounded batch scans and configurable row, frame, upload, and materialization limits
- Online table compaction under an exclusive table lock
- Persistent username/password authentication and table-level privileges
- Persistent global and per-session system variables with bounded memory caches
- Rotating JSON-lines general, error, audit, and slow-query logs
- PHP client with certificate verification, parameter binding, and chunk upload support

## Requirements

- 64-bit PHP 8.2 or newer
- `json`, `mbstring`, `openssl`, and `zlib` PHP extensions
- Permission to create and update the configured data directory

## Start

From the `server` directory:

```console
php bin/foxydb.php
```

The default endpoint is `tls://127.0.0.1:2002` and the default data directory is `server/data`. Plaintext network sessions are rejected.

Command-line options:

```console
php bin/foxydb.php --host=127.0.0.1 --port=2002 --data-dir=./data
```

The daemon does not accept usernames or passwords through command-line options or environment variables. On first initialization, if `foxydb.users_schema` is empty, FoxyDB creates `root` with password `root`. Change that password through the authenticated database connection after startup.

The server binds only to loopback by default. If it is exposed to another host, configure authentication and place it behind a TLS tunnel or trusted private network.

On first startup, FoxyDB generates a 3072-bit RSA private key and a ten-year self-signed server certificate:

- `data/tls/server.key`
- `data/tls/server.crt`

The certificate includes `localhost`, `127.0.0.1`, `::1`, and the configured bind host as applicable. Protect and back up the TLS directory with the data directory.

## PHP Library

```php
<?php

require dirname(__DIR__) . '/library/src/Autoloader.php';

use FoxyDB\Client;

$db = Client::connect('127.0.0.1', 2002, 'root', 'root');
$db->query('CREATE DATABASE IF NOT EXISTS app');
$db->query('USE app');
$db->query(
    'CREATE TABLE IF NOT EXISTS users ('
    . 'id BIGINT PRIMARY KEY AUTO_INCREMENT, '
    . 'email VARCHAR(255) NOT NULL UNIQUE, '
    . 'enabled BOOLEAN NOT NULL DEFAULT TRUE, '
    . 'created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP'
    . ')'
);

$insert = $db->query('INSERT INTO users (email) VALUES (?)', ['fox@example.test']);
echo $insert->lastInsertId . PHP_EOL;

$result = $db->query('SELECT id, email FROM users WHERE email = ?', ['fox@example.test']);
foreach ($result as $row) {
    echo $row['email'] . PHP_EOL;
}
```

The standalone library in `../library` materializes returned chunks and applies client-side row and byte limits. Applications that need fully streaming downloads can implement the documented frame protocol directly.

`Client` uses `REQUIRED` TLS mode by default, which encrypts traffic but accepts the automatically generated self-signed certificate. Use identity verification when the certificate file is available:

```php
use FoxyDB\TlsOptions;

$db = Client::connect(
    host: '127.0.0.1',
    port: 2002,
    username: 'root',
    password: 'your-password',
    tlsOptions: new TlsOptions(
        mode: 'VERIFY_IDENTITY',
        caFile: __DIR__ . '/data/tls/server.crt',
    ),
);
```

TLS modes are `DISABLED`, `PREFERRED`, `REQUIRED`, `VERIFY_CA`, and `VERIFY_IDENTITY`. The daemon itself is TLS-only, so `DISABLED` cannot connect. `PREFERRED` is provided for client compatibility with other endpoints and should not be used for administration.

## System Database

The server automatically creates and selects the `foxydb` database after login. It contains:

- `users_schema`: usernames, immutable server-generated account UUIDs, password hashes, account state, and timestamps
- `privileges`: per-account database, table, and privilege grants
- `config_schema`: persistent server configuration records
- `performance_schema`: performance and lifecycle metrics
- `sys_config`: runtime storage settings and descriptions

`SYS_config` from SQL is normalized to `sys_config` because FoxyDB identifiers are case-insensitive.

A daemon-private initialization marker prevents FoxyDB from recreating root or restoring revoked root privileges on later starts. The marker contains no username, password, hash, or privilege. All login information comes only from `users_schema` and `privileges`.

Passwords are stored with PHP's strongest available password hashing algorithm. To change the root password, bind a new hash rather than plaintext:

```php
$newHash = password_hash('new-password', PASSWORD_DEFAULT);
$db->query('USE foxydb');
$db->query(
    'UPDATE users_schema SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
    [$newHash, 'root'],
);
```

Root receives `ALL` on `*.*`. Other accounts require rows in `privileges`. Grants include both `username` and the matching `account_id`, so deleting and recreating a username does not inherit stale access. Clients cannot insert or update `users_schema.account_id`. Supported authorization names are `ALL`, `SHOW`, `CONNECT`, `CREATE`, `DROP`, `INDEX`, `SELECT`, `INSERT`, `UPDATE`, `DELETE`, and `ALTER`. A grant can use `*` for its database or table. System database and table deletion is blocked.

## System Variables

Global variables are persisted in `foxydb.sys_config`. Session overrides last until the connection closes. `SET GLOBAL` requires `ALTER` on `foxydb.sys_config`; ordinary authenticated sessions can change variables that support session scope. Managed `sys_config` rows reject direct `INSERT`, `UPDATE`, and `DELETE` so validation and live application cannot be bypassed.

```sql
SHOW VARIABLES;
SHOW GLOBAL VARIABLES LIKE 'max_%';
SET SESSION sort_buffer_size = '8M';
SET GLOBAL max_allowed_packet = 16777216;
```

Supported variables:

| Variable | Scope | Runtime effect |
| --- | --- | --- |
| `foxydb_buffer_pool_size` | Global | Decoded row cache size |
| `max_heap_table_size` | Global, session | In-memory operation staging limit |
| `sort_buffer_size` | Global, session | `ORDER BY` memory limit |
| `join_buffer_size` | Global, session | Reserved for join execution |
| `query_cache_size` | Global | Process-wide SELECT cache size |
| `tmp_table_size` | Global, session | Temporary result and mutation limit |
| `max_allowed_packet` | Global, session | Maximum framed protocol packet |
| `connect_timeout` | Global | TLS and authentication deadline |
| `wait_timeout` | Global, session | Non-interactive idle timeout |
| `interactive_timeout` | Global, session | Interactive idle timeout |
| `max_connect_errors` | Global | Failed connections allowed per address in five minutes |
| `skip_name_resolve` | Global | Enables or disables reverse DNS lookups |
| `thread_cache_size` | Global | Reusable session-object cache size |
| `thread_stack` | Global, read-only | Compatibility value; PHP owns the stack |
| `thread_handling` | Global, read-only | Reports the `event-loop` scheduler |
| `system_time_zone` | Global | Server-side date and log timezone |

Byte values accept integer bytes or `K`, `M`, `G`, and `T` suffixes. Global cache-size changes take effect immediately. Query-cache entries are account, database, SQL, parameter, session-variable, and source-table-revision specific. Source-table writes invalidate only dependent results; global runtime-setting changes clear the complete result cache.

The hot query path uses bounded parsed-statement, authorization, table-handle, decoded-row, index-lookup, and result caches. Authorization caches are revision-checked against `users_schema` and `privileges`, so account and grant changes take effect immediately. Result-cache keys include the source table revision, allowing writes to unrelated tables to retain valid cached reads. Row and index cache keys include immutable table and generation identity, and old entries remain bounded by LRU eviction.

FoxyDB permits one `StorageEngine` owner per data directory. A second daemon or embedded engine fails with `STORAGE_IN_USE`; this keeps process-local cache revisions coherent and prevents concurrent recovery or mutation of the same files.

## Logs

The daemon creates these JSON-lines files in `data/logs` by default:

- `general.log`: server lifecycle, connections, and query outcomes
- `error.log`: initialization, socket, and unexpected internal failures
- `audit.log`: accepted connections, TLS, authentication, queries, and disconnects
- `slow.log`: queries meeting `FOXYDB_SLOW_QUERY_MS`

Each record contains `timestamp`, `channel`, `level`, `event`, `pid`, and `context`. Logs rotate by size to `.1`, `.2`, and later archives. Parameter values are never logged. SQL string and binary literals, comments, password assignments, and sensitive context keys are redacted. Log files are created with owner-only permissions where the platform supports POSIX modes.

## Secure Installation

Run the secure installation tool after the first daemon startup:

```console
php bin/foxydb_secure_installation.php --password \
    --ssl-mode=VERIFY_IDENTITY --ssl-ca=data/tls/server.crt
```

Bare `--password` prompts without echo. Avoid `--password=value` in normal use because process arguments can be inspected. The tool never writes plaintext passwords to daemon configuration or environment variables.

Recommended noninteractive hardening:

```console
php bin/foxydb_secure_installation.php --no-defaults --password=root \
    --ssl-mode=VERIFY_IDENTITY --ssl-ca=data/tls/server.crt --use-default
```

`--use-default` removes orphan privileges, removes privileges for the `test` database, drops that database, generates a strong random account password, records TLS state in `sys_config`, and prints the generated password once. The completion record is written only after the password update succeeds.

Supported options:

```text
--defaults-extra-file       --defaults-file
--defaults-group-suffix     --help
--host                      --no-defaults
--password                  --port
--print-defaults            --protocol
--socket                    --ssl-ca
--ssl-capath                --ssl-cert
--ssl-cipher                --ssl-crl
--ssl-crlpath               --ssl-fips-mode
--ssl-key                   --ssl-mode
--ssl-session-data          --ssl-session-data-continue-on-failed-reuse
--tls-ciphersuites          --tls-version
--use-default               --user
```

`--protocol=TCP` and `--protocol=TLS` use the TLS TCP daemon. `SOCKET` is parsed for command compatibility but reports unsupported because this server exposes the required TCP port. PHP streams cannot enforce CRL or FIPS provider settings, so non-empty CRL options and FIPS modes other than `OFF` fail closed instead of being ignored.

`--ssl-session-data` stores binary FoxyDB peer-certificate pin data, negotiated protocol, and cipher details. It does not store a password or private TLS session secret. A changed peer certificate fails unless `--ssl-session-data-continue-on-failed-reuse` is explicitly enabled.

Defaults files use `[client]` and `[foxydb_secure_installation]` INI groups. `--defaults-group-suffix=_name` also loads `[client_name]` and `[foxydb_secure_installation_name]`. Command-line values override file values. Do not place passwords in defaults files.

```ini
[client]
host = 127.0.0.1
port = 2002
user = root
ssl_mode = VERIFY_IDENTITY
ssl_ca = data/tls/server.crt

[foxydb_secure_installation]
tls_version = TLSv1.2,TLSv1.3
```

## Chunk Upload

Large parameters can be uploaded to a temporary disk-backed transfer, then referenced by a query:

```php
$blob = $db->uploadFile(__DIR__ . '/archive.bin', 'binary');
$db->query('INSERT INTO files (name, body) VALUES (?, ?)', ['archive.bin', $blob]);
```

Use format `binary` for `BLOB` and `BINARY`. Use format `utf8` for `TEXT` and `LONGTEXT`. UTF-8 uploads are validated before they become query parameters. Completed transfers are single-use and are removed after the query.

## SQL

Supported statements:

```sql
CREATE DATABASE [IF NOT EXISTS] name;
DROP DATABASE [IF EXISTS] name;
USE name;
SHOW DATABASES;
SHOW TABLES [FROM database];
SHOW [GLOBAL | SESSION] VARIABLES [LIKE pattern];
SET [GLOBAL | SESSION] variable = value;

CREATE TABLE [IF NOT EXISTS] name (...);
DROP TABLE [IF EXISTS] name;
TRUNCATE TABLE name;
DESCRIBE name;
COMPACT TABLE name;

CREATE [UNIQUE] INDEX [IF NOT EXISTS] name ON table (column, ...);
DROP INDEX [IF EXISTS] name ON table;
SHOW INDEXES FROM table;

INSERT INTO table [(column, ...)] VALUES (...), (...);
SELECT columns FROM table
    [WHERE expression]
    [ORDER BY column [ASC|DESC], ...]
    [LIMIT count [OFFSET offset]];
UPDATE table SET column = value [, ...] [WHERE expression];
DELETE FROM table [WHERE expression];
```

`WHERE` supports `AND`, `OR`, `NOT`, comparison operators, `IS NULL`, `IS NOT NULL`, `IN`, `NOT IN`, `LIKE`, and `NOT LIKE`. In `LIKE` patterns, `%` matches any sequence, `_` matches one character, and a backslash escapes either wildcard. SQL NULL uses three-valued predicate behavior. `COUNT(*)` is supported without grouping.

Positional `?` and named `:name` parameters are supported. Parameter values are never interpolated into SQL text.

Column examples:

```sql
CREATE TABLE events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    external_id UUID NOT NULL UNIQUE DEFAULT UUID(),
    label VARCHAR(200) NOT NULL,
    payload BLOB,
    description LONGTEXT,
    score DOUBLE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    happened_at DATETIME,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_active_created (active, created_at)
);
```

`BINARY(n)` is fixed width and zero-pads shorter inline values. `TIMESTAMP` is normalized to UTC. `DATETIME` stores a timezone-free date and time. UUID values are validated and stored in lowercase. `JSON` columns validate and canonicalize their input; large JSON documents use the deduplicated chunk store like `LONGTEXT`.

`JSON_EXTRACT(column, path)` evaluates a JSON path such as `$.status`, `$.meta.rating`, or `$.items[2]` (bracket forms like `$['status']` are also accepted). It can appear in `WHERE`, `HAVING`, and `SELECT` projections, and returns `NULL` when the path does not exist or the operand is not valid JSON. Use `JSON_EXTRACT` in `SELECT` to project a JSON member, or in `WHERE` to filter on extracted values:

```sql
SELECT JSON_EXTRACT(doc, '$.profile.email') AS email
FROM contacts
WHERE JSON_EXTRACT(doc, '$.status') = 'active';
```

Indexes have a maximum encoded key size of 4096 bytes. `TEXT`, `LONGTEXT`, `BLOB`, and `JSON` cannot be indexed. Equality predicates can use a complete matching hash index. Range and pattern predicates use bounded-memory table scans.

## Wire Protocol

FoxyDB protocol version `2` starts after TLS negotiation. Version `1` JSON frames are rejected rather than auto-detected or downgraded. Every frame begins with this 16-byte network-order header:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| `0` | `4` | Magic `FXDB` |
| `4` | `1` | Version `2` |
| `5` | `1` | Frame kind `1` for a typed map |
| `6` | `2` | Flags, currently zero |
| `8` | `4` | Payload byte length, excluding the 16-byte header |
| `12` | `4` | CRC32C of header bytes `0..11` plus payload |

The payload contains one non-empty map. Multibyte lengths and integers use big-endian order:

| Tag | Type | Encoding |
| ---: | --- | --- |
| `0` | Null | No body |
| `1`, `2` | False, true | No body |
| `3` | Signed integer | 8-byte two's-complement integer |
| `4` | Float | 8-byte finite IEEE-754 double |
| `5` | Text | 4-byte length plus UTF-8 bytes |
| `6` | Binary | 4-byte length plus raw bytes |
| `7` | List | 4-byte count plus typed values |
| `8` | Map | 4-byte count plus length-prefixed UTF-8 keys and typed values |

The codec requires 64-bit PHP and limits one payload to 16 MiB, nesting to 64 levels, one container to 65,536 entries, aggregate entries to 100,000, and map keys to 1,024 bytes. Values up to the separate 1 GiB upload limit use bounded chunk frames. Empty maps are non-canonical; duplicate, empty, numeric, or invalid UTF-8 map keys are rejected. Unknown versions, kinds, flags, tags, trailing bytes, invalid checksums, and oversized declarations are fatal protocol errors.

Messages retain semantic `type` fields such as `hello`, `auth`, `query`, `result`, `result_start`, `row`, `result_end`, `error`, `chunk_start`, `chunk_data`, `chunk_end`, and `chunk_abort`. Query maps carry `id`, `sql`, and `params`; authentication maps carry `id`, `username`, `password`, and `interactive`. Request IDs are non-negative signed integers. The `hello.limits` map advertises `frame_payload_bytes` and `chunk_payload_bytes`; clients must use the lower of their local limits and these server limits.

Command responses use one `result` frame. Row queries use `result_start`, zero or more `row` frames, and `result_end`. Large values use `$chunk` declarations followed by chunk frames. Inline binary parameters, result values, and `chunk_data.data` use tag `6` raw bytes directly, with no JSON or Base64 expansion.

Every TCP connection must authenticate before sending another request.

## Storage

Each table contains:

- `meta.fdb`: versioned, checksummed binary schema, indexes, and active generation
- `sequence.fdb`: checksummed row and auto-increment sequences
- `gNNNNNN/rows.fdb`: append-only row records
- `gNNNNNN/rows.fdx`: fixed 24-byte row slots for direct lookup
- `gNNNNNN/indexes/`: 256-way on-disk hash index buckets
- `chunks/`: SHA-256 addressed large-value chunks
- `row.journal.fdb` and `dirty`: binary redo metadata and a transient recovery marker

Binary metadata starts with a 16-byte `FXMD` header containing version, flags, payload length, and a four-byte CRC32. The payload uses typed TLV values for maps, lists, strings, integers, doubles, booleans, and null. Metadata is limited to 4 MiB and 100,000 aggregate collection items. Schema and journal metadata do not use JSON or PHP serialization.

Writes append the new record first, synchronize it when sync writes are enabled, publish a redo slot, then update indexes. A dirty index is rebuilt from row slots before another operation proceeds. Compaction copies active records into a new generation and atomically changes the metadata pointer. One prior generation is retained for fallback until a later generation switch.

On Unix, synchronized atomic writes also attempt to synchronize the parent directory after replacement. Standard PHP on Windows does not expose directory synchronization, so FoxyDB relies on Windows file replacement durability there.

Large values are split into configurable chunks. Identical chunk content is stored once. Compaction removes dead row versions and garbage-collects chunks that are no longer referenced by the active and fallback data.

Table and catalog locks are stored separately from removable table directories. Reads release table locks between bounded batches, so an abandoned result iterator does not indefinitely block writes.

## Configuration

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `FOXYDB_HOST` | `127.0.0.1` | TLS TCP bind host |
| `FOXYDB_PORT` | `2002` | TCP port |
| `FOXYDB_DATA_DIR` | `server/data` | Persistent data directory |
| `FOXYDB_MAX_FRAME_BYTES` | `8388608` | Initial `max_allowed_packet` value |
| `FOXYDB_CHUNK_BYTES` | `1048576` | Stored and transferred chunk size |
| `FOXYDB_INLINE_VALUE_BYTES` | `65536` | Large-value chunking threshold |
| `FOXYDB_MAX_MATERIALIZED_BYTES` | `67108864` | Initial heap and temporary-table limits |
| `FOXYDB_MAX_RESULT_ROWS` | `1000000` | Result and mutation row bound |
| `FOXYDB_IDLE_TIMEOUT` | `300` | Initial interactive and non-interactive idle timeout |
| `FOXYDB_MAX_CONNECTIONS` | `256` | Connected client limit |
| `FOXYDB_MAX_TRANSFERS` | `8` | Active transfers per client |
| `FOXYDB_MAX_GLOBAL_TRANSFERS` | `64` | Active transfers for the server |
| `FOXYDB_MAX_UPLOAD_BYTES` | `1073741824` | Per-client and server upload reservation |
| `FOXYDB_SYNC_WRITES` | `true` | Flush durable files with `fsync` when available |
| `FOXYDB_LOG_DIR` | `data/logs` | Structured log directory |
| `FOXYDB_LOG_MAX_BYTES` | `10485760` | Bytes per active log before rotation |
| `FOXYDB_LOG_MAX_FILES` | `5` | Rotated archives retained per channel |
| `FOXYDB_SLOW_QUERY_MS` | `1000` | Slow-query threshold in milliseconds; `0` logs every query |

Disabling sync writes improves throughput but weakens power-loss durability.

## Performance

Use the included repeatable in-process benchmark to compare changes on the target host:

```console
php tests/benchmark.php 1000
```

It reports average microseconds per uncached indexed lookup, uncached `LIKE` scan, and result-cache hit, plus cache statistics. The benchmark disables durable synchronization only for its temporary fixture; production durability remains controlled by `FOXYDB_SYNC_WRITES`.

For predictable low latency, use parameterized indexed predicates, keep frequently read data within `foxydb_buffer_pool_size`, size `query_cache_size` for repeated reads, and use finite `LIMIT` values. `LIMIT 0` avoids row scans, unfiltered `COUNT(*)` scans only checksummed row slots, constant `LIKE` patterns are compiled once per execution, and result frames are written in bounded batches.

## Tests

Run all storage, SQL, recovery, and live TCP tests:

```console
php tests/run.php
```

The TCP test starts a real authenticated TLS FoxyDB child process on an available local port. It verifies certificate identity, session pinning, privilege enforcement, secure installation password rotation, and a chunked binary round trip.

## Current Boundaries

- There is no transaction API, join engine, grouping, subquery support, replication, or `ALTER TABLE` yet.
- Constraint and value errors are prevalidated for multi-row inserts and updates. An operating-system or disk failure during a multi-row commit can still leave a committed prefix, with each published row individually recoverable.
- Query execution is synchronous in one server process. Idle sockets are multiplexed, but one expensive query or slow network peer can delay other clients.
- Hash indexes accelerate equality lookups. Ordered range indexes are not implemented.
- Schema identifiers are ASCII and case-insensitive after normalization.
- Privileges are exact string grants with `*` wildcards. Roles and row-level policies are not implemented.
