# Database

Fedimint uses a simple key-value store as its database. In theory any such KV store with the following features can be used:

* insert, update, delete actions
* transactions
* key prefix search
* optimistic transactions

We currently use RocksDB on both the client and the server.

## Server DB Layout
The database is logically partitioned based on the module instance id of the module. Each module's keyspace is split up based on prefixing. Each prefix within a module identifies a logical entity.
Entity prefixes between modules can overlap because they are logically partitioned by the module instance id. The key value pairs that belong to consensus do not belong to any specific module, so they are
not prepended with a module prefix. Below is the format for prefixes within a module:

<GLOBAL PREFIX BYTE><2 BYTE MODULE ID><ENTITY PREFIX>

Example for the Mint Module: 0xFF 0x00 0x00 0x10
In the above example, the module instance id = 0 and the entity it identifies is a NoteNonce, because it uses the 0x10 byte. 0xFF is the global prefix byte that identifies this as module data.

Example for consensus data: 0x01
In the above example, because the consensus data does not apply to any specific module, the global prefix byte and module instance id prefixes are missing.

The client uses the same isolation mechanism as `fedimintd` to store data for each module.


## Database Transactions
In Fedimint, all interactions with the database use a database transaction. Database transactions are an abstraction
for accessing the database in an atomic, consistent, and isolated way. Underneath, Fedimint uses RocksDb's optimistic transactions
which means database transactions are allowed to read and write to the database concurrently. If there are two concurrent transactions
that modify the same key, RocksDb's optimistic transactions will detect this "write-write" conflict and cause the transaction that
commits second to fail. 

Fedimint has defined a number of different structs for implementing the necessary functionality for database transactions. These structs
follow the [adapter pattern](https://en.wikipedia.org/wiki/Adapter_pattern) to wrap and isolate the features. At the bottom is an explanation of
each interface/struct.

## Migrations
In order to avoid breaking changes, `fedimintd`, `gatewayd`, and the client must know of the structure of the data written to disk. If a code upgrade
has occurred, it is possible that the new version of the code expects the data written to disk to be structured differently. When this happens, a database
migration must occur to maintain backwards compatibility. Migrations are defined on a per-module basis in the `get_database_migrations` function and applied
using `apply_migrations`.

Since introducing a database breaking change is easy (just modifying a struct), tests have been introduced to catch DB breaking changes. `just prepare_db_migration_snapshots` will prepare a database backup of dummy data for a module. `test_migrations` will try to read from this database backup. If the
structure of the data has changed and the backup cannot be reading, this test will fail.

There are some times when making a DB breaking change (not backwards compatible) is intentional. In that case, to fix the migration tests, `just prepare_db_migration_snapshot` needs to be updated
to reflect the new structure of the data. Then, the db/ folder at the root of the repository needs to be deleted. Then `just prepare_db_migration_snapshot` can
be run to re-generate the database backup. `test_migrations` will need to be updated to read the newly added/modified data.

### Interfaces

 - `IRawDatabase` and `IRawDatabaseTransaction` - The interfaces raw database crates implement.
 - `IDatabase` and `IDatabaseTransaction` - The interfaces including key subscribe & notify functionality, added on top of databases.
 - `IDatabaseTransactionOps` and `IDatabaseTransactionCoreOps` - The interfaces of database transaction operations
 - `IDatabaseTransactionOpsCoreTyped` - Like `IDatabaseTransactionOps` but with typed keys and values. Implemented generically over everything implements `IDatabaseTransactionOps`.

### Structs
#### Public

 - `Database` and `DatabaseTransaction` - Public facing newtypes over `IDatabase` and `IDatabaseTransaction` that also holds `decoders` and minor helper logic.
 - `DatabaseTransactionRef` - A logical reference to `DatabaseTransaction` that does not expose the commit operation.

#### Internal

 - `BaseDatabase` and `BaseDatabaseTransaction` - Adapter implementing `IDatabase` for `IRawDatabase`
 - `PrefixDatabase` and `PrefixDatabaseTransaction` - Adapter over `IDatabase` and `IDatabaseTransaction` implementing key prefix handling to provide database partitioning/isolation.

#### Raw Implementations

 - `MemDatabase` and `MemDatabaseTransaction` - Base implementation of an in-memory database transaction.
 - `RocksDbDatabase` and `RocksDbDatabaseTransaction` - Base implementation of a Rocksdb database. Uses optimistic transaction internally.
 - `RocksDbReadOnly` and `RocksDbReadOnlyTransaction` - Base implementation of a Rocksdb read-only database. Will panic on writes.

```mermaid
classDiagram
    DatabaseTransaction ..* IDatabaseTransaction : wraps
    DatabaseTransactionRef ..* DatabaseTransaction : wraps
    PrefixDatabaseTransaction ..|> IDatabaseTransaction : implements
    PrefixDatabaseTransaction ..* IDatabaseTransaction : wraps
    BaseDatabaseTransaction ..|> IDatabaseTransaction : implements
    BaseDatabaseTransaction ..* IRawDatabaseTransaction : wraps
    MemTransaction ..|> IRawDatabaseTransaction : implements
    RocksDbTransaction ..|> IRawDatabaseTransaction : implements

    DatabaseTransactionRef ..|> IDatabaseTransactionOpsCore : implements
    DatabaseTransaction ..|> IDatabaseTransactionOpsCore : implements
    BaseDatabaseTransaction ..|> IDatabaseTransactionOpsCore : implements
    PrefixDatabaseTransaction ..|> IDatabaseTransactionOpsCore : implements
    MemTransaction ..|> IDatabaseTransactionOpsCore : implements
    RocksDbTransaction ..|> IDatabaseTransactionOpsCore : implements

    class IDatabaseTransactionOpsCore {
      <<interface>>
      + raw_insert_bytes()
      + raw_get_bytes()
      + raw_remove()
    }

    class IDatabaseTransaction {
      <<interface>>
      + commit_tx()
    }

    class DatabaseTransaction {
      - IDatabaseTransaction
    }

    class DatabaseTransactionRef {
      - &DatabaseTransaction
    }

    class PrefixDatabaseTransaction {
      - IDatabaseTransaction
    }

    class BaseDatabaseTransaction {
      - IRawDatabaseTransaction
    }

    class RocksDbTransaction {
    }

    class MemTransaction {
    }
