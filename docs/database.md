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
 - **ISingleUseDatabaseTransaction** - The interface that each adapter struct implements. The main difference with this interface is that commit_tx
does not take self by move.
 - **IDatabaseTransaction** - The interface that each individual database must implement, such as `MemTransaction` and `RocksDbTransaction`.

### Structs
#### Public
 - **DatabaseTransaction** - Public facing struct that can do atomic database transactions across modules.
 - **ModuleDatabaseTransaction** - Public facing struct that can only access the namespace of the module inside the database. This database transaction cannot
commit and the lifetime of the transaction is always managed by a higher layer. `ModuleDatabaseTransaction` can be created by calling `with_module_prefix` on
`DatabaseTransaction`.

#### Internal
 - **IsolatedDatabaseTransaction** - Internal wrapper struct that implements the isolation mechanism for preventing modules from reading/writing outside their 
database namespace.
 - **CommittableIsolatedDatabaseTransaction** - Internal wrapper struct that wraps `IsolatedDatabaseTransaction`, but holds onto the transaction instead of holding
onto a reference. This struct is always wrapped inside `DatabaseTransaction` and is used to expose the full interface to the developer (i.e `commit_tx`), but restrict the transaction
from accessing keys/values outside of its database namespace.
 - **NotifyingTransaction** - Internal wrapper struct that implements the notification mechanism when values of specified keys change.
 - **SingleUseDatabaseTransaction** - Internal wrapper struct that holds an `Option<Tx>` which allows `commit_tx` to take `self` as a reference instead of by move.

#### Base Implementations
 - **MemTransaction** - Base implementation of a memory database transaction.
 - **RocksDbTransaction** - Base implementation of a RocksDb database transaction. Uses optimistic transaction internally.

```mermaid
classDiagram
    DatabaseTransaction --|> NotifyingTransaction
    NotifyingTransaction --|> SingleUseDatabaseTransaction
    DatabaseTransaction --|> CommittableIsolatedDatabaseTransaction : new_module_tx
    CommittableIsolatedDatabaseTransaction --|> IsolatedDatabaseTransaction
    DatabaseTransaction --|> ModuleDatabaseTransaction : with_module_prefix
    ModuleDatabaseTransaction --|> IsolatedDatabaseTransaction
    IsolatedDatabaseTransaction --|> NotifyingTransaction
    SingleUseDatabaseTransaction --|> RocksDbTransaction
    SingleUseDatabaseTransaction --|> MemTransaction
    class DatabaseTransaction{
      Box ISingleUseDatabaseTransaction tx
      ModuleDecoderRegistry decoders
      CommitTracker commit_tracker
      with_module_prefix()
      new_module_tx()
      get_value()
      insert_entry()
      commit_tx()
    }
    class CommittableIsolatedDatabaseTransaction{
        <<interface ISingleUseDatabaseTransaction>>
        Box ISingleUseDatabaseTransaction tx
        ModuleInstanceId prefix
    }
    class ModuleDatabaseTransaction{
      &ISingleUseDatabaseTransaction tx_ref
      &ModuleDecoderRegistry decoder_ref
      &CommitTracker commit_tracker_ref
      get_value()
      insert_entry()
    }
    class NotifyingTransaction{
        <<interface ISingleUseDatabaseTransaction>>
        Box ISingleUseDatabaseTransaction
    }
    class SingleUseDatabaseTransaction{
        <<interface ISingleUseDatabaseTransaction>>
        Option tx
    }
    class IsolatedDatabaseTransaction{
        <<interface ISingleUseDatabaseTransaction>>
        &ISingleUseDatabaseTransaction
    }
    class RocksDbTransaction{
        <<interface IDatabaseTransaction>>
        Transaction optimistic_tx
    }
    class MemTransaction{
        <<interface IDatabaseTransaction>>
        BTreeMap tx_data
    }
