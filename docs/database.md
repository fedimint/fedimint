# Database

Fedimint uses a simple key-value store as its database. In theory any such KV store with the following features can be used:

* insert, update, delete actions
* transactions
* key prefix search

We currently use RocksDB on both the client and the server.

## Server DB Layout
The database is logically partitioned based on the module instance id of the module. Each module's keyspace is split up based on prefixing. Each prefix within a module identifies a logical entity.
Entity prefixes between modules can overlap because they are logically partitioned by the module instance id. The key value pairs that belong to consensus do not belong to any specific module, so they are
not prepended with a module prefix. Below is the format for prefixes within a module:

<GLOBAL PREFIX BYTE><2 BYTE MODULE ID><ENTITY PREFIX>

Example for the Mint Module: 0xFF 0x00 0x00 0x10
In the above example, the module instance id = 0 and the entity it identifies is a NoteNonce. 0xFF is the global prefix byte that identifies this as module data.

Example for consensus data: 0x01
In the above example, because the consensus data does not apply to any specific module, the global prefix byte and module instance id prefixes are missing.

The client is not currently modularized, so nothing is prepended to the below prefixes.


### Consensus

| Name                | Entity Prefix | Key                              | Value                         |
|---------------------|---------------|----------------------------------|-------------------------------|
| ProposedTransaction |     `0x01`    | Transaction ID (sha256, 32bytes) | Transaction                   |
| AcceptedTransaction |     `0x02`    | Transaction ID (sha256, 32bytes) | AcceptedTransaction           |
| DropPeer            |     `0x03`    | Peer ID (u16)                    | None                          |
| RejectedTransaction |     `0x04`    | Transaction ID (sha256, 32bytes) | Reason for rejection (string) |
| EpochHistory        |     `0x05`    | Epoch ID (u16)                   | Epoch history record          |
| LastEpoch           |     `0x06`    | none                             | Epoch ID (u16)                |

### Mint

| Name               | Entity Prefix | Key                                                 | Value                 |
|--------------------|---------------|-----------------------------------------------------|-----------------------|
| NoteNonce          |     `0x10`    | note nonce (unknown bytes, bincode magic currently) | none                  |
| ProposedPartialSig |     `0x11`    | mint outpoint (40 bytes)                            | blind signature share |
| ReceivedPartialSig |     `0x12`    | mint outpoint (40 bytes), peer (2 bytes)            | blind signature share |
| OutputOutcome      |     `0x13`    | mint outpoint (40 bytes)                            | blind signature       |
| MintAuditItem      |     `0x14`    | AuditItem                                           | Amount                |
| EcashBackup        |     `0x15`    | backup id (public key)                              | ts + encrypted data   |

### Wallet

| Name                  | Entity Prefix | Key                                       | Value                                     |
|-----------------------|---------------|-------------------------------------------|-------------------------------------------|
| BlockHash             |     `0x30`    | block hash (32 bytes)                     | none                                      |
| Utxo                  |     `0x31`    | OutPoint (32 bytes txid + 4 bytes output) | data necessary for spending               |
| RoundConsensus        |     `0x32`    | none                                      | block height, fee rate, randomness beacon |
| UnsignedTransaction   |     `0x34`    | bitcoin tx id (32 bytes)                  | PSBT                                      |
| PendingTransaction    |     `0x35`    | bitcoin tx id (32 bytes)                  | consensus encoded tx, change tweak        |
| PegOutTxSigCi         |     `0x36`    | bitcoin tx id (32 bytes)                  | list of signatures (1 per input)          |
| PegOutBitcoinOutPoint |     `0x37`    | Fedimint out point                        | Outpoint                                  |

### Lightning

| Name                     | Entity Prefix | Key                                 | Value                        |
|--------------------------|---------------|-------------------------------------|------------------------------|
| Contract                 |     `0x40`    | ContractId                          | `ContractAccount`            |
| Offer                    |     `0x41`    | payment hash (sha256)               | `IncomingContractOffer`      |
| ProposedDecryptionShare  |     `0x42`    | contract id (sha256)                | `DecryptionShare`            |
| AgreedDecryptionShare    |     `0x43`    | contract id (sha256), peer id (u16) | `DecryptionShare`            |
| ContractUpdate           |     `0x44`    | out point (sha256, out idx)         | `fedimint_ln::OutputOutcome` |
| LightningGateway         |     `0x45`    | Node Pubkey (PublicKey)             | `LightningGateway`           |

## Client DB Layout
| Name                    | Entity Prefix | Key                                | Value                        |
|-------------------------|---------------|------------------------------------|------------------------------|
| ClientSecret            |     `0x29`    | none                               | `ClientSecret`               |

### LightningClient
| Name                    | Entity Prefix | Key                         | Value                        |
|-------------------------|---------------|------------------------------------|------------------------------|
| OutoingPayment          |     `0x23`    | contract id (sha256 payment hash)  | `OutgoingContractData`       |
| OutgoingPaymentClaim    |     `0x24`    | contract id (sha256)               | `Transaction`                |
| OutgoingContractAccount |     `0x25`    | contract id (sha256)               | `OutgoingContractAccount`    |
| ConfirmedInvoice        |     `0x26`    | contract id (sha256 payment hash)  | `ConfirmedInvoice`           |
| LightingGateway         |     `0x28`    | none                               | `LightningGateway`           |
| LastECashNoteIndex      |     `0x2a`    | none                               | `u64`                        |

### MintClient
| Name                   | Entity Prefix | Key                                | Value                        |
|------------------------|---------------|------------------------------------|------------------------------|
| Note                   |     `0x20`    | amount (8 bytes), nonce (32 bytes) | `SpendableNote`              |
| OutputFinalizationData |     `0x21`    | issuance_id (32 bytes)             | `NoteIssuanceRequests`       |
| PendingNotes           |     `0x27`    | mint tx id (sha256 payment hash)   | `TieredMulti<SpendableNote>` |
| NotesPerDenomination   |     `0x2b`    | determines how many notes to issue | `u16`                        |

### WalletClient
| Name                        | Entity Prefix | Key      | Value      |
|-----------------------------|---------------|----------|------------|
| PegIn                       | `0x22`        | `Script` | `[u8; 32]` |
| Next tweak derivation index | `0x2c`        | `()`      | `u64`     |

## State Machine Client DB Layout
### Executor

| Name          | Entity Prefix | Key     | Value                                       |
|---------------|---------------|---------|---------------------------------------------|
| ActiveState   | `0xa1`        | `State` | Creation time                               |
| InactiveState | `0xa2`        | `State` | Creation time and time of becoming inactive |

## Database Transactions
In Fedimint, all interactions with the database use a database transaction. Database transactions are a nice abstraction
for accessing the database in an atomic, consistent, and isolated way. Underneath, Fedimint uses RocksDb's optimistic transactions
which means database transactions are allowed to read and write to the database concurrently. If there are two concurrent transactions
that modify the same key, RocksDb's optimistic transactions have a mechanism for detecting this, which will cause the transaction that
commits second to fail. 

Fedimint has defined a number of different structs for implementing the necessary functionality for database transactions. These structs
follow the [adapter pattern](https://en.wikipedia.org/wiki/Adapter_pattern) to wrap and isolate the features. Below is an explanation of
each interface/struct.

## Migrations
In order to avoid breaking changes, `fedimintd`, `gatewayd`, and the client must know of the structure of the data written to disk. If a code upgrade
has occurred, it is possible that the new version of the code expects the data written to disk to be structured differently. When this happens, a database
migration must occur to maintain backwards compatibility. Migrations are defined on a per-module basis in the `get_database_migrations` function and applied
using `apply_migrations`.

Since introducing a database breaking change is easy (just modifying a struct), tests have been introduced to catch DB breaking changes. `prepare_migration_snapshots` will prepare a database backup of dummy data for a module. `test_migrations` will try to read from this database backup. If the
structure of the data has changed and the backup cannot be reading, this test will fail.

There are sometimes when making a DB breaking change is intentional. In that case, to fix the migration tests, `prepare_migration_snapshot` needs to be updated
to reflect the new structure of the data. Then, the db/ folder at the root of the repository needs to be deleted. Then `cargo test prepare_migration_snapshot` can
be run to re-generate the database backup. `test_migrations` will need to be updated to read the newly added/modified data.

### Interfaces
 - **ISingleUseDatabaseTransaction** - The interface that each adapter struct implements. The main difference with this interface is that commit_tx
does not take self by move.
 - **IDatabaseTransaction** - The interface that each individual database must implement, such as `MemTransaction`, `RocksDbTransaction`, and `SqliteDbTransaction`.

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
 - **SqliteDbTransaction** - Base implementation of a Sqlite database transaction.

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
    SingleUseDatabaseTransaction --|> SqliteDbTransaction
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
    class SqliteDbTransaction{
        <<interface IDatabaseTransaction>>
        Transaction tx
    }
