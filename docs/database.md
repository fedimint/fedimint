# Database

MiniMint uses a simple key-value store as its database. In theory any such KV store with the following features can be used:

* insert, update, delete actions
* transactions
* key prefix search

In practice we use [sled](https://docs.rs/sled/) as it is a native rust database and seems sufficiently performant.

## Server DB Layout
The Database is split into different key spaces based on prefixing that can be understood as different tables (each "table's" content can be retrieved using prefix search). There are three general prefix ranges:

* `0x00-0x0A`: consensus
* `0x10-0x1A`: mint
* `0x20-0x2A`: client (different db, but to be sure)
* `0x30-0x3A`: wallet
* `0x40-0x4A`: lightning

### Consensus

| Name                  | Prefix | Key                              | Value                           |
|-----------------------|--------|----------------------------------|---------------------------------|
| Pending Transactions  | `0x01`   | Transaction ID (sha256, 32bytes) | Transaction                     |
| Accepted Transactions | `0x02`   | Transaction ID (sha256, 32bytes) | Confirmation epoch, Transaction |

### Mint

| Name                              | Prefix | Key                                                 | Value                 |
|-----------------------------------|--------|-----------------------------------------------------|-----------------------|
| Used Coins                        | `0x10`   | coin nonce (unknown bytes, bincode magic currently) | none                  |
| Proposed signature shares         | `0x11`   | mint outpoint (40 bytes)                            | blind signature share |
| Received signature shares         | `0x12`   | mint outpoint (40 bytes), peer (2 bytes)            | blind signature share |
| Finalized (still blind) signature | `0x13`   | mint outpoint (40 bytes)                            | blind signature       |

### Wallet

| Name                      | Prefix | Key                                       | Value                                     |
|---------------------------|--------|-------------------------------------------|-------------------------------------------|
| Blocks                    | `0x30`   | block hash (32 bytes)                     | block height                              |
| Our UTXOs                 | `0x31`   | OutPoint (32 bytes txid + 4 bytes output) | data necessary for spending               |
| Round Consensus           | `0x32`   | none                                      | block height, fee rate, randomness beacon |
| Unsigned transaction      | `0x34`   | bitcoin tx id (32 bytes)                  | PSBT                                      |
| Pending transaction       | `0x35`   | bitcoin tx id (32 bytes)                  | consensus encoded tx, change tweak        |
| Pending Peg Out Signature | `0x36`   | bitcoin tx id (32 bytes)                  | list of signatures (1 per input)          |

### Lightning

| Name                             | Prefix | Key                                 | Value                        |
|----------------------------------|--------|-------------------------------------|------------------------------|
| Offers                           | `0x41` | payment hash (sha256)               | `IncomingContractOffer`      |
| Our Decryption Shares            | `0x42` | contract id (sha256)                | `DecryptionShare`            |
| Consensus Decryption Shares      | `0x43` | contract id (sha256), peer id (u16) | `DecryptionShare`            |
| Contract Update (output outcome) | `0x44` | out point (sha256, out idx)         | `minimint_ln::OutputOutcome` |

## Client DB Layout

| Name                      | Prefix | Key                                | Value                        |
|---------------------------|--------|------------------------------------|------------------------------|
| Coins                     | `0x20` | amount (8 bytes), nonce (32 bytes) | serialized `SpendableCoin`   |
| Issuances                 | `0x21` | issuance_id (32 bytes)             | serialized `IssuanceRequest` |
| Peg-Ins                   | `0x22` | secret contract key (32 bytes)     | none                         |
| Outoing Payment           | `0x23` | contract id (sha256 payment hash)  | `OutgoingContractData`       |
| Outgoing Payment Claim    | `0x24` | contract id (sha256)               | `Transaction`                |
| Outgoing Contract Account | `0x25` | contract id (sha256)               | `OutgoingContractAccount`    |
| Confirmed Invoice         | `0x26` | contract id (sha256 payment hash)  | `ConfirmedInvoice`           |
| Pending Coins             | `0x27` | mint tx id (sha256 payment hash)   | `Coins<SpendableCoin>`       |
