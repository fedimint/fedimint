# Database

minimint uses a simple key-value store as its database. In theory any such KV store with the following features can
be used:

* insert, update, delete actions
* transactions
* key prefix search

In practice we use [sled](https://docs.rs/sled/) as it is a native rust database and seems sufficiently performant.

## Server DB Layout
The Database is split into different key spaces based on prefixing that can be understood as different tables (each
"table's" content can be retrieved using prefix search). There are three general prefix ranges:

* 0x00-0x0A: consensus
* 0x10-0x1A: mint
* 0x20-0x2A: client (different db, but to be sure)
* 0x30-0x3A: wallet

The following "tables" exist:

| Name                 | Prefix | Key                                                                                             | Value                           |
|----------------------|--------|-------------------------------------------------------------------------------------------------|---------------------------------|
| Consensus Items      | 0x01   | issuance_request_id (8 bytes, 0 if no issuance involved), serialized `ConsensusItem` (variable) | none                            |
| Partial Signature    | 0x02   | issuance_request_id (8 byte), peer_id (8 byte)                                                  | serialized `PartialSigResponse` |
| Finalized Signatures | 0x03   | issuance_request_id (8 bytes)                                                                   | serialized `SigResponse`        |
| Used Coins           | 0x10   | coin nonce (unknown bytes, bincode magic currently)                                             | none                            |
| Blocks               | 0x30   | block hash (32 bytes)                                                                           | block height (4 bytes)          |
| Our UTXOs            | 0x31   | OutPoint (32 bytes txid + 4 bytes output)                                                       | data necessary for spending     |

## Client DB Layout

| Name      | Prefix | Key                                | Value                        |
|-----------|--------|------------------------------------|------------------------------|
| Coins     | 0x20   | amount (8 bytes), nonce (32 bytes) | serialized `SpendableCoin`   |
| Issuances | 0x21   | issuance_id (32 bytes)             | serialized `IssuanceRequest` |