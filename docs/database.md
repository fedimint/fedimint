# Database

minimint uses a simple key-value store as its database. In theory any such KV store with the following features can
be used:

* insert, update, delete actions
* transactions
* key prefix search

In practice we use [sled](https://docs.rs/sled/) as it is a native rust database and seems sufficiently performant.

## Layout
The Database is split into different key spaces based on prefixing that can be understood as different tables (each
"table's" content can be retrieved using prefix search). The following "tables" exist:

| Name                 | Prefix | Key                                                                                             | Value                           |
|----------------------|--------|-------------------------------------------------------------------------------------------------|---------------------------------|
| Consensus Items      | 0x01   | issuance_request_id (8 bytes, 0 if no issuance involved), serialized `ConsensusItem` (variable) | none                            |
| Partial Signature    | 0x02   | issuance_request_id (8 byte), peer_id (8 byte)                                                  | serialized `PartialSigResponse` |
| Finalized Signatures | 0x03   | issuance_request_id (8 bytes)                                                                   | serialized `SigResponse`        |
| Used Coins           | 0x10   | coin nonce (unknown bytes, bincode magic currently)                                             | none                            |
