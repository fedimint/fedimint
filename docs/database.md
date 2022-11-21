# Database

Fedimint uses a simple key-value store as its database. In theory any such KV store with the following features can be used:

* insert, update, delete actions
* transactions
* key prefix search

We currently use RocksDB on both the client and the server.

## Server DB Layout
The Database is split into different key spaces based on prefixing that can be understood as different tables (each "table's" content can be retrieved using prefix search). There are three general prefix ranges:

* `0x00-0x0A`: consensus
* `0x10-0x1A`: mint
* `0x20-0x2A`: client (different db, but to be sure)
* `0x30-0x3A`: wallet
* `0x40-0x4A`: lightning

### Consensus

| Name                | Prefix | Key                              | Value                         |
|---------------------|--------|----------------------------------|-------------------------------|
| ProposedTransaction | `0x01` | Transaction ID (sha256, 32bytes) | Transaction                   |
| AcceptedTransaction | `0x02` | Transaction ID (sha256, 32bytes) | AcceptedTransaction           |
| DropPeer            | `0x03` | Peer ID (u16)                    | None                          |
| RejectedTransaction | `0x04` | Transaction ID (sha256, 32bytes) | Reason for rejection (string) |
| EpochHistory        | `0x05` | Epoch ID (u16)                   | Epoch history record          |
| LastEpoch           | `0x06` | none                             | Epoph ID (u16)                |

### Mint

| Name               | Prefix | Key                                                 | Value                 |
|--------------------|--------|-----------------------------------------------------|-----------------------|
| CoinNonce          | `0x10` | coin nonce (unknown bytes, bincode magic currently) | none                  |
| ProposedPartialSig | `0x11` | mint outpoint (40 bytes)                            | blind signature share |
| ReceivedPartialSig | `0x12` | mint outpoint (40 bytes), peer (2 bytes)            | blind signature share |
| OutputOutcome      | `0x13` | mint outpoint (40 bytes)                            | blind signature       |
| MintAuditItem      | `0x14` | AuditItem                                           | Amount                |

### Wallet

| Name                  | Prefix | Key                                       | Value                                     |
|-----------------------|--------|-------------------------------------------|-------------------------------------------|
| BlockHash             | `0x30` | block hash (32 bytes)                     | none                                      |
| Utxo                  | `0x31` | OutPoint (32 bytes txid + 4 bytes output) | data necessary for spending               |
| RoundConsensus        | `0x32` | none                                      | block height, fee rate, randomness beacon |
| UnsignedTransaction   | `0x34` | bitcoin tx id (32 bytes)                  | PSBT                                      |
| PendingTransaction    | `0x35` | bitcoin tx id (32 bytes)                  | consensus encoded tx, change tweak        |
| PegOutTxSigCi         | `0x36` | bitcoin tx id (32 bytes)                  | list of signatures (1 per input)          |
| PegOutBitcoinOutPoint | `0x37` | Fedimint out point                        | Outpoint                                  |

### Lightning

| Name                             | Prefix | Key                                 | Value                        |
|----------------------------------|--------|-------------------------------------|------------------------------|
| Contract                         | `0x40` | ContractId                          | `ContractAccount`            |
| Offer                            | `0x41` | payment hash (sha256)               | `IncomingContractOffer`      |
| ProposedDecryptionShare          | `0x42` | contract id (sha256)                | `DecryptionShare`            |
| AgreedDecryptionShare            | `0x43` | contract id (sha256), peer id (u16) | `DecryptionShare`            |
| ContractUpdate                   | `0x44` | out point (sha256, out idx)         | `fedimint_ln::OutputOutcome` |
| LightningGateway                 | `0x45` | Node Pubkey (PublicKey)             | `LightningGateway`           |

## Client DB Layout
| Name                    | Prefix | Key                                | Value                        |
|-------------------------|--------|------------------------------------|------------------------------|
| ClientSecret            | `0x29` | none                               | `ClientSecret`               |

### LightningClient
| Name                    | Prefix | Key                                | Value                        |
|-------------------------|--------|------------------------------------|------------------------------|
| OutoingPayment          | `0x23` | contract id (sha256 payment hash)  | `OutgoingContractData`       |
| OutgoingPaymentClaim    | `0x24` | contract id (sha256)               | `Transaction`                |
| OutgoingContractAccount | `0x25` | contract id (sha256)               | `OutgoingContractAccount`    |
| ConfirmedInvoice        | `0x26` | contract id (sha256 payment hash)  | `ConfirmedInvoice`           |
| LightingGateway         | `0x28` | none                               | `LightningGateway`           |
| LastECashNoteIndex      | `0x2a` | none                               | `u64`                        |

### MintClient
| Name                   | Prefix | Key                                | Value                        |
|------------------------|--------|------------------------------------|------------------------------|
| Coin                   | `0x20` | amount (8 bytes), nonce (32 bytes) | `SpendableCoin`              |
| OutputFinalizationData | `0x21` | issuance_id (32 bytes)             | `NoteIssuanceRequests`       |
| PendingCoins           | `0x27` | mint tx id (sha256 payment hash)   | `TieredMulti<SpendableCoin>` |

### WalletClient
| Name                    | Prefix | Key        | Value                        |
|-------------------------|--------|------------|------------------------------|
| PegIn                   | `0x22` | `Script`   | `[u8; 32]`                   |
