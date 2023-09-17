# What is a transaction

- A [`Transaction`](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint-core/src/transaction.rs#L12) Consists of inputs and outputs
  - Each input and output belongs to a certain module (e.g. Mint, Wallet, …)
  - All inputs have to add up to the same sum as all outputs
- Also contains a signature
  - Each input has an associated secret/public key pair
  - The signature is a MuSig2 multi signature with all these input keys signing the entire transaction

```rust
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub signature: Option<schnorr::Signature>,
}
…
pub enum Input {
    Mint(<fedimint_mint::Mint as FederationModule>::TxInput),
    Wallet(<fedimint_wallet::Wallet as FederationModule>::TxInput),
    LN(<fedimint_ln::LightningModule as FederationModule>::TxInput),
}
```

# Transaction Creation

- One client module for each federation module
- There are specialized user and gateway clients that use these to construct transactions
- [E.g. deposit](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/client/client-lib/src/lib.rs#L190)

# Transaction processing

- [Submit transaction](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L105), first validation
- [Save to DB](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L115)
- [Generate consensus proposal](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L386) with all transactions submitted in the meantime
- [Propose to HBBFT](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/lib.rs#L132)
- [Process all transactions that were agreed on](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L436)
- [Each input](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L447) and output are processed by its respective module, e.g. for the [Mint module](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/modules/fedimint-mint/src/lib.rs#L194)
- Some operations need a second round to submit signature shares, they are submitted via [per-module consensus items](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint-api/src/module/mod.rs#L141) (see also [Generate consensus proposal](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint/src/consensus/mod.rs#L386))
- These are also [processed by their respective module](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/modules/fedimint-mint/src/lib.rs#L119)

# Modules

- [For more details, look at the docs, they are great (at least for modules)!](https://github.com/fedimint/fedimint/blob/a1f57e3c6ff860a9c4a998bf88ebad73ebdb67c9/fedimint-api/src/module/mod.rs#L129)
