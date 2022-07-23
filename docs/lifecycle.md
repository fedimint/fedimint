# What is a transaction

- A [`Transaction`](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint-core/src/transaction.rs#L12-L16) Consists of inputs and outputs
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

- [One client module for each federation module](https://github.com/fedimint/fedimint/tree/master/client/client-lib/src)
- There are specialized user and gateway clients that use these to construct transactions
- [E.g. deposit](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/client/client-lib/src/clients/user.rs#L103-L125)

# Transaction processing

- [Submit transaction](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L92), first validation
- [Save to DB](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L149-L152)
- [Generate consensus proposal](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L294-L335) with all transactions submitted in the meantime
- [Propose to HBBFT](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/lib.rs#L135-L149)
- [Process all transactions that were agreed on](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L337)
- [Each input](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L348-L379) and output are processed by its respective module, e.g. for the [Mint module](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/modules/fedimint-mint/src/lib.rs#L195-L214)
- Some operations need a second round to submit signature shares, they are submitted via [per-module consensus items](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint-api/src/module/mod.rs#L141-L144) (see also [Generate consensus proposal](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint/src/consensus/mod.rs#L294-L335))
- These are also [processed by their respective module](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/modules/fedimint-mint/src/lib.rs#L120-L135)

# Modules

- [For more details, look at the docs, they are great (at least for modules)!](https://github.com/fedimint/fedimint/blob/563c600287decd47e89e15e29ab478648395f378/fedimint-api/src/module/mod.rs#L128-L248)
