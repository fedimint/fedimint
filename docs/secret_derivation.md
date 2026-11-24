# Secret Derivation

`fedimint-client` needs a `DerivableSecret`. Since `fedimint-client` is intended to be used as a library, the consumer of `fedimint-client` is free to arrive at this `DerivableSecret` in a number of ways. Here we describe a recommended approach to encourage interoperability.

Let's say that the consuming application of `fedimint-client` has some `global_root_secret` that it may use for deriving all sorts of secrets deterministically. We then arrive at `fedimint-client`'s `DerivableSecret` using the derivation path:

```
global_root_secret/<key-type=per-federation=0>/<federation-id>/<wallet-number=0>/<key-type=fedimint-client=0>
```

For convenience, the provided `Bip39RootSecretStrategy` can be used to:
- generate a BIP-39 mnemonic, and then
- generate the `global_root_secret` from the mnemonic by calling `Bip39RootSecretStrategy::to_root_secret(mnemonic)`

Then starting with the `global_root_secret`, the following derivation steps are performed:

1. Call `global_root_secret.child_key(0)`. The 0 here indicates the first segment of the derivation path, `<key-type=per-federation=0>`. The returned value is `multi_federation_root_secret` of type `DerivableSecret`.
2. Call `multi_federation_root_secret.federation_key(federation_id)` with the ID of the federation that the `fedimint-client` is being instantiated for. The returned value is `federation_root_secret` of type `DerivableSecret`.
3. Call `federation_root_secret.child_key(0)`. The 0 here indicates the "wallet_number" segment of the derivation path, and we call the returned value `federation_wallet_root_secret` of type `DerivableSecret`. Always use 0 here: a single `fedimint-client` instance already provides several balances for one federation through its accounts, described below, so there is no need for a second client with its own secret.
4. Finally call `federation_wallet_root_secret.child_key(0)`. The 0 here indicates that this child is for the `fedimint-client` instance. The consuming app is free to use other indices for auxiliary federation-specific secrets.

## Accounts

A `fedimint-client` instance holds five accounts per federation, `Account::Primary` through `Account::Quinary`. An account is purely client-side: the federation cannot tell them apart. Every account exists from the moment the client is built, nothing creates one, and all five share one database, one set of scanners and one recovery, so holding a balance in several accounts costs no more than holding it in one.

The accounts are derived below the `DerivableSecret` handed to `fedimint-client`, inside each module's secret, so the consuming application does not derive anything for them. `Account::Primary` is derived exactly where a client without accounts already derived, so a wallet that predates accounts keeps its funds in the primary account. The other four each take an account-specific child of the module secret.

Every client API that touches a balance takes the account explicitly: funding a transaction, reading or subscribing to a balance, and in the mint, lightning and wallet modules sending and receiving. Funds move between accounts the same way they move between wallets, by sending e-cash out of one account and receiving it into another. A recovery from the root secret restores all five accounts and credits each account's notes back to it.

As an additional reference, the `fedimint-cli` package demonstrates this derivation when constructing the `fedimint-client` instance. Note that `fedimint-cli` also leverages `fedimint-client`'s database to store the mnemonic behind `global_root_secret`. This is simply done for convenience (since `fedimint-cli` doesn't have its own database). We expect applications that integration `fedimint-client` to have their own storage for data that doesn't directly belong to `fedimint-client`.

Note that `fedimint-client` also internally does an additional derivation using the federation ID. This is to ensure that the same root secret cannot accidentally be reused across multiple `fedimint-client` instances for different federations.