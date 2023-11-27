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
3. Call `federation_root_secret.child_key(0)`. The 0 here indicates the "wallet_number" segment of the derivation path, and we call the returned value `federation_wallet_root_secret` of type `DerivableSecret`. This affords us an arbitrary number of "wallets" for a single federation.
4. Finally call `federation_wallet_root_secret.child_key(0)`. The 0 here indicates that this child is for the `fedimint-client` instance. The consuming app is free to use other indices for auxiliary federation-specific secrets.

As an additional reference, the `fedimint-cli` package demonstrates this derivation when constructing the `fedimint-client` instance. Note that `fedimint-cli` also leverages `fedimint-client`'s database to store the mnemonic behind `global_root_secret`. This is simply done for convenience (since `fedimint-cli` doesn't have its own database). We expect applications that integration `fedimint-client` to have their own storage for data that doesn't directly belong to `fedimint-client`.

Note that `fedimint-client` also internally does an additional derivation using the federation ID. This is to ensure that the same root secret cannot accidentally be reused across multiple `fedimint-client` instances for different federations.