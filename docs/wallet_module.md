# Wallet Module
The wallet module allows users to peg-in or peg-out from the fed using on-chain bitcoin transactions.

### Pegging In - User Client
- [WalletClient::get_new_pegin_address](../fedimint-client-legacy/src/wallet/mod.rs) - the user client generates a new peg-in address by creating a random private/public key pair, and tweaking the fed's public multisig with the random public key.
- Next the user sends an on-chain bitcoin transaction to the generated peg-in address using whatever wallet software they prefer.
- [WalletClient::create_pegin_input](../fedimint-client-legacy/src/wallet/mod.rs) - after sending bitcoin on-chain to the address, the client sends a `PegInProof` to the fed which includes the public key tweak that allows the federation to spend the UTXO, and signs the transaction using the private key tweak to prove they sent the bitcoin.

```rust
let address = user_client.get_new_pegin_address();
let (txout_proof, btc_transaction) = bitcoin.send(&address, amount);
let (keys, proof) = user_client.create_pegin_input(txout_proof, btc_transaction);
tx.input(keys, proof);
user_client.submit_tx_with_change(tx);
```

Using a public key tweak instead of querying the federation for a new address avoids an unnecessary request to the federation and allows a client to prove they sent bitcoin by signing a message.

### Pegging In - Federation
- [Wallet::validate_input](../modules/fedimint-wallet-server/src/lib.rs) - verifies that the `PegInProof` is in a block and is spendable by the federation's multisig.
- [Wallet::apply_input](../modules/fedimint-wallet-server/src/lib.rs) - stores the `SpendableUTXO` containing the transaction details and tweak key in the federation's wallet database.
- [Wallet::begin_consensus_epoch](../modules/fedimint-wallet-server/src/lib.rs) - determines the `RoundConsensus` containing the consensus block height which is delayed by a configurable `finality_delay` of 10 blocks after which peg-ins accepted.

### Pegging Out - User Client
- [Client::new_peg_out_with_fees](../fedimint-client-legacy/src/lib.rs) - creates a new `PegOut` for users by requesting the current peg-out fees from the fed's wallet API which is estimated based on the on-chain size of the transaction and the sats/byte to confirm in a `CONFIRMATION_TARGET` of 10 blocks.
- [Client::peg_out](../fedimint-client-legacy/src/lib.rs) - submits a transaction to the fed to spend input ecash and receive bitcoin on-chain.

```rust
let peg_out = user_client.new_peg_out_with_fees(amount, address);
if (peg_out.fees < user_configured_amount) {
  user_client.peg_out(peg_out);
}
```

### Pegging Out - Federation
- [Wallet::validate_output](../modules/fedimint-wallet-server/src/lib.rs) - verifies the address is valid, the fees are high enough, and the federation has enough `SpendableUTXO` to create the transaction.
- [Wallet::apply_output](../modules/fedimint-wallet-server/src/lib.rs) - generates a PSBT (partially signed bitcoin transaction) with a signature and removes UTXOs so they are not double-spent.
- [Wallet::consensus_proposal](../modules/fedimint-wallet-server/src/lib.rs) - proposes the PSBT and the `RoundConsensus` containing the block height, peg-out fees, and randomness beacon (tweak for receiving peg-out change) as new consensus items.
- [Wallet::end_consensus_epoch](../modules/fedimint-wallet-server/src/lib.rs) - if all peers behave properly they will have submitted PSBT signatures which can be combined into a final `PendingTransaction`.
- [run_broadcast_pending_tx](../modules/fedimint-wallet-server/src/lib.rs) - is a thread that will periodically look broadcast any pending transactions.

### Future
In the future there are a number of improvements we could make:
- Allow for users to bump their transaction fees using RBF if the transactions are stuck
- Aggregate transactions to reduce the total fees paid (or lower the min sat/byte)
- Make the multisig a taproot UTXO, saving on fees, adding privacy, and allowing for federations beyond 20 peers
