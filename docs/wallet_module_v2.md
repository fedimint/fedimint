# Fedimint On-Chain Wallet Improvements

### Goal

Support high volume on-chain withdrawals.

### Potential Improvements

- On-Chain Gateway
- RBF / Lazy Batching

---

### On-Chain Gateway

Similar to the lightning gateway, the on-chain gateway incentivizes a trustless third party to source liquidity to satisfy on-chain deposits/withdrawals.

GitHub [discussion](https://github.com/fedimint/fedimint/discussions/3264).

There may be multiple designs for an on-chain gateway, however I've only considered a gateway that uses submarine swaps, which has significant UX drawbacks.

#### Withdrawal Flow / Loop Out

Lightning Labs Loop Out [Architecture](https://github.com/lightninglabs/loop/blob/master/docs/architecture.md)

> 1. Initiation: Client queries for terms of a swap
> 2. Fee: Client sends a small fee HTLC that is unrestricted
> 3. Funding: Client sends a funding HTLC locked to a preimage they generate
> 4. Payment: Server sends the funds on-chain locked to the funding preimage hash
> 5. Complete: Client uses the preimage to take the on-chain funds.
> 6. Final: The server uses the on-chain-revealed preimage to claim funding HTLC

This approach requires two on-chain transactions and needs the user to sweep the funds from the on-chain HTLC. If the user does not sweep the funds prior to the timeout, the gateway can sweep both the on-chain and LN HTLCs.

---

### RBF / Lazy Batching

- All withdrawals use a single UTXO as an input
- Each additional withdrawal creates an RBF tx spending the same input with an additional output

#### Known Issues

[Transaction pinning](https://bitcoinops.org/en/topics/transaction-pinning/)

**RBF Transaction Pinning**

[BIP-125](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki) rule 3

> 3. The replacement transaction pays an absolute fee of at least the sum paid by the original transactions.

If a user withdraws to a service that sweeps unconfirmed transactions, a child transaction could have a low feerate but a high absolute fee if several addresses are swept. The RBF transaction we use would need to pay a higher absolute fee than all transactions evicted from the mempool, thus _pinning_ the transaction.

_Mitigation_

Detect when an RBF transaction has a child transaction that is uneconimical, then use [CPFP](https://bitcoinops.org/en/topics/cpfp/) spending the unconfirmed change output. The federation will need to reach consensus to switch to CPFP. It is possible to then RBF this single CPFP tx with additional withdrawals.


**CPFP Transaction Pinning**

> Maximum package size limitations prevent CPFP from being used if a transaction has more than 101,000 vbytes of children or other descendants in a mempool, or has more than 25 descendants or ancestors. This can allow an attacker to completely block fee bumping by creating the maximum amount of child transactions.

_Mitigation_

Use feerates that ensure initial transaction is included in an upcoming block. If there's a fee spike, no mitigation is known.

**UX Confusion**

- It may be confusing for the user if they're monitoring their pending transaction and the txid changes due to RBF
- If anyone spends unconfirmed outputs, RBF will introduce complexity
- Feerates may be difficult to surface to users
    - Need to consider how to surface what the user will pay if their withdrawal is a:
        - New tx (full tx overhead)
        - RBF tx (one additional output plus fee bump)
        - CPFP tx (full tx overhead plus fee bump)
        - Tx that consolidates inputs

_Mitigation_

???

#### Edge Cases (not exhaustive)

**Case 1**

- User 1 requests withdrawal
- Tx 1 including User 1's withdrawal is signed, broadcast, and in mempool
- User 2 requests withdrawal prior to Tx 1 being mined
- Tx 2 including User 1 and User 2's withdrawals is created using RBF, signed, broadcast, and in mempool
- Tx 1 is mined, invalidating Tx 2
    - This could happen due to various reasons including network latency, miners that don't use ancestor feerate mining, etc

We need to detect Tx 1 was mined and generate a new transaction to satisfy User 2's withdrawal request.

_Solution_

- The federation needs to reach consensus that Tx 1 was included in a block, not Tx 2
- A new transaction is constructed satisfying User 2's withdrawal request, **using the change output from Tx 1**

**Case 2**

- Use case 1 as the initial condition
- User 2's withdrawal request is included in Tx 3
- Tx 3 is mined
- Reorg that includes Tx 2

We need to ensure that if there's a reorg that includes Tx 2, Tx 3 will be invalid. Otherwise, we'll issue duplicate withdrawals for User 2's single withdrawal request.

_Solution_

- Using the solution for Case 1, Tx 3 was constructed using the change output from Tx 1
- Since the reorg included Tx 2 instead of Tx 1, Tx 3 will be invalid since the change output from Tx 1 no longer exists

**Case 3**

- One UTXO exists in wallet
- User 1 requests withdrawal
- Tx 1 including User 1's withdrawal is signed, broadcast, and in mempool
- Prior to Tx 1 being mined, deposit confirmation threshold is reached giving the wallet two available UTXOs
- User 2 requests withdrawal prior to Tx 1 being mined

We need to handle consolidating multiple UTXOs while ensuring we don't introduce risk of duplicate withdrawals.

_Solution_

Create Tx 4, which uses both UTXOs as inputs along with outputs that satisfy User 1 and User 2's withdrawal requests.
