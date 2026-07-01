# Custodial Receive for Fedimint Gateways: Executive Summary

> Companion to [`custodial-receive-gateway-detailed.md`](./custodial-receive-gateway-detailed.md).
> Status: draft spec. Target: LNv2 (`fedimint-lnv2-*`).

## Problem

A small federation wants Lightning **receive**, but its gateway runs a managed,
notify-only Lightning backend (phoenixd) that auto-settles incoming payments and
exposes neither **hold invoices** nor **HTLC interception**, the two primitives the
trustless LNv2 receive depends on. Such a backend therefore cannot do trustless
receive at all.

## Solution

Offer receive **custodially**, confined to a single DB-intact crash-recoverable handoff:
the gateway takes the Lightning payment on its own backend invoice, then funds the receiver's
**normal** `IncomingContract` from its federation ecash float so the receiver claims ecash the
standard, trustless way. The trust is "operator funds the contract after the payment lands", for
seconds, not an ongoing balance.

## How it works: "reuse the contract, change the trigger"

- The receiver builds its normal `IncomingContract` and owns its own preimage.
- The trigger changes from "gateway intercepts + holds an HTLC" to "the backend's own
  invoice is paid and auto-settled → gateway funds the receiver's contract."
- The receiver claims with its locally-derived decryption key. The LNv2 server never
  checks *who* funded a contract, so this needs **zero consensus-module changes**:
  gateway, gateway-API, LNv2 client, and generic `fedimint-client` transaction-preparation changes.

## Key properties & caveats

- **No abort once settled.** The payer is irrevocably paid the instant the backend
  settles. The gateway is then committed to crediting the receiver, with no
  cancel/refund path. This shapes every edge case.
- **Custodial handoff window.** Trust = operator honesty + DB durability between settle
  and funding, bounded by per-receive caps, liability tracking, and liquidity replenishment, and
  **normally** crash-recoverable via durable status + ledger-first startup reconciliation using
  backend correlation IDs while the gateway DB survives (crashed ≠ lost, only delayed). But if the
  funding deadline passes before acceptance (observer staleness / extended downtime), it becomes a
  mandatory unresolved-liability path requiring manual / receiver-cooperative resolution. Physical
  gateway DB loss, rollback, or key loss is out of scope.
- **MVP consensus-time handling.** The funding deadline is the contract `expiration_or_fee` under
  LNv2 `consensus_unix_time`. MVP requires no new Fedimint module endpoint: the gateway derives a
  fresh observed consensus time from existing signed session outcomes by tracking `UnixTimeVote`s
  and applying the same threshold rule as the LNv2 server. If the observer is stale or lacks fresh
  threshold votes, custodial receive quote creation is unavailable for that federation. The gateway
  advertises its deadline policy in `RoutingInfo` before the wallet builds the contract, and repeats
  the exact terms in the signed quote.
- **Gateway-signed quote.** The gateway returns a signed receipt binding the backend
  invoice hash to the federation, contract, amounts, gateway keys, invoice expiry, and
  funding deadline, and records the gateway-observed LNv2 consensus time used for deadline
  validation. The quote embeds `CustodialReceiveTerms`, with `terms_hash` equal to the canonical
  hash of those terms, so the receipt is self-contained. The gateway persists that signed quote in
  its `AwaitingPayment` record before returning, and the receiver stores the full quote as
  dispute/support evidence of what the gateway committed to do, not as a guarantee that lost gateway
  state can be safely rebuilt.
- **Dispute evidence is contract-level.** A third party with the signed quote and federation session
  history can verify whether the quoted contract was not funded, funded but unclaimed, claimed
  through `claim_pk`, or refunded through `refund_pk`. They cannot verify the receiver's private
  wallet balance, local note persistence, or later spending.
- **Exactly-once funding is load-bearing.** Consensus does **not** dedupe (funding a
  contract at two outpoints = two liabilities), so the gateway enforces single funding
  (durable status machine with a pre-submit reservation, serialized per `contract_id`,
  and fedimint's deterministic `operation_id` idempotency to block a restart resubmit while
  the authoritative client DB prefix survives, re-driving the exact stored prepared tx if only the
  client operation log diverged). If that prefix is lost or rolled back, this spec does not try to
  reconstruct funding from the signed quote.
- **Prepared transaction persistence is required.** MVP needs a generic `fedimint-client`
  prepare/submit split so the gateway can finalize, lock inputs for, and persist the exact funding
  transaction before broadcast. After `FundingPrepared`, recovery must re-drive that exact stored tx,
  never rebuild a fresh funding transaction.
- **Invoice re-binding.** The backend invoice's hash no longer matches the contract, so
  the client drops the hash check and instead binds the invoice to the gateway's
  advertised `lightning_public_key` (+ expiry).
- **Claimability self-check.** The client must verify it can claim the contract it built
  *before* requesting the invoice (valid preimage and a derivable claim key). An invalid-preimage
  contract refunds to the gateway, which holds an auditable liability. A decrypts-but-wrong-claim-key
  contract is the receiver's own error (the gateway audit can't catch it), so the self-check is the
  real defense.
- **Direct-swap exclusion.** A custodial invoice is signed by the gateway's own node
  key, which would trip LNv2's intra-federation direct-swap. The gateway must never
  register custodial invoices as trustless incoming contracts. If a same-gateway sender
  hits the custodial invoice, the selected send path must be able to see the custodial
  pending-receive registry and return a forfeit signature so the sender refunds immediately.
  Alternate-gateway routing is a post-MVP optimization.
- **Not transparent to legacy clients.** Custodial receive needs an explicit opt-in
  entrypoint and a *separate* gateway endpoint. Capability advertisement alone is
  insufficient for legacy clients, because gateway selection is reachability-based. New clients use
  policy-driven selection (`select_gateway_for_receive`) to skip custodial-only gateways during
  trustless receive and continue to the next reachable gateway. Endpoint rejection alone isn't enough:
  custodial-only gateways must not appear on the legacy `GATEWAYS_ENDPOINT`, since old
  clients cannot distinguish send and receive capability. MVP does **not** add a
  `CUSTODIAL_GATEWAYS_ENDPOINT`; custodial candidate URLs are wallet-supplied out-of-band
  (for example by operator config, app policy, or a future Nostr-style announcement), and the wallet
  then verifies live custodial support through `RoutingInfo`.
- **Separate operator binary.** The preferred MVP implementation is a new `custodial-gatewayd`
  binary. Existing `gatewayd` remains the legacy-compatible trustless gateway; `custodial-gatewayd`
  owns the custodial receive endpoint, state machine, backend observer, reconciliation,
  exactly-once funding, liabilities, quote signing, and metrics. A custodial-only instance stays off
  legacy `GATEWAYS_ENDPOINT`; shared helpers may be factored out, but the goal is to avoid changing
  existing `gatewayd` behavior. A dual-capable gateway that remains in the legacy list is a separate
  deployment mode and must share the custodial receive registry with the send/direct-swap path.
- **Accounting.** The receiver gets exactly `commitment.amount`. The gateway spends
  `commitment.amount + module fees` and absorbs backend liquidity skim. Size
  `receive_fee` and float against the full spend. Unpaid issued invoices are contingent exposure:
  track and alert on them, but do not reject new receives solely because they exist. Once an invoice
  settles, it is a debt. If federation ecash is short, the MVP alerts and can drive or prompt a pegin
  from available on-chain funds. Post-MVP can automate loop-out, channel close, splice, swap-out, or
  backend-specific liquidity actions. The MVP keeps the existing `PaymentFee::RECEIVE_FEE_LIMIT`. A
  higher custodial fee cap would need separate explicit consent.
- **MVP observability.** The gateway must expose minimal metrics for issued-unpaid exposure,
  settled-but-unfunded debt, unresolved liabilities, ecash float, liquidity shortfall, funding
  deadline slack, backend cursor lag / retention margin, consensus-time observer freshness, and
  settlement-to-funding latency. These metrics drive alerts and operator action; they do not add new
  create-invoice behavior beyond the specified hard gates.
- **Generic.** Any notify-only backend with these primitives (external-id unpaid lookup,
  authenticated settled-ledger lookup, retention) can reuse the same path, not just phoenixd.

## When to use

Choose custodial receive when the operator wants phoenixd-grade simplicity and the
federation accepts a bounded operator-honesty trust on receive. Otherwise prefer a
trustless gateway (LND/LDK, optionally LSP-backed). **Send** can stay trustless on the
same backend (`/payinvoice` returns the preimage), but a custodial-only gateway is not
legacy-discoverable through `GATEWAYS_ENDPOINT`; new wallets must include the out-of-band
custodial URL in their send candidate set if they want to use that gateway for send.

## Status

Draft position: the "reuse the contract" design appears to require no consensus-module
changes, but this is still pre-implementation and under review. Open items:
`receive_fee` sizing within the existing cap, two-deadline / observer values, authenticated
settlement confirmation details, canonical quote/terms encoding, limit / metric-alert thresholds,
backend-trait shape, richer backend capability typing, out-of-band gateway discovery UX, consent UX,
the prepared-transaction API shape, audit timing, and richer operator-liability taxonomy. See the detailed spec for the full protocol, trust analysis,
failure modes, and implementation plan.
