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
  cancel/refund path. If the backend invoice expires unpaid, no federation contract
  has been funded, so there is no on-federation contract to cancel. This shapes every
  edge case.
- **Custodial handoff window.** Trust = operator honesty + DB durability between settle
  and funding, bounded by per-receive caps, liability tracking, and liquidity replenishment, and
  **normally** crash-recoverable via durable status + ledger-first startup reconciliation using
  backend correlation IDs while the gateway DB survives (crashed ≠ lost, only delayed). Once an
  invoice settles, the gateway owes the receiver until the original contract is funded. Physical
  gateway DB loss, rollback, or key loss is out of scope.
- **MVP consensus-time handling.** The funding deadline is the contract `expiration_or_fee` under
  LNv2 `consensus_unix_time`; it is a Fedimint funding-admission check, not a liability boundary.
  Custodial receive uses a long-lived funding deadline, strictly after invoice expiry, so automatic
  funding of settled invoices remains possible. MVP requires no new Fedimint module endpoint: the
  gateway derives a fresh observed consensus time from existing signed session outcomes by tracking
  `UnixTimeVote`s and applying the same threshold rule as the LNv2 server. If the observer is stale or
  lacks fresh threshold votes, custodial receive quote creation is unavailable for that federation.
  The gateway advertises its custodial fee and deadline policy in `RoutingInfo` before the wallet
  builds the contract, and repeats the exact terms in the signed quote. Deadlines are bounded on
  both sides: gateway-enforced minimums keep settled invoices fundable, and gateway-enforced
  maximums (`max_invoice_expiry_secs` / `max_funding_deadline_secs`) keep retained records,
  namespace reservations, and required backend retention coverage finite instead of a one-request
  DoS lever. The wallet also checks the
  quote's observed consensus time and deadline arithmetic against an independent time reference (its
  local wall clock with margin; optionally its own observed federation time), so a stale gateway
  cannot make an unsafe funding deadline look valid.
- **Gateway-signed quote.** The gateway returns a signed receipt binding the backend
  invoice hash to the federation, contract, amounts, gateway keys, invoice expiry, and
  funding deadline, and records the gateway-observed LNv2 consensus time used for deadline
  validation. The quote embeds `CustodialReceiveTerms` under the quote signature, so the receipt is
  self-contained. The gateway persists a `QuoteDraft` before
  calling the backend, validates the returned backend invoice before signing, then persists the signed
  quote in its `AwaitingPayment` record before returning. The receiver persists a provisional receive
  with claim material before the gateway request leaves, then upgrades it with the returned quote and
  invoice. The full quote is dispute/support evidence of what the gateway committed to do, not a
  guarantee that lost gateway state can be safely rebuilt.
- **Dispute evidence is contract-level.** A third party with the signed quote and federation session
  history can verify whether the quoted contract was not funded, funded but unclaimed, claimed
  through `claim_pk`, or refunded through `refund_pk`. They cannot verify the receiver's private
  wallet balance, local note persistence, or later spending. The payer's own settlement preimage
  proves payment to the gateway's node, not to the receiver's contract, so payer-side receiver-bound
  proof-of-payment is weaker than under trustless receive.
- **Exactly-once funding is load-bearing.** Consensus does **not** dedupe (funding a
  contract at two outpoints = two liabilities), so the gateway enforces single funding
  (durable status machine with a pre-submit reservation, serialized per `contract_id`,
  and fedimint's deterministic `operation_id` idempotency to block a restart resubmit while
  the authoritative client DB prefix survives, re-driving the exact stored prepared tx if only the
  client operation log diverged). If that prefix is lost or rolled back, this spec does not try to
  reconstruct funding from the signed quote.
- **Non-idempotent backend create stays conservative.** If a backend invoice create request may have
  been sent but the gateway cannot prove whether the backend created it, the receive goes to operator
  review instead of retrying and risking a second backend invoice for the same contract.
- **Recovered invoices are not a weaker path.** Any backend invoice discovered through crash recovery,
  inconclusive-create reconciliation, or tombstone reconciliation must pass the same draft validation
  and direct-swap namespace reservation as the happy path. Retained unreturned-invoice records carry a
  `fund_on_settlement` policy: safe stale/unreturned invoices fund automatically if settled; unsafe
  validation or namespace failures become auditable liabilities.
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
  register custodial invoices as trustless incoming contracts; that rule alone prevents the
  wrong-preimage hazard. If a same-gateway sender hits the custodial invoice, the send already
  cancels with a forfeit signature (the failed registered-contract lookup path), so the sender
  refunds immediately; the shared `backend_invoice_hash -> CustodialPending` registry labels that
  outcome as custodial self-pay and enforces the cross-path namespace at creation time. Retained custodial records that still own a backend invoice hash
  keep that hash reserved until pruning. Pre-funding alternate-gateway routing is a post-MVP
  optimization.
- **Not transparent to legacy clients.** Custodial receive needs an explicit opt-in
  entrypoint and a *separate* gateway endpoint. Capability advertisement alone is
  insufficient for legacy clients, because gateway selection is reachability-based. New clients use
  policy-driven selection (`select_gateway_for_receive`) to skip custodial-only gateways during
  trustless receive and continue to the next reachable gateway. Endpoint rejection alone isn't enough:
  custodial-only gateways must not appear on the legacy `GATEWAYS_ENDPOINT`, since old
  clients cannot distinguish send and receive capability. MVP does **not** add a
  `CUSTODIAL_GATEWAYS_ENDPOINT`; custodial candidate URLs are wallet-supplied out-of-band
  (for example by operator config, app policy, a future Nostr-style announcement, or explicit user
  consent). The URL source is the authorization input; `RoutingInfo` is only the live capability/key
  check.
- **Separate operator binary.** The preferred MVP implementation is a new `custodial-gatewayd`
  binary. Existing `gatewayd` remains the legacy-compatible trustless gateway; `custodial-gatewayd`
  owns the custodial receive endpoint, state machine, backend observer, reconciliation,
  exactly-once funding, liabilities, quote signing, and metrics. A custodial-only instance stays off
  legacy `GATEWAYS_ENDPOINT`; shared helpers may be factored out, but the goal is to avoid changing
  existing `gatewayd` behavior. A dual-capable gateway that remains in the legacy list is a separate
  deployment mode and must share the custodial receive registry with the send/direct-swap path.
- **Accounting.** The payer amount equals `commitment.amount + receive_fee`. After backend settlement,
  the gateway fronts `commitment.amount + module fees` from ecash float, while the backend credits the
  payer amount minus any backend skim. The gateway's net margin is the advertised custodial
  `receive_fee` minus module fees, backend skim, and liquidity/rebalance costs, so operators must size
  `receive_fee` and float against that full outgoing funding leg. Note the structural gap: the MVP
  fee cap (50 sats + 0.5%) sits below phoenixd's roughly 1%-plus-mining-fee liquidity cost, so any
  receive that triggers an inbound liquidity purchase loses money by construction — and an attacker
  can deliberately force such purchases. Operators must pre-provision inbound headroom, and the
  gateway can refuse issuance that would force a liquidity purchase. Unpaid issued invoices are contingent
  exposure: track and alert on them, but do not reserve their face value against ecash float and do not
  expose public unpaid-record quotas. Such quotas are DoS-prone because an attacker can cheaply fill
  them with unpaid requests. Internal rate/storage/abuse controls still protect the service, but if
  they close before backend invoice creation the client sees generic
  `BackendInvoiceCreationUnavailable`, not a protocol quota reason. Actual
  settled/funding/unresolved obligations gate new invoice creation via `max_in_flight` (tracked and
  enforced per federation); issued-unpaid
  face value does not. Invoice expiry bounds unpaid contingent exposure; once an invoice settles, it is
  a debt until funded. If federation ecash is short, the MVP alerts and can drive or prompt a
  pegin from available on-chain funds. Post-MVP can automate loop-out, channel close, splice, swap-out,
  or backend-specific liquidity actions. The MVP keeps the existing `PaymentFee::RECEIVE_FEE_LIMIT`. A
  higher custodial fee cap would need separate explicit consent.
- **MVP observability.** The gateway must expose minimal metrics for issued-unpaid exposure,
  settled-but-unfunded debt, unresolved liabilities, ecash float, liquidity shortfall, funding
  deadline slack, backend cursor lag / retention margin, consensus-time observer freshness, and
  settlement-to-funding latency, plus retained-record pressure. These metrics drive alerts, abuse
  detection, and operator action; they do not add a public resource-quota rejection.
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
`receive_fee` sizing within the existing cap, two-deadline / observer values and the concrete
maximum expiry/deadline bounds, authenticated
settlement confirmation details, canonical quote/terms encoding, limit / metric-alert thresholds,
backend-trait shape, richer backend capability typing, out-of-band gateway discovery UX, consent UX,
the prepared-transaction API shape, audit timing, and richer liability taxonomy. See the detailed spec for the full protocol, trust analysis,
failure modes, and implementation plan.
