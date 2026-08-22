# Custodial Receive for Fedimint Gateways: Executive Summary

> Companion to [`custodial-receive-gateway-detailed.md`](./custodial-receive-gateway-detailed.md)
> (the authoritative spec) and the buildable implementation specs in
> [`custodial-receive-impl/`](./custodial-receive-impl/00-overview.md).
> Status: draft spec. Target: LNv2 (`fedimint-lnv2-*`).

## The one-paragraph version

Some Lightning backends — phoenixd and similar managed "node in a box" daemons — are very easy to
operate but cannot support Fedimint's trustless Lightning receive. This spec lets a gateway
running such a backend offer receive anyway, by accepting one small, explicit, bounded trust
assumption: the gateway takes the Lightning payment on its **own** invoice first, then pays the
receiver by funding the receiver's normal federation contract from the gateway's ecash. The
receiver trusts the gateway from invoice creation until that contract is funded; the
money-at-risk part of that window — after the payer's payment settles — is normally seconds.
Everything in this spec exists to make the window bounded, crash-recoverable, and auditable. No
federation consensus code changes at all.

## Background: the pieces involved (skip if you know Fedimint)

- A **federation** is a group of guardians jointly running Fedimint and issuing **ecash** to
  clients.
- A **gateway** bridges a federation to the Lightning Network. It holds ecash (its "float") and
  runs a Lightning node, earning fees for swapping between the two.
- When a federation client (the **receiver**) wants to be paid over Lightning, the LNv2 module
  uses an **`IncomingContract`**: a contract on the federation that, once **funded** by anyone,
  can be **claimed** for ecash only by the receiver — it commits to a secret (a payment preimage)
  that only the receiver holds. The federation never checks *who* funded a contract.
- Today's **trustless receive** works because the gateway's Lightning node (LND/LDK) supports
  **hold invoices**: it can accept an incoming Lightning payment, *pause* it mid-flight, fund the
  receiver's contract, and only then release the payment using the preimage the federation
  reveals. If anything fails, the paused payment is cancelled back and the payer automatically
  gets their money back. Lightning payment and contract funding are atomic; nobody trusts anybody.

## The problem

phoenixd-style backends hide exactly the two primitives that atomicity needs. They cannot create
an invoice for an externally chosen payment hash, and they **auto-settle** every incoming payment
instantly — no pause, no cancel hook. On such a backend trustless receive is not merely hard, it
is impossible: the federation only ever reveals the preimage for the *receiver's* hash, and the
backend cannot put that hash in an invoice. The only alternative to abandoning these
easy-to-operate backends is to give up atomicity between the Lightning leg and the federation
leg — deliberately, visibly, and with the smallest possible blast radius.

## The idea: reuse the contract, change the trigger

Nothing changes about the receiver's contract or how it is claimed. Only the *event that causes
the gateway to fund it* changes:

```
trustless: payer's payment arrives → gateway HOLDS it → funds contract → federation reveals
           preimage → gateway releases the payment → receiver claims ecash

custodial: payer pays the BACKEND'S OWN invoice → backend auto-settles (gateway has the money)
           → gateway funds the receiver's contract from its ecash float → receiver claims ecash
```

Step by step:

1. The wallet — with explicit user/app opt-in to custodial receive — asks the gateway
   (`/routing_info`) whether it offers custodial receive and on what terms: fee, per-receive cap,
   and deadline policy.
2. The receiver builds its normal `IncomingContract`, **self-checks that it will actually be able
   to claim it**, persists everything needed to claim (including arming its standard
   "watch this contract and claim it" state machine), and only then asks the gateway for an
   invoice. Order matters: the claim machinery exists *before* any money can move.
3. The gateway validates the request, creates an invoice on its backend (the backend picks its
   own payment hash), and returns the invoice plus a **signed quote** — a receipt binding that
   exact invoice to that exact contract, amounts, deadlines, and fee terms.
4. The wallet verifies the quote and shows the invoice. The payer pays it; the backend
   auto-settles. **From this instant the payer is irrevocably paid and the gateway owes the
   receiver.** There is no cancel or refund path on this leg — this "no abort once settled" fact
   shapes every rule below.
5. The gateway confirms the settlement against the backend's **authenticated ledger** (push
   notifications are only wake-up hints, never proof), then funds the receiver's contract from
   its ecash float — **exactly once**, with the exact funding transaction persisted before
   broadcast so no crash or retry can ever produce a duplicate.
6. The receiver's watcher sees the funded contract and claims ecash exactly as in trustless
   receive.

The federation just sees an ordinary contract funded and claimed: **zero consensus-module
changes**. What changes: a new gateway binary, the gateway HTTP API, the LNv2 client, and one
generic `fedimint-client` addition (a transaction prepare/submit split).

## What "custodial" means here — and what bounds it

The trust window opens when the invoice is issued and closes when the contract is funded. Inside
it, each party's exposure:

| Party | Exposure |
|---|---|
| **Payer** | If the gateway fails *after* the backend settles, the payer has paid and cannot be refunded. Their settlement preimage proves payment to the gateway's node, not to the receiver's contract — weaker proof-of-payment than trustless receive. |
| **Receiver** | From invoice issuance on, trusts the gateway to return an honest invoice (mitigated by checks below) and, after settlement, to actually fund the contract. A dishonest or dead gateway means the payer paid and the receiver got nothing. |
| **Gateway** | Fronts the contract from its ecash float after settlement; bears backend fee variance, liquidity cost, and liability risk. |

Users of a custodial gateway are trusting three things: **(a)** the operator's honesty to fund,
**(b)** the gateway's ability to durably persist its local state across the handoff (a crashed
gateway with an intact database delays funds, never loses them), and **(c)** the Lightning
backend's integrity — settlement confirmation is backend-attested, so a compromised backend
fabricating "settled" receipts could drain the gateway's ecash float over repeated cycles;
operators should reconcile attested receipts against backend node balance deltas. Physical
database loss, rollback, or key loss is explicitly out of scope, matching the broader Fedimint
assumption that local state is durably persisted and backed up.

This is strictly weaker than trustless receive, but far narrower than a custodial wallet: per
receive it is capped, evidenced by a signed receipt, and usually seconds long. Once the contract
is funded, the claim is fully trustless again.

## Safety rules, grouped

**Receiver protections.**
- The backend invoice's hash cannot match the contract, so the usual hash check is replaced by
  binding the invoice to the gateway's advertised Lightning node key (plus expiry checks).
  Because that key is self-asserted, custodial gateway URLs must be `https` (explicit
  localhost/onion/dev exceptions) and out-of-band sources should **pin the expected gateway
  module key** — a live probe is a consistency check, not a trust root.
- The wallet self-checks claimability *before* requesting an invoice (valid preimage, derivable
  claim key). An unclaimable contract is far worse custodially: the payer pays irreversibly for
  nothing. An invalid-preimage contract that slips through refunds to the gateway post-funding
  (never pocketed — it becomes an auditable liability); a decrypts-but-wrong-key contract is the
  receiver's own unrecoverable error, which is why the self-check is the real defense.
- The claim keys live inside the armed watcher state machine itself, which no rejection,
  deletion, or pruning path ever removes. Whatever goes wrong around it — including a buggy or
  malicious gateway response — a contract funded before its deadline is still claimed.
- The signed quote (which embeds the full fee/limit terms) is the receiver's dispute evidence: a
  third party can verify from federation history whether the quoted contract was never funded,
  funded-but-unclaimed, claimed, or refunded. It is evidence, not a recovery mechanism.
- The advertised custodial fee is capped at the existing receive limit (50 sats + 0.5%),
  enforced **component-wise** (base and proportional parts each within the limit — not the
  lexicographic struct comparison the trustless path happens to use today).

**Gateway correctness (exactly-once and crash safety).**
- Funding must happen exactly once: the federation does **not** deduplicate (funding one contract
  at two outpoints creates two claimable liabilities). The gateway enforces this with a durable
  per-receive status machine, at most one backend invoice per contract (a single-flight create
  lease; if a create request *might* have reached the backend but can't be proven, the receive
  goes to operator review rather than risking a second invoice), settlement handling serialized
  per contract, and a deterministic operation id that blocks resubmission across restarts.
- The funding transaction is finalized, its ecash inputs locked, and its exact bytes persisted
  **before** broadcast (the new `fedimint-client` prepare/submit split). Recovery re-drives that
  exact stored transaction — never rebuilds a fresh one — which is consensus-idempotent because
  its inputs can only be spent once.
- Settlement is confirmed ledger-first: webhooks/websockets only wake the reconciler; funding
  advances only on the backend's authenticated ledger. Any invoice rediscovered through crash
  recovery or reconciliation passes the same validation as the happy path; anything that cannot
  be safely funded becomes a durable, auditable **liability record**, never a silent drop.
- Two deadlines govern timing: the invoice expiry (the payment window, bounding unpaid exposure)
  and a much longer contract **funding deadline**, measured against the federation's consensus
  time, chosen so a settled invoice stays fundable across realistic downtime. Both are bounded
  above and below by advertised policy, and the gateway tracks consensus time by observing signed
  session outcomes (no new federation endpoint); it refuses to quote when its observation is
  stale, and the wallet independently sanity-checks the quote's deadline arithmetic.
- Issuance halts are scoped to who can trigger them: backend/operator-produced faults (duplicate
  correlation ids, settlements in the gateway's own correlation-id namespace that match no record
  — other activity on a shared backend is ignored — retention gaps, persistence failure) halt the
  whole backend; per-federation faults (a settled record's deadline slack running low) halt that
  federation. Conditions an anonymous client can trigger only ever reject that one request —
  never a halt — so the halt machinery cannot be turned into a denial-of-service lever.
- Required metrics expose contingent exposure, settled-but-unfunded debt, liabilities, float and
  liquidity shortfall, deadline slack, backend cursor lag and retention margin, observer
  freshness, retained-record pressure, and settlement-to-funding latency, recomputed from durable
  state on restart.

**Economics.** The payer pays `contract amount + receive_fee`. After settlement the gateway
fronts `contract amount + federation module fees` from float and is reimbursed by the Lightning
receipt minus any backend fee skim. Note the structural gap: the fee cap sits below phoenixd's
~1%-plus-mining-fee cost for automatic inbound-liquidity purchases, so any receive that triggers
one loses money by construction — and an attacker can deliberately force such purchases.
Operators must pre-provision inbound capacity, and the gateway may refuse issuance that would
force a liquidity purchase. Unpaid invoices are contingent exposure only: tracked and alerted,
but never reserved against float and never exposed as a public quota (a public quota would be a
DoS lever — an attacker could fill it with unpaid requests). Actual settled/funding/unresolved
obligations gate new issuance via a per-federation `max_in_flight` limit. If float runs short, a
settled receive waits as explicit debt while the operator replenishes (e.g. a pegin); the long
funding deadline exists so this resolves by funding the original contract.

## Deployment and discovery

- **Separate binary.** The MVP ships as a new `custodial-gatewayd`; the existing `gatewayd` and
  its trustless behavior are untouched. A dual-capable deployment (one operator offering both
  paths) is a distinct, heavier mode that must share the custodial receive registry with the
  trustless path; its cross-path enforcement and tests are deferred with it.
- **Not discoverable by legacy clients — on purpose.** Custodial-only gateways must not appear on
  the federation's legacy gateway list (old clients can't tell send-capability from
  receive-capability and would strand receives on them). There is no new discovery endpoint in
  the MVP: wallets get custodial gateway URLs **out-of-band** (operator config, app policy,
  explicit user entry), and that trusted source — not the network — is the authorization.
  Custodial receive is always an explicit opt-in with its own entry point; new clients'
  policy-driven selection also skips custodial-only gateways during normal trustless receive.
- **Self-payment quirk.** If a sender in the same federation pays a custodial invoice through the
  *same* gateway, the gateway can neither swap it internally nor route Lightning to itself. The
  send fails cleanly with a forfeit signature and the sender is refunded immediately (this
  outcome already falls out of existing code; the spec pins and labels it). The gateway must
  never register a custodial invoice as if it were a trustless one — that single rule prevents a
  wrong-preimage hazard.
- **Generic by design.** Any notify-only backend offering the same primitives (lookup of unpaid
  invoices by correlation id, an authenticated settled-payments ledger, declared retention) can
  reuse the whole path; phoenixd is the reference implementation.

## What gets built

Seven phases, each with a buildable spec in `custodial-receive-impl/`:

1. **`fedimint-client` prepare/submit split** (spec 01) — finalize + lock inputs + persist the
   exact transaction before broadcast; the exactly-once foundation and the riskiest piece.
2. **Public API semantics** (spec 02) — capability advertisement in `RoutingInfo`, the create
   endpoint, the signed quote/terms encoding, typed rejection reasons, the same-gateway
   forfeit-signature send outcome, and the rule that the legacy gateway list stays
   trustless-only.
3. **Notify-only backend trait + phoenixd adapter** (spec 03).
4. **`custodial-gatewayd`** (spec 04) — records, lease, observer, funding workers, audit,
   liabilities, metrics.
5. **Capability selection** (spec 05) — candidate sources, key pinning, policy-driven selection.
6. **Client `receive_custodial`** (spec 06) — provisional persistence, quote verification,
   conservative pruning.
7. **Deterministic test harness** (spec 07) — a fake notify-only backend with crash points; every
   test in the detailed spec's §15 mapped to a named test.

## When to use

Choose custodial receive when the operator wants phoenixd-grade simplicity and the federation
accepts a bounded operator-honesty trust on receive. Otherwise run a trustless gateway (LND/LDK,
optionally LSP-backed). **Send** stays trustless on the same backend; but remember a
custodial-only gateway is invisible to legacy discovery, so wallets that want it for send must
include its out-of-band URL in their send candidate set too.

## Status

Draft position: the "reuse the contract" design requires no consensus-module changes, but this is
pre-implementation and under review. Open items include `receive_fee` sizing within the existing
cap, concrete deadline/observer values, limit and alert thresholds, discovery/consent UX,
`api_version` evolution, audit timing, and richer liability taxonomy. See the detailed spec for
the full protocol, trust analysis, failure modes, and test plan.
