# Custodial Receive for Fedimint Gateways (notify-only Lightning backends)

> Status: **draft spec**. Builds on the current LNv2 receive design and earlier
> gateway/LSP research notes. Targets the LNv2 module (`fedimint-lnv2-*`).
> Scope decisions (stated for correction):
> (1) a **generic custodial-receive capability** for any notify-only backend, with
> **phoenixd as the reference backend**. (2) The **reuse-the-contract** design with
> **zero consensus-module changes** (no spend-rule or encoding changes, per §7.5). (3) **Receive-focused**: send remains the
> normal trustless flow (companion, §13). (4) **MVP-scoped**: the unmarked core is what an MVP must
> implement for correctness. Mechanisms tagged **(optional, post-MVP)** and the list of deferred
> non-goals in §14 are deliberately out of v1, since DB-intact recovery or simpler choices already
> cover correctness. Physical gateway DB loss, rollback before a receive record existed, and gateway
> key loss are out of scope (§16), matching the broader Fedimint assumption that local client/server
> state must be durably persisted and backed up.

## 1. Goal

Let a Fedimint LNv2 gateway offer Lightning **receive** to its federation users
when its Lightning backend **cannot do trustless receive**, i.e. a backend that
auto-settles incoming payments and exposes neither hold invoices nor HTLC
interception (phoenixd, and managed "node-in-a-box" stacks generally).

The gateway provides receive **custodially**: it takes the Lightning payment on its
own (backend-chosen) invoice, then funds the user's `IncomingContract` from its own
federation float so the user claims ecash normally. The trust degradation is
confined to a single, DB-intact crash-recoverable **handoff window**, not an ongoing balance.

## 2. Motivation & when to use

A small federation wants Lightning receive without running and babysitting an
LND/LDK node and its channels. A managed daemon like phoenixd gives "operator never
touches a channel," but its API hides the two primitives trustless receive needs
(see §4). Rather than abandon such backends entirely, this spec defines a
custodial fallback so they can still serve receive, with the trust cost made
explicit and bounded.

This is one of three receive options. Pick per deployment (full comparison §12):

| Option | Receive trust | Operator burden |
|---|---|---|
| **Trustless gatewayd** (LND/LDK, optionally LSP-backed) | trustless | runs a node, manages (or LSP-outsources) channels |
| **Custodial-receive gatewayd** (this spec) | custodial at handoff | runs a notify-only daemon, near-zero channel ops |
| **gateway-lite** (proxy via another federation) | trust the host federation's gateway | none locally, depends on a remote gatewayd |

Custodial-receive is the right call when the operator wants phoenixd-grade
simplicity and the federation accepts a bounded, operator-honesty trust assumption
on the receive path.

## 3. Background: the trustless LNv2 receive being relaxed

The normal LNv2 receive is atomic via a hold invoice + threshold-decrypted preimage.
The invariant: the gateway can obtain the preimage (and thus get paid) **only** by
funding the contract. The federation reveals the preimage only after funding. The
receiver claims the funded contract for ecash. On any failure the HTLC is
**cancelled back** to the payer. Concretely the gateway must be able to:

1. **hold** an incoming HTLC across a multi-second federation round-trip, and
2. **settle it with an externally-obtained preimage**, or **cancel** it.

## 4. Why a notify-only backend can't do that

phoenixd (and similar) generate their **own** preimage and **auto-settle** every
incoming payment. They cannot create an invoice for an externally-chosen
`payment_hash`, cannot hold an HTLC, and expose no settle/cancel hook. So:

- they can't mint the hold invoice LNv2 receive requires, and
- there's no cryptographic loophole: the federation only ever reveals the preimage
  for the contract's `payment_image`, so a backend-chosen-hash HTLC could never be
  settled by the federation's preimage anyway. (The receiving client also rejects a
  mismatched invoice, `modules/fedimint-lnv2-client/src/lib.rs:977`.)

The only remaining path is to stop trying to make the Lightning receipt *atomic*
with the contract, and instead bridge them custodially.

## 5. Design principle: reuse the contract, change the trigger

The receiver keeps its **normal** `IncomingContract` (it still owns its own
preimage). Only the event that causes the gateway to **fund** that contract changes:

```
trustless:  intercept+hold HTLC → fund contract → federation reveals preimage
            → SETTLE HTLC → receiver claims

custodial:  backend's own invoice is paid & auto-settled → gateway has the money
            → gateway FUNDS the receiver's contract → receiver claims
            (no hold, no HTLC settle, no preimage gating — gateway already got paid)
```

**Why this is sound at the server layer:** the LNv2 incoming-contract spend rule
(`modules/fedimint-lnv2-server/src/lib.rs:508-532`) gates a claim on **only** three things:
contract funded, valid `agg_decryption_key`, valid preimage → routed to `claim_pk`.
It **never checks who funded the contract**, and never sees an invoice or HTLC.

Because the receiver encrypted its own valid preimage, the funded contract routes to
the receiver's `claim_pk` and the receiver's existing claim machinery works unchanged.

**No fedimint consensus-module change is required**. The required changes are in the gateway,
gateway API, LNv2 client, and generic `fedimint-client` transaction-preparation APIs (§7). The
federation's server module is untouched.

**Economic model (unchanged from trustless):** the gateway funds the contract from
its **federation ecash float** and is reimbursed by the Lightning receipt in its
backend, exactly as a trustless gateway fronts ecash and is reimbursed by settling
the HTLC. The only difference is sequencing and the trust that bridges it.

## 6. Protocol

Actors: **Receiver** (federation client), **Gateway**, **Backend** (phoenixd),
**Payer** (external), **Federation**.

```
Receiver                              Gateway                  Backend        Federation
   │ 1. routing_info ───────────────────▶│
   │  ◀── receive_capabilities.custodial │
   │ 2. build IncomingContract           │
   │    (own preimage P, claim_pk,       │
   │     refund_pk=gateway, TPE→agg),    │
   │    persist provisional receive,     │
   │    arm ReceiveSM (watch contract)   │
   │ 3. create_custodial_bolt11_invoice ▶│ 4. reserve InvoiceCreating(QuoteDraft),
   │    (contract, amount)               │    createinvoice(externalId) ─▶│ (own hash H′,
   │                                     │    ◀── invoice ────────────────│  preimage P′)
   │                                     │ 5. sign quote, then commit AwaitingPayment
   │                                     │    (fed-client DB, including signed_quote)
   │  ◀── invoice(H′) + quote ───────────│
   │ 6. verify quote/payee/expiry        │
   │    (skip hash check), store quote   │
   │                                     │
   │                  7. Payer pays invoice(H′) ──────────────▶│ auto-settles
   │                                     │ 8. invoice-settled(H′, A) ◀─────│
   │                                     │ 9. ledger-confirm, look up by externalId
   │                                     │ 10. prepare + submit funding tx ──────────▶│
   │                                     │     (gateway ecash inputs → contract output) │
   │                                     │                           11. store contract, │
   │                                     │                               emit dk shares  │
   │ 12. ReceiveSM sees contract funded, claim with locally-precomputed               │
   │     agg_decryption_key (valid → claim_pk) ─────────────────────────────────────▶│
   │ 13. ◀── ecash ─────────────────────────────────────────────────────────────────│
```

Steps 2, 6, 12-13 are the receiver's **existing** receive machinery (step 2 adds the provisional
persist and pre-armed watcher — before the request leaves, §7.4 — and step 6 relaxes the hash
check and adds quote verification). Steps 8-11 are the gateway's
new custodial path. The federation side (10-11) is the **existing** `process_output`
contract funding.

**Receiver claim (step 12):** the receiver decrypts with an `agg_decryption_key` it
**precomputes locally** from its own secret key and the contract's `ephemeral_pk`
(`modules/fedimint-lnv2-client/src/lib.rs:1046`) and submits directly in the claim input.
It does **not** request the federation's per-peer decryption shares. (Those shares,
emitted at step 11, are consumed by the *gateway's trustless* receive path. The
custodial receiver never needs them.) So the receiver's claim is fully self-contained
once the contract is funded, and it still works when the gateway funds it outside any
HTLC flow.

**Two deadlines (step 3):** the backend invoice's expiry must be **strictly earlier**
than the contract's funding deadline. Invoice expiry bounds the unpaid contingent exposure; once the
backend invoice settles, the gateway owes the receiver until the original contract is funded. The
funding deadline is the contract's `expiration_or_fee`, interpreted against the LNv2 server's
`consensus_unix_time` (`modules/fedimint-lnv2-server/src/lib.rs:563`), and is only the federation's
admission check for funding the original contract. For custodial receive the client chooses a
long-lived funding deadline, within the gateway's advertised minimum and maximum bounds (§7.1, §8),
so settled invoices remain automatically fundable. For MVP, the gateway
does **not** require a new federation endpoint for this value: it derives a
`gateway_observed_lnv2_consensus_time` by watching existing signed session outcomes, tracking the
latest `UnixTimeVote` per guardian, and applying the same threshold-time selection used by the LNv2
server. If that observer has not seen fresh threshold votes, custodial receive quote creation is
unavailable.

## 7. Component changes

### 7.1 Capability advertisement: `RoutingInfo`

Add an optional receive-**capability** descriptor to `RoutingInfo`
(`modules/fedimint-lnv2-common/src/gateway_api.rs`), backward-compatible (absent ⇒
trustless-only legacy gateway):

```rust
pub struct ReceiveCapabilities {
    pub trustless: Option<TrustlessReceiveCapability>,
    pub custodial: Option<CustodialReceiveCapability>,
}

pub struct CustodialReceiveCapability {
    pub receive_fee: PaymentFee,              // pre-request fee used to size the contract
    pub max_receive_amount: Amount,           // per-receive cap (§9)
    pub max_in_flight: Amount,                // aggregate settled/funding liability target, per federation (§9)
    pub min_invoice_to_funding_deadline_delta_secs: u64, // invoice-expiry to funding-deadline gap; MUST be > 0 (strictly-earlier rule, §8)
    pub min_contract_lifetime_secs: u64,      // minimum lifetime from observed consensus time (§8)
    pub max_invoice_expiry_secs: u64,         // upper bound on requested invoice lifetime (§8)
    pub max_funding_deadline_secs: u64,       // upper bound on funding deadline past observed consensus time (§8)
    pub consensus_time_observation_max_age_secs: u64, // stale-observer budget (§8)
    pub safety_margin_secs: u64,              // extra gateway policy margin (§8)
    pub invoice_amount_granularity_msats: u64, // phoenixd = 1000 (sat-only backend, §7.4)
    pub backend_retention_secs: u64,          // declared backend ledger retention (§7.2); mirrored in terms so every terms field has an advertised counterpart (§7.4)
    pub quote_api_version: u16,               // CustodialReceiveQuote version the gateway signs (§7.3)
}

// RoutingInfo {
//     #[serde(default = "ReceiveCapabilities::legacy_trustless")]
//     receive_capabilities: ReceiveCapabilities,
// }
// Absent field ⇒ ReceiveCapabilities { trustless: Some(default), custodial: None }.
```

A capability struct (not a binary `Trustless | Custodial` mode) lets a gateway advertise
trustless receive, custodial fallback, or custodial-only receive, and carries the limits the
client needs to size and select, not just a flag. `RoutingInfo` derives no Fedimint
`Encodable`/`Decodable` — its wire surface is serde JSON (plus std traits including `Hash`,
`gateway_api.rs:142`) — so this
is a `#[serde(default)]` add. `CustodialReceiveCapability.receive_fee` is the fee the client uses to
size the custodial contract before requesting the backend invoice. The top-level legacy
`RoutingInfo.receive_fee` remains the trustless-receive fee for existing clients. A dual-capable
gateway may set the two equal, but the custodial client must use the mode-specific custodial fee and
must reject a quote whose `terms.receive_fee` differs from the advertised fee it used to construct
the contract. If the gateway changes fees between selection and request, the request is rejected
with `FeeOrAmountBindingMismatch` (§7.9) before backend invoice creation and the client
reselects/retries with fresh `RoutingInfo`. The
deadline-policy fields intentionally duplicate fields later embedded in `CustodialReceiveTerms`:
`RoutingInfo` is the pre-request policy the wallet needs before it builds an `IncomingContract`,
while the signed quote is the exact per-receive commitment the client verifies and stores.

Selection becomes **policy-driven**, not a reuse of the generic reachability-based
`select_gateway` (`modules/fedimint-lnv2-client/src/lib.rs:481`):

- New wallets build a **gateway candidate set** as the union of:
  - federation-provided legacy `GATEWAYS_ENDPOINT` URLs, which remain trustless-receive compatible;
  - wallet/app/operator-supplied custodial gateway URLs, which are authorized only by that trusted
    source or by explicit user consent, then live-probed via `/routing_info` for the target federation.
  Each candidate is annotated with its source (`LegacyFederationList` or `OutOfBandCustodial`) and
  live `RoutingInfo`. A custodial candidate URL MUST use `https` (or an explicitly configured
  exception: localhost/loopback, `.onion`, or a deliberate insecure-dev flag): every key the client
  later verifies against chains to this probe, so a cleartext probe hands a network MITM the whole
  gateway identity. An out-of-band source SHOULD supply candidates as
  `(url, expected_gateway_module_pk)` pairs; when a pin is present, the probed
  `RoutingInfo.module_public_key` and every quote's `gateway_module_pk` MUST match it, upgrading
  the binding from "whoever answers this URL" to a key the trusted source chose.

The live `/routing_info` probe is a capability and key-consistency check, not an authorization
source. A custodial-only URL learned from an untrusted channel must not become eligible merely
because it responds. The client stores the candidate source with the operation metadata and surfaces
it in consent / support UI.

- `select_gateway_for_receive(policy)`: trustless receive **skips** any custodial-only gateway
  (`custodial.is_some() && trustless.is_none()`) and continues to the next reachable trustless
  gateway, so a normal receive never strands on a custodial-only gateway. Custodial receive
  requires explicit opt-in (§7.4), starts from wallet-supplied candidate gateway URLs, and selects
  only gateways whose live `RoutingInfo` has `custodial.is_some()`.
- `select_gateway_for_send(invoice, policy)`: a sender can't reliably tell from a Bolt11 invoice
  that it's custodial, so it doesn't pre-classify arbitrary invoices. It considers the same union
  candidate set. If the invoice payee key matches a trustless-capable candidate, preserve today's
  direct-swap preference. MVP does **not** add pre-funding custodial self-pay classification or
  alternate-gateway reselection. A same-payee gateway hitting its own custodial invoice returns a
  **forfeit signature** so the sender refunds the funded contract (the **required outcome**, which
  already emerges from the failed registered-contract lookup; the custodial pending-receive registry
  lookup labels it, §7.6). **(Optional,
  post-MVP)** a `select_gateway_for_send(avoid_payee_gateway = true)` reselection can avoid this
  wasted funding/refund round-trip, but it must happen **pre-funding** so the alternate gateway is the
  contract's `claim_pk` from the start (there's no in-place reroute after funding, §7.6).

Custodial receive is still exposed via a **separate endpoint** (e.g.
`create_custodial_bolt11_invoice`) gated behind an API version, with a custodial-only gateway
rejecting the normal `create_bolt11_invoice` with an explicit error (it can't mint the hold
invoice that path expects). Since the MVP does **not** add a federation
`CUSTODIAL_GATEWAYS_ENDPOINT`, custodial discovery is out-of-band: the wallet/app/operator supplies
candidate URLs by some non-protocol mechanism (for example local config, app policy, or a future
Nostr-style announcement). After a candidate URL is known, the wallet queries `/routing_info` with
the federation id and treats `RoutingInfo.receive_capabilities` as the live authority for whether
that gateway supports trustless receive, custodial receive, or both. The separate custodial endpoint
makes a trustless client that somehow reaches a custodial-only gateway fail fast and cleanly.

The existing `GATEWAYS_ENDPOINT` remains the trustless-compatible legacy gateway list. A gateway
that cannot satisfy the normal trustless receive endpoint MUST NOT appear there, even if it can
support send, because legacy clients cannot distinguish send and receive capabilities and may strand
receive on that gateway. A gateway that supports both trustless receive and custodial receive can
remain in the legacy list. A custodial-only gateway is invisible to legacy clients: it is reachable
for custodial receive only if the wallet obtains its URL out-of-band and then verifies the live
custodial capability via `RoutingInfo`.

**Binary / deployment boundary:** the preferred MVP implementation is a separate operator binary,
tentatively `custodial-gatewayd`, rather than adding custodial receive inline to the existing
`gatewayd` request handlers. Existing `gatewayd` remains the legacy-compatible trustless gateway.
`custodial-gatewayd` owns the custodial receive endpoint, durable receive state, backend settlement
observation, ledger reconciliation, exactly-once funding, liability records, quote signing, and
metrics. A custodial-only instance MUST NOT register in the legacy `GATEWAYS_ENDPOINT`; wallets may
learn its URL out-of-band and must verify custodial support through `RoutingInfo`. Shared startup,
config, client, or key-management helpers may be factored out if needed, but the MVP goal is to avoid
changing existing `gatewayd` behavior and legacy discovery semantics.

**Deployment modes are load-bearing.** The MVP must distinguish two modes:

1. **Custodial-only, out-of-band mode.** `custodial-gatewayd` is not registered in the legacy
   `GATEWAYS_ENDPOINT`, and new wallets reach it only through wallet/app/operator-supplied candidate
   URLs. This is the preferred MVP shape and can avoid changing existing `gatewayd` request handling.
   If this process also exposes trustless send for new wallets, a same-payee custodial invoice
   already cancels with a forfeit signature when the registered-contract lookup fails (§7.6);
   inspecting the custodial pending-receive registry lets the handler label that cancellation as
   custodial self-pay instead of a generic registration error.
2. **Dual-capable mode.** A gateway that advertises both trustless and custodial receive and remains
   in `GATEWAYS_ENDPOINT` must run the send/direct-swap path with access to the custodial pending
   receive registry. That can be one process, a shared DB-backed receive registry, or a local service
   call from `gatewayd` to `custodial-gatewayd`, but it must be atomic enough for invoice creation on
   either path to enforce the cross-path namespace invariant (§7.3) and for the direct-swap path to
   label a same-payee custodial invoice precisely; the forfeit-refund outcome itself already emerges
   from the failed registered-contract lookup (§7.6). A dual-capable gateway
   is not the "no existing gatewayd behavior change" path.

A deployment SHOULD NOT share one Lightning node key and gateway module key between a legacy-listed
`gatewayd` and a separate `custodial-gatewayd` unless the two processes share the custodial receive
registry. The failure mode is **not** a stuck sender: an unregistered same-gateway custodial invoice
already cancels through `Cancelled::RegistrationError`
(`modules/fedimint-gwv2-client/src/send_sm.rs:203`), and every `Cancelled` outcome already returns
the forfeit signature that refunds the sender (`modules/fedimint-gwv2-client/src/lib.rs:379-388`).
What is lost without a shared registry is the creation-time cross-path namespace enforcement (§7.3)
and custodial-aware reason reporting — and the refund outcome comes to depend silently on the
registered-contract lookup continuing to fail with an error for unknown hashes.

### 7.2 Backend abstraction: notify-only receive

The backend reports capabilities. A notify-only backend declares it **cannot** do
trustless receive and instead supports two custodial primitives:

```rust
struct LightningCapabilities { trustless_receive: bool, /* … */ }

// notify-only backend must provide:
fn create_plain_invoice(amount, description, expiry, external_id) -> Bolt11Invoice; // own hash; external_id = gateway correlation id
fn get_invoices_by_external_id(external_id, include_unpaid) -> Vec<BackendInvoice>; // crash-safe issuance lookup (§7.3); >1 result = backend-invariant violation
fn subscribe_invoice_settled() -> Stream<Item = SettlementHint>;                    // low-latency wakeup, not proof
fn list_settled_invoices(cursor, from, to) -> Page<SettledInvoice>; // authenticated ledger, paginated
fn get_settled_invoice_by_hash(hash) -> Option<SettledInvoice>;                             // authenticated point lookup
```

The push stream is a **hint** (a wakeup), and the paginated ledger queries are the **proof**
(§7.3). Hints must still pass backend authentication where available (phoenixd
`X-Phoenix-Signature` on webhooks) before waking reconciliation, so a forged stream can't create
cheap load. Backend adapters must expose **cursor semantics explicitly**: if the backend only has
offset pagination, the adapter uses a high-watermark (`completed_at_ms`) plus an overlap window
and de-dupes by `backend_invoice_hash` / `backend_correlation_id`. Offset alone is not a valid
durable cursor (newer payments can shift offsets, missing or duplicating records). The cursor is
**rebuildable**, not a source of truth: on loss the gateway point-looks-up **every nonterminal
authoritative record and every retained `InvoiceCreateInconclusive`, `InvoiceExpiredUnpaid`,
`BackendInvoiceRejected`, or `InvoiceExpiredUnreturned` tombstone** (the `AwaitingPayment` and other
nonterminal `PendingCustodialReceive` entries, plus retained terminal records, that persist in the
federation client DB prefix) by `backend_correlation_id` /
`backend_invoice_hash`, driven by the records themselves rather than a fixed time window (downtime
can exceed any window). This works **within backend ledger retention**, which is a **hard
prerequisite**, not just something to monitor: ledger-first recovery is only as good as the ledger's
historical horizon. The backend adapter must **declare** that retained settlement history covers every
record that could still affect a liability: unpaid records until invoice expiry plus late-settlement
finality, and settled records until the receiver is funded. If it can't establish coverage of all
nonterminal records and retained tombstones, **new custodial invoice creation is disabled** (distinct
from the optional *runtime* retention monitoring in §7.8). phoenixd documents listing and point lookup
of incoming payments but **no retention SLA**, so phoenixd support treats retention as an
operator-configured, monitored assumption rather than a backend guarantee. The advertised
`max_invoice_expiry_secs` / `max_funding_deadline_secs` bounds (§7.1, §8) exist partly to keep this
coverage obligation finite: without them, a single long-dated request could make declared coverage
unsatisfiable and shut off all new issuance through this gate. A recovery-relevant record
whose invoice predates available retention **can't be confirmed** and goes to the unresolved-liability
path (§7.7, §11), never a silently missed settlement. So losing the cursor (a rebuildable index) to
logical corruption stays a recoverable rebuild from the surviving records and ledger (§11).

For phoenixd: `create_plain_invoice` → `POST /createinvoice` carrying `externalId` and an optional
per-invoice `webhookUrl`. `get_invoices_by_external_id` and `list_settled_invoices` /
`get_settled_invoice_by_hash` → the upstream incoming-payment list and lookup endpoints.
`subscribe_invoice_settled` → the `/websocket` or webhook payment-received stream. `route_htlcs`
returns an inert stream and `complete_htlc` is never invoked. (LND/LDK already expose equivalent
invoice-settled streams, so the same custodial path could run on them too, but they don't need it,
since they can do trustless receive.)

### 7.3 `custodial-gatewayd` custodial-receive service

New `custodial-gatewayd` logic, per connected federation:

1. **On `create_custodial_bolt11_invoice`**: validate the contract (`contract.verify()`,
   `refund_pk == module_public_key`) as today.
   It must also **bind the amounts before issuing the invoice or signing the quote**: reject unless
   `contract.commitment.amount == receive_fee.subtract_from(invoice_amount)` (§8), so a small backend
   invoice can never later fund an oversized contract. Because `PaymentFee::subtract_from` saturates,
   this check must be preceded by an explicit lower-bound check that does not rely on equality after
   saturation: a zero-valued or below-minimum incoming contract is rejected with `AmountTooSmall`
   before backend invoice creation. A binding failure at or above the minimum — including a contract
   sized with a stale advertised fee — is rejected with `FeeOrAmountBindingMismatch` (§7.9), so the
   client knows to refresh `RoutingInfo` and rebuild; both rejections happen before backend invoice
   creation.
   The gateway derives a stable `client_request_id =
   H("custodial-receive-v1" || federation_id || contract_id || gateway_module_pk)` **from the
   request's own contract identity** (not a trusted supplied value, and it binds the gateway's
   durable module key, not the mutable URL). It confirms its
   `gateway_observed_lnv2_consensus_time` is fresh enough and the requested contract is not too close
   to expiry (§8), then builds and **atomically reserves** an `InvoiceCreating` quote draft keyed for
   uniqueness on **`(federation_id, contract_id)`** so there's never more than one outstanding backend
   invoice per contract. While that record persists, a duplicate request must not create a second
   backend invoice; after `AwaitingPayment` exists, a duplicate returns the stored invoice and quote
   if the invoice is still safe to return under the same staleness rules recovery applies (an
   expired or otherwise unsafe stored invoice yields `BackendInvoiceUnreturnable` while the record
   stays in reconciliation). Once the backend ledger has confirmed settlement, staleness no longer
   applies: a same-fingerprint duplicate of a settled/funding/funded record returns the stored
   invoice and quote unconditionally — the invoice cannot be paid twice and the signed quote is
   the durable receipt the client needs. An in-flight `InvoiceCreating` is handled by a
   **single-flight backend-create lease**. A
   handler may call `create_plain_invoice` only after atomically acquiring or renewing the
   `backend_create_lease` and marking the draft `backend_create_maybe_sent = true` before the backend
   request can leave the process. A duplicate request that finds an unexpired lease waits, returns
   "in progress", or polls the stored record; it must not call the backend. If the lease expired
   after a crash, recovery first calls `get_invoices_by_external_id`. If the backend invoice exists,
   recovery proceeds through the validation below. If it does not, and the draft was ever marked
   `backend_create_maybe_sent`, the MVP treats the attempt as unprovable: the record becomes
   `InvoiceCreateInconclusive` for operator review and the gateway must not issue a second backend
   invoice for the same contract. (A backend-declared create-visibility barrier that would make a
   not-found lookup authoritative and allow a safe retry is deferred, §14: phoenixd declares no such
   guarantee, so that branch would be dead code in the MVP.) A retry without operator review is
   allowed only when the draft is still fresh and no create attempt was ever marked maybe-sent. A duplicate request whose request fingerprint differs from the
   stored draft is rejected with `DuplicateContractConflict` (or an operator-visible invariant
   violation if it suggests corruption). The gateway then calls `create_plain_invoice` with the
   draft's opaque `backend_correlation_id` as the backend `externalId` (so no raw federation or
   contract IDs leak into backend-visible metadata). It uses an invoice expiry **strictly earlier than
   the contract's funding deadline** (§8). For backends that take relative expiry, the adapter derives
   the relative value from the draft's absolute `invoice_expiry` at the moment it holds the
   backend-create lease; if the derived relative expiry is below the minimum safe value, the draft is
   stale and no backend invoice is created. Before signing, the gateway parses and validates the
   returned BOLT11 invoice against the persisted draft: amount, payee, expiry within the adapter's
   tolerance, description hash / direct description, payment hash, and backend granularity/kind
   assumptions must all match. If validation fails, the gateway retains a reason-tagged
   `BackendInvoiceRejected` tombstone for reconciliation, disables new custodial invoice creation if
   the mismatch indicates backend corruption, and does not return the invoice:

   ```rust
   enum BackendInvoiceRejectedReason {
       StaleOrExpiredButOtherwiseValid,
       AmountMismatch,
       PayeeMismatch,
       DescriptionMismatch,
       ExpiryOutOfTolerance,
       PaymentHashMismatch,
       BackendKindOrGranularityMismatch,
       DirectSwapNamespaceCollision,
       BackendInvariantViolation,
   }

   enum FundOnSettlement {
       FundOriginalContract,
       OpenUnresolvedLiability,
   }
   ```

   Each retained tombstone that a settlement may still match (`InvoiceExpiredUnpaid`,
   `BackendInvoiceRejected`, `InvoiceExpiredUnreturned`, retained `InvoiceCreateInconclusive`)
   carries a `fund_on_settlement` policy; for `InvoiceExpiredUnpaid` it is always
   `FundOriginalContract` (its invoice was returned and passed validation). Only
   stale/expired-but-otherwise-valid invoices and explicitly safe `InvoiceCreateInconclusive`
   recoveries may return to automatic funding when settlement is proven. Amount, payee, payment-hash,
   namespace, granularity, or backend-invariant failures open `UnresolvedLiability` / `BackendMismatch`
   with the retained draft and backend ledger proof instead of blindly funding the original contract.
   Otherwise it signs the quote using the stored draft plus the returned backend invoice hash, and
   **commits the full `AwaitingPayment` record including `signed_quote` before returning**, advancing
   `InvoiceCreating → AwaitingPayment`.
   A crash after backend invoice creation but before the `AwaitingPayment` commit is recovered by
   querying the backend by `externalId` (`get_invoices_by_external_id`). The recovered backend invoice
   must then pass the same draft validation and direct-swap namespace reservation as the happy path
   before any quote is signed or any funding path is activated. Recovery must not sign or fund from an
   invoice that would have been rejected during initial creation. A backend that can't look up unpaid
   invoices by external id can't support crash-safe custodial invoice creation. If the
   **authoritative federation client DB prefix itself is lost or rolled back**, the receive record is
   gone. That is operator data loss and out of scope for this spec (§10, §16), not a path that creates
   a fresh receive from a client-supplied quote.

   The record is **state-variant**: its fields are populated progressively as `status` advances, not
   all at once. `InvoiceCreating` is not just a lock; it persists a **quote draft** before the backend
   call:

   ```rust
   struct CustodialReceiveQuoteDraft {
       quote_id: sha256::Hash,
       client_request_id: sha256::Hash,
       backend_correlation_id: String,
       federation_id: FederationId,
       contract_id: ContractId,
       contract: IncomingContract,
       invoice_amount: Amount,
       backend_requested_sat: u64,
       invoice_description_hash: sha256::Hash,
       backend_invoice_expiry_request: BackendInvoiceExpiryRequest,
       contract_amount: Amount,
       invoice_expiry: u64,
       funding_deadline: u64,
       observed_lnv2_consensus_time: u64,
       terms: CustodialReceiveTerms,
       gateway_api: SafeUrl,
       gateway_module_pk: PublicKey,
       gateway_ln_pk: PublicKey,
       created_at: u64,
       backend_create_attempt: u64,
       backend_create_lease_until: Option<u64>,
       backend_create_maybe_sent: bool,
       request_fingerprint: sha256::Hash,
   }
   ```

   `InvoiceCreating` holds `{ quote_draft, status }` and **no `backend_invoice_hash` yet**, since the
   backend invoice does not exist until `create_plain_invoice` returns. The draft is the durable
   policy decision: retries and crash recovery must use it rather than recomputing fees, deadlines,
   terms, keys, URLs, or observed consensus time from current config.
   `request_fingerprint` is the canonical hash of the duplicate-sensitive **request payload**:
   contract identity, invoice amount, invoice description hash, requested invoice expiry, and
   requested quote API version — computed by the same shared function on client and gateway from
   payload fields only, never from either side's current fee/policy config (a config change must not
   reclassify an identical retry as a conflict). The selected fee/policy needs no fingerprint input:
   it is bound through the amount-binding check, and an idempotent duplicate receives the stored
   signed quote, not a re-quote. The fingerprint is how the gateway distinguishes an
   idempotent duplicate from a conflicting request for the same contract.
   `backend_create_maybe_sent` records that a non-idempotent backend create request may have reached
   the backend; an expired local lease alone is not proof that it did not, and the MVP never retries
   a maybe-sent create whose invoice a lookup cannot find — such a record becomes
   `InvoiceCreateInconclusive`. That retained record remains in ledger reconciliation by
   `backend_correlation_id`: if the maybe-sent invoice later appears or settles, the recovered invoice
   must pass the same draft validation and direct-swap namespace reservation as the original create
   path, then follows its `fund_on_settlement` policy instead of being silently missed.

   The draft is still bounded by freshness. If no backend invoice exists yet, a handler may call
   `create_plain_invoice` only while the draft still satisfies the create-time safety checks:
   the invoice expiry is in the future with enough client/payment slack, the funding deadline still
   satisfies the consensus-time deadline rule, and the observer is fresh enough. If those checks no
   longer hold, the gateway tombstones the draft as `InvoiceCreationExpired` / rejected and asks the
   client to build a fresh contract. It must not create a backend invoice from a stale draft.

   If a backend invoice already exists but `AwaitingPayment` was not committed, recovery completes the
   signed quote from the draft only if the invoice is still safe to return. If it is expired or too
   close to the funding deadline, the gateway keeps a retained tombstone for late-settlement
   reconciliation (`BackendInvoiceRejected` / `InvoiceExpiredUnreturned`) and returns
   `BackendInvoiceUnreturnable` instead of exposing a stale invoice to the client.

   A settlement matching a retained unreturned-invoice tombstone never disappears. It follows the
   tombstone's `fund_on_settlement` policy: safe stale/unreturned invoices transition back to the
   automatic funding path for the original quoted contract with `UnreturnedInvoiceSettled` evidence
   while the funding deadline has not passed in observed consensus time (after it, the settlement
   opens an `UnresolvedLiability` instead, see the status-machine rules below);
   unsafe validation, namespace, granularity, or backend-invariant failures transition to
   `UnresolvedLiability` / `BackendMismatch` with the backend ledger proof and retained draft as
   evidence. The client may have been told the invoice was rejected, but if the backend ledger proves
   settlement the gateway must either fund the original contract or retain an auditable liability for
   why automatic funding would be unsafe.

   The `AwaitingPayment` commit adds
   `{ quote_id, backend_invoice, backend_invoice_hash, backend_requested_sat, invoice_amount,
   contract_amount, invoice_expiry, funding_deadline, signed_quote, created_at }` (the full
   `backend_invoice` BOLT11 string is stored because idempotent duplicates and post-settlement
   retries must answer `Created { invoice, quote }` from the stored record alone — an invoice is
   not reconstructible from its hash, and a backend lookup would fail exactly when the backend is
   unreachable or the record is past backend retention; `invoice_expiry` and
   `funding_deadline` drive `InvoiceExpiredUnpaid`, retention, and late-settlement handling, §7.3
   limits, and the **`signed_quote`** is stored with embedded `terms` so a retry can return the
   original self-contained quote, §7.3, and a liability carries its evidence, §7.7). The funding
   phases add
   `{ prepared_tx, input_reservation, operation_id, txid }` (the ecash-input reservation is
   authoritative and committed atomically with `FundingPrepared`, §7.3) and finally `outpoint` (§7.3). So the full `PendingCustodialReceive` at `AwaitingPayment` is
   `{ quote_id, client_request_id, backend_correlation_id, backend_invoice, backend_invoice_hash,
   backend_requested_sat, federation_id, contract, invoice_amount, contract_amount, invoice_expiry,
   funding_deadline, signed_quote, created_at, status }`. A crash after backend invoice creation
   but before storing the invoice hash is recovered by querying the backend by `externalId` and
   completing the quote from the stored `quote_draft`. A backend that can't look up unpaid invoices
   by external id can't support crash-safe custodial invoice creation. **Uniqueness is the gateway's
   `(federation_id, contract_id)` reservation, not
   the backend**: phoenixd documents `externalId` as lookup metadata, not a unique or idempotent
   key, so the adapter treats a lookup that returns **more than one** invoice for a single
   `backend_correlation_id` as a backend-invariant violation (recorded as
   `BackendInvoiceRejectedReason::BackendInvariantViolation`, duplicate `externalId`) that
   disables new custodial invoice creation and routes the record to operator review, never silently
   picking one. (Halting issuance rather than quarantining the one record is deliberate: duplicate
   external ids mean correlation-id aliasing, and reconciliation relies on correlation ids for
   settlement attribution, so continuing to issue against an aliasing backend risks misattributing
   settlements beyond the affected record.) Return the backend invoice plus a gateway-signed custodial receive quote:

   ```rust
   struct CustodialReceiveQuote {
       quote_id: sha256::Hash,          // unique handle for one receive
       api_version: u16,
       backend_kind: String,            // e.g. "phoenixd"
       backend_correlation_id: String,  // opaque externalId, see below
       federation_id: FederationId,
       contract_id: ContractId,
       contract: IncomingContract,
       backend_invoice_hash: sha256::Hash,
       invoice_amount: Amount,          // Fedimint msat amount requested from payer
       backend_requested_sat: u64,      // exact backend API amount for sat-only backends
       contract_amount: Amount,
       created_at: u64,
       invoice_expiry: u64,
       funding_deadline: u64,
       observed_lnv2_consensus_time: u64, // gateway_observed_lnv2_consensus_time used for §8
       terms: CustodialReceiveTerms,    // self-contained fee/limit/backend terms in effect
       gateway_api: SafeUrl,
       gateway_module_pk: PublicKey,
       gateway_ln_pk: PublicKey,
       signature: Signature,
   }

   struct CustodialReceiveTerms {
       receive_fee: PaymentFee,
       max_receive_amount: Amount,
       max_in_flight: Amount, // aggregate settled/funding liability target per federation, not unpaid gating
       min_invoice_to_funding_deadline_delta_secs: u64,
       min_contract_lifetime_secs: u64,
       max_invoice_expiry_secs: u64,
       max_funding_deadline_secs: u64,
       consensus_time_observation_max_age_secs: u64,
       safety_margin_secs: u64,
       invoice_amount_granularity_msats: u64,
       backend_retention_secs: u64,
   }
   ```

   `quote_id` is a unique handle for one receive (the MVP doesn't re-issue quotes, so it needn't be
   deterministic). The signature covers the embedded `terms` along with every other field: a BIP-340-style
   tagged hash (tag `"fedimint-custodial-receive-quote-v1"`) of the canonical encoding without the
   signature field, signed by `gateway_module_pk` (byte-exact construction in the implementation
   specs). (A separate `terms_hash` field was deliberately dropped: it would only be a
   checksum of data already embedded and signed in the same struct, §14.) The domain tag stops the signature being reused in another context, and
   `created_at` plus the signature give replay protection. `observed_lnv2_consensus_time` records
   the gateway-observed federation time used for the deadline rule in §8, so the quote's deadline
   arithmetic is auditable against the advertised terms. It does **not** prove observer freshness by
   itself; freshness is a gateway hard gate before signing, backed by metrics (§7.8), not a
   client-verifiable property of the quote. `gateway_module_pk` is the gateway's self-asserted
   `RoutingInfo.module_public_key` (the same key the client sets as the contract `refund_pk`), so the
   quote is an auditable record of operator intent, not an independent cryptographic root of trust.
   This quote replaces the missing invoice-hash binding with an auditable gateway commitment: if the
   backend invoice settles, this gateway has committed to fund this exact contract for this
   federation under the embedded terms. The receiver stores the full quote, including `terms`, with
   the receive operation as dispute/support evidence and as the receipt for what the gateway
   committed to do. It is not a protocol guarantee that the gateway can safely rebuild lost
   authoritative state.
2. **Settlement observation is ledger-first.** Push events (websocket/webhook) are only
   **hints** that wake a `CustodialSettlementObserver`. The observer also polls the backend's
   authenticated ledger on a durable cursor (`list_settled_invoices`), reconciling by
   `backend_correlation_id` first and `backend_invoice_hash` second, so a missed frame or webhook gap
   becomes routine recovery, not a lost payment. A record advances only after **authenticated
   ledger confirmation** (`get_settled_invoice_by_hash` or the ledger page): does its requested/face amount
   match the quote, is it paid, and what are `received_msat`, `fees_msat`, and `completed_at_ms`
   (captured for liability evidence, §7.7)? The **net** credited after backend skim may be lower,
   which §8 handles by funding the full contract and recording the loss, never by rejecting a
   settled invoice. (This authenticated confirmation is new: the trustless path is
   HTLC-driven and has no equivalent.) A confirmed record still in `AwaitingPayment` then funds
   the `IncomingContract` for its **full `commitment.amount`** (the amount is fixed, partial
   funding is impossible, §8) from gateway ecash. A record already past `AwaitingPayment` starts no
   new funding and routes by state: `SettledAwaitingLiquidity` waits for float, `FundingReserved` /
   `FundingPrepared` / `FundingSubmitted` wait or re-drive (§10), `Funded` is a no-op, a settlement
   matching an `InvoiceExpiredUnpaid`, `BackendInvoiceRejected`, or `InvoiceExpiredUnreturned`
   tombstone follows the retained record's `fund_on_settlement` policy, and a settlement matching no
   record at all is handled by the `UnmatchedSettlement` rule below (recording and halting are in
   scope; automated *reconstruction* of a lost record is not, §10, §16). A
   **settled-but-mismatched** record is **not** ignored, and the mismatch rule is
   **direction-aware**: a deviation within expected backend skim still funds the full contract and
   records the loss (§8); an **overpayment** (credited at or above the quoted face amount) always
   funds the quoted contract, records the surplus as auditable evidence, and alerts if gross
   (funding is owed and safe regardless of surplus, §11); a gross **shortfall** or a non-amount
   inconsistency opens a `BackendMismatch` liability (§7.7) and alerts, never a silent drop. A ledger settlement whose `externalId` lies in the gateway's
   correlation-id namespace (decidable on a shared backend: every gateway-issued
   `backend_correlation_id` carries a recognizable constant namespace prefix, impl specs) but
   matches **no** authoritative record and no retained tombstone
   indicates record loss or correlation-id aliasing: it is durably recorded as an
   `UnmatchedSettlement`, alerts, and disables new custodial invoice creation until reviewed, never
   silently skipped. The MVP `UnmatchedSettlement` record is a minimal audit marker; because an unmatched settlement by
   definition matches no record in **any** federation, it is stored once as backend-scoped state at
   the gateway root (impl specs), not in a federation client prefix:
   `{ backend_correlation_id, backend_invoice_hash, received_msat, completed_at_ms,
   backend_ledger_proof, resolution: Open | Resolved }`. It is deliberately **not** a
   `CustodialReceiveLiability` (§7.7): with no matching quote or contract there is no known
   receiver or amount owed, so resolution is operator investigation, not an automatic payout path.
   Settlements whose `externalId` lacks the gateway's namespace prefix are outside custodial
   reconciliation (other operator activity on a shared backend).

   **Fund via a new client-core prepare-then-submit API.** Exactly-once recovery depends on the
   exact transaction being durable **before** it can land. This is **not** just a
   `fedimint-gwv2-client` helper: today `finalize_and_submit_transaction` does it all in one path
   (it finalizes the tx and locks inputs in the private `finalize_transaction`,
   `fedimint-client/src/client.rs:657`, then creates the `TxSubmissionStates::Created` submission SM,
   stores fees, and writes the operation-log entry, `:1000-1052`), and there is **no public way** to
   prepare-and-lock without also creating the operation and submission SM. So the split is generic
   client-core work (illustratively, a `Client::prepare_transaction` that finalizes + locks inputs +
   returns bytes and a durable reservation token without an op-log entry or submission SM, and a
   `Client::submit_prepared_transaction` that installs the stored op-log entry and
   `TxSubmissionStates::Created(prepared.tx)` in one autocommit dbtx, refusing to rebuild). The exact
   API shape is open (§14):
   - `GatewayClientModuleV2::prepare_custodial_incoming_funding(contract)`, a thin wrapper over that
     core API, returns the deterministic `operation_id` (`OperationId::from_encodable(&contract)`),
     the finalized transaction (bytes, txid, outpoint range), its pinned ecash inputs, and the
     submission state machines for acceptance monitoring. It does **not** submit. (It models the
     *output construction* of `relay_direct_swap`, `modules/fedimint-gwv2-client/src/lib.rs:476`,
     but builds a **bare** incoming-contract output with no gwv2 `ReceiveStateMachine` attached:
     that SM's post-funding branch auto-refunds non-decrypting contracts, which would race the
     `CustodialContractAuditSM` that owns invalid-contract refunds here.)
   - `submit_prepared_custodial_funding(prepared)` submits that exact prepared tx and **refuses
     to rebuild** a transaction for any record already past `FundingReserved`.

   The durable, ordered status machine is `InvoiceCreating → AwaitingPayment →
   SettledAwaitingLiquidity → FundingReserved → FundingPrepared(prepared_tx) →
   FundingSubmitted(prepared_tx, operation_id, txid) → Funded(outpoint)`, with
   `SettledAwaitingLiquidity` skipped when float is already sufficient and marking **`Funded` only on
   federation acceptance**. Several terminal branches leave this path.
   `AwaitingPayment` goes to `InvoiceExpiredUnpaid` only after the backend invoice has expired and the
   backend ledger/finality window proves it did not settle. A settled invoice remains a debt and stays
   on the funding path (`SettledAwaitingLiquidity` if float is short), unless there is a gross
   `BackendMismatch` or another invariant failure that requires an `UnresolvedLiability` marker. An
   `InvoiceExpiredUnpaid`, `BackendInvoiceRejected`, or `InvoiceExpiredUnreturned` retained record that
   later matches a settlement follows its reason-tagged `fund_on_settlement` policy. Safe retained
   records transition back to the automatic funding path with reason `UnreturnedInvoiceSettled`
   recorded as evidence — **provided the funding deadline has not yet passed in observed consensus
   time**. A settlement that surfaces after the deadline can no longer fund the original contract
   (the server rejects expired contracts, `modules/fedimint-lnv2-server/src/lib.rs:563`) and opens
   an `UnresolvedLiability` with the settlement proof instead; this is a critical operator fault,
   since the deadline bounds (§8) are sized so it cannot happen in normal operation. Unsafe
   validation, namespace, granularity, or backend-invariant failures
   become `UnresolvedLiability` / `BackendMismatch`. `InvoiceCreateInconclusive` requires operator
   review because the gateway cannot safely prove whether a backend invoice was created, but it is
   still retained in ledger reconciliation; a matching settlement also follows the recovered invoice's
   validation and `fund_on_settlement` policy. Any funding state goes to `UnresolvedLiability` only
   for funding-tx inconclusiveness or another invariant failure (§11). The record **retains
   `prepared_tx`** from
   `FundingPrepared` onward (the `operation_id` and `txid` are added markers, not a replacement),
   so a later state re-drives the exact transaction with its pinned inputs, not just a txid.
   A short-float receive commits `SettledAwaitingLiquidity`: backend settled, actual debt exists, but
   no ecash inputs are reserved and no prepared transaction exists. When liquidity becomes available,
   one funding worker atomically claims it into `FundingReserved`. A liquid receive can move directly
   from `AwaitingPayment` to `FundingReserved`. `FundingReserved` means the funding worker owns the
   record and may prepare a tx, so duplicate hints or concurrent handlers can't both proceed. Funding
   then commits in **two atomic phases**, both inside the **federation client DB prefix** (alongside
   the mint notes), so no partial state is possible:
   - **Prepare** commits `FundingPrepared(prepared_tx)` together with the **ecash-input
     reservation**, atomically. No operation or submission state machine exists yet.
   - **Submit** commits `FundingSubmitted` together with the **operation log and submission state
     machines**, atomically, and only then does the executor broadcast.

   So `operation_exists` becomes true at `FundingSubmitted`, never at `FundingPrepared`, which keeps
   the "operation exists, never resubmit" recovery path tied to submission, not preparation. The
   authoritative funding state is the `PendingCustodialReceive` record itself, carrying its funding
   fields (`prepared_tx`, `operation_id`, input reservation) in this prefix — either inline or as a
   companion key in the **same prefix** written in the **same database transaction** (e.g. a generic
   client prepared-transaction record referenced by operation id); never a separate physical store
   and never a separate commit.
   The gateway DB's **root-level** secondary indexes
   (`quote_id` / `backend_invoice_hash` / `backend_correlation_id` → `federation_id`) are
   rebuildable and **not** the source of truth for whether a prepared funding tx exists. They sit at
   the root of the same physical gateway DB that holds this prefix (§11), so only their **logical**
   corruption is the cheap rebuild case. Physical loss of the file takes the prefix too. This
   federation client DB prefix is the **same fedimint client database** that backs `operation_exists`,
   so "the client DB survives" and "the authoritative funding state survives" are one condition.
   Losing only the rebuildable root-level index prefixes is the cheap case. Losing the physical
   gateway DB file loses the authoritative client-prefix state too. A design that commits
   `FundingPrepared` in the root gateway DB and reserves inputs in the federation client DB in a
   **separate** commit is invalid: a crash between the two reintroduces the exact double-spend the
   machinery removes. Input release depends on **whether the tx can still land**, not just on
   reaching a terminal state. Inputs release on `Funded` (the tx landed, they're spent). A transient
   submission or network error keeps them locked and re-driven. For a terminal liability with the
   tx **proven dead** (the federation deterministically rejected it — e.g. contract expiry, whose
   consensus-time check is monotonic — so no prior submission can ever land), the liability is
   recorded with reason `FundingRejected` (§7.7) and resolution may proceed without waiting on the
   tx; the MVP still keeps those inputs quarantined with the liability record because it has no
   ecash input re-credit ("unprepare") mechanism (§14). A
   `FundingTxInconclusive` liability **quarantines** the inputs (never released, never reused) until
   the prior tx is accepted, rejected, or proven impossible, so a late landing can't race an alternate
   payout/resolution (§7.7, §10). So `SettledAwaitingLiquidity` records wait for ecash and never build a tx.
   A `FundingReserved` record has been claimed by a funding worker but has no prepared tx and never
   submitted, so it is the **only** state that may prepare a fresh tx. Any record at
   `FundingPrepared` or later holds the exact tx and can only re-drive it, never build a new one. On
   restart, the gateway re-derives that same `operation_id` and checks
   `operation_exists` (`modules/fedimint-gwv2-client/src/lib.rs:483-485`). If the operation
   already exists the gateway **never resubmits**: it subscribes to that operation's
   outcome and advances to `Funded` on acceptance. This is fedimint's built-in
   client-side idempotency and needs no new federation endpoint. The dedup is enforced
   atomically at submit time: `finalize_and_submit_transaction` re-checks `operation_exists`
   inside its `autocommit` database transaction (`fedimint-client/src/client.rs:968`), so two
   concurrent submissions sharing the id can't both land. The no-operation branch
   **splits by state**: `SettledAwaitingLiquidity` records wait for ecash and never build a tx. A
   `FundingReserved` record has been claimed by a funding worker but has no prepared tx and never
   submitted, so when no operation exists and the contract is still fundable it prepares and submits
   fresh. A
   `FundingPrepared` or `FundingSubmitted` record holds the exact `prepared_tx` (a `FundingPrepared`
   tx was not yet submitted, a `FundingSubmitted` one may already have landed), so on a missing
   operation the gateway re-drives that exact tx and must **not** build a fresh funding tx. A point-in-time
   funded-contract lookup that returns "not funded" is **not** proof the prior tx is dead: fedimint
   submits and accepts transactions asynchronously (`TxSubmissionStates::Created` =
   "potentially already submitted", `fedimint-client-module/src/transaction/sm.rs:54`), so an
   earlier submission can still land after the query. The only safe recovery is to re-drive **the
   exact stored `prepared_tx`**: resubmitting the identical transaction is consensus-idempotent because its
   pinned ecash inputs can be spent only once, so the contract is funded at most once. If the
   gateway can't re-drive that exact tx, or can't otherwise prove no prior submission can still
   land, the record is **inconclusive** and goes to the unresolved-liability path (§11), never a
   fresh second tx and never a silent strand. A proven-**funded** lookup just advances to `Funded`.
   If funding is rejected, the record moves to a terminal **`UnresolvedLiability`** status with
   reason `FundingRejected` that drives explicit liability handling (§11), never a silent drop.
   Rejection because the long-lived contract expired is a critical policy/invariant failure, not a
   normal expiry path.
3. **Exactly-once funding is load-bearing: consensus does not protect it.** The server
   stores incoming contracts by `OutPoint` and only overwrites the `contract_id →
   outpoint` index (`modules/fedimint-lnv2-server/src/lib.rs:567-584`). Funding the **same**
   contract at two outpoints yields **two** claimable liabilities (the receiver could
   claim both → gateway double-loss). So the gateway must make exactly-once explicit:
   one outstanding backend invoice per contract, atomic status transitions, serialized
   per-`contract_id` settlement handling, and a notification arriving in
   `SettledAwaitingLiquidity`, `FundingReserved`, `FundingPrepared`, or `FundingSubmitted` **waits**
   on liquidity, the stored reservation, prepared tx, or operation rather than resubmitting. The
   deterministic funding `operation_id` plus
   `operation_exists` carries this across restarts: re-deriving the id from the contract
   and finding the operation already present blocks any second funding tx, while the
   operation's own outcome (not `operation_exists` alone) confirms federation acceptance.
   (Consensus-level dedup would be a server change, breaking the no-consensus-change
   property.)

   **Cross-path receive namespace invariant.** On any gateway process or deployment that can serve
   both trustless and custodial receive for the same federation/module key, there is exactly one
   active owner for each `(federation_id, contract_id)`, each contract `PaymentImage`, and each
   same-gateway direct-swap payment hash:
   `TrustlessRegistered` or `CustodialPending`, never both. Concretely, the direct-swap registry has a
   `backend_invoice_hash -> CustodialPending { federation_id, contract_id, quote_id, invoice_amount }`
   entry for each returned custodial backend invoice. The normal
   `create_bolt11_invoice_v2` path must reject a contract/payment image already reserved by
   custodial receive, and `create_custodial_bolt11_invoice` must reject a contract/payment image
   already registered for trustless receive. The rejection is `DuplicateContractConflict` if the full
   contract collides; if only the payment image collides with a different contract the request is
   likewise rejected (`DuplicateContractConflict`) with an operator-visible alarm/metric — but it
   MUST NOT disable issuance: the payment image is client-chosen (and, for trustless invoices,
   public), so an image collision is attacker-reachable and a halt here would be a one-request
   denial-of-service lever. Issuance-disabling halts are reserved for conditions only the backend
   or operator can produce (the backend hash collision below, duplicate `externalId`, unmatched
   settlements, and the retention/persistence/slack gates). After the backend returns a custodial invoice, the gateway must also
   reserve `backend_invoice_hash` in the shared direct-swap namespace before returning the invoice. If
   that hash collides with an active trustless registration or another custodial pending receive, the
   gateway must not return the invoice; it records a retained `BackendInvoiceRejected` tombstone keyed
   by `backend_correlation_id` / `backend_invoice_hash`, disables new custodial invoice creation until
   reviewed, and continues ledger reconciliation for that invoice through the retention window.
   Retained custodial records and tombstones that own a `backend_invoice_hash` keep that hash reserved
   in the direct-swap namespace until the retained record is pruned. A trustless receive registration
   must reject a payment hash owned by a retained custodial record, not only by nonterminal custodial
   receives. If the tombstone exists because the hash already collided with an active trustless owner,
   the custodial tombstone records that unsafe collision but does **not** take ownership from the
   existing trustless registration; any later settlement follows the unsafe `fund_on_settlement`
   policy rather than automatic funding.

   This invariant must be enforced by the same transaction/registry used for direct-swap detection in
   dual-capable mode. Recovery of any post-create custodial record must re-derive and atomically
   reassert the `backend_invoice_hash -> CustodialPending` entry before the record is treated as
   active or the quote/invoice is returned. A separate custodial-only binary that does not share such
   a registry SHOULD NOT share the same gateway module key and Lightning node key with a
   legacy-listed trustless gateway (§7.1): the forfeit-refund outcome still emerges from the failed
   registered-contract lookup, but this creation-time invariant becomes unenforceable across the two
   processes, degrading it from a guaranteed property to a hash-collision-improbable one.

4. **Post-funding invalid-contract audit (never blocks the receiver).** The custodial funding
   helper skips the gateway receive state machine, so it also skips that machine's invalid-contract
   detection. The gateway therefore starts a **non-blocking** `CustodialContractAuditSM` after
   funding. It waits for the federation's decryption shares (the same ones the trustless gateway
   path consumes): if the contract decrypts it records `Claimable` and never spends (the receiver
   claims normally with its own key). If it does **not** decrypt, it submits the refund spend to
   `refund_pk` (the gateway key) and opens an unresolved liability with reason `InvalidContract`
   (§7.7, §9). The receiver's pre-invoice claimability self-check (§7.4) is the primary
   defense, and this audit is the backstop that actually performs the refund §9 relies on. It must
   **never** delay marking the receiver's contract funded.
5. **Float and liabilities:** the gateway must hold enough federation ecash to front contracts.
   The backend Lightning receipt reimburses it. Expose ecash float, settled-but-unfunded debt, and
   headroom in balances. Once the backend ledger confirms settlement, the receive is an actual debt:
   the gateway must fund the contract if it still can. If ecash float is short, the record moves to
   explicit `SettledAwaitingLiquidity`: backend settled, actual debt exists, but no ecash inputs are
   reserved and no prepared transaction exists. When liquidity becomes available, one funding worker
   atomically claims it into `FundingReserved`, then prepares and submits the exact tx. When several
   settled records are waiting, workers claim them in minimum-funding-deadline-slack-first order, so
   recovered float protects the tightest deadline (this backs the
   `min_funding_deadline_slack_seconds` invariant, §7.8). The MVP can make
   liquidity replenishment semi-automatic: alert the operator and, when configured on-chain wallet
   funds are available, drive or prompt a pegin to create federation ecash. Post-MVP automation can
   add loop-out, channel close, splice, swap-out, or backend-specific liquidity actions. The contract
   funding deadline is chosen long-lived enough that liquidity shortage is expected to resolve by
   funding the original contract after liquidity recovers.
6. **Limits and unpaid invoices:** enforce the per-receive cap from the gateway's advertised
   `CustodialReceiveCapability` (§7.1, §9) to bound single-receive blast radius. The aggregate
   `max_in_flight` value is a hard gate for actual obligations, not a reservation against every issued
   unpaid invoice: if open settled-but-unfunded debt plus open unresolved liabilities plus records in
   funding states is at or above `max_in_flight`, new custodial invoice creation is disabled until the
   operator reduces the debt. `max_in_flight` is advertised, tracked, and enforced **per federation**
   (the obligations live in that federation's client DB prefix); an operator serving several
   federations must size total ecash float and alert thresholds across all of them. An issued unpaid
   invoice is **contingent exposure**, not debt. The
   gateway tracks issued-unpaid count and face value for metrics and operator alerts, but unpaid
   invoice **face value** is not reserved against `max_in_flight`.

   Public unpaid-record quotas are **not** part of the custodial receive protocol. They are
   attacker-controlled DoS levers: a cheap stream of unpaid invoice requests could fill a public
   `max_open_unpaid_records` / retained-record quota and force honest receivers to get rejected. The
   gateway still needs internal durability and deployment controls (request throttling, authentication
   policy, storage alarms, DB-size ceilings, abuse detection), but those controls are outside
   `CustodialReceiveCapability` and are not advertised as wallet-visible selection semantics. If the
   gateway is genuinely unable to persist or reconcile safely, it disables only **new** invoice
   creation and reports generic `BackendInvoiceCreationUnavailable`; already-issued and
   already-settled invoices continue through reconciliation.

   Late settlements are possible because a notify-only backend can report settlement after local
   invoice expiry, so the record is **retained in full** (contract, amounts, `invoice_expiry`,
   `funding_deadline`, `quote_id`, `backend_invoice_hash`) until the backend ledger/finality window
   proves no settlement occurred. Then it terminalizes: settled-and-funded → `Funded`; settled but not
   yet funded → stays on the funding/liquidity path; never settled → **`InvoiceExpiredUnpaid`** (the
   terminal that keeps `AwaitingPayment` from being nonterminal forever). If a supposedly unpaid
   retained record later matches a settlement, the gateway treats that as a backend/finality surprise
   and returns it to the automatic funding path, never a silent miss. If the invoice never settled and
   the contract was never funded, there is no on-federation contract to cancel: the `IncomingContract`
   was only a quoted object until the gateway funds it. Splitting the backend finality and ledger
   retention bounds **in the wire terms and tombstone model** is deferred to §14; the backend
   *adapter* may keep separate internal retention/finality knobs (impl specs) while the signed
   terms carry the single `backend_retention_secs`.

   **Retained-record pruning.** A retained terminal record (`InvoiceExpiredUnpaid`,
   `BackendInvoiceRejected`, `InvoiceExpiredUnreturned`, or a resolved `InvoiceCreateInconclusive`)
   becomes prunable only once (a) its funding deadline has passed in observed consensus time, so the
   original contract can never be funded (§8), and (b) the backend ledger/finality window has proven
   no settlement can still surface for its invoice. Pruning releases the record's
   `backend_invoice_hash` reservation in the direct-swap namespace (§7.3). `UnresolvedLiability`
   records and unresolved `InvoiceCreateInconclusive` records are never pruned automatically.
   `InvoiceCreationExpired` tombstones are the opposite extreme: provably pre-create (never
   maybe-sent), they own no invoice and no hash reservation and no settlement can ever match them,
   so they may be deleted once the draft-freshness window that governs duplicate retries has
   passed, with no ledger proof required. A
   settlement that surfaces after pruning (a backend surprise beyond its declared finality) matches
   no record and is handled as an `UnmatchedSettlement` (settlement observation, above), never
   silently dropped. The `max_invoice_expiry_secs` / `max_funding_deadline_secs` bounds (§7.1, §8)
   keep this retention horizon finite.

### 7.4 Client custodial-receive variant

A new entry point in `fedimint-lnv2-client` (e.g. `receive_custodial(...)`), or a
mode flag on `receive`:

- **Select via policy, with explicit opt-in.** Use `select_gateway_for_receive` with a custodial
  policy (§7.1), reachable only when the app/user has opted into custodial receive. It picks only
  a gateway advertising `custodial.is_some()`, and surfaces that the gateway is custodial.
- Build the `IncomingContract` exactly as today (receiver owns preimage), but set a **long-lived
  contract funding deadline later than the invoice expiry** the gateway will use.
  Pass the two deadlines separately rather than the single `expiry_secs` used today
  (`lib.rs:943` for the contract expiration and `:972` for the invoice expiry currently
  reuse one value). The client chooses the funding deadline using the selected gateway's advertised
  `CustodialReceiveCapability` deadline-policy fields before it requests the invoice; the chosen
  invoice expiry and funding deadline must respect both the minimum rules and the advertised
  `max_invoice_expiry_secs` / `max_funding_deadline_secs` upper bounds (§8). This funding
  deadline is not the invoice's UX expiry and not a liability cutoff; it only keeps the original
  contract fundable after any backend settlement. The client sizes `contract.commitment.amount` using
  that same capability's `receive_fee`, not the legacy top-level trustless receive fee. The returned
  signed quote repeats the terms actually used and must still pass the checks below.
- **Self-check claimability before requesting the invoice.** The client must verify it can actually
  claim the contract it built: that `recover_contract_keys` succeeds
  (`modules/fedimint-lnv2-client/src/lib.rs:1025-1055`), confirming a valid preimage and a derivable
  claim key. An unclaimable contract is far worse in custodial mode (§9, §11): the payer pays
  irreversibly but the receiver can never claim.
- **Persist a provisional custodial receive before the gateway request leaves.** Once the client has
  built and self-checked the contract, it stores the contract, receiver secret material needed to
  claim it, selected gateway identity, `client_request_id` / request fingerprint, invoice amount,
  requested invoice expiry, funding deadline, the advertised deadline-policy fields used
  (`consensus_time_observation_max_age_secs`, `safety_margin_secs` — so the pruning rule below has
  persisted inputs even when no quote is ever returned), and provisional operation id in the client
  DB. It then starts or arms the normal
  receive watcher for that contract before calling `create_custodial_bolt11_invoice`. A successful
  `Created { invoice, quote }` upgrades the provisional record with the signed quote and invoice.
  Deletion vs retention is keyed on the **public rejection reason**, never on gateway-internal state
  the client cannot observe: every reason except `BackendInvoiceUnreturnable` and `CreateInProgress`
  is defined as strictly pre-create (§7.9), so those rejections delete the provisional record —
  except `DuplicateContractConflict`, which is pre-create for the rejected request but proves the
  gateway holds a same-contract reservation that may be post-create under another fingerprint, so
  the client retains the contract's claim material (§7.9). A
  `BackendInvoiceUnreturnable` or `CreateInProgress` response — or any network outcome with no
  definitive response after the request left the process — retains the provisional receive until a
  later response resolves it. Retention is bounded client-side, but pruning must be
  **conservative**, because the federation admits funding against LNv2 `consensus_unix_time`, not
  the client clock (§8): a client whose wall clock runs ahead could otherwise delete the only claim
  material for a contract the gateway can still fund. The client may prune only once its locally
  observed LNv2 consensus time (if it tracks one) is past the funding deadline, or its wall clock
  is past the deadline by at least the **persisted** policy margin
  (`consensus_time_observation_max_age_secs + safety_margin_secs`, from the stored provisional
  record's capability values or from `terms` once a quote arrived) **plus the client's configured
  maximum assumed clock skew**. Wall-clock pruning is only as safe as that skew assumption; a
  wallet that cannot bound its clock skew must track observed consensus time or keep the record.
  Claim material is small; when in doubt, retain. Deletion and pruning apply to the provisional
  **record** only and MUST never abort or remove the armed receive state machine: the SM's own
  state carries the claim keypair and aggregate decryption key
  (`modules/fedimint-lnv2-client/src/receive_sm.rs`), there is no operation-abort API, and it
  resolves against the *federation's* consensus-time view of the funding deadline — so a contract
  funded any time before its deadline is still claimed by the armed SM even if the record was
  already deleted or pruned. This backstop is what keeps every delete/prune path claim-safe,
  including the case of a buggy or malicious gateway returning a pre-create reason after an
  invoice was actually created.
- Request the invoice, and **skip** the `invoice.payment_hash() == preimage hash`
  check (`lib.rs:977`): the invoice is deliberately the backend's own hash. Keep the **amount**
  check (`lib.rs:981`). The requested amount must also be compatible with
  `invoice_amount_granularity_msats` (§7.1). For a sat-only backend like phoenixd, the client and
  gateway **reject** a non-satoshi (sub-1000-msat-granularity) amount rather than silently rounding.
- **Re-bind the invoice to the gateway (replaces the hash check).** Skipping the hash
  check removes the only strong invoice↔contract binding, so a malicious gateway could
  otherwise hand back *any* payee's invoice and pocket the payment. The custodial client
  MUST instead verify the invoice payee equals the selected gateway's advertised
  `RoutingInfo.lightning_public_key` (`gateway_api.rs:147`), and that the invoice expiry
  is before the contract funding deadline. With the hash check gone, the binding the
  client relies on becomes "this invoice is payable to the gateway I chose." This key is
  the gateway's self-asserted `RoutingInfo.lightning_public_key`, not federation-authenticated
  data: the federation registers only the gateway URL (`select_gateway`, `lib.rs:457`, vetted
  by at least one guardian), so the binding is exactly as strong as that operator vetting, no
  stronger. That is why custodial candidates require `https` and support module-key pinning
  (§7.1): without them, a MITM on the probe (or a poisoned URL source) can present a fully
  self-consistent fake identity — its own keys, its own signed quote, an invoice payable to its
  own node — that passes every client check while the payment goes to the attacker with no
  refund path.
- **Verify and persist the gateway quote.** The client must verify the
  `CustodialReceiveQuote` domain-separated signature (`api_version`, `quote_id`), and that
  `contract_id`, full `contract`, `federation_id`, `backend_invoice_hash`, invoice amount,
  contract amount, `gateway_module_pk`, `gateway_ln_pk`, invoice expiry, and funding deadline match
  its selected gateway, returned invoice, and locally-built contract. It must verify
  that the embedded `terms` are **compatible** with the selected gateway's advertised capabilities
  and the client's local policy. Compatible means: every terms field that also appears in
  `CustodialReceiveCapability` equals the stored capability snapshot the client selected and sized
  with (byte-equality — restart-deterministic, no live re-probe), and the fee cap holds
  **component-wise**: `terms.receive_fee.base <= PaymentFee::RECEIVE_FEE_LIMIT.base` **and**
  `terms.receive_fee.parts_per_million <= RECEIVE_FEE_LIMIT.parts_per_million`. (The `.le()` the
  trustless path compares with today is the *derived lexicographic* `PartialOrd` — `PaymentFee` has
  no inherent `le` method — under which `{ base: 0, ppm: 500_000 }`, a 50% fee, passes the cap
  because `0 < 50` sats; custodial verification MUST NOT reuse it as a cap.) It must verify the
  amount binding is exact:

  ```text
  contract_amount == terms.receive_fee.subtract_from(invoice_amount.msats)
  contract.commitment.amount == contract_amount
  ```

  Because `PaymentFee::subtract_from` saturates, the client also enforces its own lower bound before
  requesting the invoice, using the advertised `CustodialReceiveCapability.receive_fee`, and again
  during quote verification, using `terms.receive_fee`:

  ```text
  invoice_amount.msats > receive_fee.fee(invoice_amount.msats).msats
  contract_amount >= client_min_incoming_contract_amount
  ```

  `client_min_incoming_contract_amount` is at least the existing
  `MINIMUM_INCOMING_CONTRACT_AMOUNT` used by trustless receive, unless wallet policy is stricter. The
  client rejects a quote whose `terms.receive_fee` differs from the advertised custodial fee it used to
  build the contract.

  It must also verify that the quote's
  `observed_lnv2_consensus_time` satisfies the §8 deadline rules:

  ```text
  funding_deadline >
      observed_lnv2_consensus_time
    + terms.min_contract_lifetime_secs
    + terms.consensus_time_observation_max_age_secs
    + terms.safety_margin_secs

  invoice_expiry + terms.min_invoice_to_funding_deadline_delta_secs <= funding_deadline

  funding_deadline <= observed_lnv2_consensus_time + terms.max_funding_deadline_secs
  invoice_expiry   <= observed_lnv2_consensus_time + terms.max_invoice_expiry_secs
  ```

  These checks verify the deadline arithmetic against the quoted observed consensus time. They do
  not prove that the gateway's observer was fresh when it signed, so the client also sanity-checks
  the quote against an independent time reference. The baseline reference is the client's local wall
  clock with a generous configured margin; a wallet that already tracks LNv2 `UnixTimeVote`s from
  signed session outcomes MAY use its own observed consensus time instead (optional hardening —
  requiring every mobile/wasm wallet to stream session outcomes would be heavy machinery against a
  marginal threat, since a malicious gateway can simply refuse to fund regardless of any deadline
  excuse). The client rejects the quote if `observed_lnv2_consensus_time` lags its reference by more
  than `terms.consensus_time_observation_max_age_secs`, or if applying the same funding-deadline
  rule to its reference time would fail. This client check catches honest-but-stale gateways and
  crude dishonesty; the gateway remains responsible for not signing when its observer is stale
  (§7.8).

  The client must also confirm the contract's own `refund_pk` equals
  `gateway_module_pk`, so the unclaimable-contract windfall (§9, §11) can only route back
  to the audited gateway. The full quote, including `terms`, is stored with the operation metadata so
  the receiver can later prove what the gateway committed to fund.
- The armed watcher uses the existing `ReceiveStateMachine` behavior (watch contract → claim)
  **unchanged** once the contract appears. It claims with the receiver's locally-precomputed
  `agg_decryption_key`, so it needs nothing from the gateway beyond the contract being funded.

### 7.5 Server / consensus

**No fedimint consensus-module changes.** "Consensus/server changes" here means
consensus semantics: no spend-rule, validation, or wire-encoding changes. The federation
sees an ordinary `IncomingContract` funded and claimed. The MVP also needs **no new
server endpoints**: restart double-fund prevention rides the existing deterministic
`operation_id` idempotency. While the authoritative federation client DB prefix survives, an
operation-log divergence re-drives the prepared record's exact stored tx (`FundingPrepared` or
`FundingSubmitted`). If that prefix itself is gone, so the stored tx is unrecoverable, the gateway
has suffered local data loss out of scope for this spec (§10, §16). The trust relaxation lives
entirely in the gateway and client (§7.1-7.4), which do change. The consensus module does not.

### 7.6 Interaction with the direct-swap send path

A custodial invoice is signed by the gateway's **own backend node key**, and LNv2
senders use `RoutingInfo.lightning_public_key` to choose a fedimint-internal **direct
swap** over paying via Lightning (the client compares the invoice payee to this key in
`send_parameters`, `gateway_api.rs:179`, the field at `:147`, and the gateway side is
`is_direct_swap`, `gateway/fedimint-gateway-server/src/lib.rs:3283`). So when the
**same** gateway is both the receiver's custodial gateway and a sender's send gateway
(shared-gateway / intra-federation self-pay), the sender's client takes the direct-swap
path and looks up a registered incoming contract by the invoice hash `H′`
(`gateway/fedimint-gateway-server/src/lib.rs:3283`). But a custodial invoice's `H′` is the backend's
hash, **not** a trustless `IncomingContract` hash, so the lookup finds nothing and the
send cancels with a `RegistrationError`. If the custodial contract were wrongly
registered under `H′`, `relay_direct_swap` would return the receiver's preimage `P`,
which does not satisfy the sender's outgoing contract keyed to `H′`.

The load-bearing requirement is the first of these; the second is reporting hygiene:
- The gateway MUST **never** register a custodial pending-receive as if it were a trustless incoming
  contract keyed on the invoice hash. This alone prevents the wrong-preimage hazard above.
- The forfeit-refund outcome itself needs no new mechanism: a failed registered-contract lookup
  already cancels the gateway-side send with `Cancelled::RegistrationError`
  (`modules/fedimint-gwv2-client/src/send_sm.rs:203`), and **every** `Cancelled` outcome already
  returns the forfeit signature to the sender (`modules/fedimint-gwv2-client/src/lib.rs:379-388`),
  who refunds immediately. Same-gateway self-pay of a custodial invoice cannot complete over
  Lightning either (a node cannot route to its own invoice), so the refund is the correct domain
  outcome. The gateway SHOULD additionally detect its own custodial invoice by looking up `H′` in
  the shared `backend_invoice_hash -> CustodialPending` registry (§7.3), so the cancellation is
  labeled as custodial self-pay for metrics/support instead of a generic registration error, and so
  the outcome stops depending silently on the lookup's failure semantics. A future version may add
  an internal custodial self-pay that funds the receiver's contract directly from the sender's
  outgoing contract.

For the common case (sender and receiver use *different* gateways), the custodial
invoice's payee is not the sender-gateway's key, so direct swap never triggers and the
payment routes over real Lightning, which the backend auto-settles into the normal
custodial funding path.

One caveat for same-federation senders: default send selection prefers the gateway whose
key matches the invoice payee (`select_gateway` with the invoice,
`modules/fedimint-lnv2-client/src/lib.rs:467`, used by `send`, `:576`) to enable a direct swap. A
custodial invoice's payee is the custodial gateway itself, which can neither direct-swap it nor
route to its own node. The send path must **not** require the sender to pre-classify the invoice as
custodial, since a Bolt11 invoice doesn't carry that fact. Instead the payee gateway, because it can
neither direct-swap nor route to its own node, **returns a forfeit signature** (the existing
`Err(Signature)` half of the
send response, `modules/fedimint-lnv2-common/src/gateway_api.rs:48`), so the sender refunds the
just-funded `OutgoingContract` immediately via `OutgoingWitness::Cancel`
(`modules/fedimint-lnv2-client/src/send_sm.rs:238-266`). The forfeit-refund **outcome** is the
required MVP behavior; it already emerges today from the `RegistrationError` cancellation path, and
the `CustodialPending` registry lookup upgrades it from an accidental property of lookup-failure
semantics to a labeled, tested one. A
typed `CannotDirectSwapCustodialInvoice` **cannot** travel as a `PublicGatewayError` (those redact
to one generic string, `gateway/fedimint-gateway-server/src/error.rs:81-84`) nor as a transport
error (the send SM retries those forever, `send_sm.rs:193-216`), so the forfeit signature is the
domain outcome that drives the refund (§7.9).

There is **no MVP pre-funding custodial self-pay avoidance** and no in-place retry through another
gateway: by the time the gateway is contacted the
`OutgoingContract` is already funded with `claim_pk` = the payee gateway's module key
(`modules/fedimint-lnv2-client/src/lib.rs:597-639`), so re-routing means a fresh send funded to the
alternate gateway. Doing that automatically without a wasted funding round-trip needs a
**pre-funding classification** step, deferred (§14). The MVP refunds and the caller reselects.
Tested in §15.

### 7.7 Liability record and status

A settlement the gateway can't safely fund (an unclaimable contract refunded to the gateway, an
inconclusive funding tx, or a gross backend mismatch) leaves an obligation, so it keeps a **durable
liability record** rather than losing it to a support ticket. The MVP needs a minimal marker, stored
in the **federation client DB prefix** alongside the funding record so terminalizing to
`UnresolvedLiability` and writing the liability are one **atomic** commit:

```rust
struct CustodialReceiveLiability {
    quote_id: sha256::Hash,          // the receive it belongs to
    federation_id: FederationId,
    contract_id: ContractId,
    amount_owed: Amount,
    reason: LiabilityReason,         // InvalidContract | FundingRejected | FundingTxInconclusive | BackendMismatch
    evidence: LiabilityEvidence,     // { signed_quote, backend_ledger_proof, funding_txid? }
    resolution: LiabilityResolution, // Open | Resolved (richer taxonomy deferred, §14)
}
```

The **load-bearing rule** is the no-double-pay gate. For `FundingTxInconclusive`, any alternate
automatic payout must wait until the original funding is proven terminal: confirmed funded means the
receiver was already paid (no payout), while a prior tx that can still land must be quarantined.
Resolving while a prior tx can still land would double-pay. For an `InvalidContract` refund the
receiver got nothing, so the automatic payout/resolution path starts once the refund is terminal.
For `FundingRejected` the tx is proven dead (deterministic federation rejection), so resolution may
start immediately; its quarantined inputs are released only by a post-MVP re-credit mechanism or
operator action (§14). Other reasons resolve directly.

**Deferred (§14):** richer liability tooling (a full reason/resolution taxonomy, evidence-bundle
export, operator-visible audit records, automated resolution integrations). Disaster-recovery tooling
for physical gateway DB loss is out of scope for this spec (§16). The MVP keeps the liability record
in the same authoritative federation client DB prefix as the funding state and does not define a
manual or receiver-cooperative resolution path.

**(Optional, post-MVP):** a `custodial_receive_status` query so a receiver can ask "what happened?"
without blocking on `await_incoming_contract`. It must authenticate with the full signed
`CustodialReceiveQuote` or a MACed status token derived from it, not a bare `quote_id`. Responses
must avoid leaking `backend_correlation_id`, raw invoice hashes, or user-identifying labels unless
the caller already supplied the signed quote containing that data, and the endpoint must be
rate-limited. It's a UX/support aid, not correctness: the receiver's own receive state machine drives
claiming, and DB-intact gateway recovery drives funding. The held quote remains useful evidence, but
it does not make physical gateway DB loss recoverable. Note the gateway knows `Funded`, not `Claimed`
(the receiver claims independently with its own key).

### 7.8 Health gates

Since there's **no abort after settlement**, the gateway must stop taking on new settled obligations
only when it can't safely operate the handoff. The **required** hard gates that disable new custodial
invoice creation: it can't durably persist the record / input reservation, it can't make progress on
actual settled liabilities, it can't do authenticated backend-ledger settlement confirmation, or the
backend can't establish **declared retention coverage** of all nonterminal records and tombstones
(§7.2). Internal storage and abuse controls can also disable only new invoice creation when the
gateway cannot persist or reconcile safely, but those controls are not advertised protocol quotas and
must not become wallet-visible selection semantics. Exposing a public unpaid-record quota would create
a DoS lever: an attacker could cheaply fill it with unpaid invoices and force honest receives to be
rejected. Already-settled invoices keep flowing through reconciliation and liquidity replenishment.
Issued-unpaid invoice count and face value drive metrics and operator alerts; they do not reserve
ecash and do not produce a distinct protocol-level rejection reason.

The MVP must expose a **minimal observability set** so operators can see contingent exposure,
actual debts, liquidity shortfall, deadline pressure, reconciliation health, and observer freshness.
These metrics are operational evidence and alert inputs; they do not add new create-invoice behavior
except for hard gates already specified above and in §8.

Required gauges:

```text
gateway_custodial_receive_issued_unpaid_count
gateway_custodial_receive_issued_unpaid_msats
gateway_custodial_receive_settled_unfunded_count
gateway_custodial_receive_settled_unfunded_msats
gateway_custodial_receive_unresolved_liability_count{reason}
gateway_custodial_receive_unresolved_liability_msats{reason}
gateway_custodial_receive_ecash_float_available_msats
gateway_custodial_receive_liquidity_shortfall_msats
gateway_custodial_receive_min_funding_deadline_slack_seconds
gateway_custodial_receive_backend_cursor_lag_seconds
gateway_custodial_receive_backend_retention_margin_seconds
gateway_custodial_receive_consensus_time_observer_age_seconds
gateway_custodial_receive_retained_record_count{state}
gateway_custodial_receive_unmatched_settlement_count
```

Required histogram:

```text
gateway_custodial_receive_settlement_to_funding_seconds
```

`issued_unpaid_*` is contingent exposure only. `settled_unfunded_*` is actual debt: backend
settled, but the contract is not yet accepted as funded. `liquidity_shortfall_msats =
max(0, settled_unfunded_msats - usable_ecash_float_msats)` and should drive operator action such as
pegin / liquidity replenishment. `min_funding_deadline_slack_seconds` is the minimum seconds until
funding deadline among settled-but-unfunded records; approaching zero is a critical invariant failure
because settled debts must remain automatically fundable through the original contract.
`backend_retention_margin_seconds` measures how long the oldest recovery-relevant record remains
inside backend ledger retention. `consensus_time_observer_age_seconds` backs the §8 rule that stale
LNv2 consensus-time observation disables new quote creation. `retained_record_count` exposes
storage/reconciliation pressure for alerts and abuse detection without turning unpaid records into
protocol-level admission control. `unmatched_settlement_count` counts ledger settlements in the
gateway's correlation-id namespace that match no record or tombstone (§7.3); any nonzero value is an
alert, since it implies record loss or correlation-id aliasing.

Metrics must avoid high-cardinality labels. Acceptable labels are low-cardinality values such as
`federation_id`, `backend_kind`, `reason`, and coarse `state`. They must not label by `quote_id`,
invoice hash, contract id, URL, or user identity. Obligation gauges are recomputed from durable DB
state on startup; counters and histograms are useful but are not authoritative for liabilities.

**(Optional, post-MVP):** richer dashboards, soft breakers driven by configured metric thresholds
(for example unresolved-liability thresholds or too many stuck funding records), and extra debugging
counters such as `gateway_custodial_receive_invoice_requests_total{outcome,reason}`.

### 7.9 Typed client-actionable outcomes

A client-actionable decision must ride in a **successful domain response**, not in an error. The
existing gateway error channel can't carry one: `PublicGatewayError::LNv2` redacts every failure to
one generic string (`gateway/fedimint-gateway-server/src/error.rs:81-84`), and the send state machine
retries transport/server errors **forever** (`modules/fedimint-lnv2-client/src/send_sm.rs:193-216`).
A new typed error like `CannotDirectSwapCustodialInvoice` returned as an HTTP/LNv2 error would
therefore be either indistinguishable from any other failure or retried indefinitely.

So custodial decisions the client must act on are explicit result enums in `Ok` responses:
custodial-receive creation returns `Created { invoice, quote }` or a typed `Rejected(reason)`, and
the same-gateway send signal is the **forfeit signature** in the existing
`Result<[u8; 32], Signature>` send response (§7.6), not an error. Genuine transport/server failures
stay on the error channel and stay retryable. Only client-actionable domain outcomes move into `Ok`.

The MVP custodial-receive creation rejection enum is deliberately small and covers refusal before the
client receives a usable invoice and quote:

```rust
enum CustodialReceiveRejectionReason {
    CustodialReceiveDisabled,          // Gateway/federation policy currently disables the feature.
    UnsupportedQuoteVersion,           // Client requested an unsupported quote API version.
    InvalidContract,                   // Contract verification failed.
    WrongRefundKey,                    // Contract refund key is not the gateway module key.
    AmountTooSmall,                    // Receive fee would make the contract amount below minimum.
    AmountTooLarge,                    // Request exceeds the gateway's per-receive cap.
    NonSatoshiAmount,                  // Backend granularity cannot represent the amount exactly.
    FeeOrAmountBindingMismatch,        // Contract amount does not match receive_fee.subtract_from(invoice_amount) under current terms.
    DeadlineTooNear,                   // Deadline rule in §8 fails or consensus-time observer is stale.
    DeadlineTooFar,                    // Requested expiry or funding deadline exceeds the advertised maximum.
    BackendInvoiceCreationUnavailable, // Backend cannot currently create the invoice (strictly pre-create).
    BackendLedgerUnavailable,          // Backend cannot provide required ledger/reconciliation support.
    DuplicateContractConflict,         // Existing reservation conflicts with this request.
    CreateInProgress,                  // Same request is already creating an invoice; retry/poll.
    BackendInvoiceUnreturnable,        // A backend invoice may exist for this contract but will not be returned.
    ActualLiabilityLimitExceeded,      // Actual settled/funding/unresolved obligations exceed policy.
}
```

The reasons carry a hard **pre-create invariant**, scoped **per request fingerprint**: every
variant except `CreateInProgress` and `BackendInvoiceUnreturnable` may be returned only when the
gateway can prove no backend create attempt was ever marked maybe-sent **for the rejected
request's own fingerprint**. Any state in which a backend invoice for that fingerprint exists,
existed, or cannot be proven absent must map to `BackendInvoiceUnreturnable` (or
`CreateInProgress` while the create lease is live). `DuplicateContractConflict` fits the
invariant through this scoping: it rejects a **conflicting** request (mismatched fingerprint for
an already-reserved contract) that never triggered its own backend create, even when the stored
record for that contract is post-create. But because the conflict itself proves the gateway holds
a same-contract reservation that may be post-create under another fingerprint — and the client
keeps claim material per **contract**, not per fingerprint — the client deletes only the failed
flow state, never the contract's claim material: a same-contract retry with a changed fingerprint
must not be able to destroy the only claim material for an invoice that may still settle under
the original fingerprint. This invariant is what makes the client's
delete-vs-retain rule (§7.4) implementable from the public reason alone; without it, the same
reason would demand contradictory client actions depending on gateway-internal state the client
cannot observe.

This enum is the stable client-facing API surface. The richer operator liability taxonomy remains
deferred (§14). There is intentionally no unpaid-invoice **face-value** or float-shortage rejection:
unpaid invoice buildup drives metrics / alerts and deployment-level abuse controls, while
post-settlement float shortage is handled as a debt / liquidity problem (§8, §11), not as
create-invoice admission control. There is no public `ResourceQuotaExceeded`: exposing a typed
unpaid-record quota would let attackers intentionally fill it and create a wallet-visible DoS.
Internal resource exhaustion or abuse throttling is surfaced as generic
`BackendInvoiceCreationUnavailable` before backend invoice creation. `ActualLiabilityLimitExceeded`
is based only on actual settled/funding/unresolved obligations, never on issued-unpaid face value.

Internal terminal states and gates map to public rejections as follows:

| Internal state / gate | Public rejection | Client action |
|---|---|---|
| Local validation, amount, or capability rejection before `InvoiceCreating` | Matching typed rejection | Delete the provisional receive; build a fresh contract only after fixing the local/request issue. |
| Amount-binding / advertised-fee mismatch before `InvoiceCreating` | `FeeOrAmountBindingMismatch` | Delete the provisional receive; refresh `RoutingInfo` and rebuild the contract with the current custodial fee. |
| Requested expiry or deadline beyond the advertised maximum | `DeadlineTooFar` | Delete the provisional receive; rebuild within the advertised bounds. |
| `InvoiceCreationExpired` before any create attempt was maybe sent | `DeadlineTooNear` | Delete the provisional receive; build a fresh contract after refreshing `RoutingInfo`. |
| Safe duplicate while a create lease is live | `CreateInProgress` or wait/poll response | Keep the provisional receive; retry/poll the same request and do not build a new contract yet. |
| Conflicting request (fingerprint mismatch) against any stored record | `DuplicateContractConflict` | Treat the flow as failed and build a fresh contract for any retry, but **retain** the contract's claim material and watcher under the standard retention bound — the conflict proves a same-contract reservation exists that may be post-create under another fingerprint. |
| `InvoiceCreateInconclusive` | `BackendInvoiceUnreturnable` | Retain the provisional receive until its funding deadline passes; build a fresh contract for any user-visible retry. |
| `BackendInvoiceRejected` before return | `BackendInvoiceUnreturnable` | Retain the provisional receive until its funding deadline passes; build a fresh contract for any user-visible retry. |
| `InvoiceExpiredUnreturned` before return | `BackendInvoiceUnreturnable` | Retain the provisional receive until its funding deadline passes; build a fresh contract for any user-visible retry. |
| Stale stored invoice on an idempotent duplicate retry (pre-settlement only; a settled record's stored invoice+quote return unconditionally, §7.3) | `BackendInvoiceUnreturnable` | Retain the provisional receive until its funding deadline passes; build a fresh contract for any user-visible retry. |
| Actual settled/funding/unresolved obligations at policy limit | `ActualLiabilityLimitExceeded` | Retry later or choose another gateway; no backend invoice was created for this contract. |
| Internal resource exhaustion or abuse throttling before backend create | `BackendInvoiceCreationUnavailable` | Retry later or choose another gateway; no backend invoice was created for this contract. |

## 8. Fee & amount accounting

The face amount `A` is what the payer pays. The quoted custodial receive fee `Q` sizes the receiver's
contract amount `R = A - Q`. A notify-only backend may **skim a liquidity fee** `S` from the receipt
(e.g. phoenixd splicing in inbound), so the backend credits the gateway `A - S`. Because the gateway
funds the contract **after** settlement, it knows the exact backend credit before funding.

- **No-abort constraint (critical):** once the backend auto-settles, the payer is
  **irrevocably paid**: there is **no cancel/refund path** on this receive. The
  gateway is committed to crediting the receiver. This is the sharpest consequence
  of a notify-only backend and shapes every edge case in §11.
- **Fixed contract amount: no partial funding.** A contract's value is fixed in
  `commitment.amount = R`. The **receiver** receives exactly that. Funding it costs the gateway
  `R + M`, where `M` is the federation module / transaction fee. `process_output` returns the
  contract amount (`contract.commitment.amount`, `contracts.rs:31`,
  `modules/fedimint-lnv2-server/src/lib.rs:595`) and adds module fees on top in the returned
  `TransactionItemAmounts` (`:599`), so the gateway cannot "fund what it can". It always funds the
  full fixed amount. Size float headroom against the full ecash funding leg (`R + M`), not just `R`.
- **Policy: gateway prices skim into the receive fee.** The gateway quotes `Q` to cover expected module
  fees, backend skim, liquidity/rebalance cost, and operator margin. The operation's margin is:

  ```text
  gateway_net = (A - S) - (R + M)
              = Q - S - M
  ```

  So the operation is profitable or break-even when `Q` covers `S + M` plus any desired liquidity /
  operator margin. Define the absorbed per-receive loss as `F = max(0, S + M - Q)`. The receiver
  still gets `R`: if unexpected skim makes `Q < S + M`, the gateway
  funds the full contract and records the loss `F` (it can neither stiff the payer, which is
  impossible, nor under-fund the fixed-amount contract). Large/abnormal skim is alerted, and the per-receive cap
  (§9) bounds the worst case. `receive_fee` semantics: "covers gateway + backend liquidity cost". Tune
  from observed skim.
- **Custodial fee-cap decision.** The MVP uses the existing client
  `PaymentFee::RECEIVE_FEE_LIMIT` (50 sats + 0.5%, `gateway_api.rs:223`) for custodial receive too,
  enforced **component-wise** (base and parts_per_million each within the limit, §7.4 — not the
  derived lexicographic `PartialOrd` the trustless path compares with today, which admits any
  proportional fee whenever `base` is under 50 sats), so the gateway must quote backend liquidity
  cost within that cap and absorb excess variance. Be
  explicit about what that means for the reference backend: phoenixd's auto-liquidity costs roughly
  1% **plus an absolute mining-fee component** per splice, so any receive that triggers an inbound
  liquidity purchase loses `F > 0` **by construction** under the cap — a structural gap, not tail
  variance. The MVP therefore treats liquidity-purchase avoidance as an operating requirement: the
  operator maintains pre-provisioned inbound headroom, and the gateway SHOULD refuse new custodial
  invoice creation (surfaced as generic `BackendInvoiceCreationUnavailable`; it is an internal
  policy gate, §7.8) when the requested amount would exceed available inbound headroom and force a
  splice whose expected skim exceeds the quoted fee by a configured tolerance. A higher or
  differently-shaped custodial fee cap would require a separate explicit-consent client
  policy, not a silent reuse of normal receive selection.
- **Two deadlines.** The backend invoice expiry is the user/payment expiry and bounds unpaid
  contingent exposure. The contract funding deadline is the LNv2 `IncomingContract.expiration_or_fee`,
  evaluated by the federation against `consensus_unix_time`
  (`modules/fedimint-lnv2-server/src/lib.rs:563`), and is only the admission check for funding the
  original contract. (The same `expiration_or_fee` field carries fee-encoded near-`u64::MAX` values
  for LNURL receives — `fee_encoded_expiration`, `modules/fedimint-lnv2-common/src/contracts.rs` —
  custodial deadlines are real timestamps and cannot collide with that range numerically, but any
  logic that classifies contracts by expiration magnitude must be checked against long-lived
  custodial contracts. The one known instance is the claim-event fee fallback in
  `ReceiveStateMachine::transition_incoming_contract`
  (`modules/fedimint-lnv2-client/src/receive_sm.rs:151`): every operation meta other than
  `LightningOperationMeta::Receive` recovers the fee as `u64::MAX - expiration`, which for a real
  custodial timestamp yields a ~1.8e19-msat garbage fee and overflows the unchecked `amount + fee`
  event arithmetic whenever the contract amount exceeds the timestamp's msat value. The custodial
  operation meta MUST take the invoice-difference fee path, like `Receive` (§7.4, impl specs,
  tested in §15).) For custodial receive it must be **strictly later** than the backend invoice
  expiry and long-lived enough that a settled invoice can be funded automatically under realistic
  downtime and liquidity-replenishment delays, and it is bounded above by gateway policy (below). The gateway must not issue a quote using only its local
  wall clock. For MVP, without any new Fedimint module endpoint, the gateway observes existing signed
  session outcomes, tracks the latest `UnixTimeVote` per guardian, and computes
  `gateway_observed_lnv2_consensus_time` with the same threshold rule as the server (`times[threshold -
  1]` after sorting descending). Quote creation is unavailable until that observer is fresh enough. The
  signed quote records this value as `observed_lnv2_consensus_time` so the deadline calculation is
  auditable (§7.3), but the quote does not itself prove observer freshness; that remains a
  gateway-enforced hard gate and metric (§7.8). The client also checks this quoted value against an
  independent time reference — its local wall clock with margin, or optionally its own observed LNv2
  consensus time (§7.4) — so a stale or crudely dishonest gateway cannot make an
  unsafe funding deadline look valid by reporting an old observation.

  The gateway rejects custodial invoice creation unless:

  ```text
  funding_deadline >
      gateway_observed_lnv2_consensus_time
    + min_contract_lifetime_secs
    + consensus_time_observation_max_age_secs
    + safety_margin_secs
  ```

  It also requires:

  ```text
  invoice_expiry + min_invoice_to_funding_deadline_delta_secs <= funding_deadline
  ```

  and, symmetrically, the advertised upper bounds:

  ```text
  funding_deadline <= gateway_observed_lnv2_consensus_time + max_funding_deadline_secs
  invoice_expiry   <= gateway_observed_lnv2_consensus_time + max_invoice_expiry_secs
  ```

  Requests beyond either bound are rejected with `DeadlineTooFar` before backend invoice creation.
  Without an upper bound, a single request could pin the gateway's retained-record set, its
  direct-swap namespace reservation, and the required backend retention coverage (§7.2) arbitrarily
  far into the future — and because declared retention coverage of every nonterminal record is a
  hard issuance gate, one absurd-deadline request could otherwise disable all new custodial
  issuance.

  If the observer is stale or lacks fresh threshold votes, the gateway disables custodial receive
  quote creation for that federation rather than falling back to a small local-clock margin. If a
  record's funding-deadline slack approaches the safety margin, the gateway treats that as a critical
  operational fault, disables new custodial invoice creation, and prioritizes funding/replenishment;
  the deadline is not used to erase or downgrade a settled invoice debt.

## 9. Trust & security analysis

**The trust window.** With the invoice hash check gone, the receiver trusts the gateway
from **invoice issuance** onward. The client mitigates the issuance-side risk by
binding the invoice to the gateway's advertised key (§7.4), but a malicious gateway can
still refuse service or, after the backend settles, hold the money.

The money-at-risk exposure is concentrated between the backend settling (payer paid,
gateway holds the money) and the gateway funding the contract (receiver can claim). Once
funded, the receiver claims **trustlessly**. So the gateway is custodial **across the
receive handoff**, not over an ongoing balance.

**What each party risks:**

| Party | Exposure |
|---|---|
| Payer | **No refund** if the gateway fails post-settle (the payer already paid), and **degraded proof-of-payment**: the settlement preimage `P′` proves payment to the gateway's node, not to the receiver's contract — only the receiver-held signed quote links `H′` to the contract, whereas trustless receive hands the payer a receiver-bound preimage. |
| Receiver | From invoice issuance onward, trusts the gateway: it could hand back a wrong-payee invoice (mitigated by the payee-binding check, §7.4) or, after settlement, refuse/fail to fund → receiver gets nothing for a payment the payer made. |
| Gateway | Funds the contract from its float after authenticated backend settlement, still bearing backend skim variance, liquidity, and liability risk. |

**Custodial-specific failure modes (no abort available):**
- **Unclaimable / invalid contract.** Two distinct cases the gateway can't tell apart at funding.
  (a) **Invalid preimage / non-decrypting:** post-funding the contract routes to `refund_pk` (the
  gateway) (`modules/fedimint-gwv2-client/src/receive_sm.rs:234-260`). The custodial funding helper
  skips the receive state machine, so the non-blocking **`CustodialContractAuditSM`** (§7.3) detects
  this and submits the refund. The **payer already paid**, the receiver gets nothing, and the gateway
  recovers its funding, a windfall it must treat as an **auditable `InvalidContract` liability, not
  income** (§7.7). (b) **Decrypts but the receiver can't claim** (a `claim_pk` the receiver doesn't
  own or can't derive): the contract is valid and routes to whoever owns `claim_pk`, **not** back to
  the gateway, so it's **not a gateway liability**, just the receiver's own mistake. The
  audit SM can't detect (b), so the **primary defense is the client self-check**: `recover_contract_keys`
  verifies a valid preimage **and** a derivable claim key before the invoice (§7.4), and a receiver
  that bypasses it pays for its own error.
- **Double funding.** If exactly-once funding (§7.3) fails, the gateway double-funds and
  double-loses. Consensus will not stop it.
- **Adversarial skim-forcing (economic griefing).** The backend skim `S` is partly
  attacker-influenceable: a cooperating payer/receiver pair can drain the gateway's inbound
  liquidity between receives, or size receives so each one triggers a phoenixd liquidity purchase,
  whose absolute mining-fee component does not scale down with amount. Each cycle costs the
  attacker roughly `Q` while costing the gateway `F = max(0, S + M - Q)` (§8), which can exceed `Q`
  by a wide margin at high mining fees. The per-receive cap bounds a single event, not the bleed
  rate. Mitigations: the §8 inbound-headroom issuance gate, per-receive minimums, abnormal-skim
  alerts, and the `max_in_flight` gate on open obligations.

**Trust assumption.** Users trust (a) the operator's **honesty** to fund, (b)
the gateway's ability to durably persist its local state across the handoff, and (c) the
Lightning **backend's integrity**: settlement confirmation is backend-attested, so a compromised
backend can fabricate "settled" receipts for colluding receivers and drain the gateway's ecash
float cumulatively — per-receive and in-flight caps bound each cycle, not the sum, because
headroom returns after every claim. The backend is trusted not merely to custody the Lightning
leg but not to attest false receipts. Operators SHOULD reconcile cumulative attested receipts
against the backend node's balance/channel deltas and alert on divergence; an enforced cumulative
cap is deferred (§14). The primary recovery
path is the durable authoritative funding state (the federation client DB prefix, §7.3). The
client-held signed quote is auditable evidence of the gateway's commitment, but it is not a
cryptographic enforcement mechanism and does not make physical gateway DB loss recoverable. The
intended handoff is seconds when the gateway is online, and per-receive caps bound the amount (§9),
but a settled backend invoice remains a gateway debt until the receiver is funded.
This is strictly weaker than trustless receive but much narrower than a custodial wallet holding
balances indefinitely.

**Third-party dispute verification.** A receiver can later claim "I did not receive the money", but
the verifiable question is narrower than human wallet balance. Given the signed quote, the funding
output, and signed federation session history, an auditor can verify the contract-level state:

| State | Third-party evidence |
|---|---|
| **Not funded** | No accepted `IncomingContract` output matches the quoted `contract_id` / full contract. The gateway still owes the receiver if the backend ledger shows settlement. |
| **Funded but unclaimed** | An accepted funding outpoint exists for the quoted contract and no later `LightningInputV0::Incoming(outpoint, ...)` spend consumes it. The receiver can still claim; the gateway did its funding job. |
| **Claimed** | A later accepted `LightningInputV0::Incoming(outpoint, agg_decryption_key)` consumes the funding outpoint, the aggregate decryption key verifies, and decrypting the quoted contract succeeds, routing the spend through `claim_pk` (`modules/fedimint-lnv2-server/src/lib.rs:508-532`). Protocol-level evidence says the receiver-side claim path succeeded. |
| **Refunded / invalid** | A later accepted `LightningInputV0::Incoming(outpoint, agg_decryption_key)` consumes the funding outpoint, but decrypting the quoted contract fails and routes value through `refund_pk`. The receiver did not get paid; the gateway records an auditable liability (§7.7). |

This audit serves the **receiver-side** dispute only: the payer holds `P′` but no quote, so a
payer-side dispute reduces to ordinary custodial-LSP bookkeeping against the gateway's backend
ledger (see the payer row above). The audit also does **not** prove the receiver's app persisted
notes, still has spendable ecash, or did
not later spend the claimed ecash. Once the claim path succeeds, any later "my balance did not show
up" dispute is a client/local-wallet support issue, not gateway liability. The optional
`custodial_receive_status` endpoint (§7.7) need not track `Claimed`; the gateway's obligation ends
at `Funded`, while a separate audit can inspect federation history to distinguish unclaimed,
claimed, and refunded contracts.

**Bounding blast radius:** per-receive cap, actual-liability tracking, optional allow-list of
receivers, prompt funding + reconciliation (§10), and liquidity replenishment so honest-but-crashed
gateways lose nothing, only delay.

## 10. Crash & recovery

Durability is what turns "gateway crashed mid-handoff" from "lost funds" into "delayed funds".
This section assumes the gateway's persistent DB is intact and not rolled back. Physical gateway DB
loss, loss of the authoritative federation client DB prefix, and restore-from-stale-backup are
operator data-loss events outside this spec's recovery model (§16).

- **Durable record** (§7.3) of every `PendingCustodialReceive` with its explicit
  status (`InvoiceCreating → AwaitingPayment → SettledAwaitingLiquidity → FundingReserved →
  FundingPrepared(prepared_tx) → FundingSubmitted(prepared_tx, operation_id, txid) →
  Funded(outpoint)`), with terminal branches `InvoiceExpiredUnpaid` (tombstoned),
  `InvoiceCreationExpired` (no backend invoice created), `InvoiceCreateInconclusive` (retained
  maybe-sent backend create cannot be proven absent), `BackendInvoiceRejected` /
  `InvoiceExpiredUnreturned` (retained tombstones for unreturned backend invoices), and
  `UnresolvedLiability`.
- **Idempotent invoice creation** (§7.3): a record stuck in `InvoiceCreating` after a crash is
  resolved by `get_invoices_by_external_id(backend_correlation_id, include_unpaid = true)`. If the
  backend invoice exists, complete the `AwaitingPayment` record if the invoice is still safe to
  return, otherwise retain an unreturned-invoice tombstone for reconciliation. If no backend invoice
  exists, the request can be retried only by a handler holding the durable backend-create lease, only
  if the draft is still fresh enough to expose to a client, and only if no prior create attempt was
  ever marked maybe-sent. Otherwise it is
  dropped/tombstoned without creating a backend invoice, or held as `InvoiceCreateInconclusive` for
  operator review if a maybe-sent attempt cannot be proven absent (the MVP has no backend
  visibility barrier that could prove it, §14). A duplicate
  `create_custodial_bolt11_invoice` whose
  `request_fingerprint` matches the stored draft never creates a second backend invoice; a duplicate
  with mismatched amount, description hash, requested invoice expiry, or quote API version is
  rejected against the stored draft.
- **Idempotent funding** keyed on `backend_invoice_hash` / `contract_id`: fund each
  contract exactly once. A hint arriving in `SettledAwaitingLiquidity` waits for float; one in
  `FundingReserved`, `FundingPrepared`, or `FundingSubmitted` waits on the stored reservation /
  prepared tx / operation result rather than building a second tx. One in `Funded` is a no-op.
- **Startup reconciliation:** on boot, the `CustodialSettlementObserver` polls the backend's
  authenticated ledger from its durable cursor (phoenixd `GET /payments/incoming` /
  `list_settled_invoices`), matching by `backend_correlation_id` first and `backend_invoice_hash`
  second against **every nonterminal record and every retained `InvoiceCreateInconclusive`,
  `InvoiceExpiredUnpaid`, `BackendInvoiceRejected`, and `InvoiceExpiredUnreturned` tombstone**.
  For each `AwaitingPayment` record, ledger-confirmed settlement moves to the funding path
  (exactly-once permitting). If the invoice is expired and the backend's declared finality/retention
  window proves no settlement occurred, the record becomes `InvoiceExpiredUnpaid`. Contract funding
  deadline slack is still checked as a critical health condition, but it is not the unpaid/paid
  terminalization rule. A settlement matching an `InvoiceExpiredUnpaid` tombstone is a
  backend/finality surprise and returns to the automatic funding path while the funding deadline
  has not passed in observed consensus time (after it, the contract is unfundable and the
  settlement opens an `UnresolvedLiability`, §7.3), never a silent miss. A
  settlement matching `InvoiceCreateInconclusive`, `BackendInvoiceRejected`, or
  `InvoiceExpiredUnreturned` reruns recovered-invoice validation, reasserts the direct-swap namespace
  reservation when it is safe to own the hash, and then follows the retained record's
  `fund_on_settlement` policy. Safe records return to the automatic funding path with
  `UnreturnedInvoiceSettled` evidence until the receiver is funded; unsafe validation, namespace,
  granularity, or backend-invariant failures become auditable `UnresolvedLiability` /
  `BackendMismatch` records. A settlement in the gateway's correlation-id namespace that matches no
  record and no tombstone is recorded as an `UnmatchedSettlement`, alerts, and disables new issuance
  pending review (§7.3). This closes the crash gap for an honest operator without allowing a
  rejected mismatched invoice to fund the wrong contract.
- **Reserved/submitted reconciliation:** on boot, every `SettledAwaitingLiquidity` record rechecks
  deadline slack and float. If liquidity is available, one worker atomically claims it into
  `FundingReserved`; otherwise it remains a debt waiting for liquidity and triggers liquidity
  replenishment / critical slack alerts. Every `FundingReserved`,
  `FundingPrepared`, or `FundingSubmitted` record re-derives its deterministic funding `operation_id`
  and checks `operation_exists`. If the operation is present the gateway never resubmits: it
  awaits that operation's outcome and advances to `Funded` on acceptance. The no-operation branch
  **splits by state**. A `FundingReserved` record never submitted a tx, so no operation is
  expected: if the contract is still fundable it builds and prepares a fresh tx, transitioning
  through `FundingPrepared` and `FundingSubmitted`. A
  `FundingPrepared` or `FundingSubmitted` record holds the exact `prepared_tx`. A missing operation
  means different things by state: for `FundingPrepared` it's **expected** (the operation is created
  at submit, so the tx was never submitted), and for `FundingSubmitted` it's a genuine
  **operation-log divergence** (the tx may already have landed). Either way the gateway **must not**
  build a fresh tx (that would risk a second funding at another outpoint). The authoritative
  federation client DB prefix is intact here (the gateway just read this record from it), so it
  re-drives **the exact stored `prepared_tx`** (consensus-idempotent on its pinned inputs),
  escalating to the unresolved-liability path only if it can't. The operation-present path covers the
  crash-after-acceptance-before-DB-update case with no federation endpoint: a surviving client
  DB still holds the operation, so the gateway awaits its outcome and marks `Funded`. A fresh tx
  may be built only for `FundingReserved`. If the **authoritative federation client DB prefix** is
  gone, the stored tx is unrecoverable and the case is out of scope for automatic recovery.
- **Funding-tx monitoring:** track acceptance, retry on transient federation/tx
  errors, advance to `Funded` **only on acceptance**. If funding is rejected, surface it as an
  unresolved liability (§11), never a silent drop. A rejection due to contract expiration is a critical
  policy/invariant failure because custodial receive is supposed to use a long-lived funding deadline
  that keeps settled invoices automatically fundable.
- **Out-of-scope local data loss:** if the authoritative federation client DB prefix is missing,
  corrupt, or rolled back, then `operation_exists`, the stored `prepared_tx`, input reservations,
  liabilities, and the funding state are gone with it. The gateway must not treat a receiver-held
  quote as permission to build a fresh funding tx, because a previously submitted async tx may still
  land. The quote and backend ledger can support operator investigation or dispute handling, but
  they are not an MVP protocol recovery path.

## 11. Edge cases & policies

| Case | Policy |
|---|---|
| **Contract expiry vs funding** | The contract funding deadline is an LNv2 funding-admission check, not a liability boundary. Custodial receive uses a long-lived funding deadline, strictly after invoice expiry, so settled invoices remain automatically fundable through the original contract. If the invoice expired and never settled, there is no funded on-federation contract to cancel; the quoted `IncomingContract` is just local/gateway state until funded. If a settled record approaches the funding deadline, that is a critical operational fault: disable new invoice creation, replenish liquidity, and fund before expiry. |
| **Receiver offline** at claim time | Fine. The funded contract persists. Contract expiry is a **funding** deadline, not a claim deadline: the incoming spend has no expiry check (`modules/fedimint-lnv2-server/src/lib.rs:508`), so a funded contract stays claimable after expiry **unless already spent**. |
| **Underpayment / amount mismatch** | The backend enforces the fixed invoice amount, so this shouldn't occur. A deviation within expected skim funds the full contract and records the loss (§8). A gross **shortfall** or non-amount inconsistency opens a `BackendMismatch` liability (§7.7) instead of funding, consistent with the direction-aware rule in §7.3. It **cannot** under-fund the fixed-amount contract, and **cannot** refund the payer. |
| **Overpayment** | Fund the quoted `commitment.amount` — always, regardless of surplus size (the mismatch-liability rule is direction-aware and funding is owed and safe, §7.3). Record the surplus as auditable evidence, treat it per fee policy, and alert if gross: it signals a backend anomaly even though funding proceeds. |
| **Settled but gateway float momentarily short** | This is a debt, not a failed receive. Hold in explicit `SettledAwaitingLiquidity` with no reserved inputs or prepared tx, alert the operator, and fund when ecash float recovers by transitioning `SettledAwaitingLiquidity → FundingReserved → FundingPrepared`. The MVP can drive or prompt a pegin from available on-chain funds. Post-MVP can automate loop-out, channel close, splice, swap-out, or backend-specific liquidity actions. The long-lived funding deadline is chosen so liquidity recovery resolves by funding the original contract after liquidity recovers. |
| **Receiver says they were not paid** | Resolve by contract-level evidence (§9): not funded → gateway liability if backend settled; funded but unclaimed → receiver can still claim; claimed through `claim_pk` → gateway paid at the protocol level; refunded through `refund_pk` → receiver was not paid and the gateway records a liability. A third party cannot verify the receiver's private wallet balance or local note persistence. |
| **Webhook redelivery / double settle** | Gateway-side exactly-once (explicit-status idempotency, serialized per `contract_id`) prevents double-funding. **Consensus does not dedupe** (§7.3, §10). |
| **Crash after funding acceptance but before DB update** | With the client DB intact the re-derived `operation_id` still exists, so the gateway awaits its outcome and marks `Funded` on acceptance, never resubmitting. A missing operation lets the gateway build a fresh tx only for a `FundingReserved` record (no prepared tx). A missing operation on a `FundingPrepared` record is expected (operation is created at submit). On a `FundingSubmitted` record it's an operation-log divergence and the tx may already have landed. Either way the gateway re-drives its exact stored `prepared_tx` (consensus-idempotent on its pinned inputs) rather than building a new one, escalating to unresolved-liability if it can't (§7.3, §10). |
| **Backend reports settle but funds never arrived** (backend bug) | Fund only after **authenticated ledger confirmation** (§7.3), never on the push event alone. Authentication proves the claim came from the backend, not that a payer paid: a compromised backend attesting fabricated settlements drains ecash float, which is why backend integrity is an explicit trust assumption with recommended cumulative reconciliation (§9). |
| **DB loss / inconsistency** | The per-federation client DB is a **logical prefix under the single physical gateway DB**, not a separate file (`gateway/fedimint-gateway-server-db/src/lib.rs:35`), so the real split is logical vs physical. **Logical** corruption of just the rebuildable root indexes (the `quote_id` / hash / correlation-id → `federation_id` maps) is a rebuild from the surviving authoritative client-prefix state plus backend ledger (§7.3). **Physical** loss of the gateway DB file, loss of the authoritative client-prefix state, rollback before the receive record existed, or gateway key loss is out of scope for this spec (§10, §16). The receiver's signed quote and backend ledger may be evidence for operator investigation, but they are not an automated reconstruction or safe refunding protocol. |
| **Invalid / unclaimable contract** (buggy or malicious receiver) | Client self-checks claimability before the invoice (§7.4). If one slips through, the non-blocking `CustodialContractAuditSM` (§7.3) detects the non-decrypting contract and submits the refund to the gateway while the payer already paid. The gateway records the recovered funding as an **auditable liability** (`InvalidContract`, §7.7), never pocketed (§9). |

## 12. Comparison

| | Trustless (LND/LDK, ±LSP) | **Custodial-receive (this spec)** | gateway-lite |
|---|---|---|---|
| Receive trust | trustless | custodial at handoff | trust host federation's gateway |
| Backend | LND/LDK (hold + intercept) | notify-only (phoenixd) | none local |
| Consensus/server changes | none | **none (module); gateway, gateway API, LNv2 client, and `fedimint-client` tx-prep changes** | new cross-fed authenticated API |
| Operator burden | node + channel mgmt (LSP can outsource) | run a managed daemon, ~zero channel ops | none local, depends on remote gatewayd |
| New client code | none | custodial receive variant + consent | client unaffected (transparent) |
| Payer refund on failure | yes (HTLC cancel) | **no** (already settled) | depends |
| Send | trustless | trustless (companion, §13) | proxied |

Custodial-receive sits between full trustless and gateway-lite: it keeps the
gateway local and self-custodied for routing, trades only the receive-handoff
atomicity, and needs no federation-protocol changes.

## 13. Send (companion, trustless, out of detailed scope)

A phoenixd-backed gateway does **send** with the normal trustless LNv2 flow:
`POST /payinvoice` returns the preimage to claim the `OutgoingContract`. Resolve
in-flight via `GET /payments/outgoingbyhash/{hash}`. Constraints: pre-fund outbound
liquidity (swap-in), and map `OutgoingContract` expiration/fee onto the pay call,
refusing to pay too close to expiry. Specced separately, included here only so the
reference backend is a complete gateway.

## 14. Open questions / decisions

1. **`receive_fee` sizing within the existing cap**: how to quote so the absorbed per-receive loss
   `F = max(0, S + M - Q)` (§8) stays near zero. The absorb-full-skim policy and MVP cap are fixed
   in §8; the open parts are the quoting heuristic, the inbound-headroom target, and the
   splice-avoidance gate tolerance (§8). If deployments need a higher
   fee, design a separate explicit-consent custodial fee cap.
2. **Two-deadline / observer values**: concrete invoice-expiry vs funding-deadline gap,
   minimum contract lifetime, maximum invoice expiry and funding deadline
   (`max_invoice_expiry_secs` / `max_funding_deadline_secs`), consensus-time observation max age,
   and safety margin.
3. **Authenticated-settlement mechanism**: the per-backend ledger-confirmation call
   (phoenixd ledger query, generalization for other notify-only backends).
4. **Capability typing**: the `ReceiveCapabilities` struct, custodial deadline-policy fields, and
   policy selectors are chosen (§7.1). The open part is how richly to type the backend capability
   descriptor.
5. **Limits / alert defaults**: concrete per-receive cap, actual-liability target, internal
   abuse/storage-control policy, and alert thresholds for the required MVP metrics (§7.1, §7.3, §7.8).
6. **Backend trait shape**: extend `ILnRpcClient` with capability + custodial
   primitives, vs a separate `NotifyOnlyBackend` trait.
7. **Out-of-band discovery and consent UX**: how wallets accept custodial gateway URLs from
   non-protocol sources, remember operator/app policy, and surface "this gateway is custodial for
   receive."
8. **Quote/receipt wire shape**: the fields, embedded `CustodialReceiveTerms`,
   domain-separated signature, `quote_id`, and the exact canonical encoding (BIP-340-style
   tagged hash over the fedimint consensus encoding, normative in impl spec 02) are chosen
   (§7.3). The open part is `api_version` evolution and where the client persists the
   `CustodialReceiveQuote`. A separate `terms_hash` field was dropped from MVP as redundant with the
   signed embedded terms; reintroduce a compact terms reference only if a post-MVP status API needs
   one.
9. **Audit timing**: how long the `CustodialContractAuditSM` (§7.3) waits for decryption shares
    before declaring a contract invalid and refunding.
10. **Prepared transaction API shape**: how the client API exposes prepare-with-input-reservation
    separately from submission while preserving existing transaction idempotency and autocommit
    semantics.

**Deferred to post-MVP (intentional non-goals for v1).** These were considered and cut from the core
because DB-intact recovery (§10) or simpler choices already cover correctness, and they add build/test
surface without preventing a double-fund, double-spend, lost-funds, or trust hole:

- **Rich liability tooling** (full reason/resolution taxonomy, evidence-bundle export,
  operator-visible audit records, automated resolution integrations). The MVP keeps a minimal
  in-prefix liability record (§7.7) and does not define a manual or receiver-cooperative resolution
  path.
- **Quote-authenticated `custodial_receive_status` query**, rich dashboards, and soft health gates
  beyond the required MVP metrics (§7.7, §7.8).
- **Two-window tombstone model** (separate settlement-finality vs ledger-retention bounds) and a
  richer late-settlement finality model (§7.3 limits).
- **A second concrete backend and a richer backend capability matrix** beyond the phoenixd reference
  path (the generic notify-only *design* stands, §7.2, and only additional backends and a fuller
  capability matrix are post-MVP).
- **Automatic pre-funding alternate-gateway routing** for a same-gateway custodial invoice. This needs
  a pre-funding classification step so the alternate gateway is the contract `claim_pk` from the
  start. The MVP forfeit-refunds and the caller reselects (§7.6); the optimization only saves a wasted
  funding/refund round-trip, so it is deferred.
- **Create-visibility barrier for maybe-sent backend creates**: a backend-declared point after which
  a not-found `get_invoices_by_external_id` lookup is authoritative, turning some
  `InvoiceCreateInconclusive` outcomes into safe retries (§7.3). phoenixd declares no such
  guarantee, so the MVP never retries a maybe-sent create.
- **Client-side LNv2 consensus-time observer** as the quote cross-check time reference (§7.4). The
  MVP baseline is a wall-clock margin check; streaming session outcomes on every mobile/wasm wallet
  is optional hardening against a marginal threat.
- **Ecash input re-credit ("unprepare") for proven-dead prepared transactions.** The MVP
  quarantines a `FundingRejected` liability's inputs with the liability record (§7.7) rather than
  re-crediting them; a re-credit API is module-specific work with its own double-spend hazards.
- **Cumulative backend-receipt reconciliation cap.** The MVP recommends operator reconciliation of
  attested receipts against backend node balance/channel deltas (§9); an enforced cumulative cap
  that halts issuance on divergence is deferred.

## 15. Implementation phases

Ordering front-loads the hardest risks. The phoenixd adapter is tempting to build first but doesn't
retire them: the real risks are client-core transaction persistence and the public-API semantics, so
those come first.

1. **Client-core transaction preparation**: a generic `fedimint-client` prepare/submit split with
   durable input reservations and exact-tx replay (finalize + lock inputs + return bytes and a
   reservation token without an op-log entry or submission SM, then install a stored exact tx as a
   submission SM in one autocommit dbtx, §7.3). Highest-risk, and it gates the rest.
2. **Public API semantics**: `RoutingInfo` receive capabilities, the custodial-receive result enums
   including `ActualLiabilityLimitExceeded` but no public resource-quota rejection, and the
   same-gateway send **forfeit-signature** outcome that rides successful domain responses (§7.6,
   §7.9; the refund outcome already emerges from the `RegistrationError` cancellation path, so this
   phase adds the labeled registry detection, not the mechanism), plus the
   rule that legacy `GATEWAYS_ENDPOINT` remains trustless-compatible only. If dual-capable mode is
   included in MVP, this phase also adds the direct-swap receive-registry hook in the legacy-listed
   gateway process. If MVP is custodial-only/out-of-band only, that hook is needed only for send
   handlers that share the custodial gateway's payee key; handlers that do not share that key never
   receive the same-gateway self-pay case.
3. **Backend**: `LightningMode::Phoenixd` + notify-only backend adapter (send + `create_plain_invoice`
   with `external_id` + `subscribe_invoice_settled` hints + `list_settled_invoices` /
   `get_settled_invoice_by_hash` / `get_invoices_by_external_id` ledger queries, the declared retention
   contract, capability flag).
4. **`custodial-gatewayd` service**: build the separate custodial receive binary (§7.1), persist
   `PendingCustodialReceive` with explicit states, run the ledger-first
   `CustodialSettlementObserver`, fund-on-settle via the prepare/submit helper
   (`prepare_custodial_incoming_funding` / `submit_prepared_custodial_funding`, §7.3) with
   `FundingPrepared` storing the exact tx and reserving its ecash inputs, enforce **exactly-once**
   funding, run the `CustodialContractAuditSM`, sign quotes, maintain reason-tagged retained
   tombstones with `fund_on_settlement`, maintain the minimal in-prefix `CustodialReceiveLiability`
   record (§7.7), reconcile on startup, enforce internal persistence / abuse controls without
   exposing public unpaid-record quotas, alert on issued-unpaid records, handle liquidity
   replenishment, and expose the required MVP metrics (§7.8).
5. **Capability advertisement and selection**: `ReceiveCapabilities` in `RoutingInfo`, the
   `select_gateway_for_receive` / `select_gateway_for_send` policy selectors, version handling, and
   wallet-supplied custodial candidate URLs.
6. **Client**: `receive_custodial` variant (self-check claimability, persist provisional receive
   state before the gateway request leaves, skip hash check, verify/persist signed quote, retain
   provisional state for `BackendInvoiceUnreturnable` / `CreateInProgress` / no-response outcomes
   and prune it only after the funding deadline has passed conservatively in consensus-time terms
   (§7.4), enforce custodial fee cap, consent,
   surface mode).
7. **Tests**: a deterministic `FakeNotifyOnlyBackend` is the **primary** correctness harness. It
   creates invoices, reorders / drops hints, forges unauthenticated hints, serves ledger pages with
   duplicate or shifted offsets, simulates skim, and pauses at crash hooks around **every** durable
   status transition. The critical failures are state-machine and DB-ordering bugs, so they need
   exact crash points, not a live backend. Add **one** phoenixd-on-mutinynet smoke test for API
   compatibility. Key cases:
   - a **duplicate-funding test across restart + webhook redelivery**, proving a contract is never
     funded at two outpoints
   - **`FundingPrepared` survives restart and re-drives identical tx bytes**, and a missing prepared
     tx **never** builds a fresh replacement
   - a `FundingPrepared` record's **reserved ecash inputs are not consumed** by a concurrent
     gateway/client operation, so the exact tx stays re-drivable after restart
   - an **operation-log divergence with the record intact** (authoritative prefix survives): the
     gateway re-drives the exact stored `prepared_tx`, never a second different tx, even when a
     lookup reads "not funded" mid-flight (§7.3, §10)
   - crash after `InvoiceCreating(quote_draft)` commits and the backend invoice is created, but before
     `AwaitingPayment(signed_quote)` commits: recovery looks up by `backend_correlation_id`, reruns
     draft validation and direct-swap namespace reservation, then signs the recovered invoice hash
     using the exact stored draft, even if gateway fee/deadline config changed while it was down
   - duplicate create requests while the first backend create call is in flight: the second handler
     observes the unexpired durable create lease and does not call the backend, proving the gateway
     itself cannot create two invoices for one `backend_correlation_id`
   - expired create lease after a maybe-sent backend request: if backend lookup does not find the
     invoice, the record becomes `InvoiceCreateInconclusive` and no second backend invoice is
     created (the MVP never retries a maybe-sent create)
   - an `InvoiceCreateInconclusive` record remains in ledger reconciliation by
     `backend_correlation_id`; if the maybe-sent invoice later appears or settles, it reruns recovered
     invoice validation and follows its `fund_on_settlement` policy rather than being silently missed
   - stale draft recovery: if no backend invoice exists and the draft is no longer within freshness /
     deadline margins, no backend invoice is created; if a backend invoice exists but is no longer safe
     to return, the gateway retains a tombstone for late-settlement reconciliation and returns a typed
     rejection
   - rejected-but-retained client receive: a backend invoice settles after the client saw
     `BackendInvoiceUnreturnable`, and the provisional receiver state still
     claims the original contract when the gateway funds it
   - backend invoice validation before quote signing: amount, payee, expiry tolerance, description
     hash/direct description, payment hash, and backend kind/granularity assumptions must match the
     persisted draft, otherwise the invoice is retained as `BackendInvoiceRejected` and not returned
   - recovered backend invoice validation: an invoice discovered through crash recovery or
     `InvoiceCreateInconclusive` reconciliation must pass the same draft validation and direct-swap
     namespace reservation as the original create path before quote signing or funding
   - a **backend lookup returning two invoices for one `externalId`** disables new issuance and never
     silently picks one (§7.3)
   - duplicate create with the same contract but different amount, description hash, quote API version,
     or requested invoice expiry is rejected against the stored `request_fingerprint`, and the
     client's `DuplicateContractConflict` handling retains the contract's claim material, which
     still claims the original contract when the first fingerprint's invoice settles and the
     gateway funds it
   - client provisional-record pruning is conservative: a wall clock running ahead of LNv2
     consensus time by up to the configured maximum assumed clock skew does not prune claim
     material before the funding deadline has passed in consensus time, and the pruning margin is
     computed from the persisted policy fields even when no quote was ever returned
   - logical root-index loss with the authoritative client-prefix records intact: indexes rebuild
     from surviving records and backend-ledger confirmation
   - a **forged webhook ignored** unless the backend ledger confirms settlement
   - the **payee-binding rejection** and full **quote verification**
   - legacy `GATEWAYS_ENDPOINT` excluding a custodial-only gateway, and normal trustless receive using
     only trustless-capable gateway candidates
   - a **same-federation sender paying a custodial invoice via a non-payee gateway** (§7.6), and a
     same-gateway custodial self-pay where the gateway **returns a forfeit signature** so the sender
     refunds the funded contract immediately and never retries it as an infinite transport error (§7.6)
   - crash after backend invoice creation but before `backend_invoice_hash -> CustodialPending`
     reservation: recovery re-derives and atomically reasserts the registry entry before the quote is
     returned or the receive is treated as active
   - an **invalid contract opening a liability after the gateway refund audit** (§7.3, §7.7)
   - **offset-pagination recovery** with overlap + dedupe, proving no settled invoice is missed or
     double-counted
   - a **duplicate `create_custodial_bolt11_invoice` retry** while the authoritative record persists
     returning the same invoice and quote, **never** a second backend invoice, and returning
     `BackendInvoiceUnreturnable` instead when the stored invoice is no longer safe to return
   - cross-path collisions **(dual-capable mode only, deferred with it)**: trustless registration
     rejects a contract/payment image already owned by custodial receive, custodial creation rejects
     a contract/payment image already owned by trustless receive, and a dual-capable direct-swap
     lookup returns the custodial forfeit-signature outcome rather than falling through to the
     trustless registered-contract table — the trustless-side rejections live in legacy
     gatewayd/gwv2 and ship with dual-capable mode, not the MVP custodial-only binary; the
     custodial-side image-collision rejection is MVP and is tested intra-custodially
   - backend invoice hash collision: a custodial backend invoice hash that matches an existing owner
     (another custodial pending receive in MVP; an active trustless registered payment hash in
     dual-capable mode) is not returned to the client and disables new custodial issuance for
     operator review while retaining a `BackendInvoiceRejected` tombstone for reconciliation
   - retained custodial tombstones that own a `backend_invoice_hash` keep the namespace reserved
     until pruning **(MVP, intra-custodial)**; tombstones caused by an already-active trustless
     collision remaining unsafe without stealing ownership is **dual-capable mode only**
   - settlement of an `InvoiceCreateInconclusive`, `BackendInvoiceRejected`, or
     `InvoiceExpiredUnreturned` retained record follows its `fund_on_settlement` policy: safe records
     return to the automatic funding path with `UnreturnedInvoiceSettled` evidence, while unsafe
     validation / namespace / backend-invariant failures open an auditable liability
   - client quote verification rejects a quote whose `observed_lnv2_consensus_time` is too far behind
     the client's time reference (the wall-clock margin baseline, or the optional locally-observed
     LNv2 consensus time), or whose deadline rule fails under that reference
   - issued-unpaid invoice buildup increments metrics / alerts but does **not** reject new custodial
     invoice creation by face value alone; internal persistence / abuse controls surface as generic
     `BackendInvoiceCreationUnavailable`, while actual settled/funding/unresolved obligation limits
     return `ActualLiabilityLimitExceeded`
   - a settled invoice with short ecash float remains a debt, waits in `SettledAwaitingLiquidity`, and
     after float or a pegin replenishes the gateway transitions
     `SettledAwaitingLiquidity → FundingReserved → FundingPrepared`
   - required MVP gauges are recomputed from durable DB state after restart, including
     issued-unpaid, settled-unfunded, unresolved-liability, liquidity-shortfall, deadline-slack,
     backend-retention-margin, and consensus-time-observer-age metrics
   - **non-satoshi amounts rejected** before invoice creation on a sat-only backend
   - amount-too-small cases where `PaymentFee::subtract_from` would saturate to zero or below the
     minimum incoming contract amount reject before backend invoice creation, both before request and
     during client quote verification
   - client contract sizing uses `CustodialReceiveCapability.receive_fee`, rejects quotes whose
     `terms.receive_fee` differs, and does not accidentally use the legacy trustless receive fee
   - a contract sized with a stale advertised fee is rejected with `FeeOrAmountBindingMismatch`
     before backend invoice creation
   - a request whose funding deadline or invoice expiry exceeds the advertised maximum is rejected
     with `DeadlineTooFar` before backend invoice creation, so no prunable retained
     invoice/tombstone record's reconciliation or namespace reservation outlives the bounded
     retention horizon (`UnresolvedLiability` and unresolved `InvoiceCreateInconclusive` records
     are excepted: they are never pruned automatically, §7.3)
   - the rejection-reason pre-create invariant holds: no code path returns a reason other than
     `CreateInProgress` or `BackendInvoiceUnreturnable` after `backend_create_maybe_sent` is set
   - an unmatched ledger settlement in the gateway's correlation-id namespace records
     `UnmatchedSettlement`, alerts, and disables new issuance, never a silent skip
   - pruning a retained tombstone releases its direct-swap hash reservation only after the funding
     deadline has passed and the ledger/finality window has closed; a post-pruning settlement
     surfaces as `UnmatchedSettlement`
   - the custodial operation meta takes the invoice-difference claim-event fee path: a custodial
     claim never enters the magnitude-decoding `fee_from_expiration` fallback (§8), asserted at the
     claim event of a receive whose contract amount exceeds the deadline timestamp's msat value
   - a settled record whose funding-deadline slack approaches the safety margin disables new
     custodial invoice creation (§8) while funding/replenishment proceeds
   - deleting or pruning a client provisional record never removes the armed receive SM: a contract
     funded after such a deletion (any pre-deadline settlement path) is still claimed (§7.4)

## 16. Out of scope

- Trustless LSP-backed receive (separate research/design work).
- Breez backends, LSPS1/LSPS2 integration.
- A detailed send-path spec for phoenixd (§13).
- LNv1 custodial receive (the same principle applies via offer/interception, but
  LNv2 is the target here).
- Fedimint-provided custodial gateway discovery for MVP. Wallets may learn custodial gateway URLs
  out-of-band (for example operator config, app policy, or a future Nostr-style announcement), but
  this spec does not define or implement a `CUSTODIAL_GATEWAYS_ENDPOINT`.
- Physical gateway DB loss, rollback before the custodial receive record existed, loss of the
  authoritative federation client DB prefix, and gateway module-key loss. Like the rest of the
  Fedimint stack, the MVP assumes local client/server state is durably persisted and backed up.

## References

- `modules/fedimint-lnv2-client/src/lib.rs` (`receive`, `create_contract_and_fetch_invoice`, hash check `:977`, amount check `:981`)
- `modules/fedimint-lnv2-server/src/lib.rs` (`process_output` funding `:545-603`, `process_input` spend `:508-532`)
- `modules/fedimint-lnv2-common/src/{contracts.rs,gateway_api.rs}` (`IncomingContract`, `RoutingInfo`)
- `modules/fedimint-gwv2-client/src/lib.rs` (`relay_incoming_htlc` `:395`, `relay_direct_swap` `:476`, model for the lower-level funding helper)
- `gateway/fedimint-gateway-server/src/lib.rs` (`create_bolt11_invoice_v2` `:3049`, existing
  trustless receive endpoint kept behavior-compatible)
- `gateway/fedimint-lightning/src/{lib.rs,lnd.rs}` (`ILnRpcClient`, hold-invoice path)
- phoenixd API docs: `https://phoenix.acinq.co/server/api`
