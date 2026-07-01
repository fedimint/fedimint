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
   │     refund_pk=gateway, TPE→agg)     │
   │ 3. create_custodial_bolt11_invoice ▶│ 4. reserve InvoiceCreating(QuoteDraft),
   │    (contract, amount)               │    createinvoice(externalId) ─▶│ (own hash H′,
   │                                     │    ◀── invoice ────────────────│  preimage P′)
   │                                     │ 5. sign quote, then commit AwaitingPayment
   │                                     │    (fed-client DB, including signed_quote)
   │  ◀── invoice(H′) + quote ───────────│
   │ 6. verify quote/payee/expiry,       │
   │    skip hash check, consent         │
   │    start ReceiveSM (watch contract) │
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

Steps 2, 6, 12-13 are the receiver's **existing** receive machinery (only step 6
relaxes the hash check and adds quote verification). Steps 8-11 are the gateway's
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
than the contract's funding deadline, with a conservative margin, so a settled payment
is **normally** still fundable. The funding deadline is the contract's
`expiration_or_fee`, interpreted against the LNv2 server's `consensus_unix_time`
(`modules/fedimint-lnv2-server/src/lib.rs:563`). For MVP, the gateway does **not**
require a new federation endpoint for this value: it derives a
`gateway_observed_lnv2_consensus_time` by watching existing signed session outcomes,
tracking the latest `UnixTimeVote` per guardian, and applying the same threshold-time
selection used by the LNv2 server. If that observer has not seen fresh threshold votes,
custodial receive quote creation is unavailable. This is a mitigation, not a guarantee.
Notification delay, observer staleness, or downtime can still leave a
settled-but-unfundable payment, which becomes a gateway liability (§8, §11).

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
    pub max_in_flight: Amount,                // aggregate settled/funding liability target (§9)
    pub min_invoice_to_funding_deadline_delta_secs: u64, // invoice-expiry to funding-deadline gap (§8)
    pub min_contract_lifetime_secs: u64,      // minimum lifetime from observed consensus time (§8)
    pub consensus_time_observation_max_age_secs: u64, // stale-observer budget (§8)
    pub safety_margin_secs: u64,              // extra gateway policy margin (§8)
    pub invoice_amount_granularity_msats: u64, // phoenixd = 1000 (sat-only backend, §7.4)
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
client needs to size and select, not just a flag. `RoutingInfo` derives only
`Serialize`/`Deserialize`, not Fedimint `Encodable`/`Decodable` (`gateway_api.rs:142`), so this
is a `#[serde(default)]` add. `CustodialReceiveCapability.receive_fee` is the fee the client uses to
size the custodial contract before requesting the backend invoice. The top-level legacy
`RoutingInfo.receive_fee` remains the trustless-receive fee for existing clients. A dual-capable
gateway may set the two equal, but the custodial client must use the mode-specific custodial fee and
must reject a quote whose `terms.receive_fee` differs from the advertised fee it used to construct
the contract. If the gateway changes fees between selection and request, the request is rejected
before backend invoice creation and the client reselects/retries with fresh `RoutingInfo`. The
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
  live `RoutingInfo`.

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
  direct-swap preference. If it matches only a known custodial-only candidate, do not select that
  candidate to pay its own invoice; choose another send-capable candidate or fail before funding with
  a typed local "no non-self gateway" error. If the payee key matches a dual-capable candidate, or a
  caller explicitly chooses a same-payee gateway, the selected gateway detects the invoice's
  `backend_invoice_hash` in `PendingCustodialReceive` and returns a **forfeit signature** so the
  sender refunds the funded contract (the **required** behavior, §7.6). **(Optional, post-MVP)** a
  `select_gateway_for_send(avoid_payee_gateway = true)` reselection, done **pre-funding** so the
  alternate gateway is the contract's `claim_pk` from the start (there's no in-place reroute after
  funding, §7.6). The MVP refunds and the caller reselects.

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
   If this process also exposes trustless send for new wallets, that send handler must be able to
   inspect its own custodial pending-receive registry; otherwise new-wallet send selection must avoid
   routing same-payee custodial invoices to it before funding.
2. **Dual-capable mode.** A gateway that advertises both trustless and custodial receive and remains
   in `GATEWAYS_ENDPOINT` must run the send/direct-swap path with access to the custodial pending
   receive registry. That can be one process, a shared DB-backed receive registry, or a local service
   call from `gatewayd` to `custodial-gatewayd`, but it must be atomic enough for the direct-swap path
   to detect `backend_invoice_hash` and return the forfeit signature (§7.6). A dual-capable gateway
   is not the "no existing gatewayd behavior change" path.

A deployment MUST NOT share one Lightning node key and gateway module key between a legacy-listed
`gatewayd` and a separate `custodial-gatewayd` unless the legacy-listed send path can query the
custodial pending-receive registry. Otherwise same-gateway custodial invoices fail as ordinary
registration errors instead of the specified forfeit-refund outcome.

### 7.2 Backend abstraction: notify-only receive

The backend reports capabilities. A notify-only backend declares it **cannot** do
trustless receive and instead supports two custodial primitives:

```rust
struct LightningCapabilities { trustless_receive: bool, /* … */ }

// notify-only backend must provide:
fn create_plain_invoice(amount, description, expiry, external_id) -> Bolt11Invoice; // own hash; external_id = gateway correlation id
fn get_invoice_by_external_id(external_id, include_unpaid) -> Option<BackendInvoice>; // crash-safe issuance lookup (§7.3)
fn subscribe_invoice_settled() -> Stream<Item = SettlementHint>;                    // low-latency wakeup, not proof
fn list_settled_invoices(cursor, from, to) -> Page<SettledInvoice>; // authenticated ledger, paginated
fn get_invoice_by_hash(hash) -> Option<SettledInvoice>;                             // authenticated point lookup
```

The push stream is a **hint** (a wakeup), and the paginated ledger queries are the **proof**
(§7.3). Hints must still pass backend authentication where available (phoenixd
`X-Phoenix-Signature` on webhooks) before waking reconciliation, so a forged stream can't create
cheap load. Backend adapters must expose **cursor semantics explicitly**: if the backend only has
offset pagination, the adapter uses a high-watermark (`completed_at_ms`) plus an overlap window
and de-dupes by `backend_invoice_hash` / `backend_correlation_id`. Offset alone is not a valid
durable cursor (newer payments can shift offsets, missing or duplicating records). The cursor is
**rebuildable**, not a source of truth: on loss the gateway point-looks-up **every nonterminal
authoritative record and every retained `InvoiceExpiredUnpaid` tombstone** (the `AwaitingPayment`
and other nonterminal `PendingCustodialReceive` entries, plus tombstones, that persist in the
federation client DB prefix) by `backend_correlation_id` /
`backend_invoice_hash`, driven by the records themselves rather than a fixed time window (downtime
can exceed any window). This works **within backend ledger retention**, which is a **hard
prerequisite**, not just something to monitor: ledger-first recovery is only as good as the ledger's
historical horizon. The backend adapter must **declare** that retained settlement history covers at
least the **max funding deadline** (the longest a record or tombstone stays recovery-relevant) plus
a safety margin, and if it can't establish coverage of all nonterminal records and retained
tombstones, **new custodial invoice creation is disabled** (distinct from the optional *runtime*
retention monitoring in §7.8). phoenixd documents listing and point lookup of incoming payments but
**no retention SLA**, so phoenixd support treats retention as an operator-configured, monitored
assumption rather than a backend guarantee. A record whose invoice predates available retention (an
outage longer than retention) **can't be confirmed** and goes to the unresolved-liability path (§7.7,
§11), never a silently missed settlement. So losing the cursor (a rebuildable index) to logical
corruption stays a recoverable rebuild from the surviving records and ledger (§11).

For phoenixd: `create_plain_invoice` → `POST /createinvoice` carrying `externalId` and an optional
per-invoice `webhookUrl`. `get_invoice_by_external_id` and `list_settled_invoices` /
`get_invoice_by_hash` → the upstream incoming-payment list and lookup endpoints.
`subscribe_invoice_settled` → the `/websocket` or webhook payment-received stream. `route_htlcs`
returns an inert stream and `complete_htlc` is never invoked. (LND/LDK already expose equivalent
invoice-settled streams, so the same custodial path could run on them too, but they don't need it,
since they can do trustless receive.)

### 7.3 `custodial-gatewayd` custodial-receive service

New `custodial-gatewayd` logic, per connected federation:

1. **On `create_custodial_bolt11_invoice`**: the
   `client_request_id = H("custodial-receive-v1" || federation_id || contract_id || gateway_module_pk)` is
   **recomputed by the gateway from the request's own contract identity**, not trusted as a supplied
   value, so a forged or mismatched id is rejected. Validate the contract (`contract.verify()`,
   `refund_pk == module_public_key`) as today.
   It must also **bind the amounts before issuing the invoice or signing the quote**: reject unless
   `contract.commitment.amount == receive_fee.subtract_from(invoice_amount)` (§8), so a small backend
   invoice can never later fund an oversized contract. Because `PaymentFee::subtract_from` saturates,
   this check must be preceded by an explicit lower-bound check that does not rely on equality after
   saturation: a zero-valued or below-minimum incoming contract is rejected with `AmountTooSmall`
   before backend invoice creation.
   The gateway derives a stable `client_request_id =
   H("custodial-receive-v1" || federation_id || contract_id || gateway_module_pk)` **from the
   request's own contract identity** (not a trusted supplied value, and it binds the gateway's
   durable module key, not the mutable URL). It confirms its
   `gateway_observed_lnv2_consensus_time` is fresh enough and the requested contract is not too close
   to expiry (§8), then builds and **atomically reserves** an `InvoiceCreating` quote draft keyed for
   uniqueness on **`(federation_id, contract_id)`** so there's never more than one outstanding backend
   invoice per contract. While that record persists, a duplicate request must not create a second
   backend invoice; after `AwaitingPayment` exists, a duplicate returns the stored invoice and quote,
   while an in-flight `InvoiceCreating` is handled by a **single-flight backend-create lease**. A
   handler may call `create_plain_invoice` only after atomically acquiring or renewing the
   `backend_create_lease` for the draft. A duplicate request that finds an unexpired lease waits,
   returns "in progress", or polls the stored record; it must not call the backend. If the lease
   expired after a crash, recovery first calls `get_invoice_by_external_id`. Only if no backend
   invoice exists and the draft is still fresh may one handler acquire a new lease and retry
   `create_plain_invoice`. A duplicate request whose request fingerprint differs from the stored
   draft is rejected with `DuplicateContractConflict` (or an operator-visible invariant violation if
   it suggests corruption). The gateway then calls `create_plain_invoice` with the draft's opaque
   `backend_correlation_id` as the backend `externalId` (so no raw federation or contract IDs leak
   into backend-visible metadata). It uses an invoice expiry **strictly earlier than the contract's
   funding deadline** (§8). For backends that take relative expiry, the adapter derives the relative
   value from the draft's absolute `invoice_expiry` at the moment it holds the backend-create lease;
   if the derived relative expiry is below the minimum safe value, the draft is stale and no backend
   invoice is created. It signs the quote using the stored draft plus the returned backend invoice
   hash, and **commits the full `AwaitingPayment` record including `signed_quote` before returning**,
   advancing `InvoiceCreating → AwaitingPayment`.
   A crash after backend invoice creation but before the `AwaitingPayment` commit is recovered by
   querying the backend by `externalId` (`get_invoice_by_external_id`), then signing the recovered
   backend invoice hash against the already-persisted quote draft. A backend that can't look up unpaid
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
       terms_hash: sha256::Hash,
       gateway_api: SafeUrl,
       gateway_module_pk: PublicKey,
       gateway_ln_pk: PublicKey,
       created_at: u64,
       backend_create_attempt: u64,
       backend_create_lease_until: Option<u64>,
       request_fingerprint: sha256::Hash,
   }
   ```

   `InvoiceCreating` holds `{ quote_draft, status }` and **no `backend_invoice_hash` yet**, since the
   backend invoice does not exist until `create_plain_invoice` returns. The draft is the durable
   policy decision: retries and crash recovery must use it rather than recomputing fees, deadlines,
   terms, keys, URLs, or observed consensus time from current config.
   `request_fingerprint` is the canonical hash of the duplicate-sensitive request envelope: contract,
   invoice amount, invoice description hash, requested quote API version, selected custodial
   fee/policy fields, and backend invoice expiry request shape. It is how the gateway distinguishes an
   idempotent duplicate from a conflicting request for the same contract.

   The draft is still bounded by freshness. If no backend invoice exists yet, a handler may call
   `create_plain_invoice` only while the draft still satisfies the create-time safety checks:
   the invoice expiry is in the future with enough client/payment slack, the funding deadline still
   satisfies the consensus-time deadline rule, and the observer is fresh enough. If those checks no
   longer hold, the gateway tombstones the draft as `InvoiceCreationExpired` / rejected and asks the
   client to build a fresh contract. It must not create a backend invoice from a stale draft.

   If a backend invoice already exists but `AwaitingPayment` was not committed, recovery completes the
   signed quote from the draft only if the invoice is still safe to return. If it is expired or too
   close to the funding deadline, the gateway keeps a retained tombstone for late-settlement
   reconciliation (`BackendInvoiceRejected` / `InvoiceExpiredUnreturned`) and returns a typed rejection
   instead of exposing a stale invoice to the client.

   The `AwaitingPayment` commit adds
   `{ quote_id, backend_invoice_hash, backend_requested_sat, invoice_amount, contract_amount,
   invoice_expiry, funding_deadline, terms_hash, signed_quote, created_at }` (`invoice_expiry` and
   `funding_deadline` drive `InvoiceExpiredUnpaid`, retention, and late-settlement handling, §7.3
   limits, and the **`signed_quote`** is stored with embedded `terms` so a retry can return the
   original self-contained quote, §7.3, and a liability carries its evidence, §7.7). The funding
   phases add
   `{ prepared_tx, input_reservation, operation_id, txid }` (the ecash-input reservation is
   authoritative and committed atomically with `FundingPrepared`, §7.3) and finally `outpoint` (§7.3). So the full `PendingCustodialReceive` at `AwaitingPayment` is
   `{ quote_id, client_request_id, backend_correlation_id, backend_invoice_hash, backend_requested_sat,
   federation_id, contract, invoice_amount, contract_amount, invoice_expiry, funding_deadline,
   terms_hash, signed_quote, created_at, status }`. A crash after backend invoice creation
   but before storing the invoice hash is recovered by querying the backend by `externalId` and
   completing the quote from the stored `quote_draft`. A backend that can't look up unpaid invoices
   by external id can't support crash-safe custodial invoice creation. **Uniqueness is the gateway's
   `(federation_id, contract_id)` reservation, not
   the backend**: phoenixd documents `externalId` as lookup metadata, not a unique or idempotent
   key, so the adapter treats a lookup that returns **more than one** invoice for a single
   `backend_correlation_id` as a backend-invariant violation (`BackendDuplicateExternalId`) that
   disables new custodial invoice creation and routes the record to operator review, never silently
   picking one. Return the backend invoice plus a gateway-signed custodial receive quote:

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
       terms_hash: sha256::Hash,        // sha256(canonical_encoding(terms))
       gateway_api: SafeUrl,
       gateway_module_pk: PublicKey,
       gateway_ln_pk: PublicKey,
       signature: Signature,
   }

   struct CustodialReceiveTerms {
       receive_fee: PaymentFee,
       max_receive_amount: Amount,
       max_in_flight: Amount, // aggregate settled/funding liability target, not unpaid gating
       min_invoice_to_funding_deadline_delta_secs: u64,
       min_contract_lifetime_secs: u64,
       consensus_time_observation_max_age_secs: u64,
       safety_margin_secs: u64,
       invoice_amount_granularity_msats: u64,
       backend_retention_secs: u64,
   }
   ```

   `quote_id` is a unique handle for one receive (the MVP doesn't re-issue quotes, so it needn't be
   deterministic). `terms_hash` is checked as
   `sha256(canonical_encoding(terms))`, and the signature covers both `terms` and `terms_hash` via
   `"fedimint-custodial-receive-quote-v1" || canonical_encoding_without_signature`, using
   `gateway_module_pk`. The domain tag stops the signature being reused in another context, and
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
   ledger confirmation** (`get_invoice_by_hash` or the ledger page): does its requested/face amount
   match the quote, is it paid, and what are `received_msat`, `fees_msat`, and `completed_at_ms`
   (captured for liability evidence, §7.7)? The **net** credited after backend skim may be lower,
   which §8 handles by funding the full contract and recording the loss, never by rejecting a
   settled invoice. (This authenticated confirmation is new: the trustless path is
   HTLC-driven and has no equivalent.) A confirmed record still in `AwaitingPayment` then funds
   the `IncomingContract` for its **full `commitment.amount`** (the amount is fixed, partial
   funding is impossible, §8) from gateway ecash. A record already past `AwaitingPayment` starts no
   new funding and routes by state: `SettledAwaitingLiquidity` waits for float, `FundingReserved` /
   `FundingPrepared` / `FundingSubmitted` wait or re-drive (§10), `Funded` is a no-op, a settlement
   matching an `InvoiceExpiredUnpaid` tombstone is a late settlement to the liability path (§7.7), and
   an absent authoritative record is an operator data-loss / corruption case out of scope for this
   spec (§10, §16). A
   **settled-but-mismatched** record is **not**
   ignored: a deviation within expected backend skim still funds the full contract and records the
   loss (§8), while a gross or abnormal mismatch opens a `BackendMismatch` liability (§7.7) and
   alerts, never a silent drop.

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
     submission state machines for acceptance monitoring. It does **not** submit. (It reuses the
     funding logic of `relay_direct_swap`, `modules/fedimint-gwv2-client/src/lib.rs:476`, minus its
     `await_receive` / decryption-share wait, since custodial funding doesn't need the preimage.)
   - `submit_prepared_custodial_funding(prepared)` submits that exact prepared tx and **refuses
     to rebuild** a transaction for any record already past `FundingReserved`.

   The durable, ordered status machine is `InvoiceCreating → AwaitingPayment →
   SettledAwaitingLiquidity → FundingReserved → FundingPrepared(prepared_tx) →
   FundingSubmitted(prepared_tx, operation_id, txid) → Funded(outpoint)`, with
   `SettledAwaitingLiquidity` skipped when float is already sufficient and marking **`Funded` only on
   federation acceptance**. Several terminal branches leave this path.
   `AwaitingPayment` goes to `InvoiceExpiredUnpaid` (the **funding deadline** passed, never settled,
   §7.3 limits) or to `UnresolvedLiability` (settled-but-overdue, or gross `BackendMismatch`). An
   `InvoiceExpiredUnpaid` tombstone goes to `UnresolvedLiability` on a late settlement. Any funding
   state goes to `UnresolvedLiability` (§11). The record **retains `prepared_tx`** from
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
   fields (`prepared_tx`, `operation_id`, input reservation) in this prefix, not a separate record.
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
   submission or network error keeps them locked and re-driven. For a terminal liability they release
   only if the tx is **proven dead** (e.g. `ExpiredBeforeFunding` before any submission). A
   `FundingTxInconclusive` liability **quarantines** the inputs (never released, never reused) until
   the prior tx is accepted, rejected, or proven impossible, so a late landing can't race manual
   resolution (§7.7, §10). So `SettledAwaitingLiquidity` records wait for ecash and never build a tx.
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
   If funding is rejected (e.g. the contract expired, §11),
   the record moves to a terminal **`UnresolvedLiability`** status that drives an
   explicit operator / receiver-cooperation workflow (§11), never a silent drop.
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
   `TrustlessRegistered` or `CustodialPending`, never both. The normal
   `create_bolt11_invoice_v2` path must reject a contract/payment image already reserved by
   custodial receive, and `create_custodial_bolt11_invoice` must reject a contract/payment image
   already registered for trustless receive. The rejection is `DuplicateContractConflict` if the full
   contract collides, and an operator-visible invariant violation if only the payment image collides
   with a different contract. After the backend returns a custodial invoice, the gateway must also
   reserve `backend_invoice_hash` in the shared direct-swap namespace before returning the invoice. If
   that hash collides with an active trustless registration or another custodial pending receive, the
   gateway must not return the invoice; it records a retained `BackendInvoiceRejected` tombstone keyed
   by `backend_correlation_id` / `backend_invoice_hash`, disables new custodial invoice creation until
   reviewed, and continues ledger reconciliation for that invoice through the retention window.

   This invariant must be enforced by the same transaction/registry used for direct-swap detection in
   dual-capable mode. A separate custodial-only binary that does not share such a registry must not
   share the same gateway module key and Lightning node key with a legacy-listed trustless gateway.

4. **Post-funding invalid-contract audit (never blocks the receiver).** The custodial funding
   helper skips the gateway receive state machine, so it also skips that machine's invalid-contract
   detection. The gateway therefore starts a **non-blocking** `CustodialContractAuditSM` after
   funding. It waits for the federation's decryption shares (the same ones the trustless gateway
   path consumes): if the contract decrypts it records `Claimable` and never spends (the receiver
   claims normally with its own key). If it does **not** decrypt, it submits the refund spend to
   `refund_pk` (the gateway key), records `InvalidContractRefunded`, and opens an unresolved
   liability (§7.7, §9). The receiver's pre-invoice claimability self-check (§7.4) is the primary
   defense, and this audit is the backstop that actually performs the refund §9 relies on. It must
   **never** delay marking the receiver's contract funded.
5. **Float and liabilities:** the gateway must hold enough federation ecash to front contracts.
   The backend Lightning receipt reimburses it. Expose ecash float, settled-but-unfunded debt, and
   headroom in balances. Once the backend ledger confirms settlement, the receive is an actual debt:
   the gateway must fund the contract if it still can. If ecash float is short, the record moves to
   explicit `SettledAwaitingLiquidity`: backend settled, actual debt exists, but no ecash inputs are
   reserved and no prepared transaction exists. When liquidity becomes available, one funding worker
   atomically claims it into `FundingReserved`, then prepares and submits the exact tx. The MVP can make
   liquidity replenishment semi-automatic: alert the operator and, when configured on-chain wallet
   funds are available, drive or prompt a pegin to create federation ecash. Post-MVP automation can
   add loop-out, channel close, splice, swap-out, or backend-specific liquidity actions before
   falling back to operator intervention. If the contract expires before liquidity arrives, the debt
   does not disappear: it moves to `UnresolvedLiability` (§11).
6. **Limits and unpaid invoices:** enforce the per-receive cap from the gateway's advertised
   `CustodialReceiveCapability` (§7.1, §9) to bound single-receive blast radius. The aggregate
   `max_in_flight` value is an operating target for actual settled/funding liabilities, not a hard
   reservation against every issued unpaid invoice. An issued unpaid invoice is **contingent
   exposure**, not debt. The gateway tracks issued-unpaid count and face value for metrics and
   operator alerts, but unpaid invoices **do not** change gateway behavior and do not by themselves
   reject new custodial invoice creation. Generic service protections such as HTTP rate limits,
   authentication policy, and database-size limits remain deployment concerns, not custodial receive
   capability semantics.

   Late settlements are unavoidable because a notify-only backend auto-settles even an expired
   invoice, so the record is **retained in full** (contract, amounts, `invoice_expiry`,
   `funding_deadline`, `quote_id`, `backend_invoice_hash`) across this window. At the funding
   deadline it terminalizes: settled-and-funded → `Funded`; settled-but-unfundable →
   `UnresolvedLiability`; never settled → **`InvoiceExpiredUnpaid`** (the terminal that keeps
   `AwaitingPayment` from being nonterminal forever). The full record (now a tombstone) is retained
   for a **conservative window** past the funding deadline, long enough that a late settlement can no
   longer land or appear, then pruned. A late settlement against a tombstone is by definition past
   the funding deadline, so it's unfundable and opens an `UnresolvedLiability` (the tombstone still
   carries the data to do so), never a silent miss. Splitting that window into separate
   settlement-finality and ledger-retention bounds is deferred to §14.

### 7.4 Client custodial-receive variant

A new entry point in `fedimint-lnv2-client` (e.g. `receive_custodial(...)`), or a
mode flag on `receive`:

- **Select via policy, with explicit opt-in.** Use `select_gateway_for_receive` with a custodial
  policy (§7.1), reachable only when the app/user has opted into custodial receive. It picks only
  a gateway advertising `custodial.is_some()`, and surfaces that the gateway is custodial.
- Build the `IncomingContract` exactly as today (receiver owns preimage), but set the
  **contract funding deadline later than the invoice expiry** the gateway will use.
  Pass the two deadlines separately rather than the single `expiry_secs` used today
  (`lib.rs:943` for the contract expiration and `:972` for the invoice expiry currently
  reuse one value). The client chooses the funding deadline using the selected gateway's advertised
  `CustodialReceiveCapability` deadline-policy fields before it requests the invoice, and sizes
  `contract.commitment.amount` using that same capability's `receive_fee`, not the legacy top-level
  trustless receive fee. The returned signed quote repeats the terms actually used and must still pass
  the checks below.
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
  stronger.
- **Verify and persist the gateway quote.** The client must verify the
  `CustodialReceiveQuote` domain-separated signature (`api_version`, `quote_id`), and that
  `contract_id`, full `contract`, `federation_id`, `backend_invoice_hash`, invoice amount,
  contract amount, `gateway_module_pk`, `gateway_ln_pk`, invoice expiry, and funding deadline match
  its selected gateway, returned invoice, and locally-built contract. It must verify
  `terms_hash == sha256(canonical_encoding(terms))`, that the embedded `terms` are compatible with
  the selected gateway's advertised capabilities and the client's local policy, including
  `terms.receive_fee <= PaymentFee::RECEIVE_FEE_LIMIT`, and that the amount binding is exact:

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
  ```

  These checks verify the deadline arithmetic against the quoted observed consensus time. They do
  not prove that the gateway's observer was fresh when it signed; MVP treats freshness as a gateway
  hard gate and operational metric, not as quote-carried evidence.

  The client must also confirm the contract's own `refund_pk` equals
  `gateway_module_pk`, so the unclaimable-contract windfall (§9, §11) can only route back
  to the audited gateway. The full quote, including `terms`, is stored with the operation metadata so
  the receiver can later prove what the gateway committed to fund.
- **Self-check claimability before requesting the invoice.** The client must verify it
  can actually claim the contract it built: that `recover_contract_keys` succeeds
  (`modules/fedimint-lnv2-client/src/lib.rs:1025-1055`), confirming a valid preimage and a
  derivable claim key. An unclaimable contract is far worse in custodial mode (§9, §11):
  the payer pays irreversibly but the receiver can never claim.
- Start the existing `ReceiveStateMachine` (watch contract → claim) **unchanged**. It
  claims with the receiver's locally-precomputed `agg_decryption_key`, so it needs
  nothing from the gateway beyond the contract being funded.

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

The gateway therefore MUST:
- **Never** register a custodial pending-receive as if it were a trustless incoming
  contract keyed on the invoice hash.
- Detect its own custodial invoice on the send/direct-swap path (its `H′` is in
  `PendingCustodialReceive`) and handle it explicitly. Same-gateway self-pay of a
  custodial invoice cannot complete over Lightning either (a node cannot route to its
  own invoice), so the gateway returns a **forfeit signature** so the sender refunds the funded
  contract (the domain outcome, since a typed error would be redacted or retried forever, §7.6, §7.9)
  rather than the confusing `RegistrationError` / wrong-preimage behavior. A future version may add an
  internal custodial self-pay that funds the receiver's contract directly from the
  sender's outgoing contract.

For the common case (sender and receiver use *different* gateways), the custodial
invoice's payee is not the sender-gateway's key, so direct swap never triggers and the
payment routes over real Lightning, which the backend auto-settles into the normal
custodial funding path.

One caveat for same-federation senders: default send selection prefers the gateway whose
key matches the invoice payee (`select_gateway` with the invoice,
`modules/fedimint-lnv2-client/src/lib.rs:467`, used by `send`, `:576`) to enable a direct swap. A
custodial invoice's payee is the custodial gateway itself, which can neither direct-swap it nor
route to its own node. The send path must **not** require the sender to pre-classify the invoice as
custodial, since a Bolt11 invoice doesn't carry that fact. Instead the payee gateway detects its
own `backend_invoice_hash` in `PendingCustodialReceive` and, because it can neither direct-swap nor
route to its own node, **returns a forfeit signature** (the existing `Err(Signature)` half of the
send response, `modules/fedimint-lnv2-common/src/gateway_api.rs:48`), so the sender refunds the
just-funded `OutgoingContract` immediately via `OutgoingWitness::Cancel`
(`modules/fedimint-lnv2-client/src/send_sm.rs:238-266`). This is the **required** MVP behavior. A
typed `CannotDirectSwapCustodialInvoice` **cannot** travel as a `PublicGatewayError` (those redact
to one generic string, `gateway/fedimint-gateway-server/src/error.rs:81-84`) nor as a transport
error (the send SM retries those forever, `send_sm.rs:193-216`), so the forfeit signature is the
domain outcome that drives the refund (§7.9).

There is **no in-place retry** through another gateway: by the time the gateway is contacted the
`OutgoingContract` is already funded with `claim_pk` = the payee gateway's module key
(`modules/fedimint-lnv2-client/src/lib.rs:597-639`), so re-routing means a fresh send funded to the
alternate gateway. Doing that automatically without a wasted funding round-trip needs a
**pre-funding classification** step, deferred (§14). The MVP refunds and the caller reselects.
Tested in §15.

### 7.7 Liability record and status

A settlement the gateway can't safely fund (an expired-then-settled invoice, an unclaimable contract
refunded to the gateway, an inconclusive funding tx) leaves an obligation, so it keeps a **durable
liability record** rather than losing it to a support ticket. The MVP needs a minimal marker, stored
in the **federation client DB prefix** alongside the funding record so terminalizing to
`UnresolvedLiability` and writing the liability are one **atomic** commit:

```rust
struct CustodialReceiveLiability {
    quote_id: sha256::Hash,          // the receive it belongs to
    federation_id: FederationId,
    contract_id: ContractId,
    amount_owed: Amount,
    reason: LiabilityReason,         // ExpiredThenSettled | InvalidContract | FundingTxInconclusive
                                     // | BackendMismatch
    evidence: LiabilityEvidence,     // { signed_quote, backend_ledger_proof, funding_txid? }
    resolution: LiabilityResolution, // Open | Resolved (richer taxonomy deferred, §14)
}
```

The **load-bearing rule** is the no-double-pay gate. For `FundingTxInconclusive`, a pay-out
resolution must wait until the original funding is proven terminal: confirmed funded means the
receiver was already paid (no payout), or it's proven impossible past the funding deadline. Resolving
while a prior tx can still land would double-pay. For an `InvalidContract` refund the receiver got
nothing, so a payout **is** the resolution once the refund is terminal. Other reasons resolve
directly.

**Deferred (§14):** the richer operator workflow (a full reason/resolution taxonomy, evidence-bundle
export, operator-signed resolutions, receiver-supplied replacement contracts). Disaster-recovery
tooling for physical gateway DB loss is out of scope for this spec (§16). The MVP keeps the
liability record in the same authoritative federation client DB prefix as the funding state.

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
(§7.2). Already-settled invoices keep flowing through reconciliation and liquidity replenishment.
Issued-unpaid invoice count or face value only drives metrics and operator alerts, never a hard
custodial-receive breaker.

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
```

Required histogram:

```text
gateway_custodial_receive_settlement_to_funding_seconds
```

`issued_unpaid_*` is contingent exposure only. `settled_unfunded_*` is actual debt: backend
settled, but the contract is not yet accepted as funded. `liquidity_shortfall_msats =
max(0, settled_unfunded_msats - usable_ecash_float_msats)` and should drive operator action such as
pegin / liquidity replenishment. `min_funding_deadline_slack_seconds` is the minimum seconds until
funding deadline among settled-but-unfunded records; negative means at least one debt is overdue.
`backend_retention_margin_seconds` measures how long the oldest recovery-relevant record remains
inside backend ledger retention. `consensus_time_observer_age_seconds` backs the §8 rule that stale
LNv2 consensus-time observation disables new quote creation.

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

The MVP custodial-receive creation rejection enum is deliberately small and covers only pre-invoice /
pre-quote refusal:

```rust
enum CustodialReceiveRejectionReason {
    CustodialReceiveDisabled,          // Gateway/federation policy currently disables the feature.
    UnsupportedQuoteVersion,           // Client requested an unsupported quote API version.
    InvalidContract,                   // Contract verification failed.
    WrongRefundKey,                    // Contract refund key is not the gateway module key.
    AmountTooSmall,                    // Receive fee would make the contract amount below minimum.
    AmountTooLarge,                    // Request exceeds the gateway's per-receive cap.
    NonSatoshiAmount,                  // Backend granularity cannot represent the amount exactly.
    DeadlineTooNear,                   // Deadline rule in §8 fails or consensus-time observer is stale.
    BackendInvoiceCreationUnavailable, // Backend cannot currently create the invoice.
    BackendLedgerUnavailable,          // Backend cannot provide required ledger/reconciliation support.
    DuplicateContractConflict,         // Existing reservation conflicts with this request.
}
```

This enum is the stable client-facing API surface. The richer operator liability taxonomy remains
deferred (§14). There is intentionally no unpaid-invoice or float-shortage rejection: unpaid invoice
buildup only alerts the operator (§7.3), and post-settlement float shortage is handled as a debt /
liquidity problem (§8, §11), not as create-invoice admission control.

## 8. Fee & amount accounting

The face amount `A` is what the payer pays. A notify-only backend may **skim a
liquidity fee** `F` from the receipt (e.g. phoenixd splicing in inbound), so the
gateway receives `A − F`. Because the gateway funds the contract **after** settlement,
it knows the exact `A − F`.

- **No-abort constraint (critical):** once the backend auto-settles, the payer is
  **irrevocably paid**: there is **no cancel/refund path** on this receive. The
  gateway is committed to crediting the receiver. This is the sharpest consequence
  of a notify-only backend and shapes every edge case in §11.
- **Fixed contract amount: no partial funding.** A contract's value is fixed in
  `commitment.amount`. The **receiver** receives exactly that. Funding it costs the
  gateway `commitment.amount + module transaction fees`. `process_output` returns the
  contract amount (`contract.commitment.amount`, `contracts.rs:31`,
  `modules/fedimint-lnv2-server/src/lib.rs:595`) and adds module fees on top in the returned
  `TransactionItemAmounts` (`:599`), so the gateway cannot "fund what it can". It
  always funds the full fixed amount. Size `receive_fee` and float headroom against the
  full ecash spend (amount + fees), not just the amount.
- **Policy: gateway absorbs skim.** It quotes a `receive_fee` sized to
  cover expected backend cost, keeps inbound headroom so most receives have `F = 0`,
  and funds the full `contract_amount = receive_fee.subtract_from(A)`. If an
  unexpected skim makes `A − F` fall short of `contract_amount`, the gateway **still
  funds the full amount and eats the loss** (it can neither stiff the payer, which is
  impossible, nor under-fund the fixed-amount contract). Large/abnormal skim is
  alerted, and the per-receive cap (§9) bounds the worst case. `receive_fee`
  semantics: "covers gateway + backend liquidity cost". Tune from observed skim.
- **Custodial fee-cap decision.** The MVP uses the existing client
  `PaymentFee::RECEIVE_FEE_LIMIT` for custodial receive too, so the gateway must quote
  backend liquidity cost within that cap and absorb excess variance. A higher or
  differently-shaped custodial fee cap would require a separate explicit-consent client
  policy, not a silent reuse of normal receive selection.
- **Two deadlines (mitigation, not guarantee).** The backend invoice expiry must be
  **strictly earlier** than the contract funding deadline, with a conservative margin,
  so a settled payment is **normally** still fundable. The contract funding deadline is
  evaluated by the federation against LNv2 `consensus_unix_time`
  (`modules/fedimint-lnv2-server/src/lib.rs:563`), so the gateway must not issue a quote
  using only its local wall clock. For MVP, without any new Fedimint module endpoint, the
  gateway observes existing signed session outcomes, tracks the latest `UnixTimeVote` per
  guardian, and computes `gateway_observed_lnv2_consensus_time` with the same threshold
  rule as the server (`times[threshold - 1]` after sorting descending). Quote creation is
  unavailable until that observer is fresh enough. The signed quote records this value as
  `observed_lnv2_consensus_time` so the deadline calculation is auditable (§7.3), but the quote does
  not itself prove observer freshness; that remains a gateway-enforced hard gate and metric (§7.8).

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

  If the observer is stale or lacks fresh threshold votes, the gateway disables custodial
  receive quote creation for that federation rather than falling back to a small local-clock
  margin. Notification delay, observer staleness, or downtime can still produce a
  settled-but-unfundable payment, so the late-settlement **unresolved-liability path remains
  mandatory** (§11), not exceptional.

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
| Payer | None beyond normal Lightning, but **no refund** if the gateway fails post-settle (the payer already paid). |
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

**Trust assumption.** Users trust (a) the operator's **honesty** to fund, and (b)
the gateway's ability to durably persist its local state across the handoff. The primary recovery
path is the durable authoritative funding state (the federation client DB prefix, §7.3). The
client-held signed quote is auditable evidence of the gateway's commitment, but it is not a
cryptographic enforcement mechanism and does not make physical gateway DB loss recoverable. Both
trust assumptions are bounded in time (seconds, if the gateway is online) and in amount (§9 limits).
This is strictly weaker than trustless receive but much narrower than a custodial wallet holding
balances indefinitely.

**Third-party dispute verification.** A receiver can later claim "I did not receive the money", but
the verifiable question is narrower than human wallet balance. Given the signed quote, the funding
output, and signed federation session history, an auditor can verify the contract-level state:

| State | Third-party evidence |
|---|---|
| **Not funded** | No accepted `IncomingContract` output matches the quoted `contract_id` / full contract before the funding deadline. The gateway still owes the receiver if the backend ledger shows settlement. |
| **Funded but unclaimed** | An accepted funding outpoint exists for the quoted contract and no later `LightningInputV0::Incoming(outpoint, ...)` spend consumes it. The receiver can still claim; the gateway did its funding job. |
| **Claimed** | A later accepted `LightningInputV0::Incoming(outpoint, agg_decryption_key)` consumes the funding outpoint, the aggregate decryption key verifies, and decrypting the quoted contract succeeds, routing the spend through `claim_pk` (`modules/fedimint-lnv2-server/src/lib.rs:508-532`). Protocol-level evidence says the receiver-side claim path succeeded. |
| **Refunded / invalid** | A later accepted `LightningInputV0::Incoming(outpoint, agg_decryption_key)` consumes the funding outpoint, but decrypting the quoted contract fails and routes value through `refund_pk`. The receiver did not get paid; the gateway records an auditable liability (§7.7). |

This audit does **not** prove the receiver's app persisted notes, still has spendable ecash, or did
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
  `InvoiceCreationExpired` (no backend invoice created), `BackendInvoiceRejected` /
  `InvoiceExpiredUnreturned` (retained tombstones for unreturned backend invoices), and
  `UnresolvedLiability`.
- **Idempotent invoice creation** (§7.3): a record stuck in `InvoiceCreating` after a crash is
  resolved by `get_invoice_by_external_id(backend_correlation_id, include_unpaid = true)`. If the
  backend invoice exists, complete the `AwaitingPayment` record if the invoice is still safe to
  return, otherwise retain an unreturned-invoice tombstone for reconciliation. If no backend invoice
  exists, the request can be retried only by a handler holding the durable backend-create lease, and
  only if the draft is still fresh enough to expose to a client. Otherwise it is dropped/tombstoned
  without creating a backend invoice. A duplicate `create_custodial_bolt11_invoice` whose
  `request_fingerprint` matches the stored draft never creates a second backend invoice; a duplicate
  with mismatched amount, description hash, quote API version, or selected custodial fee/policy is
  rejected against the stored draft.
- **Idempotent funding** keyed on `backend_invoice_hash` / `contract_id`: fund each
  contract exactly once. A hint arriving in `SettledAwaitingLiquidity` waits for float; one in
  `FundingReserved`, `FundingPrepared`, or `FundingSubmitted` waits on the stored reservation /
  prepared tx / operation result rather than building a second tx. One in `Funded` is a no-op.
- **Startup reconciliation:** on boot, the `CustodialSettlementObserver` polls the backend's
  authenticated ledger from its durable cursor (phoenixd `GET /payments/incoming` /
  `list_settled_invoices`), matching by `backend_correlation_id` first and `backend_invoice_hash`
  second against **every nonterminal record and every retained `InvoiceExpiredUnpaid` tombstone**.
  For each `AwaitingPayment` record, **first re-check its funding deadline against fresh
  `gateway_observed_lnv2_consensus_time`**, since a record can still read `AwaitingPayment` only
  because the gateway was offline when it should have terminalized. Deadline-based terminalization
  waits until the observer is fresh enough. A record still before its deadline that settled while
  down is funded (exactly-once permitting); an **overdue** one is terminalized now:
  settled-but-overdue →
  `UnresolvedLiability`, unpaid-and-overdue → `InvoiceExpiredUnpaid`. A settlement matching an
  `InvoiceExpiredUnpaid` tombstone is a **late settlement past the funding deadline** (that terminal
  is set at the deadline, §7.3), so it's unfundable and transitions
  `InvoiceExpiredUnpaid → UnresolvedLiability`, never a silent miss. This closes the crash gap for an
  honest operator.
- **Reserved/submitted reconciliation:** on boot, every `SettledAwaitingLiquidity` record rechecks
  deadline and float. If the contract is still fundable and liquidity is available, one worker
  atomically claims it into `FundingReserved`; otherwise it remains a debt waiting for liquidity or
  escalates to `UnresolvedLiability` if the deadline has passed. Every `FundingReserved`,
  `FundingPrepared`, or `FundingSubmitted` record re-derives its deterministic funding `operation_id`
  and checks `operation_exists`. If the operation is present the gateway never resubmits: it
  awaits that operation's outcome and advances to `Funded` on acceptance, or to
  `UnresolvedLiability` if the contract expired in the meantime. The no-operation branch
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
  errors, advance to `Funded` **only on acceptance**. If funding is rejected (e.g. the
  contract expired during downtime), surface it as an unresolved liability (§11),
  never a silent drop.
- **Out-of-scope local data loss:** if the authoritative federation client DB prefix is missing,
  corrupt, or rolled back, then `operation_exists`, the stored `prepared_tx`, input reservations,
  liabilities, and the funding state are gone with it. The gateway must not treat a receiver-held
  quote as permission to build a fresh funding tx, because a previously submitted async tx may still
  land. The quote and backend ledger can support operator investigation or dispute handling, but
  they are not an MVP protocol recovery path.

## 11. Edge cases & policies

| Case | Policy |
|---|---|
| **Contract expiry vs funding** | Mitigation (not guarantee): invoice expiry **strictly before** the funding deadline with a conservative margin, and MVP quote creation requires a fresh gateway-observed LNv2 consensus-time view derived from signed session outcomes (§8). Observer staleness / downtime can still produce a late settlement. The gateway **cannot** re-issue a fresh claimable contract from `claim_pk` alone (it lacks the receiver's secret + `ephemeral_pk`). So a settled-but-unfundable payment is a **mandatory unresolved-liability path** requiring receiver cooperation / manual resolution, never a silent loss. |
| **Receiver offline** at claim time | Fine. The funded contract persists. Contract expiry is a **funding** deadline, not a claim deadline: the incoming spend has no expiry check (`modules/fedimint-lnv2-server/src/lib.rs:508`), so a funded contract stays claimable after expiry **unless already spent**. |
| **Underpayment / amount mismatch** | The backend enforces the fixed invoice amount, so this shouldn't occur. A deviation within expected skim funds the full contract and records the loss (§8). A gross or abnormal mismatch opens a `BackendMismatch` liability (§7.7) instead of funding, consistent with §7.3. It **cannot** under-fund the fixed-amount contract, and **cannot** refund the payer. |
| **Overpayment** | Fund the quoted `commitment.amount`. Treat surplus per fee policy. |
| **Settled but gateway float momentarily short** (not expiry) | This is a debt, not a failed receive. Hold in explicit `SettledAwaitingLiquidity` with no reserved inputs or prepared tx, alert the operator, and fund when ecash float recovers by transitioning `SettledAwaitingLiquidity → FundingReserved → FundingPrepared`. The MVP can drive or prompt a pegin from available on-chain funds. Post-MVP can automate loop-out, channel close, splice, swap-out, or backend-specific liquidity actions. Escalate to `UnresolvedLiability` only if the contract expires before liquidity arrives (§7.3). |
| **Receiver says they were not paid** | Resolve by contract-level evidence (§9): not funded → gateway liability if backend settled; funded but unclaimed → receiver can still claim; claimed through `claim_pk` → gateway paid at the protocol level; refunded through `refund_pk` → receiver was not paid and the gateway records a liability. A third party cannot verify the receiver's private wallet balance or local note persistence. |
| **Webhook redelivery / double settle** | Gateway-side exactly-once (explicit-status idempotency, serialized per `contract_id`) prevents double-funding. **Consensus does not dedupe** (§7.3, §10). |
| **Crash after funding acceptance but before DB update** | With the client DB intact the re-derived `operation_id` still exists, so the gateway awaits its outcome and marks `Funded` on acceptance, never resubmitting. A missing operation lets the gateway build a fresh tx only for a `FundingReserved` record (no prepared tx). A missing operation on a `FundingPrepared` record is expected (operation is created at submit). On a `FundingSubmitted` record it's an operation-log divergence and the tx may already have landed. Either way the gateway re-drives its exact stored `prepared_tx` (consensus-idempotent on its pinned inputs) rather than building a new one, escalating to unresolved-liability if it can't (§7.3, §10). |
| **Backend reports settle but funds never arrived** (backend bug) | Fund only after **authenticated ledger confirmation** (§7.3), never on the push event alone. The backend custodies the Lightning leg by nature and is trusted for it. |
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

1. **`receive_fee` sizing within the existing cap**: how to quote so absorbed skim
   stays bounded while staying under `PaymentFee::RECEIVE_FEE_LIMIT` (the
   absorb-full-skim policy and MVP cap are fixed in §8, and the open part is the heuristic
   + inbound headroom target that keeps `F` near zero). If deployments need a higher
   fee, design a separate explicit-consent custodial fee cap.
2. **Two-deadline / observer values**: concrete invoice-expiry vs funding-deadline gap,
   minimum contract lifetime, consensus-time observation max age, and safety margin.
3. **Authenticated-settlement mechanism**: the per-backend ledger-confirmation call
   (phoenixd ledger query, generalization for other notify-only backends).
4. **Capability typing**: the `ReceiveCapabilities` struct, custodial deadline-policy fields, and
   policy selectors are chosen (§7.1). The open part is how richly to type the backend capability
   descriptor.
5. **Limits / alert defaults**: concrete per-receive cap, actual-liability target, and alert
   thresholds for the required MVP metrics (§7.1, §7.3, §7.8).
6. **Backend trait shape**: extend `ILnRpcClient` with capability + custodial
   primitives, vs a separate `NotifyOnlyBackend` trait.
7. **Out-of-band discovery and consent UX**: how wallets accept custodial gateway URLs from
   non-protocol sources, remember operator/app policy, and surface "this gateway is custodial for
   receive."
8. **Quote/receipt wire shape**: the fields, embedded `CustodialReceiveTerms`,
   domain-separated signature, and `quote_id` are chosen (§7.3). The open part is the exact
   canonical encoding, `api_version` evolution, and where the client persists the
   `CustodialReceiveQuote`.
9. **Audit timing**: how long the `CustodialContractAuditSM` (§7.3) waits for decryption shares
    before declaring a contract invalid and refunding.
10. **Prepared transaction API shape**: how the client API exposes prepare-with-input-reservation
    separately from submission while preserving existing transaction idempotency and autocommit
    semantics.

**Deferred to post-MVP (intentional non-goals for v1).** These were considered and cut from the core
because DB-intact recovery (§10) or simpler choices already cover correctness, and they add build/test
surface without preventing a double-fund, double-spend, lost-funds, or trust hole:

- **Rich operator workflow** (full reason/resolution taxonomy, evidence-bundle export,
  operator-signed resolutions, receiver-supplied replacement contracts). The MVP keeps a minimal
  in-prefix liability record (§7.7).
- **Quote-authenticated `custodial_receive_status` query**, rich dashboards, and soft health gates
  beyond the required MVP metrics (§7.7, §7.8).
- **Two-window tombstone model** (separate settlement-finality vs ledger-retention bounds) and a
  richer late-settlement finality model (§7.3 limits).
- **A second concrete backend and a richer backend capability matrix** beyond the phoenixd reference
  path (the generic notify-only *design* stands, §7.2, and only additional backends and a fuller
  capability matrix are post-MVP), and **automatic pre-funding alternate-gateway routing** for a
  same-gateway custodial invoice (a pre-funding classification step so the alternate gateway is the
  contract `claim_pk` from the start). The MVP forfeit-refunds and the caller reselects (§7.6), and
  the optimization only saves a wasted funding round-trip, so it's deferred.

## 15. Implementation phases

Ordering front-loads the hardest risks. The phoenixd adapter is tempting to build first but doesn't
retire them: the real risks are client-core transaction persistence and the public-API semantics, so
those come first.

1. **Client-core transaction preparation**: a generic `fedimint-client` prepare/submit split with
   durable input reservations and exact-tx replay (finalize + lock inputs + return bytes and a
   reservation token without an op-log entry or submission SM, then install a stored exact tx as a
   submission SM in one autocommit dbtx, §7.3). Highest-risk, and it gates the rest.
2. **Public API semantics**: `RoutingInfo` receive capabilities, the custodial-receive result enums,
   the same-gateway send **forfeit-signature** rejection that ride successful domain responses
   (§7.6, §7.9), plus the rule that legacy `GATEWAYS_ENDPOINT` remains trustless-compatible only.
   If dual-capable mode is included in MVP, this phase also adds the direct-swap receive-registry hook
   in the legacy-listed gateway process. If MVP is custodial-only/out-of-band only, that hook is
   deferred and same-gateway protection is limited to send handlers that can inspect the custodial
   pending-receive registry.
3. **Backend**: `LightningMode::Phoenixd` + notify-only backend adapter (send + `create_plain_invoice`
   with `external_id` + `subscribe_invoice_settled` hints + `list_settled_invoices` /
   `get_invoice_by_hash` / `get_invoice_by_external_id` ledger queries, the declared retention
   contract, capability flag).
4. **`custodial-gatewayd` service**: build the separate custodial receive binary (§7.1), persist
   `PendingCustodialReceive` with explicit states, run the ledger-first
   `CustodialSettlementObserver`, fund-on-settle via the prepare/submit helper
   (`prepare_custodial_incoming_funding` / `submit_prepared_custodial_funding`, §7.3) with
   `FundingPrepared` storing the exact tx and reserving its ecash inputs, enforce **exactly-once**
   funding, run the `CustodialContractAuditSM`, sign quotes, maintain the minimal in-prefix
   `CustodialReceiveLiability` record (§7.7), reconcile on startup, alert on issued-unpaid records,
   handle liquidity replenishment, and expose the required MVP metrics (§7.8).
5. **Capability advertisement and selection**: `ReceiveCapabilities` in `RoutingInfo`, the
   `select_gateway_for_receive` / `select_gateway_for_send` policy selectors, version handling, and
   wallet-supplied custodial candidate URLs.
6. **Client**: `receive_custodial` variant (skip hash check, verify/persist signed
   quote, enforce custodial fee cap, consent, surface mode).
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
     `AwaitingPayment(signed_quote)` commits: recovery looks up by `backend_correlation_id` and signs
     the recovered invoice hash using the exact stored draft, even if gateway fee/deadline config
     changed while it was down
   - duplicate create requests while the first backend create call is in flight: the second handler
     observes the unexpired durable create lease and does not call the backend, proving the gateway
     itself cannot create two invoices for one `backend_correlation_id`
   - stale draft recovery: if no backend invoice exists and the draft is no longer within freshness /
     deadline margins, no backend invoice is created; if a backend invoice exists but is no longer safe
     to return, the gateway retains a tombstone for late-settlement reconciliation and returns a typed
     rejection
   - a **backend lookup returning two invoices for one `externalId`** disables new issuance and never
     silently picks one (§7.3)
   - duplicate create with the same contract but different amount, description hash, quote API version,
     or selected custodial fee/policy is rejected against the stored `request_fingerprint`
   - logical root-index loss with the authoritative client-prefix records intact: indexes rebuild
     from surviving records and backend-ledger confirmation
   - a **forged webhook ignored** unless the backend ledger confirms settlement
   - the **payee-binding rejection** and full **quote verification**
   - legacy `GATEWAYS_ENDPOINT` excluding a custodial-only gateway, and normal trustless receive using
     only trustless-capable gateway candidates
   - a **same-federation sender paying a custodial invoice via a non-payee gateway** (§7.6), and a
     same-gateway custodial self-pay where the gateway **returns a forfeit signature** so the sender
     refunds the funded contract immediately and never retries it as an infinite transport error (§7.6)
   - an **invalid contract opening a liability after the gateway refund audit** (§7.3, §7.7)
   - **offset-pagination recovery** with overlap + dedupe, proving no settled invoice is missed or
     double-counted
   - a **duplicate `create_custodial_bolt11_invoice` retry** while the authoritative record persists
     returning the same invoice and quote, **never** a second backend invoice
   - cross-path collisions: trustless registration rejects a contract/payment image already owned by
     custodial receive, custodial creation rejects a contract/payment image already owned by trustless
     receive, and a dual-capable direct-swap lookup returns the custodial forfeit-signature outcome
     rather than falling through to the trustless registered-contract table
   - backend invoice hash collision: a custodial backend invoice hash that matches an active trustless
     registered payment hash is not returned to the client and disables new custodial issuance for
     operator review while retaining a `BackendInvoiceRejected` tombstone for reconciliation
   - issued-unpaid invoice buildup increments metrics / alerts but does **not** reject new custodial
     invoice creation by itself
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
