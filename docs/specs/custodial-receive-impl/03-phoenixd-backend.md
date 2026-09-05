# Impl Spec 03: Notify-Only Backend Trait + phoenixd Adapter

> Parent: design §4, §7.2, §13, §14.3, §14.6. Crates: `gateway/fedimint-lightning`,
> `gateway/fedimint-gateway-common`.

## 1. Scope & non-goals

**In scope:** a `NotifyOnlyLightningClient` trait capturing the custodial primitives; a phoenixd
adapter implementing it plus the send-path subset of `ILnRpcClient`; cursor semantics; the
declared-retention contract; webhook/websocket hint authentication. **Non-goals:** the custodial
service logic that consumes these primitives (spec 04); trustless receive on phoenixd
(impossible, §4); a second backend (§14 deferred).

## 2. Grounding in current code (verified)

- `ILnRpcClient` (`gateway/fedimint-lightning/src/lib.rs:105`) is the backend trait: `info`,
  `routehints`, `pay`/`pay_private` (documented idempotent-per-invoice), `route_htlcs`,
  `complete_htlc`, invoice creation for trustless receive, etc. `FakeLightningTest`
  (`fedimint-testing/src/ln.rs:40`) implements it for tests.
- `LightningMode` (`gateway/fedimint-gateway-common/src/lib.rs:559`) is the operator-facing
  backend selector (CLI/env parsed).
- phoenixd HTTP API (reference: https://phoenix.acinq.co/server/api): basic-auth with an API
  password; `POST /createinvoice` (`amountSat`, `description`/`descriptionHash`, `expirySeconds`,
  `externalId`, optional per-invoice `webhookUrl`); `GET /payments/incoming?externalId=`;
  `GET /payments/incoming/{paymentHash}`; `GET /payments/incoming?from=&to=&limit=&offset=&all=`;
  websocket `/websocket` and webhooks with `X-Phoenix-Signature` (HMAC-SHA256 over body with the
  webhook secret); `POST /payinvoice` returns the preimage. **Implementation must re-verify these
  shapes against the pinned phoenixd version at coding time and record that version here.**

## 3. Design

### 3.1 Trait shape (decides design §14.6)

Separate trait, not more methods on `ILnRpcClient`:

```rust
// gateway/fedimint-lightning/src/notify_only.rs
#[async_trait]
pub trait NotifyOnlyLightningClient: ILnRpcClient {
    fn custodial_capabilities(&self) -> CustodialBackendCapabilities;

    /// Non-idempotent. Caller MUST hold the backend-create lease (spec 04) and
    /// set backend_create_maybe_sent before calling. The request carries the
    /// draft's ABSOLUTE target expiry (unix secs); the adapter derives the
    /// backend-relative value at call time under the lease and returns a typed
    /// StaleDraft error (no backend call) if it falls below the minimum (§7.3).
    async fn create_plain_invoice(
        &self,
        req: CreatePlainInvoiceRequest, // amount_sat, description(hash), absolute_expiry: u64, external_id
    ) -> Result<Bolt11Invoice, LightningRpcError>;

    /// include_unpaid lookup by our correlation id. Returns ALL matches — the
    /// caller treats >1 as a duplicate-externalId backend-invariant violation
    /// (§7.3, recorded as BackendInvariantViolation), never picks one.
    async fn get_invoices_by_external_id(
        &self,
        external_id: &str,
        include_unpaid: bool,
    ) -> Result<Vec<BackendInvoice>, LightningRpcError>;

    /// Low-latency settlement HINTS (authenticated), not proof (§7.2).
    async fn subscribe_invoice_settled(&self)
        -> Result<BoxStream<'static, SettlementHint>, LightningRpcError>;

    /// Authenticated settled-ledger page. Cursor semantics per §3.3 below.
    async fn list_settled_invoices(
        &self,
        cursor: LedgerCursor,
        page_limit: usize,
    ) -> Result<LedgerPage, LightningRpcError>;

    async fn get_settled_invoice_by_hash(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<Option<SettledInvoice>, LightningRpcError>;
}

pub struct CustodialBackendCapabilities {
    pub backend_kind: String,                  // "phoenixd"
    pub invoice_amount_granularity_msats: u64, // 1000
    pub declared_retention_secs: Option<u64>,  // None ⇒ operator-configured (§7.2)
    pub late_settlement_finality_secs: u64,    // finality window for InvoiceExpiredUnpaid proof
    pub supports_unpaid_external_id_lookup: bool, // hard requirement; false ⇒ refuse to serve custodial
}

pub struct SettledInvoice {
    pub payment_hash: sha256::Hash,
    pub external_id: Option<String>,
    pub requested_msat: Amount,
    pub received_msat: Amount, // net of backend skim
    pub fees_msat: Amount,     // backend-reported skim S (§8)
    pub completed_at_ms: u64,
}
```

`BackendInvoice` = unpaid-or-paid variant of the above plus the bolt11 and absolute expiry.
`SettlementHint { payment_hash, external_id }` carries no trusted amounts.

Rationale: `ILnRpcClient` keeps its send-path contract untouched for every existing backend;
custodial-gatewayd requires `dyn NotifyOnlyLightningClient` and refuses to start custodial
service on a backend that only implements `ILnRpcClient`.

### 3.2 Full `ILnRpcClient` coverage for phoenixd (send stays trustless, §13)

`ILnRpcClient` has many required methods beyond the send path (channel management, on-chain
funds, invoice/transaction lookup, offers, wallet sync — see the trait from
`gateway/fedimint-lightning/src/lib.rs:105` onward). The adapter must compile against the **full
trait**: enumerate every required method at coding time and record its disposition in a table in
the adapter module docs. Dispositions:

- `pay`/`pay_private`: `POST /payinvoice`; resolve in-flight/duplicate via the outgoing-payment
  lookup by payment hash to satisfy the trait's idempotency contract.
- `info`: `GET /getinfo` → node pubkey (this is the `lightning_public_key` the client binds
  invoices to, §7.4 — it MUST be the key that signs phoenixd invoices; add a startup self-check
  that a freshly created invoice's `recover_payee_pub_key()` equals it, and refuse to serve
  custodial receive otherwise).
- `routehints`: empty (LNv1-only, per trait docs).
- `route_htlcs`: inert, never-yielding stream; `complete_htlc`: typed failure (never invoked on
  the custodial path).
- Trustless-receive invoice creation: typed "unsupported backend" error.
- Balance/wallet-sync-style methods: map to phoenixd equivalents where one exists
  (e.g. `GET /getbalance`); otherwise a typed `LightningRpcError` unsupported-operation error.
- Channel management, on-chain deposit/withdraw, offers, transaction listing: typed unsupported
  error unless a phoenixd endpoint maps cleanly. Never `todo!()`/panic; unsupported errors must
  be distinguishable from transient failures so callers don't retry them.

### 3.3 Cursor semantics (§7.2, decides the adapter rule)

phoenixd pagination is offset-based ⇒ the adapter exposes a **high-watermark cursor**:

```rust
pub struct LedgerCursor {
    pub high_watermark_completed_at_ms: u64,
    pub overlap_ms: u64, // configured; re-scan window behind the watermark
}
```

`list_settled_invoices` queries `from = watermark - overlap` to now, pages by offset *within one
poll*, and the **consumer** dedupes by `payment_hash` (spec 04 keeps the dedup set implicitly via
record status — a settlement already applied is a no-op). Offsets never persist. The cursor is
rebuildable: on loss, spec 04 point-looks-up every nonterminal record and retained tombstone by
`external_id`/hash instead of trusting any window (§7.2).

### 3.4 Hints and authentication

- Websocket events and webhooks are hints only. The webhook **HTTP route is hosted by
  custodial-gatewayd** (spec 04 mounts `POST /phoenixd_webhook` and forwards the raw body +
  `X-Phoenix-Signature` header); the **adapter owns verification and parsing** via
  `verify_and_parse_webhook(body, signature) -> Option<SettlementHint>` (HMAC-SHA256 over the
  body with the webhook secret, constant-time compare). Websocket authenticates at connect via
  the API password. Unauthenticated hints are dropped and counted
  (`gateway_custodial_receive_forged_hint_total` — internal counter, not in the §7.8 required set).
- **Webhook configuration is explicit, never silently degraded:** `phoenixd_webhook_secret: None`
  means webhooks are **not configured** — the hint stream is websocket + polling only and spec 04
  does not mount the webhook route. Configuring a webhook delivery URL (per-invoice
  `webhookUrl` via `phoenixd_webhook_public_url`, or phoenixd-side global webhook config) while
  the secret is `None` is a **startup error**: it would silently convert every real delivery into
  a dropped "forged" hint.
- A hint never advances a record: it only triggers `get_settled_invoice_by_hash` /
  ledger reconciliation (§7.3.2).

### 3.5 Config (`LightningMode`)

```rust
// gateway/fedimint-gateway-common/src/lib.rs
LightningMode::Phoenixd {
    phoenixd_api_url: SafeUrl,        // FM_PHOENIXD_API_URL
    phoenixd_api_password: String,    // FM_PHOENIXD_API_PASSWORD (http-password)
    phoenixd_webhook_secret: Option<String>, // FM_PHOENIXD_WEBHOOK_SECRET; None ⇒ webhooks not configured (§3.4)
    phoenixd_webhook_public_url: Option<SafeUrl>, // externally reachable URL of spec 04's webhook route;
                                      // passed as per-invoice `webhookUrl` on every create when set;
                                      // Some(_) requires Some(secret) or startup error (§3.4)
    phoenixd_retention_secs: u64,     // operator-declared retention (§7.2; no backend SLA)
    phoenixd_finality_secs: u64,      // late-settlement finality window
}
```

Retention is operator-declared for phoenixd (no upstream SLA, §7.2); the adapter surfaces it via
`declared_retention_secs` and spec 04 enforces the coverage gate against it.

Adding the variant makes legacy `gatewayd`'s `LightningMode` match non-exhaustive. Legacy
`gatewayd` MUST refuse to start on `LightningMode::Phoenixd` with a typed startup error:
trustless receive is impossible on a notify-only backend (§4) and a started instance would
register on `GATEWAYS_ENDPOINT`, violating §7.1's legacy-list rule. The variant is consumed only
by `custodial-gatewayd` (spec 04).

## 4. Edge cases

- **Sat-only granularity:** `create_plain_invoice` takes `amount_sat: u64`; the adapter rejects
  non-sat msat inputs upstream (spec 04 enforces before the lease; the adapter double-checks).
- **Relative expiry derivation:** the adapter receives an *absolute* target expiry from the draft
  and derives `expirySeconds` at call time under the lease; below-minimum ⇒ typed
  `StaleDraft` error, no backend call (§7.3).
- **Duplicate externalId:** `get_invoices_by_external_id` returning >1 is surfaced verbatim; the
  adapter never filters (the §7.3 duplicate-externalId invariant handling is spec 04's).
- **Amountless/zero-amount invoices:** never created; adapter asserts request amount > 0.
- **Clock:** `completed_at_ms` is backend time; only used for cursor/watermark, never for
  deadline decisions (§8 uses observed consensus time).

## 5. Test plan

- Adapter unit tests against a local mock HTTP server: create/lookup/list mappings, auth header,
  webhook signature verify (accept/reject), relative-expiry derivation, duplicate-externalId
  passthrough, offset-page overlap yielding duplicates that the consumer dedupes.
- `FakeNotifyOnlyBackend` (spec 07) implements this trait and is the primary correctness harness;
  one phoenixd-on-mutinynet smoke test pins real API compatibility (§15).

## 6. Acceptance criteria

- [ ] Trait object-safe; custodial-gatewayd consumes `Arc<dyn NotifyOnlyLightningClient>`.
- [ ] Existing backends untouched; `just test` for gateway crates passes unchanged.
- [ ] Startup invoice-payee self-check implemented and tested.
- [ ] All phoenixd endpoint/field names re-verified against the pinned version and recorded in §2.

## 7. Open questions (non-blocking)

- Whether `pay` maps `max_fee`/`max_delay` onto phoenixd's pay options faithfully enough for the
  trustless send companion (§13 is out of detailed scope; send ships best-effort behind the same
  adapter).
