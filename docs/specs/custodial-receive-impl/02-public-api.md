# Impl Spec 02: Public API Semantics (`fedimint-lnv2-common`)

> Parent: design §7.1, §7.3 (quote/terms), §7.6, §7.9. Crate: `modules/fedimint-lnv2-common`.
> Everything here is wire-visible client↔gateway API; nothing touches federation consensus.

## 1. Scope & non-goals

**In scope:** `ReceiveCapabilities` on `RoutingInfo`; the custodial create endpoint payload and
result types; `CustodialReceiveQuote` / `CustodialReceiveTerms` with canonical encoding and
signature; the `CustodialReceiveRejectionReason` enum with its pre-create invariant; endpoint
constants. **Non-goals:** gateway-side handlers (spec 04), client-side verification (spec 06),
any federation endpoint (none is added, §7.5).

## 2. Grounding in current code (verified)

- `RoutingInfo` derives no Fedimint `Encodable`/`Decodable` — only std traits plus
  `Serialize`/`Deserialize` (`Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize`,
  `gateway_api.rs:142`) — so additive fields with `#[serde(default)]` are backward-compatible on
  the HTTP JSON surface.
- `CreateBolt11InvoicePayload { federation_id, contract, amount, description, expiry_secs }`
  (`gateway_api.rs:125`), `SendPaymentPayload { federation_id, outpoint, contract, invoice, auth }`
  (`:134`); send response is `Result<Result<[u8; 32], Signature>, ServerError>` (`:48`).
- Endpoint constants live in `modules/fedimint-lnv2-common/src/endpoint_constants.rs`
  (gateway HTTP endpoints are the `/`-prefixed ones, e.g. `CREATE_BOLT11_INVOICE_ENDPOINT:13`).
- `PaymentFee { base, parts_per_million }` with `le`, `add_to`, `subtract_from` (saturating),
  `RECEIVE_FEE_LIMIT` = 50 sats + 0.5% (`gateway_api.rs:200-247`).

## 3. Design

### 3.1 New module `modules/fedimint-lnv2-common/src/custodial.rs`

All new types live in one module, re-exported from the crate root.

```rust
// NOTE: all three derive Hash because RoutingInfo derives Hash (gateway_api.rs:142)
// and gains a ReceiveCapabilities field; omitting Hash fails to compile. PaymentFee
// and Amount already implement Hash.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ReceiveCapabilities {
    pub trustless: Option<TrustlessReceiveCapability>,
    pub custodial: Option<CustodialReceiveCapability>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TrustlessReceiveCapability {} // marker for now; fee stays on RoutingInfo.receive_fee

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CustodialReceiveCapability {
    pub receive_fee: PaymentFee,
    pub max_receive_amount: Amount,
    pub max_in_flight: Amount, // per federation (§7.1)
    pub min_invoice_to_funding_deadline_delta_secs: u64,
    pub min_contract_lifetime_secs: u64,
    pub max_invoice_expiry_secs: u64,
    pub max_funding_deadline_secs: u64,
    pub consensus_time_observation_max_age_secs: u64,
    pub safety_margin_secs: u64,
    pub invoice_amount_granularity_msats: u64,
    pub quote_api_version: u16,
}

impl ReceiveCapabilities {
    /// Absent field on the wire ⇒ legacy trustless-only gateway (§7.1).
    pub fn legacy_trustless() -> Self {
        Self { trustless: Some(TrustlessReceiveCapability {}), custodial: None }
    }
}
```

`RoutingInfo` gains:

```rust
#[serde(default = "ReceiveCapabilities::legacy_trustless")]
pub receive_capabilities: ReceiveCapabilities,
```

Compatibility rules (tested): old gateway JSON (field absent) deserializes to
`legacy_trustless()`; old clients ignore the new field (serde tolerates unknown fields on their
side — verify `RoutingInfo` deserialization in released clients is not `deny_unknown_fields`;
it is not today). `RoutingInfo.receive_fee` keeps its legacy trustless meaning (§7.1).

### 3.2 Quote and terms

```rust
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct CustodialReceiveTerms { /* fields exactly as design §7.3, incl. max_* and backend_retention_secs */ }

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct CustodialReceiveQuote { /* fields exactly as design §7.3 (no terms_hash) */ }
```

**Canonical encoding = fedimint `Encodable`.** The signature is BIP-340 Schnorr by
`gateway_module_pk` over a BIP-340-style tagged hash, byte-exact:

```text
tag  = "fedimint-custodial-receive-quote-v1"           (ASCII, no NUL)
msg  = consensus_encode(quote_without_signature)       (fields in declaration order)
sign = schnorr_sign(sha256(sha256(tag) || sha256(tag) || msg))
```

This is the normative byte-level construction for golden vectors; the parent design's
"domain tag || canonical encoding" phrasing is realized as this tagged hash (parent §7.3 is
amended to say so).

Implement as `CustodialReceiveQuote::signing_message()` (encodes every field in declaration
order with the `signature` field excluded — model on `OutgoingContract::forfeit_message()`), plus
`sign(keypair)` and `verify(gateway_module_pk)`. Field order is frozen once released;
`api_version` governs evolution (§14.8). Serde derives exist only for embedding in JSON payloads;
the *signature* is always over the consensus encoding, never JSON.

### 3.3 Create endpoint

```rust
pub const CREATE_CUSTODIAL_BOLT11_INVOICE_ENDPOINT: &str = "/create_custodial_bolt11_invoice";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustodialBolt11InvoicePayload {
    pub federation_id: FederationId,
    pub contract: IncomingContract, // funding deadline rides in contract.commitment.expiration_or_fee
    pub amount: Amount,             // invoice face amount A (msats)
    pub description: Bolt11InvoiceDescription,
    /// ABSOLUTE requested backend-invoice expiry (unix seconds). Absolute so the
    /// fingerprint is stable across retries from a stored provisional record and
    /// so spec-03's call-time relative derivation has a fixed target (a relative
    /// value here would silently re-anchor on every retry).
    pub requested_invoice_expiry: u64,
    pub quote_api_version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustodialInvoiceCreationResult {
    Created { invoice: Bolt11Invoice, quote: CustodialReceiveQuote },
    Rejected { reason: CustodialReceiveRejectionReason },
}
```

The result enum rides in the `Ok` HTTP response (§7.9): transport/auth failures stay HTTP errors
and stay retryable; domain decisions never do.

**Shared request fingerprint.** `request_fingerprint` (§7.3) is defined here so client and
gateway compute the identical value from the payload alone — never from either side's current
config, so a gateway fee/policy change can never reclassify an identical retry as a
`DuplicateContractConflict`:

```rust
impl CreateCustodialBolt11InvoicePayload {
    /// tagged_hash("fedimint-custodial-receive-fingerprint-v1",
    ///     contract_id || amount || sha256(description) || requested_invoice_expiry || quote_api_version)
    pub fn request_fingerprint(&self) -> sha256::Hash { ... }
}
```

The selected fee/policy is deliberately NOT a fingerprint input: it is already bound through the
amount-binding check (`commitment.amount == receive_fee.subtract_from(amount)`, §7.3), and the
stored signed quote — not current config — is what an idempotent duplicate gets back.

### 3.4 Rejection reasons

`CustodialReceiveRejectionReason` exactly as the design §7.9 enum — all 16 variants, including
`FeeOrAmountBindingMismatch`, `DeadlineTooFar`, `BackendInvoiceUnreturnable`,
`BackendLedgerUnavailable`, and `ActualLiabilityLimitExceeded`; the §7.9 listing is normative,
do not transcribe from here. Doc-comment the **pre-create invariant** on the enum itself:
every variant except `CreateInProgress` and `BackendInvoiceUnreturnable` is returned only when no
backend create attempt was ever marked maybe-sent for the rejected request's fingerprint. This is
a normative API contract for any gateway implementation, not a gatewayd implementation detail.

### 3.5 Same-gateway send outcome

No new type: the same-gateway custodial self-pay signal is the existing forfeit signature
(`Err(Signature)`) in the send response (§7.6). This spec only adds a doc-comment on
`SendPaymentPayload`/the connection trait pointing at that rule, so nobody adds a typed error
later without reading §7.9.

### 3.6 Legacy list rule

`GATEWAYS_ENDPOINT` (federation-side, guardian-vetted) stays trustless-compatible-only. This is
enforced operationally (a custodial-only gateway is simply never registered) plus one assertion in
`custodial-gatewayd` (spec 04): it must not expose or call gateway registration for federations
where it has no trustless receive. No lnv2-server change.

## 4. Edge cases

- **Unknown `quote_api_version`** in payload → `Rejected { UnsupportedQuoteVersion }`.
- **Field evolution:** additive quote fields require an `api_version` bump because the signature
  covers the full encoding; clients reject versions they don't know.
- **Serde/Encodable duality:** tests must pin both the JSON round-trip and the consensus-encoding
  hash of a golden quote so accidental field reordering is caught at CI time.

## 5. Test plan

1. Golden-vector test: fixed quote → stable `signing_message()` hash; signature verifies; any
   field mutation fails verification.
2. `RoutingInfo` JSON without `receive_capabilities` → `legacy_trustless()`; with unknown extra
   fields → still parses (client side).
3. Enum exhaustiveness: a compile-time match in tests over `CustodialReceiveRejectionReason`
   ensures new variants force test updates.
4. Result-in-Ok discipline: creation handler returns `Rejected` (not HTTP error) for every §7.9
   table row — enforced in spec 04's tests against these types.

## 6. Acceptance criteria

- [ ] Types compile on wasm; no `Encodable` added to `RoutingInfo` (serde-only, §7.1).
- [ ] Quote signature domain tag string matches design §7.3 exactly.
- [ ] Backward-compat tests (3.1) pass against a captured pre-change `RoutingInfo` JSON fixture.

## 7. Open questions (non-blocking)

- Exact `TrustlessReceiveCapability` payload (empty marker vs echoing the legacy fee). Default:
  empty marker; revisit when trustless selection wants richer data (§14.4).
