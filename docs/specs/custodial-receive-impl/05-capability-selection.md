# Impl Spec 05: Gateway Candidates & Policy Selection (`fedimint-lnv2-client`)

> Parent: design §7.1 (selection), §7.6 (send caveat). Crate: `modules/fedimint-lnv2-client`.

## 1. Scope & non-goals

**In scope:** the gateway candidate set with source annotation, `select_gateway_for_receive`
policy selection, keeping trustless receive off custodial-only gateways, and the send-path
candidate union. **Non-goals:** consent UX (§14.7 — wallet-app concern; the client API only
carries the source annotation), pre-funding self-pay classification (§14 deferred), any
federation-side discovery endpoint (§16).

## 2. Grounding in current code (verified)

- `select_gateway(invoice: Option<Bolt11Invoice>)` (`modules/fedimint-lnv2-client/src/lib.rs:453`)
  fetches `module_api.gateways()` (federation `GATEWAYS_ENDPOINT`, guardian-vetted URLs), prefers
  the gateway whose `lightning_public_key` matches an invoice payee (direct swap), else the first
  reachable one via `/routing_info` probe; returns `(SafeUrl, RoutingInfo)`.
- `receive` (`:804`) and `send` (`:576`) call it; `receive` then applies the fee cap and builds
  the contract (`:931-961`).

## 3. Design

### 3.1 Candidate model

```rust
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)] // Ord: lives in a BTreeSet
pub enum GatewayCandidateSource {
    LegacyFederationList,   // federation GATEWAYS_ENDPOINT
    OutOfBandCustodial,     // wallet/app/operator-supplied (§7.1: URL source IS the authorization)
}

#[derive(Debug, Clone)]
pub struct GatewayCandidate {
    pub api: SafeUrl,
    /// BOTH provenance bits — a URL present in the legacy list AND supplied
    /// out-of-band keeps both. Collapsing to a single value would erase the
    /// out-of-band membership that custodial eligibility is keyed on (§4).
    pub sources: BTreeSet<GatewayCandidateSource>,
    /// Module-key pin from the out-of-band source (§7.1). When present, the
    /// probed RoutingInfo.module_public_key and every quote's gateway_module_pk
    /// MUST equal it (spec 06 §3.3); mismatch disqualifies the candidate.
    pub expected_module_pk: Option<PublicKey>,
    pub routing_info: RoutingInfo, // live probe result
}
```

Out-of-band URLs enter via a new module API:
`LightningClientModule::set_custodial_gateways(Vec<(SafeUrl, Option<PublicKey>)>)` persisted in
the module DB (new key prefix `CustodialGatewayUrls`), plus a per-call override parameter on the
custodial receive entry point (spec 06). Each URL MUST be `https` (explicit exceptions:
localhost/loopback, `.onion`, or a deliberate insecure-dev flag — §7.1); non-conforming URLs are
rejected at `set_custodial_gateways`, never silently skipped at selection. The client never
promotes a URL into the candidate set from any other source; `/routing_info` is capability/key
check only (§7.1).

### 3.2 Selection functions

```rust
pub enum ReceiveMode { Trustless, Custodial }

/// Trustless: legacy-list candidates only, skipping custodial-only gateways
/// (custodial.is_some() && trustless.is_none()), preserving current ordering
/// semantics. Custodial: out-of-band candidates only, requiring
/// custodial.is_some(); never falls back to the legacy list.
pub(crate) async fn select_gateway_for_receive(
    &self,
    mode: ReceiveMode,
) -> Result<GatewayCandidate, SelectGatewayError>;
```

`receive` switches to `select_gateway_for_receive(Trustless)`; behavior for existing wallets is
unchanged except that a (future) custodial-only gateway that somehow appears in the legacy list
is skipped instead of stranding the receive (§7.1). New `SelectGatewayError` variants:
`NoCustodialCandidates`, `NoTrustlessCandidates`.

Send keeps `select_gateway(invoice)` semantics over the **union** candidate set (legacy list ∪
stored custodial URLs): payee-match preference first (enables direct swap and the §7.6
same-gateway forfeit path), then reachability. No pre-classification of invoices (§7.6).

### 3.3 Metadata

Operations record the selected candidate's `sources` (and `expected_module_pk` when present) in
operation meta (spec 06 uses them for consent/support surfacing and pin verification, §7.1).

## 4. Edge cases

- A URL in both sets keeps **both** provenance bits in `sources` (collapsing to "legacy wins"
  would make the also-supplied-out-of-band case below unrepresentable); capabilities from the
  live probe decide eligibility per mode.
- Probe returns `custodial: Some` on a legacy-list gateway (dual-capable, §7.1 mode 2): eligible
  for trustless mode; eligible for custodial mode **only** if `sources` contains
  `OutOfBandCustodial` (the same URL was also supplied out-of-band), or
  `custodial_allows_legacy_list` is enabled (non-default, §6/§7 — flipping it is a documented
  authorization-semantics change, §7.1) — consistent with the MVP rule that the legacy list
  authorizes nothing custodial.
- All custodial candidates unreachable: `NoCustodialCandidates` — never silently fall back to
  trustless (mode is an explicit user opt-in, §7.4).
- Stored URLs are per-federation (`FederationId`-keyed), since capability is per federation.

## 5. Test plan

- Unit: policy matrix over (source, capabilities, reachability) → selection outcome, including
  the custodial-only-skipped-for-trustless case (§15 bullet).
- Integration (07): legacy `GATEWAYS_ENDPOINT` excludes custodial-only gateway; trustless receive
  uses only trustless-capable candidates; send over union set reaches a custodial invoice's payee
  gateway and gets the forfeit-refund.

## 6. Acceptance criteria

- [ ] No change to trustless receive behavior when no custodial URLs are configured (golden test).
- [ ] Custodial selection is impossible without an explicit out-of-band URL: empty URL store +
      custodial mode ⇒ `NoCustodialCandidates`, even when a dual-capable gateway sits in the
      legacy list. (§7.1 makes a dual-capable legacy gateway custodial-*capable*, but the MVP
      policy decision here is that custodial mode considers **out-of-band URLs only** — the URL
      source is the authorization input, and the legacy list authorizes nothing custodial.
      Encode as a `custodial_allows_legacy_list: bool` policy field, default `false`.)
- [ ] Wasm compiles.

## 7. Open questions (non-blocking)

- Whether `custodial_allows_legacy_list` should ever default to `true` for dual-capable gateways
  once consent UX exists (§14.7). MVP: `false`, explicit URLs only.
