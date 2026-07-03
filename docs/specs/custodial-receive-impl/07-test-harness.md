# Impl Spec 07: Test Harness & §15 Matrix

> Parent: design §15 (tests). Crates: `fedimint-testing`, `modules/fedimint-lnv2-tests`,
> `gateway/fedimint-custodial-gatewayd` (integration tests), devimint (one smoke test).

## 1. Scope

A deterministic `FakeNotifyOnlyBackend`, a crash-point framework around every durable custodial
transition, and the authoritative mapping from every design-§15 bullet to a named test. The §15
list is the requirement; this doc is the executable index. Any §15 bullet without a row here is a
spec bug.

## 2. `FakeNotifyOnlyBackend` (`fedimint-testing`)

Extends the existing fake-lightning pattern (`fedimint-testing/src/ln.rs`,
`FakeLightningTest:40`) with a new type implementing spec-03's `NotifyOnlyLightningClient`
(and the `ILnRpcClient` send subset):

```rust
pub struct FakeNotifyOnlyBackend {
    state: Arc<Mutex<FakeBackendState>>,   // invoices, settlements, cursor data
    controls: FakeBackendControls,         // test-side handle
}

pub struct FakeBackendControls {
    // deterministic knobs (no wall-clock dependence; explicit test time):
    pub fn create_delay_and_crash(&self, mode: CreateFailureMode); // NotSent | SentButNoResponse | DuplicateCreated
    pub fn settle(&self, hash_or_external_id: ..., received_msat: Amount, fees_msat: Amount, completed_at_ms: u64);
    pub fn emit_hint(&self, hint: SettlementHint, authenticated: bool); // forged-hint testing
    pub fn set_ledger_offset_shift(&self, shift: usize);   // offset-pagination hazard
    pub fn inject_duplicate_external_id(&self, external_id: &str);
    pub fn set_retention_horizon_ms(&self, horizon: u64);  // coverage-gate testing
    pub fn advance_time_ms(&self, delta: u64);
}
```

`SentButNoResponse` is the maybe-sent crash: the invoice exists backend-side but the create call
errors — driving `InvoiceCreateInconclusive` paths without real crashes.

## 3. Crash-point framework

Durable transitions get stable IDs; tests run scenario × crash-point:

| ID | Boundary (spec 04 §4 table) |
|----|------------------------------|
| CP1 | after draft reserve commit |
| CP2 | after lease+maybe-sent commit, before backend call returns |
| CP3 | after backend create, before AwaitingPayment commit |
| CP4 | after AwaitingPayment commit, before response sent |
| CP5 | after settle-confirm commit |
| CP6 | after prepare commit (FundingPrepared + PreparedTransactionKey) |
| CP7 | after submit commit, before broadcast observed |
| CP8 | after federation acceptance, before Funded commit |
| CP9 | after terminalize+liability commit |

Mechanism: the custodial service takes a test-only `CrashHooks` (feature-gated under
`cfg(test)`/dev-dependency injection) with `async fn at(CrashPoint)` that a test can turn into a
panic + service restart against the same DB. Restart = new service instance over the same
`Database` handle, mirroring process restart.

## 4. §15 matrix → tests

Legend: **G** = gateway integration test (custodial-gatewayd + FakeNotifyOnlyBackend + real dev
federation via `fedimint-testing` fixtures), **C** = client test (lnv2-tests), **U** = unit.

| §15 bullet (abbrev) | Test | Kind |
|---|---|---|
| duplicate funding across restart + webhook redelivery | `no_double_fund_across_restart_and_redelivery` (CP5–CP8 × duplicate hints; assert one outpoint per contract on the federation) | G |
| FundingPrepared re-drives identical bytes; missing prepared never rebuilds | `funding_prepared_redrive_exact_bytes`, `missing_prepared_never_rebuilds` (spec 01 §5.1/.6 + CP6) | G+U |
| reserved inputs not consumed concurrently | `reserved_inputs_survive_concurrent_ops` (spec 01 §5.5) | U |
| operation-log divergence re-drive | `oplog_divergence_redrives_exact_tx` (delete op-log entry between CP7/CP8) | G |
| crash between create and AwaitingPayment; recovery signs from stored draft under changed config | `cp3_recovery_signs_stored_draft` (flip gateway fee config before restart) | G |
| duplicate create while lease live | `duplicate_create_waits_on_lease` | G |
| expired lease + maybe-sent ⇒ inconclusive, no second invoice | `maybe_sent_inconclusive_no_second_invoice` (`SentButNoResponse`) | G |
| inconclusive stays in reconciliation; later settle follows fund_on_settlement | `inconclusive_settlement_funds_or_liability` | G |
| stale draft: no create / unreturnable tombstone | `stale_draft_no_create`, `stale_invoice_tombstoned_unreturnable` | G |
| rejected-but-retained client receive still claims | `retained_provisional_claims_after_unreturnable` | C+G |
| backend invoice validation before signing | `invoice_validation_matrix` (each field mutated ⇒ `BackendInvoiceRejected`) | G |
| recovered-invoice validation parity | `recovered_invoice_same_validation` (CP3 recovery path) | G |
| duplicate externalId disables issuance | `duplicate_external_id_halts_issuance` | G |
| conflicting duplicate vs fingerprint | `fingerprint_conflict_rejected`, client retains claim material `conflict_retains_claim_material` | G+C |
| root-index loss rebuild | `root_index_rebuild_from_prefix` | G |
| forged webhook ignored | `forged_hint_ignored_until_ledger_confirms` | G |
| payee-binding + quote verification | `quote_verification_matrix` (every §3.3 check of spec 06) | C |
| legacy list excludes custodial-only; trustless selection skips | `legacy_list_and_selection_policy` | C |
| non-payee-gateway send of custodial invoice; same-gateway forfeit | `custodial_invoice_lightning_path`, `same_gateway_selfpay_forfeit_refunds` | G |
| CP-crash before hash-registry reassert | `registry_reasserted_before_return` (CP3/CP4) | G |
| invalid contract audit ⇒ refund + liability | `invalid_contract_refund_liability` | G |
| offset-pagination overlap dedupe | `ledger_offset_shift_no_miss_no_double` | G |
| duplicate create retry returns same invoice+quote; stale ⇒ unreturnable | `idempotent_duplicate_returns_stored`, `stale_duplicate_unreturnable` | G |
| cross-path namespace collisions | `cross_path_namespace_matrix` (trustless↔custodial, image collision alarm) | G |
| hash collision with trustless registration | `invoice_hash_collision_tombstones_and_halts` | G |
| tombstone keeps hash reserved until pruning; unsafe collision doesn't steal ownership | `tombstone_hash_reservation_lifecycle` | G |
| retained-settlement fund_on_settlement incl. after-deadline ⇒ liability | `late_settlement_before_deadline_funds`, `late_settlement_after_deadline_liability` | G |
| client observed-time / deadline-rule quote rejection | `quote_stale_observed_time_rejected` (wall-clock reference) | C |
| issued-unpaid never gates; internal throttling generic; actual limit typed | `unpaid_buildup_never_rejects`, `actual_liability_limit_typed` | G |
| SettledAwaitingLiquidity wait + pegin resume | `short_float_waits_then_funds` (drain float, replenish, assert slack-priority order) | G |
| gauges recomputed from DB after restart | `metrics_recomputed_on_restart` | G |
| non-sat amounts rejected | `non_satoshi_amount_rejected` | C+G |
| saturation lower-bounds | `amount_saturation_rejected_both_sides` | C+G |
| client sizing uses custodial fee; fee-mismatch typed | `custodial_fee_sizing_and_mismatch` (`FeeOrAmountBindingMismatch`) | C+G |
| DeadlineTooFar bounds retention horizon | `deadline_too_far_rejected` | G |
| pre-create invariant enforced | `precreate_invariant_no_reason_after_maybe_sent` (assert on every rejection path with maybe-sent set) | G |
| unmatched settlement records + halts | `unmatched_settlement_alerts_and_halts` | G |
| pruning releases namespace only after deadline+finality; post-prune settle ⇒ unmatched | `prune_lifecycle_post_prune_unmatched` | G |
| conservative client pruning under skew | `client_pruning_skew_safe` | C |

## 5. Smoke test

One `devimint`-driven phoenixd-on-mutinynet smoke test (manual/nightly, not CI-blocking):
create → pay externally → observe settle → fund → claim. Pins real API compatibility (§15);
everything else runs on the fake.

## 6. Acceptance criteria

- [ ] Every design-§15 bullet appears in the §4 table and every named test exists and passes.
- [ ] Crash-point tests cover CP1–CP9 for at least the happy path and the maybe-sent path.
- [ ] `FakeNotifyOnlyBackend` has no wall-clock dependence (explicit test time only).
- [ ] CI wiring: G-tests run in the standard test matrix; the mutinynet smoke test is opt-in.
