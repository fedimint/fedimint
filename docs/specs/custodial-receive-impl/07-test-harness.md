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
    pub fn create_delay_and_crash(&self, mode: CreateFailureMode); // NotSent | SentButNoResponse | MaybeSentNotVisible | DuplicateCreated
    pub fn settle(&self, hash_or_external_id: ..., received_msat: Amount, fees_msat: Amount, completed_at_ms: u64);
    pub fn emit_hint(&self, hint: SettlementHint, authenticated: bool); // forged-hint testing
    pub fn set_ledger_offset_shift(&self, shift: usize);   // offset-pagination hazard
    pub fn reveal_hidden_invoice(&self, external_id: &str); // MaybeSentNotVisible recovery
    pub fn inject_duplicate_external_id(&self, external_id: &str);
    pub fn set_retention_horizon_ms(&self, horizon: u64);  // coverage-gate testing
    pub fn advance_time_ms(&self, delta: u64);
}
```

`SentButNoResponse` creates a backend invoice, loses the create response, and leaves it visible to
lookup: recovery finds it and completes `AwaitingPayment` (or validates it into the appropriate
unreturnable tombstone). It does not exercise an inconclusive lookup.
`MaybeSentNotVisible` loses the response after the maybe-sent commit and returns no matching
invoice from lookup/list until explicitly revealed. Recovery records `InvoiceCreateInconclusive`
and never retries creation. Test both no later visibility and reveal+settle, which must reconcile
through normal recovered validation and fund-on-settlement rules without a second invoice.

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
| CP10 | after atomic Funded+AwaitingShares audit commit, before task spawn |
| CP11 | while audit waits for shares (no terminal transition) |
| CP12 | after invalid-audit+liability commit and after subsequent refund prepare commit (two subcases) |
| CP13 | after audit refund submit commit, before broadcast |
| CP14 | after refund acceptance, before/during mint-output recovery and final audit commit |

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
| operation-log divergence re-drive | `state_divergence_redrives_exact_tx` (delete the operation's active/inactive state entries between CP7/CP8 — `operation_exists` is state-based, spec 01 §3.4.8; variant with surviving fees/op-log rows exercises insert-if-absent re-drive, spec 01 §3.4.9; variant with ONLY the submission SM missing while module SMs survive asserts the typed invariant error, spec 01 §3.4.10 — never a silent wait) | G |
| crash between create and AwaitingPayment; recovery signs from stored draft under changed config | `cp3_recovery_signs_stored_draft` (flip gateway fee config before restart) | G |
| duplicate create while lease live | `duplicate_create_waits_on_lease` | G |
| expired lease + maybe-sent ⇒ inconclusive, no second invoice | `maybe_sent_inconclusive_no_second_invoice` (`MaybeSentNotVisible`, lookup returns empty) | G |
| lost create response with visible invoice recovers normally | `lost_create_response_visible_lookup_recovers` (`SentButNoResponse`) | G |
| inconclusive stays in reconciliation; later settle follows fund_on_settlement | `inconclusive_settlement_funds_or_liability` (`MaybeSentNotVisible`, then reveal+settle) | G |
| stale draft: no create / unreturnable tombstone | `stale_draft_no_create`, `stale_invoice_tombstoned_unreturnable` | G |
| rejected-but-retained client receive still claims | `retained_provisional_claims_after_unreturnable` | C+G |
| backend invoice validation before signing | `invoice_validation_matrix` (each field mutated ⇒ `BackendInvoiceRejected`) | G |
| recovered-invoice validation parity | `recovered_invoice_same_validation` (CP3 recovery path) | G |
| duplicate externalId disables issuance | `duplicate_external_id_halts_issuance` | G |
| conflicting duplicate vs fingerprint | `fingerprint_conflict_rejected`, client retains claim material `conflict_retains_claim_material` | G+C |
| root-index loss rebuild | `root_index_rebuild_from_prefix` | G |
| cursor loss rebuild (§7.2, record-driven) | `cursor_loss_point_lookups_every_record` (delete `LedgerCursor`; assert every nonterminal + retained record is point-looked-up and no settlement is missed, incl. one older than any polling window) | G |
| forged webhook ignored | `forged_hint_ignored_until_ledger_confirms` | G |
| payee-binding + quote verification | `quote_verification_matrix` (every §3.3 check of spec 06) | C |
| legacy list excludes custodial-only; trustless selection skips | `legacy_list_and_selection_policy` | C |
| non-payee-gateway send of custodial invoice; same-gateway forfeit | `custodial_invoice_lightning_path`, `same_gateway_selfpay_forfeit_refunds` | G |
| CP-crash before hash-registry reassert | `registry_reasserted_before_return` (CP3/CP4) | G |
| invalid contract audit ⇒ refund + liability; durable start/resume | `invalid_contract_refund_liability` (CP10–CP14 × duplicate wakeups; one refund txid, one open liability, ecash recovered once), `share_timeout_never_invalidates`, `invalid_refund_prepare_failure_retains_liability`, `unfinished_audit_blocks_prune` | G |
| mixed legacy/prepared operation-id ownership and identity | `prepared_id_blocks_legacy_submit`, `legacy_prepare_race_one_winner`, `prepared_submit_identity_mismatch` (spec 01 §5.7) | U |
| rejected funding uses module refunds while debt persists | `funding_rejected_tracks_module_refunds` (restart during bundle/per-note refund/output recovery; assert spendable recovered ecash, open liability, no manual re-credit), `inconclusive_inputs_stay_reserved` | G |
| settlement mismatch direction | `settlement_amount_direction_matrix` (net overpay small/gross, authenticated skim normal/abnormal, unexplained shortfall, wrong binding; run on fresh + retained recovery records) | G |
| economic threshold is issuance-only with durable accounting | `outstanding_invoices_overshoot_thresholds` (concurrent settlement exceeds inbound headroom, loss budget and max_in_flight; new issuance stops, existing debt proceeds), `loss_budget_durable_backend_scope` (duplicates, fee adjustments, restart, prune, reset with unrelated health stop) | G |
| custodial URL mandatory send | `custodial_url_send_success_failure_restart` (out-of-band selection, actual endpoint succeeds, unsupported limits forfeit before pay, lost response resolves via outgoing lookup) | C+G |
| offset-pagination overlap dedupe | `ledger_offset_shift_no_miss_no_double` | G |
| duplicate create retry returns same invoice+quote; stale ⇒ unreturnable | `idempotent_duplicate_returns_stored` (run with the backend UNREACHABLE — the response is answered from the stored `backend_invoice` field, §7.3), `stale_duplicate_unreturnable` (pre-settlement only; a settled record returns stored `Created` unconditionally, covered by `settled_duplicate_returns_stored`) | G |
| cross-path namespace collisions | `cross_path_namespace_matrix` — **DEFERRED with dual-capable mode** (the trustless-side rejections live in legacy gatewayd/gwv2 and have no MVP home, §7.3/§15); MVP coverage is `image_collision_rejects_without_halt`: intra-custodial image collision → `DuplicateContractConflict` + alarm, issuance stays **enabled** (client-reachable conditions never halt, §7.3) | G |
| backend invoice-hash collision with an existing owner | `invoice_hash_collision_tombstones_and_halts` (MVP: collision with another custodial pending receive; the active-trustless-owner variant is deferred with dual-capable mode) | G |
| tombstone keeps hash reserved until pruning | `tombstone_hash_reservation_lifecycle` (MVP, intra-custodial; the unsafe-trustless-collision ownership rules are deferred with dual-capable mode) | G |
| retained-settlement fund_on_settlement incl. after-deadline ⇒ liability | `late_settlement_before_deadline_funds`, `late_settlement_after_deadline_liability` | G |
| client observed-time / deadline-rule quote rejection | `quote_stale_observed_time_rejected` (wall-clock reference) | C |
| issued-unpaid never gates; internal throttling generic; actual limit typed | `unpaid_buildup_never_rejects`, `actual_liability_limit_typed` | G |
| SettledAwaitingLiquidity wait + pegin resume | `short_float_waits_then_funds` (drain float, allocate through local operator interface, deposit on-chain, restart while pending, await spendable ecash and assert slack-priority order) | G |
| gauges recomputed from DB after restart | `metrics_recomputed_on_restart` | G |
| non-sat amounts rejected | `non_satoshi_amount_rejected` | C+G |
| saturation lower-bounds | `amount_saturation_rejected_both_sides` | C+G |
| client sizing uses custodial fee; fee-mismatch typed | `custodial_fee_sizing_and_mismatch` (`FeeOrAmountBindingMismatch`) | C+G |
| DeadlineTooFar bounds retention horizon | `deadline_too_far_rejected` | G |
| pre-create invariant enforced | `precreate_invariant_same_fingerprint_after_maybe_sent` (all identical-retry rejection paths allow only CreateInProgress/BackendInvoiceUnreturnable), `different_fingerprint_conflicts_after_maybe_sent` (every retained state gives DuplicateContractConflict; client retains watcher/claim material) | G |
| unmatched settlement records + halts | `unmatched_settlement_alerts_and_halts` | G |
| pruning releases namespace only after deadline+finality; post-prune settle ⇒ unmatched | `prune_lifecycle_post_prune_unmatched` | G |
| conservative client pruning under skew | `client_pruning_skew_safe` | C |
| custodial claim takes the invoice-difference fee path, never the magnitude fallback (§8) | `custodial_claim_fee_path_no_magnitude_fallback` (receive large enough that `amount + fee_from_expiration(deadline)` would overflow; assert claim completes and the `ReceivePaymentEvent` fee equals invoice − contract amount) | G |
| slack-based issuance halt (§8) | `slack_pressure_disables_issuance` (advance test time until a settled-unfunded record's deadline slack approaches the safety margin; assert the federation-scoped flag disables new creation while funding proceeds) | G |
| non-prefixed settlements ignored on a shared backend | `nonprefixed_settlements_ignored` (ledger entries without the `fmcr1-` correlation prefix never record `UnmatchedSettlement` and never halt issuance) | G |
| record deletion/pruning never removes the armed SM | `record_deletion_keeps_armed_sm_claiming` (delete the provisional record after a pre-create rejection, then fund the contract before the deadline; assert the SM still claims, §7.4) | C+G |
| issuance-disable scoping | `backend_scoped_halt_covers_all_federations` (duplicate-externalId on one federation's record halts creation for every federation on that backend, root flag §4) | G |

## 5. Smoke test

One `devimint`-driven phoenixd-on-mutinynet smoke test (manual/nightly, not CI-blocking):
create → pay externally → observe settle → fund → claim, plus a send selected through the
out-of-band custodial URL with success and bounded-payment refusal/recovery. Pins real API
compatibility (§15);
everything else runs on the fake.

## 6. Acceptance criteria

- [ ] Every design-§15 bullet appears in the §4 table and every named test exists and passes —
      except rows marked **DEFERRED with dual-capable mode**, which are excluded from the MVP
      gate and ship with mode 2 (matching the §15 dual-capable markers).
- [ ] Crash-point tests cover CP1–CP9 on applicable create/funding paths and CP10–CP14 on
      valid/invalid-contract audit paths, including restarts before spawn and during output recovery.
- [ ] `FakeNotifyOnlyBackend` has no wall-clock dependence (explicit test time only).
- [ ] CI wiring: G-tests run in the standard test matrix; the mutinynet smoke test is opt-in.
