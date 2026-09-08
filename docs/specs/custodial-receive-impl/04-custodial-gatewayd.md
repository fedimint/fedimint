# Impl Spec 04: `custodial-gatewayd` Service

> Parent: design §6, §7.1 (deployment modes), §7.3, §7.7, §7.8, §8, §10, §11. New crate
> `gateway/fedimint-custodial-gatewayd` (lib + bin), consuming specs 01–03. This is the largest
> phase; implement in the sub-phase order of §9 below.

## 1. Scope & non-goals

**In scope:** the custodial-only, out-of-band deployment mode (design §7.1 mode 1): HTTP API,
durable receive records and status machine, backend-create lease, settlement observer,
exactly-once funding via prepare/submit (spec 01), consensus-time observer, contract audit,
liabilities, unmatched settlements, pruning, metrics, liquidity alerts. **Non-goals for MVP:**
dual-capable mode wiring inside legacy `gatewayd` (design mode 2 — specced here only as the shared
registry interface it would need), `custodial_receive_status` endpoint, automated liquidity
actions beyond the operator deposit interface, rich liability tooling (§14).

## 2. Grounding in current code (verified)

- Gateway physical DB with per-federation *logical client prefixes*:
  `GatewayDbExt::get_client_database(federation_id)` prefixes `DbKeyPrefix::ClientDatabase=0x10`
  (`gateway/fedimint-gateway-server-db/src/lib.rs:30-40`). Root prefixes assigned today: 0x04,
  0x06–0x09, 0x10–0x12 (`gateway-server-db/src/lib.rs:288-297`); 0x05 and 0x0a–0x0f are
  unassigned but not ours to take — new custodial root prefixes start at 0x13.
- Funding-side building blocks in `modules/fedimint-gwv2-client/src/lib.rs`:
  `relay_direct_swap` (`:476`) shows the exact funding output construction
  (`ClientOutput { output: LightningOutput::V0(LightningOutputV0::Incoming(contract)), amounts }`),
  the deterministic `OperationId::from_encodable(&contract)` (`:483`), and `operation_exists`
  gating (`:484`). The gwv2 receive SM consumes federation decryption shares and routes
  non-decrypting contracts to refund (`receive_sm.rs:234-260`).
- LNv2 consensus time: guardians vote `LightningConsensusItem::UnixTimeVote`
  (`modules/fedimint-lnv2-server/src/lib.rs:416,447`); selection = sort desc,
  `times[threshold-1]` (`:773-793`). Votes are ordinary consensus items visible in signed session
  outcomes, which clients can stream via the global API session-outcome endpoints (used today by
  client recovery).
- Gateway HTTP surface pattern: axum router in `gateway/fedimint-gateway-server` exposing the
  `/`-prefixed lnv2 endpoints; reuse the same middleware/auth pattern for the new binary.

## 3. Crate layout

```
gateway/fedimint-custodial-gatewayd/
  src/lib.rs            // CustodialGateway struct, wiring
  src/bin/main.rs       // binary: config, backend, federations, serve
  src/api.rs            // axum routes: /routing_info, /create_custodial_bolt11_invoice, /phoenixd_webhook (spec 03 §3.4), /send_payment
  src/db.rs             // record types + key prefixes (below)
  src/receive.rs        // create-invoice handler, lease, validation, quote signing
  src/observer.rs       // CustodialSettlementObserver (hints + ledger polling + reconciliation)
  src/funding.rs        // funding workers, SettledAwaitingLiquidity queue, prepare/submit driving
  src/audit.rs          // post-funding contract audit (decryption-share wait, refund)
  src/consensus_time.rs // per-federation UnixTimeVote observer
  src/registry.rs       // CustodialPending hash registry (shared-registry trait for dual mode)
  src/metrics.rs        // §7.8 gauges/histogram
  src/prune.rs          // retained-record pruning
```

The binary joins federations the way `gatewayd` does conceptually (federation client per invite,
gwv2 client module for ecash float + funding), but never registers on `GATEWAYS_ENDPOINT` and
refuses a config that asks it to (§7.1 mode 1; assert at startup).

### 3.1 Federation client wiring (owned work, not free reuse)

- **`IGatewayClientV2` must be implemented by this binary.** Attaching the gwv2 client module
  requires `GatewayClientInitV2 { gateway: Arc<dyn IGatewayClientV2> }`
  (`modules/fedimint-gwv2-client/src/lib.rs:66-68`; trait at `:608-657`). Dispositions:
  `is_direct_swap` consults the `registry.rs` `CustodialPending` map first (this is where the
  §7.6 self-pay labeling lives) and otherwise returns `Ok(None)`; `complete_htlc` returns `()`
  (`gwv2-client/src/lib.rs:610`), so it is implemented as a no-op that logs an invariant error —
  it is unreachable because the notify-only `route_htlcs` stream never yields (spec 03);
  `is_lnv1_invoice` returns its actual `Option<Spanned<ClientHandleArc>>` — always `None` (no
  LNv1 module attached); `relay_lnv1_swap` returns a typed unsupported `anyhow` error; `pay` and
  `min_contract_amount` delegate to the spec-03 adapter and the fee config (needed for the
  trustless send companion). Never `todo!()`.
- **`GatewayClientBuilder` is not reusable:** it takes the concrete `Arc<Gateway>`
  (`gateway/fedimint-gateway-server/src/client.rs:65-80`). This crate builds its own client init
  (mnemonic/`RootSecret` derivation, connectors, module registry) following that code as a
  template. The module set attaches gwv2 + mint + wallet (+ core); the LNv1 gateway client module
  is NOT attached (nothing here serves LNv1). Wallet is required for the MVP replenishment path:
  expose proposed local operator commands `deposit-address <federation-id>` and
  `deposit-status <federation-id> <operation-id>` over a permission-restricted local admin socket
  served by the daemon (no second process opens the live DB, and no public HTTP route). The first
  calls `WalletClientModule::safe_allocate_deposit_address(())`, returns address + operation id,
  and errors if the federation does not support safe deposits; no silent expert-only fallback.
  The second follows `subscribe_deposit(operation_id)` and reports recovery of spendable ecash,
  not just detection of the Bitcoin transaction. The operator funds the address from an external
  wallet; wallet/mint SMs persist and recover the deposit after restart. Balance notifications
  wake waiting funding workers. No phoenixd on-chain withdrawal API is assumed. Validate wallet
  module availability and safe-deposit support before serving a federation.
- **Funding-output composition:** the funding tx uses a **bare**
  `ClientOutput { output: LightningOutput::V0(LightningOutputV0::Incoming(contract)), .. }` via
  the public `make_client_outputs` — explicitly NOT the full `relay_direct_swap` pattern, whose
  `ClientOutputSM` installs the gwv2 `ReceiveStateMachine`; that SM's post-funding branch
  auto-refunds non-decrypting contracts (`gwv2-client/src/receive_sm.rs:234-286`) and would race
  `audit.rs`, which owns invalid-contract refunds here (§7.3.4).
- **Audit refund path:** `audit.rs` awaits decryption shares via the lnv2 module API and, for a
  non-decrypting contract, submits the refund input via the public
  `ClientModule::client_ctx.make_client_inputs` — the gwv2 crate's own federation API module is
  private (`mod api;`) and its refund is only reachable from inside an SM transition, so it is
  not a reusable surface.
- **Config surface (minimum schema):** bind address; backend `LightningMode` (spec 03);
  federation invite codes; per-federation `CustodialReceiveCapability` policy values;
  `RoutingInfo`'s **mandatory send fields** (`send_fee_minimum/default`,
  `expiration_delta_*` — non-optional in the wire struct, `gateway_api.rs:143-175`, so even a
  custodial-only `/routing_info` must return valid values); webhook public URL + secret (spec
  03); metrics bind; backend-wide `absorbed_loss_budget_msat` and optional inbound-headroom
  heuristic settings (design §8); local admin socket path for deposits and loss-budget reset.
  The crate adopts a `DatabaseVersion` + migration registry for its root
  prefixes from day one (model: `get_gatewayd_database_migrations`,
  `gateway-server-db/src/lib.rs:511-542`), so the 0x13–0x18 range is versioned like the rest of
  the gateway DB.

## 4. Database design

All per-federation authoritative custodial state lives **inside the per-federation client DB
prefix** (design §7.3: one physical DB, survival is one condition). Because that prefix hosts a
fedimint *client* database whose integrity check rejects unknown root prefixes below
`UserData = 0xb0` (`fedimint-client/src/db.rs:81,102-110`; the check runs under
`is_running_in_test_env`, `fedimint-client/src/client.rs:2505` — but the
`ExternalReservedStart = 0xb1` reservation applies regardless, and any integration test would
panic on a sub-0xb0 prefix), the custodial keyspace MUST be allocated in the external application
range: one dedicated application prefix byte `>= ExternalReservedStart (0xb1)` (constant
`CUSTODIAL_APP_DB_PREFIX`, exact byte chosen and documented at coding time), with the custodial
sub-prefixes below nested under it via `Database::with_prefix` — and, inside a joint dbtx, via
`dbtx.to_ref().with_prefix(...)` (`DatabaseTransaction::with_prefix` consumes `self`,
`fedimint-core/src/db/mod.rs:1619-1633`); every §4 atomic-commit row that mixes client-core keys
and custodial keys relies on that transaction-scoped form:

```rust
// db.rs — within the federation client prefix, under CUSTODIAL_APP_DB_PREFIX (>= 0xb1).
// Federation-scoped state only.
enum CustodialDbKeyPrefix {
    PendingCustodialReceive = 0x01, // ContractId → PendingCustodialReceive
    LiabilityRecord         = 0x02, // quote_id → CustodialReceiveLiability (§7.7)
    LedgerCursor            = 0x04, // () → LedgerCursor (this federation's observer watermark)
    ConsensusTimeObserver   = 0x05, // () → ObservedConsensusTime { per-peer votes, updated_at_session }
    IssuanceDisabled        = 0x06, // () → DisabledReason — FEDERATION-scoped triggers only:
                                    // funding-deadline slack breach (§8), per-federation
                                    // reconciliation stall
    ContractAudit           = 0x07, // ContractId → durable audit/refund progress (§7)
    InputRecovery           = 0x08, // rejected funding operation → module refund progress (§6)
}

// Root-level custodial prefixes. 0x13-0x15 are REBUILDABLE indexes (never authoritative,
// §7.3). 0x16-0x18 are AUTHORITATIVE backend-scoped state — the deliberate exception to
// the rebuildable-only root rule: their subjects (backend health, settlements matching no
// record in ANY federation, aggregate loss accounting) belong to no single federation prefix, and their
// loss is the same physical-DB-loss event that loses every prefix (§16).
enum CustodialRootDbKeyPrefix {
    QuoteIdIndex          = 0x13, // quote_id → FederationId
    InvoiceHashIndex      = 0x14, // backend_invoice_hash → CustodialPendingIndexEntry
    CorrelationIdIndex    = 0x15, // backend_correlation_id → FederationId
    BackendIssuanceHealth = 0x16, // () → set of DisabledReason, independently cleared; triggers:
                                  // duplicate externalId aliasing, retention-coverage failure, unmatched
                                  // settlement, persistence failure, absorbed-loss budget. One phoenixd serving
                                  // several federations is one blast radius: a backend known
                                  // to alias correlation ids must stop issuance for ALL
                                  // federations, not just the one that noticed (§7.3).
    UnmatchedSettlement   = 0x17, // backend_invoice_hash → UnmatchedSettlement (§7.3) — an
                                  // unmatched settlement matches no record in any federation,
                                  // so it cannot live in a federation prefix.
    BackendLossAccounting = 0x18, // per-receive charged loss + cumulative total, budget,
                                  // baseline and reset history; stop lives at 0x16 (§8)
}
// New issuance is allowed only when NEITHER the federation flag (0x06) NOR the backend
// flag (0x16) is set. 0x13-0x18 must be added to gateway-server-db's DbKeyPrefix enum
// space check; collision with future gatewayd prefixes is avoided by reserving the range
// in that enum's doc comment.
```

`PendingCustodialReceive` is the state-variant record from design §7.3 (draft fields, then
AwaitingPayment fields, then funding fields `prepared_operation_id` + `txid`). The exact prepared
tx bytes live in spec 01's `PreparedTransactionKey` in the **same federation client DB prefix**
and are written **in the same dbtx** as the `FundingPrepared` record update — the design-§7.3
companion-key form: same prefix, one commit, never a separate physical store or separate commit.
"Re-drive the exact stored tx" reads through `prepared_operation_id`.

```rust
enum CustodialReceiveStatus {
    InvoiceCreating, AwaitingPayment, SettledAwaitingLiquidity, FundingReserved,
    FundingPrepared, FundingSubmitted, Funded,
    // terminal / retained:
    InvoiceCreationExpired, InvoiceCreateInconclusive, InvoiceExpiredUnpaid,
    BackendInvoiceRejected, InvoiceExpiredUnreturned, UnresolvedLiability,
}
```

**Atomic commits (each = one dbtx; do not split):**

| Transition | Written together |
|---|---|
| reserve draft | record@`InvoiceCreating` (quote draft) + root indexes |
| lease acquire/renew | `backend_create_lease_until`, `backend_create_maybe_sent`, `backend_create_attempt` on the record |
| quote commit | record@`AwaitingPayment` (full bolt11 invoice, invoice hash, signed_quote — the stored invoice is what answers every later duplicate, §7.3) + `InvoiceHashIndex` + `CustodialPending` registry entry |
| settle confirm | record@`SettledAwaitingLiquidity` or `FundingReserved` (+ evidence fields) |
| prepare | record@`FundingPrepared` + spec-01 `PreparedTransactionKey` (inputs consumed) |
| submit | record@`FundingSubmitted` + spec-01 `submit_prepared_transaction_dbtx` (op-log + submission SMs) in one dbtx |
| funded | record@`Funded(outpoint)` + `ContractAudit@AwaitingShares` (insert-if-absent/verify identity); input reservation naturally spent |
| audit invalid | `ContractAudit@InvalidAwaitingRefund` + one open `InvalidContract` liability, even if refund preparation cannot yet succeed |
| audit refund prepare | `ContractAudit@RefundPrepared` + exact prepared refund (inputs reserved); prior open liability retained |
| audit refund submit | `ContractAudit@RefundSubmitted` + spec-01 submit-prepared op-log/SM writes |
| loss accounting | settlement/fee evidence + per-receive loss contribution + root cumulative adjustment and budget-stop latch |
| terminalize | record@terminal + (if applicable) `LiabilityRecord` in the same dbtx (§7.7) |

## 5. Request path (`create_custodial_bolt11_invoice`)

Ordered validation (each rejection is a §7.9 `Rejected{reason}`). **Existing-record handling
comes FIRST** — before any issuance/health gate — because a duplicate of a post-create record
with the same request fingerprint must never receive a strictly-pre-create reason (the client would
delete provisional state while a backend invoice exists, violating the §7.9 pre-create invariant; the parent requires a
persisted duplicate to get the stored invoice+quote back even while new issuance is disabled,
§7.3 — answered from the stored `backend_invoice` field, never a backend fetch):

1. compute `contract_id` + `request_fingerprint` (shared lnv2-common function, spec 02 — payload
   fields only, never current config); look up the stored record and, on a same-fingerprint
   match, answer from it — for **every** post-create state, not just `AwaitingPayment`:
   - `AwaitingPayment` → stored `Created{invoice, quote}` if the invoice is still safe to
     return, else `BackendInvoiceUnreturnable`;
   - `SettledAwaitingLiquidity` / `FundingReserved` / `FundingPrepared` / `FundingSubmitted` /
     `Funded` → stored `Created{invoice, quote}` unconditionally (the invoice is paid; the quote
     is the durable receipt the client needs, and invoice staleness is moot once settled);
   - `InvoiceCreating` with a live lease → `CreateInProgress`;
   - `InvoiceCreating` with an **expired lease** → run the §7.3 recovery ladder inline before
     answering: `get_invoices_by_external_id(draft.backend_correlation_id, include_unpaid)`;
     (a) invoice found → recovered-invoice validation; safe → complete `AwaitingPayment` and
     return stored `Created`, unsafe/stale → tombstone → `BackendInvoiceUnreturnable`;
     (b) not found and `backend_create_maybe_sent` → tombstone `InvoiceCreateInconclusive`,
     return `BackendInvoiceUnreturnable`;
     (c) not found, never maybe-sent, draft still fresh → this request acquires the lease and
     proceeds with creation (the normal create tail below);
     (d) not found, never maybe-sent, draft stale → tombstone `InvoiceCreationExpired`, return
     `DeadlineTooNear` (pre-create is provable: maybe-sent was never set);
   - retained maybe-create / tombstone states (`InvoiceCreateInconclusive`,
     `BackendInvoiceRejected`, `InvoiceExpiredUnreturned`, `InvoiceExpiredUnpaid`) →
     `BackendInvoiceUnreturnable`;
   - same-fingerprint `UnresolvedLiability` → stored `Created` if a signed quote exists, else
     `BackendInvoiceUnreturnable`;
   - different fingerprint (any state) → `DuplicateContractConflict` (validated against the
     *stored draft*, §7.3).
   No same-contract lookup result may fall through to the new-request gates below — that is what
   keeps the §7.9 pre-create invariant airtight for every record state.
2. issuance enabled for NEW requests? Mapping is reason-specific: feature/policy disabled →
   `CustodialReceiveDisabled`; backend cannot provide authenticated ledger confirmation or the
   declared retention-coverage gate fails (§7.2) → `BackendLedgerUnavailable`; internal
   persistence/abuse/health gates (§7.8) → `BackendInvoiceCreationUnavailable`
3. `quote_api_version` supported → `UnsupportedQuoteVersion`
4. `contract.verify()` fails → `InvalidContract`; `refund_pk != module key` → `WrongRefundKey`
   (validity REQUIRES the refund key to be the gateway module key, parent §7.3 /
   `gateway/fedimint-gateway-server/src/lib.rs:3066`)
5. amount granularity (§7.4) → `NonSatoshiAmount`
6. lower bound (saturation guard, §7.3) → `AmountTooSmall`; per-receive cap → `AmountTooLarge`
7. amount binding `commitment.amount == receive_fee.subtract_from(amount)` →
   `FeeOrAmountBindingMismatch`; the quoted `receive_fee` itself must be within
   `RECEIVE_FEE_LIMIT` **component-wise** (base AND parts_per_million, §7.4/spec 02 §2) — a
   config invariant asserted at startup and re-checked here, because a gateway must never sign
   terms a compliant client will reject
8. deadline rules §8 (lower bounds, observer freshness) → `DeadlineTooNear`; upper bounds → `DeadlineTooFar`
9. actual-obligation gate (`max_in_flight`, per federation) → `ActualLiabilityLimitExceeded`
10. custodial namespace: contract/payment-image not owned by another custodial record →
   `DuplicateContractConflict` (also for image-only collisions — the image is client-chosen, so
   this is attacker-reachable: alarm/metric, but NEVER an issuance halt, §7.3; halts are reserved
   for backend/operator-producible conditions)

`client_request_id` is recomputed server-side per design §7.3; `request_fingerprint` is the
shared payload-derived function (spec 02) — the fee/policy the gateway *would* select today never
enters it, so config changes cannot reclassify an identical retry.

Then: reserve draft → acquire lease + set maybe-sent → `create_plain_invoice` → validate returned
invoice against draft (amount, payee == our node key, expiry tolerance, description, hash,
granularity; failure ⇒ retained `BackendInvoiceRejected` tombstone with `fund_on_settlement`
policy, §7.3) → reserve `backend_invoice_hash` in registry (collision ⇒ tombstone + disable
issuance, §7.3) → sign quote → commit `AwaitingPayment` → return `Created`.

`backend_correlation_id` is the constant namespace prefix `"fmcr1-"` followed by 32 random bytes
hex (opaque, no federation/contract data). The prefix makes correlation-id-namespace membership
decidable on a shared backend (§7.3): the observer's `UnmatchedSettlement` branch applies only to
settlements whose `externalId` bears the prefix; everything else is other operator activity and
outside custodial reconciliation.

## 6. Settlement observation & funding

- **Observer loop** per federation: wake on authenticated hint or poll tick; pull ledger pages
  from `LedgerCursor` with overlap. On cursor loss or corruption, do **not** trust any time
  window: rebuild by point-looking-up every nonterminal record and every retained tombstone by
  `backend_correlation_id` / `backend_invoice_hash` (record-driven, §7.2), then re-seed the
  watermark from the newest confirmed settlement. For each settled invoice: match by correlation
  id then hash
  against (a) this federation's nonterminal records, (b) its retained tombstones (apply
  `fund_on_settlement` + deadline branch §7.3), (c) else — only for `externalId`s bearing the
  `fmcr1-` namespace prefix (§5) — resolve against **all** federations before declaring it
  unmatched: consult the root `CorrelationIdIndex` / `InvoiceHashIndex`, and on an index miss
  point-look-up every other federation's records (the root indexes are rebuildable, so a miss
  there is not proof of absence). A settlement belonging to another federation is left to that
  federation's observer, never marked unmatched. Only a prefixed settlement matching no record
  in ANY federation becomes `UnmatchedSettlement` at root 0x17 (record, alert, set the
  backend-scoped `BackendIssuanceHealth` flag) — unmatched is a backend-wide statement (§4), so
  a single-federation check may never make it. Non-prefixed settlements are other operator
  activity and are skipped without recording (§7.3).
  Advance a matched `AwaitingPayment` only after `get_settled_invoice_by_hash` /
  page-entry authenticated confirmation, capturing `received_msat`, `fees_msat`,
  `completed_at_ms` as evidence. Apply the direction-aware rule (design §7.3): first authenticate
  the binding to this invoice/contract; non-amount inconsistencies open `BackendMismatch`.
  For a valid binding, net credited amount at/above quoted face value always funds the original
  contract, records surplus, and alerts if gross. A net shortfall explained by authenticated
  backend skim still funds the full contract and records absorbed loss `F` (including abnormal
  skim, which alerts and contributes to the budget stop); a gross unexplained shortfall opens
  `BackendMismatch`. Never classify an otherwise valid overpayment as a liability instead of
  funding. Persist raw requested/net/fee evidence for every branch, including unreturned invoices.
- **Funding workers:** single worker per federation processing a queue ordered by
  minimum-funding-deadline-slack (§7.3). Per-`contract_id` serialization is guaranteed by
  worker-owns-record via the `FundingReserved` claim transition. Flow:
  `FundingReserved` → build `TransactionBuilder` with the incoming-contract output (pattern from
  `relay_direct_swap`) → spec-01 `prepare_transaction_dbtx` + record@`FundingPrepared` in one
  dbtx → `submit_prepared_transaction_dbtx` + record@`FundingSubmitted` in one dbtx → await
  operation outcome → `Funded(outpoint)` on acceptance. The funding **outpoint** is derived from
  the stored prepared tx, not from `OutPointRange` (which covers primary-module change outputs,
  spec 01 §3.4.7): `OutPoint { txid, out_idx }` where `out_idx` is the position of the
  `LightningOutputV0::Incoming(contract)` output in `transaction.outputs`; assert exactly one
  such output exists. Deterministic id: `OperationId::from_encodable(&contract)`
  (same derivation as gwv2, so a cross-path double-fund is blocked by `operation_exists` even in
  dual mode).
- **Startup reconciliation** (§10): re-drive by status exactly as the design table; the
  no-operation branch splits by state; only `FundingReserved` may prepare fresh; rejection ⇒
  `UnresolvedLiability` with reason `FundingRejected`. Its installed mint input SMs retain their
  existing automatic refund/reissue behavior (`fedimint-mint-client/src/input.rs`), potentially
  including per-note fallback. Persist `InputRecovery` pending/recovered/failed evidence with the
  rejected txid and refund operation/tx ids; observe module outputs to account actual recovered
  ecash/fees, and resume observation on startup. Module terminality alone is not proof that all
  refund output notes are spendable. Never manually re-credit or race those refunds, and never
  resolve receiver liability merely because inputs recover. Unsubmitted prepared transactions
  and `FundingTxInconclusive` retain reserved inputs until their exact transaction's outcome is
  established; no generic unprepare is in MVP. The rejected-funding prepared record can only be
  pruned once module input/output recovery is terminal with durable evidence.
- **Liquidity:** `SettledAwaitingLiquidity` when the gwv2 client's spendable ecash <
  `commitment.amount + fee headroom`; recheck on balance-change notifications; alert + optional
  deposit prompt using the local operator interface (§3.1); funding resumes on spendable ecash.

## 7. Consensus-time observer, audit, pruning

- **`consensus_time.rs`:** per federation, stream signed session outcomes from the last processed
  session index; extract lnv2 `UnixTimeVote` items per peer; store latest vote per peer +
  last-session index in `ConsensusTimeObserver`; compute observed time with the server's rule
  (sort desc, `times[threshold-1]`). Freshness = votes seen within
  `consensus_time_observation_max_age_secs` of wall clock **and** observer task alive; stale ⇒
  quote creation disabled (`DeadlineTooNear` per §7.9 mapping). Metric: observer age (§7.8).
- **`audit.rs`:** every Funded transition also installs `ContractAudit@AwaitingShares` in that
  dbtx; startup resumes every unfinished audit/refund, and a periodic scan retries stalled work.
  Task spawning is only a wake-up hint, never durability. After valid threshold shares arrive,
  successful decryption records `Claimable` without spending; verified decryption failure atomically
  records `InvalidAwaitingRefund` plus one `InvalidContract` liability. Thus a local preparation
  error or insufficient fee liquidity cannot suppress the liability. Build the refund input via
  `make_client_inputs` (§3.1), then atomically prepare its exact refund tx with spec 01 and advance
  to `RefundPrepared`; transient preparation failures retain `InvalidAwaitingRefund` and retry. Use deterministic
  operation id `OperationId::from_encodable(&("custodial-audit-refund", outpoint))`; liability
  inserts keyed by quote id are insert-if-absent/verify-equal. Submit-prepared + `RefundSubmitted`
  commit together; restart resumes the exact transaction, never a second refund. Await acceptance
  and mint-output recovery before `Refunded`, with recovered amount/outcome evidence. Rejection
  alerts and retains an open liability; refund failure is not receipt of ecash. Timeouts or invalid/
  unavailable shares keep `AwaitingShares` and alert/retry, never classify the contract as invalid.
  Receive status stays `Funded`; audit progress is a separate durable record and never blocks
  reporting accepted funding. Alternate payout waits for terminal refund evidence (§7.7).
- **`prune.rs`:** a retained terminal record is prunable only when funding deadline passed in
  *observed consensus time* AND ledger/finality window closed (§7.3); pruning removes root
  indexes + registry hash reservation in the same dbtx. `UnresolvedLiability` and unresolved
  `InvoiceCreateInconclusive`: never auto-pruned. No receive, audit, prepared transaction, or
  recovery record is prunable with unfinished audit/input/output recovery or an open liability.
  Preserve compact loss contribution evidence after ordinary receive pruning so accounting and
  dedup survive (§8).

## 8. API surface, metrics, health

- Routes: `POST /routing_info` with a JSON `FederationId` body — matching the existing lnv2
  client connection and gatewayd route (`gateway_api.rs:63`,
  `gateway/fedimint-gateway-server/src/rpc_server.rs:253`), so spec-05 selection reuses the
  existing `/routing_info` client path unchanged (advertises `ReceiveCapabilities` with
  `custodial: Some(...)`, `trustless: None`) — `POST /create_custodial_bolt11_invoice`, and
  `POST /phoenixd_webhook` when webhooks are configured (raw body + signature forwarded to the
  adapter's `verify_and_parse_webhook`, spec 03 §3.4; not mounted when the secret is absent).
  The binary MUST mount `POST /send_payment` backed by the gwv2 send
  SM; the `IGatewayClientV2::is_direct_swap` impl (§3.1) consults `registry.rs` first and labels
  custodial self-pay cancellations (§7.6) — outcome is the forfeit signature either way.
- Reject `POST /create_bolt11_invoice` with a typed "custodial-only gateway" error (§7.1).
- Metrics: the exact §7.8 gauge/histogram set, recomputed from durable state on startup;
  low-cardinality labels only. Health gates that disable new issuance, split by scope (§4):
  **backend-scoped** (root `BackendIssuanceHealth` flag — halts all federations): persistence
  failure, retention-coverage gate, duplicate-externalId aliasing, unmatched settlement;
  **federation-scoped** (prefix `IssuanceDisabled` flag): funding-deadline slack approaching the
  safety margin on any settled-unfunded record (§8 — a critical operational fault, not just a
  metric), per-federation reconciliation stall. The optional §8 inbound-headroom
  policy is an admission heuristic only, never a no-purchase guarantee. Required backend loss
  accounting lives at root 0x18 (design §8): per-receive `F`, cumulative total, budget baseline,
  reset history, plus the latched backend stop at 0x16. Settlement and fee updates atomically adjust that
  receive's existing contribution by delta, not add it again; reserve conservative module-fee
  estimates until actual fees/output recovery are known. Root loss rows survive record pruning.
  Recompute/verify totals and preserve the stop on startup. Compare `max(0, total - baseline)`
  against budget, including at startup/config changes. At the budget threshold, stop new
  issuance on every federation with `BackendInvoiceCreationUnavailable`; keep existing invoices
  and funding/audits running. A local authenticated admin command records a reason/timestamp and
  new baseline/budget, then clears only the loss stop (and only if the new budget is positive). No automatic reset. Expose cumulative loss,
  budget remainder and unpaid exposure. Several outstanding invoices may settle after the stop,
  so it cannot bound total loss or prevent liquidity purchases (design §8).

## 9. Implementation order within this phase

1. db.rs + record/status types + atomic-commit helpers (tested with crash hooks first, §15)
2. receive.rs happy path + validation order + lease (FakeNotifyOnlyBackend)
3. observer.rs + funding.rs + startup reconciliation
4. consensus_time.rs, audit.rs, prune.rs, metrics.rs
5. bin wiring + routing_info + config + devimint hook

## 10. Test plan

The §15 matrix rows owned by this spec (duplicate-funding across restart, FundingPrepared
re-drive, lease/inconclusive-create, tombstone fund_on_settlement incl. after-deadline branch,
namespace collisions, unmatched settlement, metrics-from-DB, gauge recompute, liquidity wait) —
enumerated concretely in 07-test-harness.md with crash-point IDs.

## 11. Acceptance criteria

- [ ] Every atomic-commit row in §4 is a single dbtx (asserted by crash-hook tests).
- [ ] No code path creates a second backend invoice for a contract (test-enforced).
- [ ] No code path submits a funding tx except through spec-01 submit (grep-able: the crate never
      calls `finalize_and_submit_transaction` for funding).
- [ ] Startup with a populated DB reaches a fixpoint with no duplicate side effects (idempotent
      reconciliation test).
- [ ] Binary refuses legacy-registration config; `/routing_info` never advertises trustless
      receive. Mandatory `/send_payment` success/failure/restart paths pass; no receive-only MVP.
- [ ] Wallet-backed operator deposit survives restart and wakes waiting funding after ecash recovery.
- [ ] Loss-budget accounting is deduplicated, durable and backend-scoped; reset preserves other stops.

## 12. Open questions (non-blocking)

- Session-outcome streaming API choice for the observer (reuse client recovery's session
  iterator vs a thin new helper in `fedimint-client`); decide at coding time, no protocol impact.
