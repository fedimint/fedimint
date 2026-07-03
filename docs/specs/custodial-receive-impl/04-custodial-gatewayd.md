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
actions beyond pegin prompting, rich liability tooling (§14).

## 2. Grounding in current code (verified)

- Gateway physical DB with per-federation *logical client prefixes*:
  `GatewayDbExt::get_client_database(federation_id)` prefixes `DbKeyPrefix::ClientDatabase=0x10`
  (`gateway/fedimint-gateway-server-db/src/lib.rs:30-40`). Root prefixes 0x04–0x12 are taken.
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
  src/api.rs            // axum routes: /routing_info, /create_custodial_bolt11_invoice, (/send_payment)
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

The binary joins federations exactly like `gatewayd` does (federation client per invite, gwv2
client module for ecash float + funding), but never registers on `GATEWAYS_ENDPOINT` and refuses
a config that asks it to (§7.1 mode 1; assert at startup).

## 4. Database design

All authoritative custodial state lives **inside the per-federation client DB prefix** (design
§7.3: one physical DB, survival is one condition). Because that prefix hosts a fedimint *client*
database whose integrity check rejects unknown root prefixes below `UserData = 0xb0`
(`fedimint-client/src/db.rs:81,102-110`), the custodial keyspace MUST be allocated in the
external application range: one dedicated application prefix byte `>= ExternalReservedStart
(0xb1)` (constant `CUSTODIAL_APP_DB_PREFIX`, exact byte chosen and documented at coding time),
with the custodial sub-prefixes below nested under it via `Database::with_prefix`:

```rust
// db.rs — within the federation client prefix, under CUSTODIAL_APP_DB_PREFIX (>= 0xb1)
enum CustodialDbKeyPrefix {
    PendingCustodialReceive = 0x01, // ContractId → PendingCustodialReceive
    LiabilityRecord         = 0x02, // quote_id → CustodialReceiveLiability (§7.7)
    UnmatchedSettlement     = 0x03, // backend_invoice_hash → UnmatchedSettlement (§7.3)
    LedgerCursor            = 0x04, // () → LedgerCursor
    ConsensusTimeObserver   = 0x05, // () → ObservedConsensusTime { per-peer votes, updated_at_session }
    IssuanceDisabled        = 0x06, // () → DisabledReason (BackendDuplicateExternalId, coverage gate, …)
}

// Root-level, REBUILDABLE indexes only (never authoritative, §7.3):
enum CustodialRootDbKeyPrefix {
    QuoteIdIndex        = 0x13, // quote_id → FederationId
    InvoiceHashIndex    = 0x14, // backend_invoice_hash → CustodialPendingIndexEntry
    CorrelationIdIndex  = 0x15, // backend_correlation_id → FederationId
}
// 0x13-0x15 must be added to gateway-server-db's DbKeyPrefix enum space check
// (0x04..0x12 taken today); collision with future gatewayd prefixes is avoided by
// reserving the range in that enum's doc comment.
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
| quote commit | record@`AwaitingPayment` (invoice hash, signed_quote) + `InvoiceHashIndex` + `CustodialPending` registry entry |
| settle confirm | record@`SettledAwaitingLiquidity` or `FundingReserved` (+ evidence fields) |
| prepare | record@`FundingPrepared` + spec-01 `PreparedTransactionKey` (inputs consumed) |
| submit | record@`FundingSubmitted` + spec-01 `submit_prepared_transaction_dbtx` (op-log + submission SMs) in one dbtx |
| funded | record@`Funded(outpoint)`; input reservation naturally spent |
| terminalize | record@terminal + (if applicable) `LiabilityRecord` in the same dbtx (§7.7) |

## 5. Request path (`create_custodial_bolt11_invoice`)

Ordered validation (each rejection is a §7.9 `Rejected{reason}`). **Existing-record handling
comes FIRST** — before any issuance/health gate — because a duplicate of a post-create record
must never receive a strictly-pre-create reason (the client would delete provisional state while
a backend invoice exists, violating the §7.9 pre-create invariant; the parent explicitly requires
a persisted duplicate to get the stored invoice+quote back even while new issuance is disabled):

1. compute `contract_id` + `request_fingerprint` (shared lnv2-common function, spec 02 — payload
   fields only, never current config); look up the stored record and, on a same-fingerprint
   match, answer from it — for **every** post-create state, not just `AwaitingPayment`:
   - `AwaitingPayment` → stored `Created{invoice, quote}` if the invoice is still safe to
     return, else `BackendInvoiceUnreturnable`;
   - `SettledAwaitingLiquidity` / `FundingReserved` / `FundingPrepared` / `FundingSubmitted` /
     `Funded` → stored `Created{invoice, quote}` unconditionally (the invoice is paid; the quote
     is the durable receipt the client needs, and invoice staleness is moot once settled);
   - live lease (`InvoiceCreating`) → `CreateInProgress`;
   - retained maybe-create / tombstone states (`InvoiceCreateInconclusive`,
     `BackendInvoiceRejected`, `InvoiceExpiredUnreturned`, `InvoiceExpiredUnpaid`) →
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
4. `contract.verify()` → `InvalidContract`; `refund_pk == module key` → `WrongRefundKey`
5. amount granularity (§7.4) → `NonSatoshiAmount`
6. lower bound (saturation guard, §7.3) → `AmountTooSmall`; per-receive cap → `AmountTooLarge`
7. amount binding `commitment.amount == receive_fee.subtract_from(amount)` → `FeeOrAmountBindingMismatch`
8. deadline rules §8 (lower bounds, observer freshness) → `DeadlineTooNear`; upper bounds → `DeadlineTooFar`
9. actual-obligation gate (`max_in_flight`, per federation) → `ActualLiabilityLimitExceeded`
10. cross-path namespace: contract/payment-image not owned elsewhere → `DuplicateContractConflict` / invariant alarm (image collision, §7.3)

`client_request_id` is recomputed server-side per design §7.3; `request_fingerprint` is the
shared payload-derived function (spec 02) — the fee/policy the gateway *would* select today never
enters it, so config changes cannot reclassify an identical retry.

Then: reserve draft → acquire lease + set maybe-sent → `create_plain_invoice` → validate returned
invoice against draft (amount, payee == our node key, expiry tolerance, description, hash,
granularity; failure ⇒ retained `BackendInvoiceRejected` tombstone with `fund_on_settlement`
policy, §7.3) → reserve `backend_invoice_hash` in registry (collision ⇒ tombstone + disable
issuance, §7.3) → sign quote → commit `AwaitingPayment` → return `Created`.

`backend_correlation_id` is 32 random bytes hex (opaque, no federation/contract data).

## 6. Settlement observation & funding

- **Observer loop** per federation: wake on authenticated hint or poll tick; pull ledger pages
  from `LedgerCursor` with overlap. On cursor loss or corruption, do **not** trust any time
  window: rebuild by point-looking-up every nonterminal record and every retained tombstone by
  `backend_correlation_id` / `backend_invoice_hash` (record-driven, §7.2), then re-seed the
  watermark from the newest confirmed settlement. For each settled invoice: match by correlation
  id then hash
  against (a) nonterminal records, (b) retained tombstones (apply `fund_on_settlement` +
  deadline branch §7.3), (c) else `UnmatchedSettlement` (record, alert, disable issuance).
  Advance a matched `AwaitingPayment` only after `get_settled_invoice_by_hash` /
  page-entry authenticated confirmation, capturing `received_msat`, `fees_msat`,
  `completed_at_ms` as evidence. Skim within tolerance funds fully and records loss `F`; gross
  mismatch ⇒ `BackendMismatch` liability (§8, §7.7).
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
  `UnresolvedLiability` (+ quarantined inputs for `FundingTxInconclusive`).
- **Liquidity:** `SettledAwaitingLiquidity` when the gwv2 client's spendable ecash <
  `commitment.amount + fee headroom`; recheck on balance-change notifications; alert + optional
  pegin prompt (operator CLI hook, not automated).

## 7. Consensus-time observer, audit, pruning

- **`consensus_time.rs`:** per federation, stream signed session outcomes from the last processed
  session index; extract lnv2 `UnixTimeVote` items per peer; store latest vote per peer +
  last-session index in `ConsensusTimeObserver`; compute observed time with the server's rule
  (sort desc, `times[threshold-1]`). Freshness = votes seen within
  `consensus_time_observation_max_age_secs` of wall clock **and** observer task alive; stale ⇒
  quote creation disabled (`DeadlineTooNear` per §7.9 mapping). Metric: observer age (§7.8).
- **`audit.rs`:** after `Funded`, spawn non-blocking audit per contract: await the federation's
  decryption-share availability (same module API the gwv2 receive SM uses); if contract decrypts
  → mark `Claimable`, done; if not → submit refund spend to `refund_pk` via the gwv2 client
  input path, record `InvalidContractRefunded`, open `InvalidContract` liability (§7.3.4, §7.7).
  Audit never delays marking `Funded`. Wait budget: configurable, default generous (§14.9).
- **`prune.rs`:** a retained terminal record is prunable only when funding deadline passed in
  *observed consensus time* AND ledger/finality window closed (§7.3); pruning removes root
  indexes + registry hash reservation in the same dbtx. `UnresolvedLiability` and unresolved
  `InvoiceCreateInconclusive`: never auto-pruned.

## 8. API surface, metrics, health

- Routes: `POST /routing_info` with a JSON `FederationId` body — matching the existing lnv2
  client connection and gatewayd route (`gateway_api.rs:63`,
  `gateway/fedimint-gateway-server/src/rpc_server.rs:253`), so spec-05 selection reuses the
  existing `/routing_info` client path unchanged (advertises `ReceiveCapabilities` with
  `custodial: Some(...)`, `trustless: None`) — and `POST /create_custodial_bolt11_invoice`. If the
  binary also serves trustless **send**, mount `POST /send_payment` backed by the gwv2 send SM;
  its `is_direct_swap`-equivalent must consult `registry.rs` first and label custodial self-pay
  cancellations (§7.6) — outcome is the forfeit signature either way.
- Reject `POST /create_bolt11_invoice` with a typed "custodial-only gateway" error (§7.1).
- Metrics: the exact §7.8 gauge/histogram set, recomputed from durable state on startup;
  low-cardinality labels only. Health gates that disable new issuance: persistence failure,
  reconciliation stall, retention-coverage gate, duplicate-externalId, unmatched settlement.

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
      receive.

## 12. Open questions (non-blocking)

- Session-outcome streaming API choice for the observer (reuse client recovery's session
  iterator vs a thin new helper in `fedimint-client`); decide at coding time, no protocol impact.
- Whether `/send_payment` ships in the MVP binary or a fast follow (§7.1 mode-1 note); default:
  ship it, it reuses gwv2 send unchanged.
