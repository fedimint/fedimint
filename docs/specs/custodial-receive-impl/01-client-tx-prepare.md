# Impl Spec 01: Client-Core Transaction Prepare/Submit Split

> Parent: design §7.3 ("Fund via a new client-core prepare-then-submit API"), §7.5, §10, §14.10.
> Crates: `fedimint-client`, `fedimint-client-module`. Highest-risk phase; gates phase 4.

## 1. Scope & non-goals

**In scope:** a generic `fedimint-client` API that (a) finalizes a transaction and durably locks
its inputs *without* creating an operation-log entry or submission state machine, and (b) later
installs and broadcasts that exact stored transaction idempotently. This is the mechanism behind
`FundingPrepared` / `FundingSubmitted` in the custodial gateway (design §7.3).

**Non-goals:** a generic "unprepare" that re-credits consumed inputs (module-specific; the
custodial gateway never needs it — inputs quarantine on inconclusive outcomes, §7.7); changes to
transaction wire format or submission consensus semantics; RBF/replacement of prepared txs.

## 2. Grounding in current code (verified)

- `Client::finalize_and_submit_transaction` (`fedimint-client/src/client.rs:907`) wraps
  `finalize_and_submit_transaction_dbtx` (`:955`) in `db.autocommit`. The dbtx variant:
  - bails if `operation_exists_dbtx(dbtx, operation_id)` (`:968`) — the idempotency gate;
  - calls the **private** `finalize_transaction` (`:657`), which runs module funding hooks
    (adding inputs/outputs, e.g. consuming mint notes inside the dbtx) and returns
    `FinalizedTransaction { transaction, states, change_range, fees }`;
  - enforces `Transaction::MAX_TX_SIZE`;
  - pushes a `TxSubmissionStatesSM { state: TxSubmissionStates::Created(transaction) }` as a
    `DynState` under `TRANSACTION_SUBMISSION_MODULE_INSTANCE` and calls
    `executor.add_state_machines_dbtx(dbtx, states)`;
  - writes `TransactionFeesKey(txid)`, logs `TxCreatedEvent`, and separately writes the
    operation-log entry (`operation_log().add_operation_log_entry_dbtx`, `:975-983`).
- `TxSubmissionStates::Created` is documented as "potentially already been submitted"
  (`fedimint-client-module/src/transaction/sm.rs:55-58`) — broadcast happens from the state
  machine, not inline, and resubmission of an identical tx is consensus-idempotent on its inputs.
- Input "locking" is a side effect of the module funding hooks inside `finalize_transaction`'s
  dbtx: e.g. the mint module deletes selected notes from its available-notes keyspace in that
  dbtx. Committing the dbtx **is** the durable reservation. The module input state machines that
  would handle refund-on-rejection live in `FinalizedTransaction.states` and are only installed
  when we add state machines.
- `DynState` is `Encodable`/`Decodable` via the client's module decoder registry (active/inactive
  state tables already persist it), so a prepared record containing `Vec<DynState>` is persistable.

## 3. Design

### 3.1 New types (`fedimint-client-module` or `fedimint-client`)

```rust
/// A finalized, input-locked transaction that has NOT yet been installed as an
/// operation + submission state machine. Persisted by prepare, consumed by submit.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PreparedTransaction {
    pub operation_id: OperationId,
    pub transaction: Transaction,
    /// Module state machines (e.g. mint input SMs) to install at submit time.
    pub states: Vec<DynState>,
    /// Encodable index range (NOT std::ops::Range): the same `IdxRange` used by
    /// `OutPointRange` (`fedimint-core/src/lib.rs:400`); `finalize_transaction`'s
    /// `Range<u64>` is converted at construction, mirroring `client.rs:1054`.
    pub change_range: IdxRange,
    pub fees: Amounts,
    pub txid: TransactionId,
}
```

### 3.2 New client DB key (`fedimint-client/src/db.rs`)

```rust
// New variant in fedimint-client's DbKeyPrefix enum (pick the next free discriminant;
// verify against the enum at implementation time — do NOT reuse a retired one).
PreparedTransaction = <next_free>,

#[derive(Debug, Encodable, Decodable)]
pub struct PreparedTransactionKey(pub OperationId);
// value: PreparedTransaction
```

Adding a key prefix requires no migration (no existing data changes shape). Decoding
`Vec<DynState>` requires the module decoder registry: the value type must be read through the
client's usual decoding context (same mechanism as active-state tables), not raw serde.

### 3.3 New API on `Client`

```rust
/// Finalize a transaction and durably lock its inputs WITHOUT creating an
/// operation-log entry or submission state machine. Idempotent per operation_id:
/// if a PreparedTransaction already exists for this id, returns the stored one
/// and does NOT rebuild (rebuilding would double-lock fresh inputs).
/// Fails if an operation with this id already exists (already submitted).
pub async fn prepare_transaction_dbtx(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    operation_id: OperationId,
    tx_builder: TransactionBuilder,
) -> anyhow::Result<PreparedTransaction>;

/// Autocommit wrapper of the above.
pub async fn prepare_transaction(
    &self,
    operation_id: OperationId,
    tx_builder: TransactionBuilder,
) -> anyhow::Result<PreparedTransaction>;

/// Install the stored prepared transaction as an operation: writes the operation
/// log entry, installs module states + TxSubmissionStates::Created(tx), fees, and
/// TxCreatedEvent in ONE dbtx, then lets the executor broadcast. Refuses to build
/// or accept a fresh transaction: if no PreparedTransaction is stored for this id
/// and no operation exists, this is an error (never silently rebuild, §10).
/// Idempotent: if the operation already exists, returns Ok with the stored
/// outpoint range (derived from the retained PreparedTransaction record).
pub async fn submit_prepared_transaction<F, M>(
    &self,
    operation_id: OperationId,
    operation_type: &str,
    operation_meta_gen: F,
) -> anyhow::Result<OutPointRange>
where
    F: Fn(OutPointRange) -> M + Clone + MaybeSend + MaybeSync,
    M: serde::Serialize + MaybeSend;

/// Dbtx variant (mirrors finalize_and_submit_transaction_dbtx, client.rs:956).
/// Callers that must advance their own durable record atomically with the
/// submit (e.g. the custodial gateway's FundingSubmitted transition, design
/// §7.3) join this dbtx.
pub async fn submit_prepared_transaction_dbtx<F, M>(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    operation_id: OperationId,
    operation_type: &str,
    operation_meta_gen: F,
) -> anyhow::Result<OutPointRange>
where
    F: FnOnce(OutPointRange) -> M + MaybeSend,
    M: serde::Serialize + MaybeSend;
```

Also expose both on `DynGlobalClientContext` / the `ClientHandle` surface used by gateway crates,
mirroring how `finalize_and_submit_transaction` is exposed (`client.rs:2562`).

### 3.4 Semantics and invariants

1. **Prepare is the reservation.** `prepare_transaction_dbtx` calls the existing private
   `finalize_transaction` and persists `PreparedTransactionKey(operation_id)` in the same dbtx
   that consumed the inputs. One commit = inputs consumed + exact tx recorded (design §7.3's
   "Prepare commits `FundingPrepared(prepared_tx)` together with the ecash-input reservation,
   atomically"). The caller embeds its own record (e.g. `PendingCustodialReceive`) in the same
   dbtx via the dbtx variant.
2. **Prepare idempotency.** If `PreparedTransactionKey(operation_id)` exists, return it unchanged.
   If `operation_exists` for the id, bail with a typed error (`AlreadySubmitted`) — the caller
   should be in submit/await, not prepare.
3. **Submit installs, never builds.** `submit_prepared_transaction` autocommits: if
   `operation_exists` → return stored range (idempotent re-drive); else load
   `PreparedTransactionKey` → if absent, error `NothingPrepared` (the §10 rule: a missing prepared
   tx never builds a fresh replacement — that decision belongs to the caller's `FundingReserved`
   state, which uses the normal prepare→submit path); else perform exactly the tail of
   `finalize_and_submit_transaction_inner` from the point after finalization: size check already
   done at prepare; push submission SM, `add_state_machines_dbtx`, `TransactionFeesKey`,
   `TxCreatedEvent`, plus `add_operation_log_entry_dbtx`.
4. **The record is retained after submit.** Do not delete `PreparedTransactionKey` on submit:
   re-drive after an operation-log divergence needs the exact bytes (§10 "re-drives the exact
   stored `prepared_tx`"). Deletion is the caller's choice once the operation reaches a final
   state (`Accepted`/`Rejected`); provide
   `remove_prepared_transaction_dbtx(dbtx, operation_id)` for that.
5. **Concurrent submit safety.** Both idempotency checks (`operation_exists`, key load) happen
   inside the same autocommit dbtx, so two concurrent `submit_prepared_transaction` calls cannot
   both install (same guarantee as today's `finalize_and_submit_transaction_dbtx:968`).
6. **Reserved inputs are invisible to other operations by construction** — they were consumed
   from module keyspaces at prepare-commit. No additional lock table is needed. The §15 test
   "reserved ecash inputs are not consumed by a concurrent operation" verifies this property.
7. **Output outpoints are caller-derivable.** `OutPointRange` covers primary-module change
   outputs (as today, `client.rs:704,1054`). Callers needing a *specific* output's outpoint
   (e.g. the custodial funding contract output) derive it from the stored bytes:
   `OutPoint { txid, out_idx }` where `out_idx` is the position of their output in
   `transaction.outputs`. This is stable because the stored tx is final.
8. **`operation_exists` semantics.** The idempotency gate is implemented over the operation's
   active/inactive *state-machine* entries (`client.rs:1071-1090`), not the operation-log table.
   Divergence scenarios and tests must manipulate state entries, not (only) op-log entries.

### 3.5 Crash matrix

| Crash point | Durable state | Recovery |
|---|---|---|
| Before prepare commit | nothing | caller retries prepare (fresh inputs) |
| After prepare commit, before submit | inputs consumed, `PreparedTransactionKey`, caller record | caller calls `submit_prepared_transaction` (installs + broadcasts exact tx) |
| After submit commit, before broadcast | operation + `Created(tx)` SM exist | executor resumes the submission SM; no API call needed; `submit_prepared_transaction` is a safe no-op |
| Operation log diverged but key survives | `PreparedTransactionKey` present, `operation_exists` false | `submit_prepared_transaction` re-installs the exact tx (consensus-idempotent on pinned inputs) |

## 4. Edge cases

- **Size limit:** enforced at prepare (same `MAX_TX_SIZE` check); submit trusts the stored tx.
- **Module instance mismatch after restart:** decoding `states` requires the same module
  registry; a client configured without a module that has stored states must surface a decode
  error, not skip (matches existing active-state behavior).
- **No expiry:** prepared transactions do not expire client-side. Callers own lifecycle (the
  custodial gateway's deadline machinery, §8). Document this on the API.
- **Meta/fee events:** `TransactionFeesKey` and `TxCreatedEvent` fire at submit (observable
  behavior parity with today's single-shot path).

## 5. Test plan (phase-7 hooks)

Unit/integration in `fedimint-client` tests plus dedicated §15 cases:

1. prepare → crash → restart → submit drives **byte-identical** tx (compare consensus encoding).
2. prepare → submit → operation's state-machine entries deleted (simulated divergence;
   `operation_exists` is state-based per §3.4.8, so deleting only the op-log entry does not
   flip it) → submit again re-installs the same tx; federation accepts at most one funding
   (double-spend of pinned inputs rejected).
3. two concurrent submits: exactly one installs.
4. prepare idempotency: second prepare returns stored record; no additional inputs consumed
   (assert module balance).
5. concurrent unrelated operation cannot spend reserved inputs.
6. submit with neither operation nor prepared record errors `NothingPrepared`.
7. wasm build passes (API compiles for wasm even if unused there).

## 6. Acceptance criteria

- [ ] All §3.4 invariants hold under the §5 tests.
- [ ] No behavior change to existing `finalize_and_submit_transaction` callers.
- [ ] `PreparedTransaction` round-trips encode/decode through the client decoder registry.
- [ ] Public docs on the API state the no-rebuild and retention rules verbatim.

## 7. Open questions (non-blocking)

- Whether `PreparedTransaction` lives in `fedimint-client-module` (types) with storage in
  `fedimint-client`, or wholly in `fedimint-client`. Default: types in `fedimint-client-module`
  next to `TransactionBuilder`, storage/API in `fedimint-client`.
- Whether to add an optional `abandon_prepared_transaction` in a later phase for non-custodial
  users (requires per-module input re-credit hooks; explicitly out of MVP).
