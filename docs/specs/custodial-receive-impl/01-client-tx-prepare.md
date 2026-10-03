# Impl Spec 01: Client-Core Transaction Prepare/Submit Split

> Parent: design §7.3 ("Fund via a new client-core prepare-then-submit API"), §7.5, §10, §14.10.
> Crates: `fedimint-client`, `fedimint-client-module`, `modules/fedimint-mint-client`
> (recovery evidence API). Highest-risk phase; gates phase 4.

## 1. Scope & non-goals

**In scope:** a generic `fedimint-client` API that (a) finalizes a transaction and durably locks
its inputs *without* creating an operation-log entry or submission state machine, and (b) later
installs and broadcasts that exact stored transaction idempotently. This is the mechanism behind
`FundingPrepared` / `FundingSubmitted` in the custodial gateway (design §7.3). Also in scope:
the mint-owned input-recovery evidence API (§3.6) needed to observe rejected funding without
exposing private mint state or taking ownership of its existing refund execution.

**Non-goals:** a generic "unprepare" that re-credits consumed inputs (module-specific, deferred in
parent §14; unsubmitted or inconclusive prepared inputs remain reserved. Definitively rejected
submitted transactions use the existing module input state machines to refund/reissue inputs;
this does not discharge a custodial `FundingRejected` liability, parent §7.7); changes to
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
    /// Operation-log creation time, fixed at prepare, stored as unix **nanoseconds**
    /// and converted via `UNIX_EPOCH + Duration::from_nanos` to the `SystemTime` that
    /// `ChronologicalOperationLogKey.creation_time` actually is
    /// (`fedimint-client/src/db.rs:188`). Submit and every re-drive use THIS value
    /// for the op-log chronological index key (see §3.4.9), so all submit-tail
    /// writes are deterministic and idempotent across re-drives.
    pub oplog_creation_time_nanos: u64,
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
/// Idempotent: if the operation already exists, first verifies its submission
/// transaction identity against the retained prepared record; only then returns
/// Ok with that record's outpoint range. A mismatch is an invariant error.
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

Expose both on `Client` (reachable through `ClientHandleArc` deref, which is what gateway crates
hold) and mirror them on `ClientContextIface` (`client.rs:2562` — the module-facing surface where
`finalize_and_submit_transaction` lives today). They do NOT belong on `DynGlobalClientContext`:
that is the state-machine *transition* context, whose methods take a
`ClientSMDatabaseTransaction`, and nothing here prepares or submits from inside an SM transition.

### 3.4 Semantics and invariants

1. **Prepare is the reservation.** `prepare_transaction_dbtx` calls the existing private
   `finalize_transaction` and persists `PreparedTransactionKey(operation_id)` in the same dbtx
   that consumed the inputs. One commit = inputs consumed + exact tx recorded (design §7.3's
   "Prepare commits `FundingPrepared(prepared_tx)` together with the ecash-input reservation,
   atomically"). The caller embeds its own record (e.g. `PendingCustodialReceive`) in the same
   dbtx via the dbtx variant.
2. **Operation-id reservation across both APIs.** Prepare checks `operation_exists` first and
   errors `AlreadySubmitted` if true; otherwise an existing `PreparedTransactionKey(operation_id)`
   is returned unchanged without building. The prepared key reserves the id as well as inputs.
   Both `finalize_and_submit_transaction` variants MUST check for that key in their existing
   autocommit/dbtx, before finalization, and return typed `OperationIdReserved` without consuming
   inputs. This check and prepare's operation/key checks participate in the same database conflict
   detection: concurrent legacy-submit and prepare cannot both commit for the same id. Existing
   callers using ids without a prepared reservation retain their behavior. A prepared caller
   must use submit-prepared, even if its legacy builder would produce the same transaction.
3. **Submit installs, never builds.** `submit_prepared_transaction` autocommits: if
   `operation_exists` → verify transaction identity (§3.4.10), then return stored range; else load
   `PreparedTransactionKey` → if absent, error `NothingPrepared` (the §10 rule: a missing prepared
   tx never builds a fresh replacement — that decision belongs to the caller's `FundingReserved`
   state, which uses the normal prepare→submit path); else perform exactly the tail of
   `finalize_and_submit_transaction_inner` from the point after finalization: size check already
   done at prepare; push submission SM, install states (per-state, see §3.4.9),
   `TransactionFeesKey`, `TxCreatedEvent`, plus `add_operation_log_entry_dbtx`. The
   operation-exists idempotent branch derives its return range from the retained
   `PreparedTransaction` record; a caller that already pruned the record (§3.4.4 allows that only
   at a terminal operation state) MUST NOT call submit again — such a call returns a typed
   `PrunedAfterTerminal` error, never a range, and callers treat it as "already terminally
   handled".
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
9. **Re-drive tolerates partial survivors.** A divergence can lose state entries while
   `TransactionFeesKey`, the op-log entry, or event-log rows survive. The current submission tail
   uses `insert_new_entry`, which panics on overwrite (`fedimint-core/src/db/mod.rs:1124`,
   `client.rs:1048`, `oplog.rs:67`). `submit_prepared_transaction(_dbtx)` therefore MUST use
   insert-if-absent semantics for the fees key and op-log entry — verifying an existing value is
   equal to what it would write (mismatch ⇒ invariant error, never overwrite) — and re-installs
   state machines only when absent. It must not call `insert_new_entry` for these keys. The op
   log is TWO keys — `OperationLogKey` plus a chronological index keyed by creation time
   (`oplog.rs:67`, `fedimint-client/src/db.rs:187`) — and today's write stamps `now()`. Submit
   must instead pass the stored `oplog_creation_time` (fixed at prepare) through an idempotent
   op-log helper (`add_operation_log_entry_idempotent_dbtx(..., creation_time)`), so a re-drive
   writes byte-identical keys for both rows: if `OperationLogKey` exists, both writes are
   skipped after verify-equal; a fresh `now()` on re-drive would duplicate or orphan the
   chronological index row. The state-machine installer needs the same care: the existing
   `add_state_machines_dbtx` is all-or-error — it returns `StateAlreadyExists` if ANY state in
   the batch already exists (active or inactive) and also errors on already-terminal states
   (`fedimint-client/src/sm/executor.rs:232-266`) — so "install only when absent" requires a new
   in-crate helper that filters per state against the active/inactive key tables before adding,
   not a direct call to the existing installer.
10. **Partial intra-operation state survival is detected, not repaired.** `operation_exists`
   returns true if ANY active/inactive state remains for the operation (`client.rs:1081`), so a
   corruption that loses only the `TxSubmissionStatesSM` row while module input SMs survive
   would otherwise make submit treat the operation as existing and wait forever for a broadcast
   SM that is gone. Normal crashes cannot produce this (all states install in one dbtx), so it
   indicates DB corruption: when `submit_prepared_transaction(_dbtx)` takes the
   operation-exists branch, it MUST verify a `TxSubmissionStatesSM` exists (active or inactive)
   for the operation **and matches the prepared transaction**: `Created` must contain identical
   consensus-encoded transaction bytes and `Accepted`/`Rejected` must carry the prepared txid.
   Search the operation's submission states for **this prepared txid**, rather than choosing an
   arbitrary row: mint refund/reissue can legitimately add other submission transactions under
   the same operation id. Those extra transactions alone are not an identity mismatch, and they
   cannot substitute for the original transaction's identity evidence. Verify the stored txid
   against the prepared bytes too. An absent, conflicting, or unverifiable
   submission identity (including a legacy `NonRetryableError` without txid) returns a typed
   invariant error — the caller escalates (unresolved-liability path in the custodial gateway),
   never returns the prepared range as success, silently waits, or automatically reinstalls.

### 3.5 Crash matrix

| Crash point | Durable state | Recovery |
|---|---|---|
| Before prepare commit | nothing | caller retries prepare (fresh inputs) |
| After prepare commit, before submit | inputs consumed, `PreparedTransactionKey`, caller record | caller calls `submit_prepared_transaction` (installs + broadcasts exact tx) |
| After submit commit, before broadcast | operation + `Created(tx)` SM exist | executor resumes the submission SM; no API call needed; `submit_prepared_transaction` is a safe no-op |
| Operation log diverged but key survives | `PreparedTransactionKey` present, `operation_exists` false (state entries lost; fees/op-log rows may survive) | `submit_prepared_transaction` re-installs the exact tx with insert-if-absent semantics (§3.4.9; consensus-idempotent on pinned inputs) |

### 3.6 Mint-owned input-recovery evidence (phase 1)

`modules/fedimint-mint-client` owns these new APIs, types, and durable journal. Existing mint
input state/correlation fields are private (`input.rs:71-73`); OOB refund subscriptions do not
cover arbitrary rejected funding. The daemon must not decode those states or infer recovery
from a terminal input state. This is client-module work, with no mint consensus/API changes.

Proposed public methods on `MintClientModule` (Rust signatures, shared types omitted for brevity):

```rust
// root client dbtx; implementation scopes it to this mint instance internally.
// Called atomically with installation of the original submission and its input SMs.
pub async fn track_input_recovery_dbtx(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    operation_id: OperationId,
    original_transaction: &Transaction,
) -> anyhow::Result<()>;

pub async fn input_recovery(
    &self,
    operation_id: OperationId,
    original_txid: TransactionId,
) -> anyhow::Result<MintInputRecovery>;

// Immediately emits the current durable snapshot, then snapshots after every revision.
// Startup/reconnect uses the same method; correctness does not depend on receiving a wakeup.
pub async fn subscribe_input_recovery(
    &self,
    operation_id: OperationId,
    original_txid: TransactionId,
) -> anyhow::Result<BoxStream<'static, anyhow::Result<MintInputRecovery>>>;

pub struct MintInputRecovery {
    pub operation_id: OperationId,
    pub original_txid: TransactionId,
    pub input_indices: Vec<u64>, // all inputs owned by this mint instance in original tx
    pub revision: u64,
    pub outcome: MintRecoveryOutcome, // AwaitingOriginal | NotRequired (accepted)
                                    // | Recovering | Recovered | Failed | PartiallyRecovered
    pub refunds: Vec<MintRefundEvidence>,
    pub recovered_msat: Amount, // only notes actually inserted into spendable storage
}

pub struct MintRefundEvidence {
    pub txid: TransactionId,
    pub input_indices: Vec<u64>, // original-input lineage, including bundle→per-note fallback
    pub outcome: MintRefundTxOutcome, // Pending | Accepted | Rejected { reason }
    pub outputs: Vec<MintRecoveryOutput>,
}

pub struct MintRecoveryOutput {
    pub outpoint: OutPoint,
    pub amount_msat: Amount,
    pub outcome: MintRecoveryOutputOutcome, // Pending | Spendable | Failed { reason }
}
```

`track_input_recovery_dbtx` derives the txid and exact mint-input set from the transaction using
this module's decoder/instance id. It verifies correspondence to its installed input SMs in the
same dbtx, then inserts an `AwaitingOriginal` journal under `(operation_id, original_txid)`.
Repeat registration verifies the immutable identity/input set and leaves existing progress alone;
missing/mismatched SMs or inputs are errors. It creates no refund and changes no spend behavior.
The daemon calls it in the funding submit dbtx, before the executor can run. An untracked query
returns typed `RecoveryNotTracked`, never empty-success; phase 4 treats this as an invariant error.

Mint owns new non-colliding DB prefixes for the journal and its reverse transaction/output
indexes, with encode/decode and dump support. Its existing input SM transitions write journal
updates **in the same dbtx** as the state change and any `claim_inputs` call: record original
acceptance/rejection, each bundle/per-note refund txid, its original-input lineage, and the full
returned change-output range (currently reduced to txid in `input.rs`). The mint output creation
path records concrete output amounts; output SMs mark `Spendable` atomically with insertion of
those notes into the mint's spendable keyspace. Output failure and refund rejection preserve
reason/identity evidence. Reverse indexes propagate child updates to the original journal even
when original bundle input states have become inactive; note secrets never enter this API.

All writers increment the revision and recompute aggregate recovery from unique output identities,
never add the same recovered amount twice. `Recovered`, `Failed`, or `PartiallyRecovered` is
terminal only when all original input groups, their fallback branches, and resulting output SMs
are terminal; an input SM's per-note-fallback terminal state alone cannot complete the journal.
Amounts reflect notes obtained, not refund acceptance alone. `NotRequired` records original
acceptance with zero recovered amount. Refund execution/retries stay entirely in existing mint
SMs. The journal and reverse indexes survive restarts and remain retained for this MVP; no new
pruning API is introduced. Subscribers register for revision notifications before reading a
snapshot and re-read durable revisions after wake/reconnect, preventing missed-update races.

Phase 4 reads/subscribes to this API and stores only its returned evidence/revision in
`InputRecovery`. It never reads private input/output state or initiates a competing reissue.
Integration coverage in phase 7 must force bundle rejection and per-note fallback, restart across
refund creation/acceptance/output recovery, and assert that query/subscription agree on identities,
terminality, actual recovered amounts, and unchanged receiver debt. Include duplicate registration,
missing-journal error, and unrelated transactions sharing the operation id.

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
7. prepare T1 → legacy-submit a different T2 with the same id errors `OperationIdReserved`,
   consumes no additional inputs, and submit-prepared still broadcasts T1. Race both APIs: one
   reservation/submission wins and the loser consumes no inputs; legacy-submit first makes prepare
   fail `AlreadySubmitted`. Inject an existing submission for T2 alongside T1's prepared record:
   submit-prepared errors on identity mismatch in Created/Accepted/Rejected, never returns T1's
   outpoints. Also test the identity-less legacy error state.
8. wasm build passes (API compiles for wasm even if unused there).

## 6. Acceptance criteria

- [ ] All §3.4 invariants hold under the §5 tests.
- [ ] Existing `finalize_and_submit_transaction` behavior is preserved for unreserved ids;
      prepared ids are rejected atomically before finalization in both variants.
- [ ] `PreparedTransaction` round-trips encode/decode through the client decoder registry.
- [ ] Public docs on the API state the no-rebuild and retention rules verbatim.
- [ ] Mint recovery journal/API and atomic writer obligations in §3.6 pass phase-7 integration
      coverage; no daemon dependency on private mint state is required.

## 7. Open questions (non-blocking)

- Whether `PreparedTransaction` lives in `fedimint-client-module` (types) with storage in
  `fedimint-client`, or wholly in `fedimint-client`. Default: types in `fedimint-client-module`
  next to `TransactionBuilder`, storage/API in `fedimint-client`.
- Whether to add an optional `abandon_prepared_transaction` in a later phase for non-custodial
  users (requires per-module input re-credit hooks; explicitly out of MVP).
