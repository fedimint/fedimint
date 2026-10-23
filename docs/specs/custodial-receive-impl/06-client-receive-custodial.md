# Impl Spec 06: Client `receive_custodial` (`fedimint-lnv2-client`)

> Parent: design §6 (steps 2, 6, 12–13), §7.4, §7.9 client actions, §8 client checks.
> Crate: `modules/fedimint-lnv2-client`. Depends on specs 02 and 05.

## 1. Scope & non-goals

**In scope:** the explicit custodial entry point, provisional-record persistence, quote/invoice
verification, the armed receive watcher, rejection handling and conservative pruning.
**Non-goals:** consent UI (app layer; this API is only reachable through an explicit
`ReceiveMode::Custodial` call), the optional client consensus-time observer (wall-clock baseline
ships; observer is a later hardening, §7.4).

## 2. Grounding in current code (verified)

- `receive` (`lib.rs:804`) → fee-cap check `receive_fee.le(&RECEIVE_FEE_LIMIT)` (`:931`),
  `contract_amount = receive_fee.subtract_from(amount.msats)` (`:935`),
  `MINIMUM_INCOMING_CONTRACT_AMOUNT` = 5 sats (`lnv2-common/src/lib.rs:52`), single `expiry_secs`
  reused for contract expiration (`:943`) and invoice expiry (`:972`), hash check (`:977`),
  amount check (`:981`).
- Claim self-containment: `recover_contract_keys` (`:1025-1055`) derives claim keypair + agg
  decryption key from the module secret and `ephemeral_pk`; `ReceiveStateMachine` states
  `Pending → Claiming(outpoints) | Expired` (`receive_sm.rs:43-47`) with
  `ReceiveSMCommon { operation_id, contract, claim_keypair, agg_decryption_key }`.
- Payee recovery: `RoutingInfo::send_parameters` uses `invoice.recover_payee_pub_key()` (`:179`).

## 3. Design

### 3.1 Entry point

```rust
pub async fn receive_custodial(
    &self,
    amount: Amount,                       // invoice face amount A
    description: Bolt11InvoiceDescription,
    invoice_expiry_secs: u32,             // caller-relative; converted ONCE to the absolute
                                          // requested_invoice_expiry at step 3 — the payload and
                                          // fingerprint carry the absolute value (spec 02), so a
                                          // retry from the stored record never re-anchors it
    funding_deadline_secs: u64,           // relative; must satisfy §8 bounds for selected gateway
    extra_meta: Value,
    custodial_gateway_override: Option<SafeUrl>, // else spec-05 stored URLs
) -> Result<(Bolt11Invoice, CustodialReceiveQuote, OperationId), CustodialReceiveError>;
```

Flow (each numbered step is a §15-testable boundary):

1. **Select** via spec-05 (`ReceiveMode::Custodial`); read `CustodialReceiveCapability`.
2. **Validate request against capability:** granularity, per-receive cap, fee-cap
   **component-wise** (`receive_fee.base <= RECEIVE_FEE_LIMIT.base &&
   receive_fee.parts_per_million <= RECEIVE_FEE_LIMIT.parts_per_million` — NOT `.le()`, which is
   the derived lexicographic `PartialOrd` and admits e.g. a 50% proportional fee, §7.4),
   lower-bound `amount > fee(amount)` and
   `contract_amount >= max(MINIMUM_INCOMING_CONTRACT_AMOUNT, wallet_min)`, deadline min/max
   window (§8 inequalities using wall clock at this stage — final check is against the quote).
3. **Build contract** exactly as `receive` does but with
   `expiration = now + funding_deadline_secs` (real timestamp; distinct from invoice expiry) and
   `contract_amount = capability.receive_fee.subtract_from(amount.msats)`.
4. **Self-check claimability:** `recover_contract_keys(...)` must return `Some` (§7.4); else
   `CustodialReceiveError::UnclaimableContract` (never send the request).
5. **Persist provisional receive + arm watcher, then call the gateway** (order is load-bearing,
   §7.4): one dbtx writes the provisional record (below) and installs the
   `ReceiveStateMachine { state: Pending }` under a deterministic
   `operation_id = OperationId::from_encodable(&("custodial-receive", contract_id))` with an
   operation-log entry (meta: `LightningOperationMeta::ReceiveCustodial` variant carrying
   candidate source, amounts, deadlines, fingerprint). This is a **new start path** (built on
   `manual_operation_start_dbtx` so the record and operation commit together): the existing
   `receive` helper cannot be reused because it hardcodes its own
   `OperationId::from_encodable(&contract)` derivation internally (`lnv2-client/src/lib.rs:996`).
6. **Request** `CREATE_CUSTODIAL_BOLT11_INVOICE_ENDPOINT`.
7. **On `Created { invoice, quote }`:** run the §3.3 verification; on success upgrade the
   provisional record with invoice+quote (one dbtx) and return. Verification failure ⇒ treat like
   a retained-rejection (the gateway may believe it returned a valid quote): keep the provisional
   record, return `QuoteVerificationFailed` (support evidence stored).
8. **On `Rejected { reason }`:** apply the §7.9 client-action table: delete provisional record
   for strictly-pre-create reasons; retain for `BackendInvoiceUnreturnable` / `CreateInProgress`;
   `DuplicateContractConflict` deletes flow state but **retains claim material** (§7.9).
9. **On transport failure / timeout:** retain; retry the identical request (same fingerprint) —
   idempotent server-side; reselecting a different gateway requires a fresh contract.

**Claim-event fee arm (required, §8).** Introducing `LightningOperationMeta::ReceiveCustodial`
REQUIRES a matching arm in `ReceiveStateMachine::transition_incoming_contract`'s fee recovery
(`receive_sm.rs:141-154`): today every meta other than `Receive` falls into
`fee_from_expiration(expiration_or_fee)` = `u64::MAX - expiration`, which for a custodial
contract's real timestamp yields a ~1.8e19-msat garbage fee and overflows the unchecked
`amount + fee` at `receive_sm.rs:163` whenever the contract amount exceeds the timestamp's msat
value. `ReceiveCustodial` carries the invoice amount in its meta and takes the invoice-difference
fee path exactly like `Receive`. A test pins this with a large custodial receive (spec 07).

### 3.2 Provisional record (module DB, new key prefix)

```rust
// db.rs: ProvisionalCustodialReceive = <next free prefix>, key: ContractId
pub struct ProvisionalCustodialReceive {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub claim_keypair: Keypair,             // or re-derive; stored for robustness
    pub agg_decryption_key: AggregateDecryptionKey,
    pub gateway_api: SafeUrl,
    pub gateway_module_pk: PublicKey,
    pub gateway_ln_pk: PublicKey,
    pub candidate_sources: BTreeSet<GatewayCandidateSource>, // both provenance bits (spec 05)
    pub expected_module_pk: Option<PublicKey>, // pin snapshot from the candidate (spec 05);
                                            // §3.3 step 2 verifies against THIS, restart-safe
    pub client_request_id: sha256::Hash,
    pub request_fingerprint: sha256::Hash,  // computed identically to gateway (§7.3)
    pub invoice_amount: Amount,
    pub description: Bolt11InvoiceDescription, // needed to rebuild the identical payload on retry
                                            // (requires the Encodable/Decodable derives spec 02
                                            // adds to this enum — it is serde-only today)
    pub quote_api_version: u16,                // ditto
    pub selected_capability: CustodialReceiveCapability, // capability snapshot used to size the
                                            // contract; restart-deterministic verification of
                                            // terms.receive_fee (§3.3.4) reads THIS, not a fresh probe
    pub requested_invoice_expiry: u64,      // absolute
    pub funding_deadline: u64,              // absolute
    pub pruning_policy: PruningPolicy,      // persisted capability fields (§7.4): max_age + safety_margin
    pub phase: ProvisionalPhase,            // AwaitingResponse | Upgraded { invoice, quote } | RetainedAfterRejection { reason }
}
```

The `ReceiveStateMachine` watcher is armed from step 5 regardless of later rejection retention,
so a fund-on-settlement of an unreturned invoice still claims (§7.4, §15 "rejected-but-retained"
test). `Expired` watcher outcome does not delete the record; pruning does (§3.4).

### 3.3 Quote/invoice verification (ordered)

1. `quote.verify(gateway_module_pk)` (domain-tagged signature, spec 02); `api_version` known.
2. Identity binding: `federation_id`, `contract_id`, full `contract`, `gateway_module_pk`,
   `gateway_ln_pk` match selection + local contract; contract `refund_pk == gateway_module_pk`;
   when the candidate carries an `expected_module_pk` pin (spec 05), `gateway_module_pk` MUST
   equal the pin.
3. Invoice binding: `quote.backend_invoice_hash == invoice.payment_hash()`;
   `invoice.recover_payee_pub_key() == gateway_ln_pk == RoutingInfo.lightning_public_key`
   (replaces the skipped hash check, §7.4); invoice amount == `quote.invoice_amount` == requested
   `amount` (keep `:981` check); invoice expiry consistent with `quote.invoice_expiry`.
4. Terms: compatible with the **stored** `selected_capability` snapshot — every terms field with
   a capability counterpart equals the snapshot value (restart-safe — never a fresh probe, §7.4);
   `terms.receive_fee == selected_capability.receive_fee` (the fee used to size the contract,
   else reject, §7.1); fee cap **component-wise** (base AND parts_per_million within
   `RECEIVE_FEE_LIMIT` — never `.le()`, §7.4).
5. Amount binding (both §7.4 inequalities + exact `subtract_from` equality).
6. Deadline arithmetic (§7.4 text block, incl. upper bounds) against
   `quote.observed_lnv2_consensus_time`; then the independent time-reference sanity check
   (wall clock with configured margin; observer optional).

Any failure ⇒ `QuoteVerificationFailed` with the failing check identified (support evidence).

### 3.4 Pruning (conservative, §7.4)

`prune_custodial_provisional_records()` (called opportunistically): a record is prunable when
`local_reference_time > funding_deadline + pruning_policy.margin + assumed_max_clock_skew` where
`local_reference_time` is wall clock (baseline) or observed consensus time (if the wallet tracks
one; then no skew term). Default `assumed_max_clock_skew`: 1 hour, configurable. Pruning removes
the **record only** and lets the watcher's `Expired` path finalize the operation. Neither pruning
nor step-8 deletion touches the armed SM (there is no abort API): the SM's own state carries
`claim_keypair` + `agg_decryption_key` and resolves against the *federation's* consensus-time
view of the deadline, so any contract funded before its deadline is still claimed even after the
record is gone (§7.4). This is the client's claim-safety backstop; do not "optimize" it away.

## 4. Edge cases

- Duplicate local call for the same contract: blocked by the provisional record (return existing
  operation) — mirrors the gateway's `(federation_id, contract_id)` uniqueness.
- Gateway returns `Created` twice (retry): verification is deterministic; second upgrade is a
  no-op.
- Wallet restart mid-flow: provisional record + armed watcher survive; a stored
  `AwaitingResponse` phase re-sends the identical request rebuilt entirely from the record
  (contract, amount, `description`, `requested_invoice_expiry`, `quote_api_version` — fingerprint
  match ⇒ idempotent), and verifies any response against the stored `selected_capability`.
- Amount edge: `amount` such that `subtract_from` saturates ⇒ rejected at step 2 (§15 bullet).
- **Rejected attempts leave a long-lived pending operation (accepted MVP cost):** the step-5
  watcher long-polls `await_incoming_contract(contract_id, funding_deadline)` until the deadline
  (days) and cannot be aborted, so every rejected or failed attempt leaves one Pending operation
  until then. Bounded by the number of attempts a user actually makes; do NOT attempt to cancel
  the SM (that would reopen the claim-safety hole §3.4 closes). A post-MVP SM-abort API may
  revisit this.

## 5. Test plan

Client-side rows of §15: payee-binding rejection; full quote-verification matrix (each check
mutated); fee-mismatch rejection; saturation lower-bounds; rejected-but-retained claim;
DuplicateContractConflict claim-material retention; conservative pruning under skew; contract
sizing uses custodial fee not legacy fee. Plus wasm compile.

## 6. Acceptance criteria

- [ ] `receive_custodial` is unreachable without explicit custodial candidates (spec 05).
- [ ] Provisional record + watcher are committed before any network I/O to the gateway (step 5).
- [ ] Every §3.3 check has a dedicated negative test.
- [ ] No change to the trustless `receive` path (golden test).

## 7. Open questions (non-blocking)

- Where `assumed_max_clock_skew` and the wall-clock margin default live (client config vs
  constants). Default: module-level constants, override via client builder.
- Whether `claim_keypair`/`agg_decryption_key` are stored or re-derived on demand (both work;
  stored is chosen for restart cheapness — revisit if key material at rest is a concern, since
  the module secret already lives in the same DB).
