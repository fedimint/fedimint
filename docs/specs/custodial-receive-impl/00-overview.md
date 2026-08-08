# Custodial Receive: Implementation Specs Overview

> Status: draft implementation specs. Parent design spec:
> [`../custodial-receive-gateway-detailed.md`](../custodial-receive-gateway-detailed.md) (all `§`
> references in these documents point there unless prefixed with a doc number). These specs turn the
> design into buildable, per-component work packages. Each is meant to be implementable by an
> engineer or agent without re-deriving decisions from the design spec, but the design spec remains
> the source of truth on protocol semantics; on conflict, fix the implementation spec.

## Document map and build order

Build order follows design §15: the client-core transaction work and public API semantics carry the
most risk and gate everything else.

| # | Doc | Crates touched | Depends on |
|---|-----|----------------|------------|
| 1 | [`01-client-tx-prepare.md`](./01-client-tx-prepare.md) | `fedimint-client`, `fedimint-client-module` | — |
| 2 | [`02-public-api.md`](./02-public-api.md) | `fedimint-lnv2-common` | — |
| 3 | [`03-phoenixd-backend.md`](./03-phoenixd-backend.md) | `gateway/fedimint-lightning`, `gateway/fedimint-gateway-common` | 2 (types only) |
| 4 | [`04-custodial-gatewayd.md`](./04-custodial-gatewayd.md) | new `gateway/fedimint-custodial-gatewayd`, `gateway/fedimint-gateway-server-db`, `modules/fedimint-gwv2-client` | 1, 2, 3 |
| 5 | [`05-capability-selection.md`](./05-capability-selection.md) | `modules/fedimint-lnv2-client` | 2 |
| 6 | [`06-client-receive-custodial.md`](./06-client-receive-custodial.md) | `modules/fedimint-lnv2-client` | 2, 5 |
| 7 | [`07-test-harness.md`](./07-test-harness.md) | `fedimint-testing`, `modules/fedimint-lnv2-tests`, new custodial test crate | 1–6 |

Phases 1 and 2 can proceed in parallel. Phase 3 can start once phase 2's payload/terms types
compile. Phases 5 and 6 are client-side and independent of 3–4 except for integration testing.

## Shared conventions

- **No consensus-module changes.** Nothing in these specs touches `fedimint-lnv2-server` semantics,
  wire encodings, or spend rules (§7.5). Any spec change that would require one is a design bug —
  stop and escalate.
- **Naming.** Rust items use the names from the design spec verbatim where one is given
  (`PendingCustodialReceive`, `CustodialReceiveQuote`, `CustodialReceiveTerms`,
  `CustodialReceiveRejectionReason`, `SettledAwaitingLiquidity`, `FundOnSettlement`,
  `UnmatchedSettlement`, …). Do not rename during implementation; if a name is unusable, change the
  design spec first.
- **Amounts** are `fedimint_core::Amount` (msats) everywhere except backend-facing sat fields,
  which are explicit `*_sat: u64` (design §7.3 `backend_requested_sat`).
- **Timestamps** are `u64` unix seconds unless suffixed `_ms`.
- **Error handling** follows repo standards: no `unwrap()` outside tests, `expect()` with a
  reason, `anyhow` at binary edges, typed errors on public API surfaces.
- **Logging** uses `tracing` structured fields; every durable state transition of a custodial
  receive logs `quote_id`, `contract_id` (never in metric labels, §7.8).
- **Atomicity.** Every "commit X together with Y" in the design spec means one database
  transaction. Specs call out each such commit explicitly; implementers must not split them.
- **Wasm.** Changes to `fedimint-client`, `fedimint-client-module`, `fedimint-lnv2-common`, and
  `modules/fedimint-lnv2-client` must keep compiling for wasm (`just check-wasm`). Gateway-side
  crates are native-only.
- **Feature flags.** None. All additions are additive API on existing crates plus new crates.

## What "buildable" means here

Each spec contains: scope and non-goals, grounding in current code (paths and verified behaviors),
new/changed types with Rust signatures, database keys and atomicity requirements, control flow with
explicit crash points, edge-case handling mapped to design-spec sections, a test plan mapped to the
design §15 matrix, and acceptance criteria. Open questions that block coding are listed at the top
of each spec; open questions that can be settled during implementation are listed at the bottom.

## Cross-cutting acceptance gates (apply to every phase)

- `just final-lint` passes; new code has no clippy warnings.
- New DB key prefixes have non-colliding discriminants and are listed in the owning crate's
  `DbKeyPrefix` enum with dump support where the crate provides it.
- No new public unpaid-record quotas, no `ResourceQuotaExceeded`-style rejections (§7.8).
- Every §15 test bullet that names this phase's behavior has a corresponding test in phase 7's
  matrix (07-test-harness.md keeps the authoritative mapping).
