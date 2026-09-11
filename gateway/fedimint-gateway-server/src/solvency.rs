//! Forwarding solvency: per-forward margins joined across stores, a
//! peak-relative drawdown check, and the operator-facing thresholds.
//!
//! See `docs/superpowers/specs/2026-09-11-gateway-solvency-design.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bitcoin::hashes::sha256;
use fedimint_client::ClientHandleArc;
// `State` is in scope for `operation_id()` on the state-machine enums.
use fedimint_client_module::sm::State as _;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _};
use fedimint_core::{Amount, TransactionId};
use fedimint_gateway_server_db::{DrawdownPeak, GatewayDbtxNcExt};
use fedimint_gw_client::GatewayClientModule;
use fedimint_gwv2_client::GatewayClientModuleV2;
use fedimint_gwv2_client::audit::{CircuitOutcome, ForwardFact, ReceiveOutcome, SendOutcome};
use fedimint_lightning::{ILnRpcClient, OutboundPaymentStatus};
use fedimint_logging::LOG_GATEWAY;
use fedimint_mint_client::MintClientStateMachines;
use fedimint_mint_client::output::MintOutputStates;
use fedimint_mintv2_client::{
    MintClientStateMachines as MintV2ClientStateMachines, OutputSMState as MintV2OutputSMState,
};
use tracing::warn;

use crate::{Gateway, GatewayState};

/// Positions older than this are no longer counted as assets.
pub const STALE_POSITION_AGE: Duration = Duration::from_hours(24);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DrawdownThresholds {
    warn_pct: f64,
    halt_pct: f64,
}

impl DrawdownThresholds {
    pub fn new(warn_pct: f64, halt_pct: f64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            warn_pct.is_finite() && halt_pct.is_finite() && warn_pct >= 0.0 && halt_pct >= 0.0,
            "drawdown thresholds must be finite, non-negative percentages"
        );
        anyhow::ensure!(
            warn_pct < halt_pct,
            "drawdown warn threshold ({warn_pct}%) must be strictly below the halt threshold ({halt_pct}%)"
        );
        Ok(Self { warn_pct, halt_pct })
    }

    pub fn halt_pct(&self) -> f64 {
        self.halt_pct
    }

    pub fn evaluate(&self, drawdown_pct: f64) -> Verdict {
        if drawdown_pct >= self.halt_pct {
            Verdict::Halt
        } else if drawdown_pct >= self.warn_pct {
            Verdict::Warn
        } else {
            Verdict::Ok
        }
    }
}

impl Default for DrawdownThresholds {
    fn default() -> Self {
        Self {
            warn_pct: 2.0,
            halt_pct: 10.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Warn,
    Halt,
}

/// Percent of `assets_at_peak` lost since the peak. Zero on a gateway that
/// has never held funds: an empty gateway cannot have lost anything.
// The ratio is only ever logged or compared against an operator-set percentage,
// so losing the last bits of a msat-sized integer in the `f64` is harmless.
#[allow(clippy::cast_precision_loss)]
pub fn drawdown_pct(peak: &DrawdownPeak, cumulative_margin_msat: i64) -> f64 {
    if peak.assets_at_peak_msat == 0 {
        return 0.0;
    }
    let peak_margin = i64::try_from(peak.peak_cumulative_margin_msat).unwrap_or(i64::MAX);
    let decline = peak_margin.saturating_sub(cumulative_margin_msat).max(0);
    decline as f64 / peak.assets_at_peak_msat as f64 * 100.0
}

/// The peak only ever rises; the assets recorded with it are those measured
/// at that moment, so later withdrawals cannot inflate old losses.
pub fn advance_peak(
    prev: Option<DrawdownPeak>,
    cumulative_margin_msat: i64,
    total_assets: Amount,
) -> DrawdownPeak {
    let current = u64::try_from(cumulative_margin_msat).unwrap_or(0);
    match prev {
        // A peak recorded before the gateway held anything pins the drawdown
        // denominator at zero, where `drawdown_pct` is defined as zero. While
        // the margin stays at or below that peak the record never advances on
        // its own, so a gateway attacked from its very first forward would
        // report a zero drawdown forever. Re-anchor the denominator to the
        // assets now visible: an upward-only revision, consistent with the
        // rule that neither field is ever revised downward.
        Some(prev) if prev.assets_at_peak_msat == 0 && total_assets.msats > 0 => DrawdownPeak {
            peak_cumulative_margin_msat: prev.peak_cumulative_margin_msat.max(current),
            assets_at_peak_msat: total_assets.msats,
        },
        Some(prev) if prev.peak_cumulative_margin_msat >= current => prev,
        _ => DrawdownPeak {
            peak_cumulative_margin_msat: current,
            assets_at_peak_msat: total_assets.msats,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceOutcome {
    Pending,
    Succeeded,
    Failed,
}

/// How advanced an issuance outcome is. A `Failed` anywhere in an issuance's
/// history is a failure; a `Succeeded` beats any pending record of the same
/// issuance.
fn issuance_rank(outcome: IssuanceOutcome) -> u8 {
    match outcome {
        IssuanceOutcome::Pending => 0,
        IssuanceOutcome::Succeeded => 1,
        IssuanceOutcome::Failed => 2,
    }
}

/// Folds one more record for the same outpoint into what is already known
/// about it.
///
/// The executor retains every state a machine passed through, so one issuance
/// yields several records for the same outpoint. They arrive in the byte order
/// of their encoded states, which puts `MintOutputStates::CreatedMulti`
/// (variant 4, and the only variant the gateway's claims ever start in) *after*
/// the terminal `Succeeded` (variant 3): a last-write-wins join would leave
/// every realized claim reading as pending forever. Resolve by precedence
/// instead, which is independent of the scan order.
fn merge_issuance(previous: Option<IssuanceOutcome>, next: IssuanceOutcome) -> IssuanceOutcome {
    match previous {
        Some(previous) if issuance_rank(previous) >= issuance_rank(next) => previous,
        _ => next,
    }
}

pub struct FactInput {
    pub fact: ForwardFact,
    pub created_at: SystemTime,
    pub active: bool,
}

/// Which state-machine instance a fact belongs to. The executor keeps every
/// state a machine passed through, so the audit sees many facts per instance
/// and has to collapse them to one before scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FactKey {
    Send(OperationId),
    Receive(OperationId),
    Circuit(OperationId),
}

/// How advanced a circuit's outcome is; `Completed` and `Failed` are both
/// terminal, and a completion never moves between them.
fn circuit_rank(outcome: CircuitOutcome) -> u8 {
    match outcome {
        CircuitOutcome::Pending => 0,
        CircuitOutcome::Completed | CircuitOutcome::Failed => 1,
    }
}

fn fact_key(fact: &ForwardFact) -> FactKey {
    match fact {
        ForwardFact::Send { operation_id, .. } => FactKey::Send(*operation_id),
        ForwardFact::Receive { operation_id, .. } => FactKey::Receive(*operation_id),
        ForwardFact::Circuit {
            completion_operation_id,
            ..
        } => FactKey::Circuit(*completion_operation_id),
    }
}

/// How far along its family's progression an outcome is. Only the ordering
/// matters; the absolute numbers do not.
fn fact_rank(fact: &ForwardFact) -> u8 {
    match fact {
        ForwardFact::Send { outcome, .. } => match outcome {
            SendOutcome::InFlight => 0,
            SendOutcome::PaidAwaitingClaim { .. } => 1,
            SendOutcome::Claimed { .. }
            | SendOutcome::ClaimedUnknownCost { .. }
            | SendOutcome::Cancelled { .. } => 2,
        },
        ForwardFact::Receive { outcome, .. } => match outcome {
            ReceiveOutcome::Funding => 0,
            ReceiveOutcome::Success | ReceiveOutcome::Lost | ReceiveOutcome::NotFunded => 1,
        },
        ForwardFact::Circuit { outcome, .. } => circuit_rank(*outcome),
    }
}

/// Whether `candidate` is a better description of its state machine's current
/// position than `incumbent`.
///
/// An active record always wins: the machine is still running, and its
/// inactive records are its past. Between two inactive records the more
/// advanced outcome wins.
fn supersedes(candidate: &FactInput, incumbent: &FactInput) -> bool {
    match (candidate.active, incumbent.active) {
        (true, false) => true,
        (false, true) => false,
        _ => fact_rank(&candidate.fact) > fact_rank(&incumbent.fact),
    }
}

/// Reduces the raw scan to exactly one fact per state-machine instance.
///
/// Without this every state a machine ever passed through is scored: a
/// completed receive would book its own `Funding` record as a permanent open
/// position, a failed circuit's `[Pending, Pending, Failed]` history would
/// fail the `all(Failed)` test that turns a one-legged loss into a realized
/// one, and every intermediate pre-upgrade record would count as another
/// unknown forward.
pub fn collapse_facts(facts: Vec<FactInput>) -> Vec<FactInput> {
    let mut collapsed: BTreeMap<FactKey, FactInput> = BTreeMap::new();
    for input in facts {
        let key = fact_key(&input.fact);
        match collapsed.entry(key) {
            std::collections::btree_map::Entry::Vacant(vacant) => {
                vacant.insert(input);
            }
            std::collections::btree_map::Entry::Occupied(mut occupied) => {
                if supersedes(&input, occupied.get()) {
                    occupied.insert(input);
                }
            }
        }
    }
    collapsed.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationLedger {
    pub federation_id: FederationId,
    pub ecash_balance: Amount,
    /// Value committed but not yet realized, counted as an asset.
    pub open_positions_msat: u64,
    pub realized_margin_msat: i64,
    /// Forwards excluded from the margin because a cost or amount was
    /// never recorded. Non-zero on any gateway with pre-upgrade history.
    pub unknown_forwards: u64,
    pub negative_forwards: Vec<(OperationId, i64)>,
    /// Cancelled after a Lightning dispatch; the node must confirm failure.
    pub reconcile: Vec<(OperationId, sha256::Hash)>,
    pub stale_positions: Vec<OperationId>,
}

fn margin(received: Amount, paid: Amount) -> i64 {
    i64::try_from(received.msats).unwrap_or(i64::MAX)
        - i64::try_from(paid.msats).unwrap_or(i64::MAX)
}

/// An active position whose state machine has not moved for `stale_after` is
/// no longer credible as an asset, so it stops being counted as one.
fn is_stale(input: &FactInput, now: SystemTime, stale_after: Duration) -> bool {
    input.active
        && now
            .duration_since(input.created_at)
            .is_ok_and(|age| age > stale_after)
}

/// Counts `at_risk` as an open position, unless the position went stale.
fn open(
    ledger: &mut FederationLedger,
    input: &FactInput,
    operation_id: OperationId,
    at_risk: Amount,
    now: SystemTime,
    stale_after: Duration,
) {
    if is_stale(input, now, stale_after) {
        ledger.stale_positions.push(operation_id);
    } else {
        ledger.open_positions_msat = ledger.open_positions_msat.saturating_add(at_risk.msats);
    }
}

/// Books a settled forward's margin, flagging the ones that lost money.
fn realize(ledger: &mut FederationLedger, operation_id: OperationId, delta: i64) {
    ledger.realized_margin_msat = ledger.realized_margin_msat.saturating_add(delta);
    if delta < 0 {
        ledger.negative_forwards.push((operation_id, delta));
    }
}

pub fn score_federation(
    federation_id: FederationId,
    ecash_balance: Amount,
    facts: &[FactInput],
    issuance: &BTreeMap<(TransactionId, u64), IssuanceOutcome>,
    incoming_amounts: &BTreeMap<OperationId, Amount>,
    now: SystemTime,
    stale_after: Duration,
) -> FederationLedger {
    let mut ledger = FederationLedger {
        federation_id,
        ecash_balance,
        open_positions_msat: 0,
        realized_margin_msat: 0,
        unknown_forwards: 0,
        negative_forwards: vec![],
        reconcile: vec![],
        stale_positions: vec![],
    };

    // One outcome per completion, not per record: the facts handed in are
    // expected to be collapsed already, but keying by completion id keeps the
    // join right even if they are not.
    let mut circuits: BTreeMap<OperationId, BTreeMap<OperationId, CircuitOutcome>> =
        BTreeMap::new();
    for input in facts {
        if let ForwardFact::Circuit {
            completion_operation_id,
            receive_operation_id,
            outcome,
        } = &input.fact
        {
            circuits
                .entry(*receive_operation_id)
                .or_default()
                .entry(*completion_operation_id)
                .and_modify(|known| {
                    if circuit_rank(*outcome) > circuit_rank(*known) {
                        *known = *outcome;
                    }
                })
                .or_insert(*outcome);
        }
    }

    for input in facts {
        match &input.fact {
            ForwardFact::Send {
                operation_id,
                contract_amount,
                payment_hash,
                outcome,
            } => match outcome {
                SendOutcome::InFlight => {}
                SendOutcome::PaidAwaitingClaim { .. } => {
                    open(
                        &mut ledger,
                        input,
                        *operation_id,
                        *contract_amount,
                        now,
                        stale_after,
                    );
                }
                SendOutcome::Claimed { cost, outpoints } => {
                    let Some(total) = cost.total() else {
                        ledger.unknown_forwards += 1;
                        continue;
                    };
                    let outcomes = outpoints.iter().map(|o| {
                        issuance
                            .get(&(o.txid, o.out_idx))
                            .copied()
                            .unwrap_or(IssuanceOutcome::Pending)
                    });
                    let mut any_failed = false;
                    let mut any_pending = false;
                    for o in outcomes {
                        match o {
                            IssuanceOutcome::Failed => any_failed = true,
                            IssuanceOutcome::Pending => any_pending = true,
                            IssuanceOutcome::Succeeded => {}
                        }
                    }
                    if any_failed {
                        realize(&mut ledger, *operation_id, margin(Amount::ZERO, total));
                    } else if any_pending {
                        open(
                            &mut ledger,
                            input,
                            *operation_id,
                            *contract_amount,
                            now,
                            stale_after,
                        );
                    } else {
                        realize(&mut ledger, *operation_id, margin(*contract_amount, total));
                    }
                }
                SendOutcome::ClaimedUnknownCost { .. } => ledger.unknown_forwards += 1,
                SendOutcome::Cancelled { after_dispatch } => {
                    if *after_dispatch && let Some(hash) = payment_hash {
                        ledger.reconcile.push((*operation_id, *hash));
                    }
                }
            },
            ForwardFact::Receive {
                operation_id,
                contract_amount,
                outcome,
            } => {
                let Some(contract_amount) = contract_amount else {
                    if !matches!(outcome, ReceiveOutcome::NotFunded) {
                        ledger.unknown_forwards += 1;
                    }
                    continue;
                };
                match outcome {
                    ReceiveOutcome::Funding => open(
                        &mut ledger,
                        input,
                        *operation_id,
                        *contract_amount,
                        now,
                        stale_after,
                    ),
                    ReceiveOutcome::NotFunded => {}
                    ReceiveOutcome::Lost => {
                        realize(
                            &mut ledger,
                            *operation_id,
                            margin(Amount::ZERO, *contract_amount),
                        );
                    }
                    ReceiveOutcome::Success => {
                        // No circuit means this receive was the far side of a
                        // swap; its margin lives on the paying federation's send.
                        let Some(circuits) = circuits.get(operation_id) else {
                            continue;
                        };
                        let completed: Vec<OperationId> = circuits
                            .iter()
                            .filter(|(_, o)| **o == CircuitOutcome::Completed)
                            .map(|(c, _)| *c)
                            .collect();
                        if completed.is_empty() {
                            if circuits.values().all(|o| *o == CircuitOutcome::Failed) {
                                realize(
                                    &mut ledger,
                                    *operation_id,
                                    margin(Amount::ZERO, *contract_amount),
                                );
                            } else {
                                open(
                                    &mut ledger,
                                    input,
                                    *operation_id,
                                    *contract_amount,
                                    now,
                                    stale_after,
                                );
                            }
                        } else {
                            let mut received = Amount::ZERO;
                            let mut unknown = false;
                            for completion in completed {
                                match incoming_amounts.get(&completion) {
                                    Some(amount) => {
                                        received = received
                                            .checked_add(*amount)
                                            .unwrap_or(Amount::from_msats(u64::MAX));
                                    }
                                    None => unknown = true,
                                }
                            }
                            if unknown {
                                ledger.unknown_forwards += 1;
                            } else {
                                realize(
                                    &mut ledger,
                                    *operation_id,
                                    margin(received, *contract_amount),
                                );
                            }
                        }
                    }
                }
            }
            ForwardFact::Circuit { .. } => {}
        }
    }

    ledger
}

/// Cancelled sends whose payment the node reports as settled: the state
/// machine refunded the contract while the money left anyway.
pub fn phantom_losses(
    statuses: &[(OperationId, Option<OutboundPaymentStatus>)],
) -> Vec<(OperationId, i64)> {
    statuses
        .iter()
        .filter_map(|(op, status)| match status {
            Some(OutboundPaymentStatus::Succeeded { amount_sent, fee }) => {
                let paid = fee
                    .and_then(|fee| amount_sent.checked_add(fee))
                    .unwrap_or(*amount_sent);
                Some((*op, margin(Amount::ZERO, paid)))
            }
            Some(OutboundPaymentStatus::Pending | OutboundPaymentStatus::Failed) | None => None,
        })
        .collect()
}

/// How a phantom's computed loss (from `phantom_losses`) should be booked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhantomKind {
    /// A realized loss of the given (non-zero, non-positive) amount.
    Loss(i64),
    /// The node settled the payment but reported no amount (for example
    /// LDK's `amount_msat: None`), so `phantom_losses` computed a `0` that
    /// is not a genuine zero loss and must not be booked as one.
    UnknownAmount,
}

/// Classifies a `phantom_losses` loss for booking. `phantom_losses` never
/// yields a positive number (it always scores `margin(Amount::ZERO, paid)`,
/// which is `<= 0`), so a `0` can only mean the settled amount itself was
/// unknown, not that the send broke even.
fn classify_phantom(loss: i64) -> PhantomKind {
    if loss == 0 {
        PhantomKind::UnknownAmount
    } else {
        PhantomKind::Loss(loss)
    }
}

#[derive(Debug, Clone)]
pub struct Ledger {
    pub federations: Vec<FederationLedger>,
    pub node_total: Amount,
    pub cumulative_margin_msat: i64,
    pub total_assets: Amount,
}

impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "- Gateway forwarding ledger -")?;
        for fed in &self.federations {
            writeln!(
                f,
                "{}: ecash {} | open {} msat | realized {:+} msat | unknown {} | negative {} | stale {}",
                fed.federation_id,
                fed.ecash_balance,
                fed.open_positions_msat,
                fed.realized_margin_msat,
                fed.unknown_forwards,
                fed.negative_forwards.len(),
                fed.stale_positions.len(),
            )?;
        }
        writeln!(f, "node total {} msat", self.node_total.msats)?;
        writeln!(
            f,
            "cumulative margin {:+} msat",
            self.cumulative_margin_msat
        )?;
        write!(f, "total assets {} msat", self.total_assets.msats)
    }
}

async fn federation_ledger(
    federation_id: FederationId,
    client: &ClientHandleArc,
    now: SystemTime,
) -> anyhow::Result<FederationLedger> {
    let ecash_balance = client.get_balance_for_btc().await?;
    let active = client.executor().get_active_states().await;
    let inactive = client.executor().get_inactive_states().await;

    let mut issuance = BTreeMap::new();
    let mut facts = Vec::new();
    let gwv2 = client.get_first_module::<GatewayClientModuleV2>().ok();
    let gwv1 = client.get_first_module::<GatewayClientModule>().ok();

    let states = active
        .iter()
        .map(|(s, meta)| (s, meta.created_at, true))
        .chain(inactive.iter().map(|(s, meta)| (s, meta.created_at, false)));

    for (state, created_at, is_active) in states {
        if let Some(MintClientStateMachines::Output(output)) =
            state.as_any().downcast_ref::<MintClientStateMachines>()
        {
            let outcome = match output.state() {
                MintOutputStates::Created(_) | MintOutputStates::CreatedMulti(_) => {
                    IssuanceOutcome::Pending
                }
                MintOutputStates::Succeeded(_) => IssuanceOutcome::Succeeded,
                MintOutputStates::Aborted(_) | MintOutputStates::Failed(_) => {
                    IssuanceOutcome::Failed
                }
            };
            for outpoint in output.out_point_range() {
                let key = (outpoint.txid, outpoint.out_idx);
                let merged = merge_issuance(issuance.get(&key).copied(), outcome);
                issuance.insert(key, merged);
            }
        } else if let Some(MintV2ClientStateMachines::Output(output)) =
            state.as_any().downcast_ref::<MintV2ClientStateMachines>()
        {
            // The gateway attaches both mint modules and lets the client pick a
            // primary, and a federation generated with today's defaults runs
            // `mintv2`. Without this arm every claim's outpoints stay `Pending`
            // forever on such a federation: outgoing margins never realize and
            // `open_positions_msat` grows with lifetime volume.
            let outcome = match output.state {
                MintV2OutputSMState::Pending => IssuanceOutcome::Pending,
                MintV2OutputSMState::Success => IssuanceOutcome::Succeeded,
                MintV2OutputSMState::Aborted | MintV2OutputSMState::Failure => {
                    IssuanceOutcome::Failed
                }
            };
            // A machine that has not yet been assigned a transaction carries no
            // range, so it contributes no outpoints. A claim joined against one
            // simply stays `Pending`, which is what it is.
            for outpoint in output.common.range.into_iter().flatten() {
                let key = (outpoint.txid, outpoint.out_idx);
                let merged = merge_issuance(issuance.get(&key).copied(), outcome);
                issuance.insert(key, merged);
            }
        } else if let Some(sm) = state
            .as_any()
            .downcast_ref::<fedimint_gwv2_client::GatewayClientStateMachinesV2>()
        {
            facts.push(FactInput {
                fact: fedimint_gwv2_client::audit::forward_fact(sm),
                created_at,
                active: is_active,
            });
        } else if let Some(sm) = state
            .as_any()
            .downcast_ref::<fedimint_gw_client::GatewayClientStateMachines>()
        {
            let amounts = match &gwv1 {
                Some(module) => module.incoming_amounts(sm.operation_id()).await,
                None => None,
            };
            facts.push(FactInput {
                fact: fedimint_gw_client::audit::forward_fact(sm, amounts.as_ref()),
                created_at,
                active: is_active,
            });
        }
    }

    // The executor retains every state a machine passed through, so the scan
    // above yields several facts per instance. Score exactly one.
    let facts = collapse_facts(facts);

    let mut incoming_amounts = BTreeMap::new();
    for input in &facts {
        if let ForwardFact::Circuit {
            completion_operation_id,
            ..
        } = &input.fact
        {
            // LNv2 records the locked amount per completion; LNv1 keys its
            // record on the operation the receive and complete share.
            let mut amount = None;
            if let Some(module) = &gwv2 {
                amount = module.incoming_amount(*completion_operation_id).await;
            }
            if amount.is_none()
                && let Some(module) = &gwv1
            {
                amount = module
                    .incoming_amounts(*completion_operation_id)
                    .await
                    .map(|a| a.incoming_amount);
            }
            if let Some(amount) = amount {
                incoming_amounts.insert(*completion_operation_id, amount);
            }
        }
    }

    Ok(score_federation(
        federation_id,
        ecash_balance,
        &facts,
        &issuance,
        &incoming_amounts,
        now,
        STALE_POSITION_AGE,
    ))
}

/// Whether holding `ecash` plus `open_msat` in open positions plus
/// `additional` (the value an about-to-be-submitted outgoing forward would
/// add) in a federation would exceed `limit`. Overflowing the addition is
/// treated as exceeding the limit rather than panicking or wrapping.
pub fn exposure_exceeded(ecash: Amount, open_msat: u64, additional: Amount, limit: Amount) -> bool {
    ecash
        .checked_add(Amount::from_msats(open_msat))
        .and_then(|e| e.checked_add(additional))
        .is_none_or(|exposure| exposure > limit)
}

impl Gateway {
    /// Refuses an outgoing forward that would push a federation's exposure
    /// over the configured limit. Unlimited when no limit is configured.
    ///
    /// The open-positions half comes from the last solvency report rather than
    /// a fresh ledger scan: rebuilding the ledger is O(history) (a full decode
    /// pass plus per-record module-DB reads) and the routes this gates are
    /// unauthenticated, so a per-request scan is a denial-of-service lever.
    /// Open positions are therefore at most one report interval (60s) stale,
    /// which the design documents. The ecash half is read live, since that is
    /// a single cheap balance lookup and is the half an operator actually
    /// watches.
    pub(crate) async fn ensure_exposure_allows(
        &self,
        federation_id: FederationId,
        client: &ClientHandleArc,
        additional: Amount,
    ) -> anyhow::Result<()> {
        let Some(limit) = self.max_federation_exposure else {
            return Ok(());
        };
        let open_positions_msat = {
            let snapshot = self
                .open_positions_last_report
                .lock()
                .expect("open-positions snapshot mutex is never held across an .await");
            snapshot.get(&federation_id).copied()
        };
        let open_positions_msat = open_positions_msat.unwrap_or_else(|| {
            // No report has run for this federation yet (the gateway just
            // joined it, or the first tick has not landed). Nothing is known
            // to be open, so gate on the ecash balance alone until it has.
            tracing::debug!(
                target: LOG_GATEWAY,
                %federation_id,
                "No solvency report yet for this federation; gating the exposure limit on its ecash balance alone"
            );
            0
        });
        let ecash_balance = client.get_balance_for_btc().await?;
        anyhow::ensure!(
            !exposure_exceeded(ecash_balance, open_positions_msat, additional, limit),
            "federation {federation_id} exposure limit {limit} would be exceeded"
        );
        Ok(())
    }
}

/// A solvency evaluation: the ledger it was computed from, the peak it was
/// measured against, the resulting drawdown, and the verdict.
pub struct SolvencyReport {
    // Only `verdict` is read by the boot gate and the periodic check today; the
    // fields below document the full result of the evaluation for a future
    // caller (e.g. an operator-facing diagnostics endpoint) rather than being
    // recomputed from scratch.
    #[allow(dead_code)]
    pub ledger: Ledger,
    #[allow(dead_code)]
    pub peak: DrawdownPeak,
    #[allow(dead_code)]
    pub drawdown_pct: f64,
    pub verdict: Verdict,
}

impl Gateway {
    /// The current forwarding ledger, computed against the gateway's live
    /// Lightning context. Exposed for tests and operator diagnostics; the
    /// periodic check uses [`Gateway::solvency_report`], which additionally
    /// reconciles cancelled sends and advances the drawdown peak.
    pub async fn solvency_ledger(&self) -> anyhow::Result<Ledger> {
        let context = self.get_lightning_context().await?;
        self.compute_ledger(context.lnrpc.as_ref()).await
    }

    /// Scores every federation and adds the node's funds. Fails, rather than
    /// guessing, if the node cannot report its balances.
    pub(crate) async fn compute_ledger(&self, lnrpc: &dyn ILnRpcClient) -> anyhow::Result<Ledger> {
        let node = lnrpc.get_balances().await?;
        let node_total = Amount::from_msats(node.total_msats());
        let now = fedimint_core::time::now();

        let clients: Vec<(FederationId, ClientHandleArc)> = self
            .federation_manager
            .read()
            .await
            .clients()
            .map(|(id, client)| (*id, client.value().clone()))
            .collect();

        let mut federations = Vec::with_capacity(clients.len());
        for (federation_id, client) in clients {
            federations.push(federation_ledger(federation_id, &client, now).await?);
        }

        let cumulative_margin_msat = federations
            .iter()
            .fold(0i64, |acc, f| acc.saturating_add(f.realized_margin_msat));
        let mut total_assets = node_total;
        for f in &federations {
            total_assets = total_assets
                .checked_add(f.ecash_balance)
                .and_then(|t| t.checked_add(Amount::from_msats(f.open_positions_msat)))
                .unwrap_or(total_assets);
        }

        Ok(Ledger {
            federations,
            node_total,
            cumulative_margin_msat,
            total_assets,
        })
    }

    /// Computes the ledger, advances and persists the peak, evaluates the
    /// thresholds and exports the metrics.
    pub(crate) async fn solvency_report(
        &self,
        lnrpc: &dyn ILnRpcClient,
    ) -> anyhow::Result<SolvencyReport> {
        // Bounds every outbound-payment lookup below so one slow or hung
        // node call cannot stall the periodic report indefinitely.
        const RECONCILE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
        // Per-lookup bounds do not bound the pass: a fresh process starts with
        // an empty cache, so N historical after-dispatch cancellations could
        // hold the boot gate for N * 10s before the gateway can become
        // `Running`. Bound the whole pass instead and carry on with whatever
        // was gathered; anything left uncached is retried on the next tick.
        const RECONCILE_PASS_BUDGET: Duration = Duration::from_secs(30);

        let mut ledger = self.compute_ledger(lnrpc).await?;

        // The lookup cache holds only *terminal* results (`Succeeded`,
        // `Failed`, or `None` meaning the node has no record), so a hit
        // skips the network call outright; `Pending` and lookup errors are
        // never cached and are retried every tick. Regardless of whether a
        // status came from cache or a fresh call, it still has to be run
        // through `phantom_losses` this tick — `compute_ledger` rebuilds
        // `reconcile` from scratch every time, so the merged (cached +
        // fresh) set is what must be scored, not just the newly-looked-up
        // subset. The cache and reported-phantoms mutexes below are each
        // locked only for a synchronous instant, never across the lookup's
        // `.await`.
        let mut fed_statuses: Vec<Vec<(OperationId, Option<OutboundPaymentStatus>)>> =
            vec![Vec::new(); ledger.federations.len()];
        let total_lookups: u64 = ledger
            .federations
            .iter()
            .map(|fed| fed.reconcile.len() as u64)
            .sum();
        let finished_lookups = AtomicU64::new(0);

        let reconciliation = async {
            for (fed, statuses) in ledger.federations.iter().zip(fed_statuses.iter_mut()) {
                statuses.reserve(fed.reconcile.len());
                for (op, hash) in &fed.reconcile {
                    let cached = {
                        let cache = self
                            .phantom_lookup_cache
                            .lock()
                            .expect("phantom-lookup cache mutex is never held across an .await");
                        cache.get(op).cloned()
                    };
                    if let Some(cached) = cached {
                        statuses.push((*op, cached));
                        finished_lookups.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    match tokio::time::timeout(
                        RECONCILE_LOOKUP_TIMEOUT,
                        lnrpc.lookup_outbound_payment(*hash),
                    )
                    .await
                    {
                        Ok(Ok(status)) => {
                            // `Pending` is not terminal; leave it uncached so it
                            // is looked up again next tick.
                            if !matches!(status, Some(OutboundPaymentStatus::Pending)) {
                                let mut cache = self.phantom_lookup_cache.lock().expect(
                                    "phantom-lookup cache mutex is never held across an .await",
                                );
                                cache.insert(*op, status.clone());
                            }
                            statuses.push((*op, status));
                        }
                        Ok(Err(err)) => warn!(
                            target: LOG_GATEWAY,
                            federation_id = %fed.federation_id,
                            operation_id = ?op,
                            err = %err.fmt_compact(),
                            "Could not reconcile a cancelled send against the node"
                        ),
                        Err(_) => warn!(
                            target: LOG_GATEWAY,
                            federation_id = %fed.federation_id,
                            operation_id = ?op,
                            "Timed out reconciling a cancelled send against the node"
                        ),
                    }
                    finished_lookups.fetch_add(1, Ordering::Relaxed);
                }
            }
        };

        let budget_expired = tokio::time::timeout(RECONCILE_PASS_BUDGET, reconciliation)
            .await
            .is_err();
        if budget_expired {
            warn!(
                target: LOG_GATEWAY,
                budget_secs = RECONCILE_PASS_BUDGET.as_secs(),
                total_lookups,
                remaining_lookups =
                    total_lookups.saturating_sub(finished_lookups.load(Ordering::Relaxed)),
                "Reconciling cancelled sends against the node ran out of budget; \
                 scoring what was gathered and retrying the rest next report"
            );
        }

        // Nothing prunes the cache on its own, and a gateway that runs for
        // months accumulates an entry per cancelled send ever reconciled.
        // `compute_ledger` rebuilds `reconcile` from scratch every report, so
        // the set below is exactly the operations that can still be looked up;
        // an entry outside it will never be read again. Bounded by the live
        // reconcile set, which is itself bounded by the retained history.
        {
            let live: BTreeSet<OperationId> = ledger
                .federations
                .iter()
                .flat_map(|fed| fed.reconcile.iter().map(|(op, _)| *op))
                .collect();
            let mut cache = self
                .phantom_lookup_cache
                .lock()
                .expect("phantom-lookup cache mutex is never held across an .await");
            cache.retain(|op, _| live.contains(op));
        }

        // Every `.await` is done by this point, so the reported-phantoms
        // mutex below can be held for the whole (purely synchronous) pass.
        let mut phantom_count = 0u64;
        {
            let mut reported = self
                .phantom_failures_reported
                .lock()
                .expect("phantom-failures-reported mutex is never held across an .await");
            let mut current_reported = BTreeSet::new();

            for (fed, statuses) in ledger.federations.iter_mut().zip(fed_statuses.iter()) {
                for (op, loss) in phantom_losses(statuses) {
                    match classify_phantom(loss) {
                        PhantomKind::UnknownAmount => {
                            fed.unknown_forwards += 1;
                            warn!(
                                target: LOG_GATEWAY,
                                federation_id = %fed.federation_id,
                                operation_id = ?op,
                                "Phantom failure: the node settled a cancelled send but reported no amount"
                            );
                        }
                        PhantomKind::Loss(loss) => {
                            phantom_count += 1;
                            fed.realized_margin_msat =
                                fed.realized_margin_msat.saturating_add(loss);
                            if loss < 0 {
                                fed.negative_forwards.push((op, loss));
                            }

                            let key = (fed.federation_id, op);
                            current_reported.insert(key);
                            if reported.contains(&key) {
                                tracing::debug!(
                                    target: LOG_GATEWAY,
                                    federation_id = %fed.federation_id,
                                    operation_id = ?op,
                                    loss_msat = loss,
                                    "Phantom failure: the send was cancelled but the node settled the payment"
                                );
                            } else {
                                tracing::error!(
                                    target: LOG_GATEWAY,
                                    federation_id = %fed.federation_id,
                                    operation_id = ?op,
                                    loss_msat = loss,
                                    "Phantom failure: the send was cancelled but the node settled the payment"
                                );
                            }
                        }
                    }
                }
            }

            if budget_expired {
                // The pass was cut short, so `current_reported` is a partial
                // view: a phantom that was not looked up this tick is missing
                // from it, and replacing would re-escalate it to `error!` next
                // tick. Union instead, and let the wholesale replacement happen
                // on the next pass that completes.
                reported.extend(current_reported);
            } else {
                *reported = current_reported;
            }
        }
        crate::metrics::GATEWAY_PHANTOM_FAILURES
            .set(i64::try_from(phantom_count).unwrap_or(i64::MAX));

        ledger.cumulative_margin_msat = ledger
            .federations
            .iter()
            .fold(0i64, |acc, f| acc.saturating_add(f.realized_margin_msat));

        // What `ensure_exposure_allows` reads instead of rescanning per
        // request. Replaced wholesale so a federation the gateway has left
        // stops being remembered.
        {
            let mut snapshot = self
                .open_positions_last_report
                .lock()
                .expect("open-positions snapshot mutex is never held across an .await");
            *snapshot = ledger
                .federations
                .iter()
                .map(|fed| (fed.federation_id, fed.open_positions_msat))
                .collect();
        }

        let mut dbtx = self.gateway_db.begin_transaction().await;
        let previous = dbtx.load_drawdown_peak().await;
        let peak = advance_peak(previous, ledger.cumulative_margin_msat, ledger.total_assets);
        if previous != Some(peak) {
            dbtx.save_drawdown_peak(&peak).await;
        }
        dbtx.commit_tx().await;

        let drawdown_pct = drawdown_pct(&peak, ledger.cumulative_margin_msat);
        let verdict = self.drawdown_thresholds.evaluate(drawdown_pct);

        crate::metrics::GATEWAY_DRAWDOWN_PCT.set(drawdown_pct);
        crate::metrics::GATEWAY_CUMULATIVE_MARGIN_MSAT.set(ledger.cumulative_margin_msat);

        // A federation that has since left would otherwise keep exporting its
        // last-known value forever; `reset` drops every label, and the loop
        // below re-sets only the federations still present.
        crate::metrics::GATEWAY_FEDERATION_REALIZED_MARGIN_MSAT.reset();
        for fed in &ledger.federations {
            crate::metrics::GATEWAY_FEDERATION_REALIZED_MARGIN_MSAT
                .with_label_values(&[&fed.federation_id.to_string()])
                .set(fed.realized_margin_msat);
        }

        // Stale positions are sticky (a position that goes stale does not become
        // fresh again on its own), so logging this on every 60s tick would be
        // permanent warn-level noise. Warn only when a federation's stale set
        // changed since the last report; otherwise it's already-known information,
        // logged at debug. The very first report (boot gate) has an empty previous
        // set, so it always warns if there is anything stale to report.
        {
            let mut previous_stale = self
                .stale_positions_last_report
                .lock()
                .expect("stale-position tracking mutex is never held across a panic");
            let mut current_stale = BTreeSet::new();
            for fed in &ledger.federations {
                for op_id in &fed.stale_positions {
                    current_stale.insert((fed.federation_id, *op_id));
                }

                if fed.stale_positions.is_empty() {
                    continue;
                }

                let current_fed_stale: BTreeSet<OperationId> =
                    fed.stale_positions.iter().copied().collect();
                let previous_fed_stale: BTreeSet<OperationId> = previous_stale
                    .iter()
                    .filter(|(federation_id, _)| *federation_id == fed.federation_id)
                    .map(|(_, op_id)| *op_id)
                    .collect();

                if current_fed_stale == previous_fed_stale {
                    tracing::debug!(
                        target: LOG_GATEWAY,
                        federation_id = %fed.federation_id,
                        count = fed.stale_positions.len(),
                        "Open positions older than the stale threshold are no longer counted as assets"
                    );
                } else {
                    warn!(
                        target: LOG_GATEWAY,
                        federation_id = %fed.federation_id,
                        count = fed.stale_positions.len(),
                        "Open positions older than the stale threshold are no longer counted as assets"
                    );
                }
            }
            *previous_stale = current_stale;
        }

        match verdict {
            Verdict::Ok => {
                tracing::debug!(target: LOG_GATEWAY, drawdown_pct, "Solvency check passed");
            }
            Verdict::Warn => warn!(
                target: LOG_GATEWAY,
                drawdown_pct,
                breakdown = %ledger,
                "Forwarding drawdown exceeds the warning threshold"
            ),
            Verdict::Halt => tracing::error!(
                target: LOG_GATEWAY,
                drawdown_pct,
                halt_pct = self.drawdown_thresholds.halt_pct(),
                breakdown = %ledger,
                "Forwarding drawdown exceeds the halt threshold. Review the breakdown; to override, raise FM_GATEWAY_DRAWDOWN_HALT_PCT and restart"
            ),
        }

        Ok(SolvencyReport {
            ledger,
            peak,
            drawdown_pct,
            verdict,
        })
    }

    /// Re-evaluates solvency while running. A halt verdict at runtime moves
    /// the gateway to `ShuttingDown` via `Gateway::shut_down_and_drain`
    /// (exactly like an operator-initiated `/stop`), then unconditionally
    /// awaits the in-flight drain itself, bounded by the same three-minute
    /// deadline the operator path uses for its own shutdown join, before
    /// exiting the process: the boot gate then holds the gateway down until
    /// an operator intervenes, which is the behaviour the spec asks for.
    ///
    /// The unconditional await matters because `shut_down_and_drain` only
    /// waits for the drain when *it* is the one making the
    /// `Running -> ShuttingDown` transition. If an operator's `/stop`
    /// landed during this tick's (multi-second) evaluation window, the
    /// state is already `ShuttingDown` by the time this halt branch runs,
    /// so `shut_down_and_drain` would return immediately without waiting
    /// for that operator-initiated drain to finish — exiting mid-forward
    /// would leave the gateway having spent ecash for a payment its sender
    /// gets refunded, and the boot gate would then strand it at
    /// `pending()` forever.
    pub(crate) fn spawn_solvency_task(&self) {
        let self_copy = self.clone();
        self.task_group
            .spawn_cancellable_silent("solvency check", async move {
                const CHECK_INTERVAL: Duration = Duration::from_secs(60);
                // Same deadline the operator `/stop` path uses for its shutdown join.
                const DRAIN_TIMEOUT: Duration = Duration::from_mins(3);
                let mut interval = tokio::time::interval(CHECK_INTERVAL);
                loop {
                    interval.tick().await;

                    // `get_lightning_context` also accepts `ShuttingDown`, so check the
                    // state explicitly: an operator-initiated shutdown is already
                    // draining in-flight forwards, and a halt verdict firing mid-drain
                    // would race that drain instead of deferring to it.
                    if matches!(
                        self_copy.get_state().await,
                        GatewayState::ShuttingDown { .. }
                    ) {
                        continue;
                    }

                    let Ok(context) = self_copy.get_lightning_context().await else {
                        continue;
                    };
                    match self_copy.solvency_report(context.lnrpc.as_ref()).await {
                        Ok(report) if report.verdict == Verdict::Halt => {
                            // `solvency_report` already logged the halt at `error!`.
                            //
                            // `shut_down_and_drain` performs the transition (and its own
                            // drain) only when it makes the `Running -> ShuttingDown` move
                            // itself; it must stay that way so a double `/stop` from
                            // `handle_shutdown_msg` keeps returning immediately. Await the
                            // drain ourselves, unconditionally, so an operator's `/stop`
                            // landing mid-evaluation can never be cut short by this exit.
                            if let Err(err) = self_copy.shut_down_and_drain().await {
                                warn!(
                                    target: LOG_GATEWAY,
                                    err = %err.fmt_compact(),
                                    "Error draining in-flight payments before halt exit"
                                );
                            }

                            match tokio::time::timeout(DRAIN_TIMEOUT, async {
                                self_copy
                                    .federation_manager
                                    .read()
                                    .await
                                    .wait_for_incoming_payments()
                                    .await
                            })
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => warn!(
                                    target: LOG_GATEWAY,
                                    err = %err.fmt_compact(),
                                    "Error draining in-flight payments before halt exit"
                                ),
                                Err(_) => tracing::error!(
                                    target: LOG_GATEWAY,
                                    timeout_secs = DRAIN_TIMEOUT.as_secs(),
                                    "Timed out draining in-flight payments before halt exit; \
                                     in-flight forwards may be stranded. No new forwards were \
                                     accepted while shutting down"
                                ),
                            }

                            std::process::exit(1);
                        }
                        Ok(_) => {}
                        Err(err) => warn!(
                            target: LOG_GATEWAY,
                            err = %err.fmt_compact_anyhow(),
                            "Solvency check could not be evaluated"
                        ),
                    }
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    use bitcoin::hashes::{Hash as _, sha256};
    use fedimint_core::config::FederationId;
    use fedimint_core::core::OperationId;
    use fedimint_core::{Amount, OutPoint, TransactionId};
    use fedimint_gateway_server_db::DrawdownPeak;
    use fedimint_gwv2_client::audit::{CircuitOutcome, ForwardFact, ReceiveOutcome, SendOutcome};
    use fedimint_lightning::OutboundCost;

    use super::*;

    fn op(n: u8) -> OperationId {
        OperationId([n; 32])
    }

    fn txid(n: u8) -> TransactionId {
        TransactionId::from_raw_hash(sha256::Hash::hash(&[n]))
    }

    fn ln_cost(amount: u64, fee: u64) -> OutboundCost {
        OutboundCost::Lightning {
            amount_sent: Amount::from_msats(amount),
            fee: Some(Amount::from_msats(fee)),
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn fact(fact: ForwardFact, active: bool) -> FactInput {
        FactInput {
            fact,
            created_at: now(),
            active,
        }
    }

    // Owning the inputs keeps each test's call site to a single expression.
    #[allow(clippy::needless_pass_by_value)]
    fn score(
        facts: Vec<FactInput>,
        issuance: BTreeMap<(TransactionId, u64), IssuanceOutcome>,
        incoming: BTreeMap<OperationId, Amount>,
    ) -> FederationLedger {
        score_federation(
            FederationId::dummy(),
            Amount::from_msats(1_000_000),
            &facts,
            &issuance,
            &incoming,
            now(),
            Duration::from_hours(24),
        )
    }

    #[test]
    fn claimed_send_is_realized_only_once_every_note_is_issued() {
        let outpoint = OutPoint {
            txid: txid(1),
            out_idx: 0,
        };
        let send = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::Claimed {
                cost: ln_cost(1_000, 3),
                outpoints: vec![outpoint],
            },
        };

        let pending = score(
            vec![fact(send.clone(), false)],
            BTreeMap::from([((txid(1), 0), IssuanceOutcome::Pending)]),
            BTreeMap::new(),
        );
        assert_eq!(pending.realized_margin_msat, 0);
        assert_eq!(pending.open_positions_msat, 1_010);

        let issued = score(
            vec![fact(send.clone(), false)],
            BTreeMap::from([((txid(1), 0), IssuanceOutcome::Succeeded)]),
            BTreeMap::new(),
        );
        assert_eq!(issued.realized_margin_msat, 7);
        assert_eq!(issued.open_positions_msat, 0);

        let rejected = score(
            vec![fact(send, false)],
            BTreeMap::from([((txid(1), 0), IssuanceOutcome::Failed)]),
            BTreeMap::new(),
        );
        assert_eq!(rejected.realized_margin_msat, -1_003);
        assert_eq!(rejected.negative_forwards, vec![(op(1), -1_003)]);
    }

    #[test]
    fn legacy_claims_and_missing_fees_are_unknown_not_guessed() {
        let legacy = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(10),
            payment_hash: None,
            outcome: SendOutcome::ClaimedUnknownCost { outpoints: vec![] },
        };
        let no_fee = ForwardFact::Send {
            operation_id: op(2),
            contract_amount: Amount::from_msats(10),
            payment_hash: None,
            outcome: SendOutcome::Claimed {
                cost: OutboundCost::Lightning {
                    amount_sent: Amount::from_msats(9),
                    fee: None,
                },
                outpoints: vec![],
            },
        };
        let ledger = score(
            vec![fact(legacy, false), fact(no_fee, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.unknown_forwards, 2);
        assert_eq!(ledger.realized_margin_msat, 0);
    }

    #[test]
    fn incoming_margin_needs_a_completed_circuit_and_its_amount() {
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Success,
        };
        let completed = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let failed = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Failed,
        };
        let amounts = BTreeMap::from([(op(9), Amount::from_msats(1_000))]);

        let ok = score(
            vec![fact(receive.clone(), false), fact(completed.clone(), false)],
            BTreeMap::new(),
            amounts.clone(),
        );
        assert_eq!(ok.realized_margin_msat, 10);

        let one_legged = score(
            vec![fact(receive.clone(), false), fact(failed, false)],
            BTreeMap::new(),
            amounts,
        );
        assert_eq!(one_legged.realized_margin_msat, -990);

        let swap_side = score(
            vec![fact(receive.clone(), false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(swap_side.realized_margin_msat, 0);
        assert_eq!(swap_side.unknown_forwards, 0);

        let no_amount = score(
            vec![fact(receive, false), fact(completed, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(no_amount.unknown_forwards, 1);
    }

    #[test]
    fn funding_is_at_risk_until_it_goes_stale() {
        let funding = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(500)),
            outcome: ReceiveOutcome::Funding,
        };
        let fresh = score(
            vec![fact(funding.clone(), true)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(fresh.open_positions_msat, 500);

        let stale = score(
            vec![FactInput {
                fact: funding,
                created_at: now() - Duration::from_hours(25),
                active: true,
            }],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(stale.open_positions_msat, 0);
        assert_eq!(stale.stale_positions, vec![op(1)]);
    }

    #[test]
    fn cancellations_after_dispatch_are_queued_for_reconciliation() {
        let hash = sha256::Hash::hash(b"h");
        let cancelled = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(10),
            payment_hash: Some(hash),
            outcome: SendOutcome::Cancelled {
                after_dispatch: true,
            },
        };
        let ledger = score(
            vec![fact(cancelled, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.reconcile, vec![(op(1), hash)]);
    }

    #[test]
    fn drawdown_is_measured_from_the_peak_against_assets_at_peak() {
        let peak = advance_peak(None, 1_000, Amount::from_msats(100_000));
        assert_eq!(peak.peak_cumulative_margin_msat, 1_000);
        assert_eq!(peak.assets_at_peak_msat, 100_000);

        // A withdrawal after the peak must not move the ratio.
        let same = advance_peak(Some(peak), 500, Amount::from_msats(10_000));
        assert_eq!(same, peak);
        assert!((drawdown_pct(&peak, 500) - 0.5).abs() < f64::EPSILON);

        let higher = advance_peak(Some(peak), 3_000, Amount::from_msats(50_000));
        assert_eq!(higher.peak_cumulative_margin_msat, 3_000);
        assert_eq!(higher.assets_at_peak_msat, 50_000);
    }

    // Exactly zero is the assertion: a fresh gateway must not divide by zero
    // and must not report a near-zero drawdown either.
    #[allow(clippy::float_cmp)]
    #[test]
    fn fresh_gateway_has_zero_drawdown_not_a_division_by_zero() {
        let peak = DrawdownPeak {
            peak_cumulative_margin_msat: 0,
            assets_at_peak_msat: 0,
        };
        assert_eq!(drawdown_pct(&peak, -5_000), 0.0);
    }

    #[test]
    fn thresholds_validate_and_evaluate() {
        assert!(DrawdownThresholds::new(10.0, 2.0).is_err());
        assert!(DrawdownThresholds::new(2.0, 2.0).is_err());
        assert!(DrawdownThresholds::new(-1.0, 2.0).is_err());
        assert!(DrawdownThresholds::new(f64::NAN, 2.0).is_err());

        let t = DrawdownThresholds::new(2.0, 10.0).expect("valid");
        assert_eq!(t.evaluate(1.99), Verdict::Ok);
        assert_eq!(t.evaluate(2.0), Verdict::Warn);
        assert_eq!(t.evaluate(9.99), Verdict::Warn);
        assert_eq!(t.evaluate(10.0), Verdict::Halt);
    }

    // An outpoint missing from the issuance map must default to `Pending`,
    // not to `Succeeded`: this is the load-bearing regression test for
    // `unwrap_or(IssuanceOutcome::Pending)`.
    #[test]
    fn absent_outpoint_is_booked_pending_not_succeeded() {
        let outpoint = OutPoint {
            txid: txid(1),
            out_idx: 0,
        };
        let send = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::Claimed {
                cost: ln_cost(1_000, 3),
                outpoints: vec![outpoint],
            },
        };
        let ledger = score(vec![fact(send, false)], BTreeMap::new(), BTreeMap::new());
        assert_eq!(ledger.realized_margin_msat, 0);
        assert_eq!(ledger.open_positions_msat, 1_010);
        assert_eq!(ledger.unknown_forwards, 0);
    }

    #[test]
    fn multiple_completed_circuits_sum_their_amounts() {
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(1_000)),
            outcome: ReceiveOutcome::Success,
        };
        let first = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let second = ForwardFact::Circuit {
            completion_operation_id: op(10),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let amounts = BTreeMap::from([
            (op(9), Amount::from_msats(600)),
            (op(10), Amount::from_msats(500)),
        ]);
        let ledger = score(
            vec![
                fact(receive, false),
                fact(first, false),
                fact(second, false),
            ],
            BTreeMap::new(),
            amounts,
        );
        assert_eq!(ledger.realized_margin_msat, 100);
        assert_eq!(ledger.open_positions_msat, 0);
    }

    #[test]
    fn any_completed_circuit_wins_over_failed_or_pending() {
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Success,
        };
        let completed = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let amounts = BTreeMap::from([(op(9), Amount::from_msats(1_000))]);

        let failed = ForwardFact::Circuit {
            completion_operation_id: op(10),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Failed,
        };
        let with_failed = score(
            vec![
                fact(receive.clone(), false),
                fact(completed.clone(), false),
                fact(failed, false),
            ],
            BTreeMap::new(),
            amounts.clone(),
        );
        assert_eq!(with_failed.realized_margin_msat, 10);
        assert_eq!(with_failed.open_positions_msat, 0);

        let pending = ForwardFact::Circuit {
            completion_operation_id: op(11),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Pending,
        };
        let with_pending = score(
            vec![
                fact(receive, false),
                fact(completed, false),
                fact(pending, false),
            ],
            BTreeMap::new(),
            amounts,
        );
        assert_eq!(with_pending.realized_margin_msat, 10);
        assert_eq!(with_pending.open_positions_msat, 0);
    }

    #[test]
    fn pending_only_circuit_leaves_receive_open() {
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(700)),
            outcome: ReceiveOutcome::Success,
        };
        let pending = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Pending,
        };
        let ledger = score(
            vec![fact(receive, false), fact(pending, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.open_positions_msat, 700);
        assert_eq!(ledger.realized_margin_msat, 0);
    }

    #[test]
    fn lost_receive_realizes_negative_margin() {
        let lost = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(500)),
            outcome: ReceiveOutcome::Lost,
        };
        let ledger = score(vec![fact(lost, false)], BTreeMap::new(), BTreeMap::new());
        assert_eq!(ledger.realized_margin_msat, -500);
        assert_eq!(ledger.negative_forwards, vec![(op(1), -500)]);
    }

    #[test]
    fn in_flight_send_contributes_nothing() {
        let send = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_000),
            payment_hash: None,
            outcome: SendOutcome::InFlight,
        };
        let ledger = score(vec![fact(send, false)], BTreeMap::new(), BTreeMap::new());
        assert_eq!(ledger.realized_margin_msat, 0);
        assert_eq!(ledger.open_positions_msat, 0);
        assert_eq!(ledger.unknown_forwards, 0);
        assert_eq!(ledger.negative_forwards, vec![]);
        assert_eq!(ledger.reconcile, vec![]);
        assert_eq!(ledger.stale_positions, vec![]);
    }

    // Same staleness rule as `funding_is_at_risk_until_it_goes_stale`, but on
    // the Send side: `PaidAwaitingClaim` is LNv1-only and does not go through
    // `ReceiveOutcome::Funding`.
    #[test]
    fn paid_awaiting_claim_send_goes_stale_like_funding() {
        let paid = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(500),
            payment_hash: None,
            outcome: SendOutcome::PaidAwaitingClaim { cost: None },
        };
        let fresh = score(
            vec![fact(paid.clone(), true)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(fresh.open_positions_msat, 500);
        assert_eq!(fresh.stale_positions, vec![]);

        let stale = score(
            vec![FactInput {
                fact: paid,
                created_at: now() - Duration::from_hours(25),
                active: true,
            }],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(stale.open_positions_msat, 0);
        assert_eq!(stale.stale_positions, vec![op(1)]);
    }

    #[test]
    fn receive_without_amount_is_unknown_except_not_funded() {
        for outcome in [
            ReceiveOutcome::Funding,
            ReceiveOutcome::Success,
            ReceiveOutcome::Lost,
        ] {
            let receive = ForwardFact::Receive {
                operation_id: op(1),
                contract_amount: None,
                outcome,
            };
            let ledger = score(vec![fact(receive, false)], BTreeMap::new(), BTreeMap::new());
            assert_eq!(ledger.unknown_forwards, 1, "{outcome:?}");
        }

        let not_funded = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: None,
            outcome: ReceiveOutcome::NotFunded,
        };
        let ledger = score(
            vec![fact(not_funded, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.unknown_forwards, 0);
    }

    #[test]
    fn not_funded_receive_with_amount_contributes_nothing() {
        let not_funded = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(500)),
            outcome: ReceiveOutcome::NotFunded,
        };
        let ledger = score(
            vec![fact(not_funded, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.realized_margin_msat, 0);
        assert_eq!(ledger.open_positions_msat, 0);
        assert_eq!(ledger.unknown_forwards, 0);
    }

    #[test]
    fn cancellations_that_skip_reconciliation() {
        let hash = sha256::Hash::hash(b"h");
        let before_dispatch = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(10),
            payment_hash: Some(hash),
            outcome: SendOutcome::Cancelled {
                after_dispatch: false,
            },
        };
        let ledger = score(
            vec![fact(before_dispatch, false)],
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(ledger.reconcile, vec![]);

        let no_hash = ForwardFact::Send {
            operation_id: op(2),
            contract_amount: Amount::from_msats(10),
            payment_hash: None,
            outcome: SendOutcome::Cancelled {
                after_dispatch: true,
            },
        };
        let ledger = score(vec![fact(no_hash, false)], BTreeMap::new(), BTreeMap::new());
        assert_eq!(ledger.reconcile, vec![]);
    }

    // A fresh gateway with a negative cumulative margin must record a floor
    // of zero at the current assets, not a negative peak; a prior peak that
    // already exceeds the current margin must not move.
    #[test]
    fn advance_peak_floors_negative_margin_and_keeps_prior_peak() {
        let fresh = advance_peak(None, -500, Amount::from_msats(700));
        assert_eq!(fresh.peak_cumulative_margin_msat, 0);
        assert_eq!(fresh.assets_at_peak_msat, 700);

        let prior = DrawdownPeak {
            peak_cumulative_margin_msat: 1_000,
            assets_at_peak_msat: 5_000,
        };
        let unchanged = advance_peak(Some(prior), -500, Amount::from_msats(9_999));
        assert_eq!(unchanged, prior);
    }

    #[test]
    fn a_settled_payment_behind_a_cancelled_send_is_a_realized_loss() {
        let statuses = vec![
            (op(1), Some(OutboundPaymentStatus::Failed)),
            (op(2), None),
            (op(3), Some(OutboundPaymentStatus::Pending)),
            (
                op(4),
                Some(OutboundPaymentStatus::Succeeded {
                    amount_sent: Amount::from_msats(1_000),
                    fee: Some(Amount::from_msats(2)),
                }),
            ),
            (
                op(5),
                Some(OutboundPaymentStatus::Succeeded {
                    amount_sent: Amount::from_msats(1_000),
                    fee: None,
                }),
            ),
        ];
        assert_eq!(
            phantom_losses(&statuses),
            vec![(op(4), -1_002), (op(5), -1_000)]
        );
    }

    // `phantom_losses` scores a settled payment with an unknown amount
    // (`amount_sent` of zero, e.g. LDK's `amount_msat: None`) as a `0`
    // loss; the reconciler must not book that as a genuine break-even
    // forward. `classify_phantom` is the pure decision point that tells the
    // two cases apart.
    #[test]
    fn classify_phantom_treats_a_computed_zero_as_an_unknown_amount_not_a_loss() {
        assert_eq!(classify_phantom(-1_002), PhantomKind::Loss(-1_002));
        assert_eq!(classify_phantom(0), PhantomKind::UnknownAmount);
    }

    /// The gateway's claim path only ever emits `CreatedMulti`, whose encoded
    /// variant index (4) sorts *after* the terminal `Succeeded` (3), so the
    /// byte-ordered scan hands the pending record over last. Precedence has to
    /// decide, not arrival order.
    #[test]
    fn issuance_resolves_by_precedence_not_by_scan_order() {
        use IssuanceOutcome::{Failed, Pending, Succeeded};

        // `CreatedMulti` then `Succeeded`, and the reverse, for the same range.
        assert_eq!(merge_issuance(Some(Pending), Succeeded), Succeeded);
        assert_eq!(merge_issuance(Some(Succeeded), Pending), Succeeded);

        // A failure anywhere in an issuance's history is a failure.
        assert_eq!(merge_issuance(Some(Succeeded), Failed), Failed);
        assert_eq!(merge_issuance(Some(Failed), Succeeded), Failed);
        assert_eq!(merge_issuance(Some(Pending), Failed), Failed);
        assert_eq!(merge_issuance(Some(Failed), Pending), Failed);

        assert_eq!(merge_issuance(None, Pending), Pending);
        assert_eq!(merge_issuance(None, Succeeded), Succeeded);
    }

    /// The join `merge_issuance` protects, end to end: a claimed send whose
    /// outpoint the scan reports as both `Succeeded` and (later) pending must
    /// realize its margin rather than sit in an open position forever.
    #[test]
    fn a_claim_seen_as_succeeded_then_pending_is_still_realized() {
        let outpoint = OutPoint {
            txid: txid(1),
            out_idx: 0,
        };
        let send = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::Claimed {
                cost: ln_cost(1_000, 3),
                outpoints: vec![outpoint],
            },
        };

        let mut issuance = BTreeMap::new();
        for order in [
            [IssuanceOutcome::Succeeded, IssuanceOutcome::Pending],
            [IssuanceOutcome::Pending, IssuanceOutcome::Succeeded],
        ] {
            issuance.clear();
            for outcome in order {
                let key = (txid(1), 0);
                let merged = merge_issuance(issuance.get(&key).copied(), outcome);
                issuance.insert(key, merged);
            }
            let ledger = score(
                vec![fact(send.clone(), false)],
                issuance.clone(),
                BTreeMap::new(),
            );
            assert_eq!(ledger.realized_margin_msat, 7, "{order:?}");
            assert_eq!(ledger.open_positions_msat, 0, "{order:?}");
        }
    }

    /// The inactive set holds every state a machine passed through, so a
    /// completed receive's own `Funding` record is in it. Scoring both books a
    /// permanent open position for a forward that already settled.
    #[test]
    fn collapse_keeps_only_the_most_advanced_receive_record() {
        let funding = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Funding,
        };
        let success = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Success,
        };

        for order in [
            vec![fact(funding.clone(), false), fact(success.clone(), false)],
            vec![fact(success.clone(), false), fact(funding.clone(), false)],
        ] {
            let collapsed = collapse_facts(order);
            assert_eq!(collapsed.len(), 1);
            assert_eq!(collapsed[0].fact, success);
        }

        // A rejected receive is just as terminal as a successful one.
        let rejected = ForwardFact::Receive {
            operation_id: op(2),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::NotFunded,
        };
        let collapsed = collapse_facts(vec![
            fact(
                ForwardFact::Receive {
                    operation_id: op(2),
                    contract_amount: Some(Amount::from_msats(990)),
                    outcome: ReceiveOutcome::Funding,
                },
                false,
            ),
            fact(rejected.clone(), false),
        ]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, rejected);
    }

    #[test]
    fn collapse_keeps_only_the_most_advanced_send_record() {
        let sending = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::InFlight,
        };
        let paid = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::PaidAwaitingClaim { cost: None },
        };
        let claimed = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(1_010),
            payment_hash: None,
            outcome: SendOutcome::Claimed {
                cost: ln_cost(1_000, 3),
                outpoints: vec![],
            },
        };

        let collapsed = collapse_facts(vec![
            fact(sending.clone(), false),
            fact(paid.clone(), false),
            fact(claimed.clone(), false),
        ]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, claimed);

        // Reverse arrival order must not change the answer.
        let collapsed = collapse_facts(vec![
            fact(claimed.clone(), false),
            fact(paid, false),
            fact(sending, false),
        ]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, claimed);

        // A cancellation is terminal too.
        let cancelled = ForwardFact::Send {
            operation_id: op(2),
            contract_amount: Amount::from_msats(10),
            payment_hash: None,
            outcome: SendOutcome::Cancelled {
                after_dispatch: false,
            },
        };
        let collapsed = collapse_facts(vec![
            fact(
                ForwardFact::Send {
                    operation_id: op(2),
                    contract_amount: Amount::from_msats(10),
                    payment_hash: None,
                    outcome: SendOutcome::InFlight,
                },
                false,
            ),
            fact(cancelled.clone(), false),
        ]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, cancelled);
    }

    /// A failed circuit's retained history is `[Pending, Pending, Failed]`.
    /// Uncollapsed, the `all(Failed)` test that books the one-legged loss is
    /// false and the loss reads as an open position instead.
    #[test]
    fn a_failed_circuits_history_collapses_to_a_realized_loss() {
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Success,
        };
        let circuit = |outcome| ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome,
        };

        let history = vec![
            fact(receive.clone(), false),
            fact(circuit(CircuitOutcome::Pending), false),
            fact(circuit(CircuitOutcome::Pending), false),
            fact(circuit(CircuitOutcome::Failed), false),
        ];
        let collapsed = collapse_facts(history);
        assert_eq!(collapsed.len(), 2);
        assert!(
            collapsed
                .iter()
                .any(|input| input.fact == circuit(CircuitOutcome::Failed))
        );

        let ledger = score_federation(
            FederationId::dummy(),
            Amount::from_msats(1_000_000),
            &collapsed,
            &BTreeMap::new(),
            &BTreeMap::new(),
            now(),
            Duration::from_hours(24),
        );
        assert_eq!(ledger.realized_margin_msat, -990);
        assert_eq!(ledger.open_positions_msat, 0);
    }

    /// The machine is still running, so its inactive records are its past and
    /// the active one is where it actually is -- even when the inactive record
    /// looks more advanced.
    #[test]
    fn an_active_record_beats_every_inactive_one_for_the_same_instance() {
        let funding = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Funding,
        };
        let success = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(990)),
            outcome: ReceiveOutcome::Success,
        };

        let collapsed = collapse_facts(vec![
            fact(success.clone(), false),
            fact(funding.clone(), true),
        ]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, funding);
        assert!(collapsed[0].active);

        let collapsed = collapse_facts(vec![fact(funding.clone(), true), fact(success, false)]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].fact, funding);
        assert!(collapsed[0].active);
    }

    /// Distinct instances are never merged: two completions of the same
    /// receive, and a send and a receive sharing an operation id, all survive.
    #[test]
    fn collapse_keeps_one_record_per_instance_not_per_operation() {
        let first = ForwardFact::Circuit {
            completion_operation_id: op(9),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let second = ForwardFact::Circuit {
            completion_operation_id: op(10),
            receive_operation_id: op(1),
            outcome: CircuitOutcome::Completed,
        };
        let send = ForwardFact::Send {
            operation_id: op(1),
            contract_amount: Amount::from_msats(10),
            payment_hash: None,
            outcome: SendOutcome::InFlight,
        };
        let receive = ForwardFact::Receive {
            operation_id: op(1),
            contract_amount: Some(Amount::from_msats(10)),
            outcome: ReceiveOutcome::Funding,
        };

        let collapsed = collapse_facts(vec![
            fact(first, false),
            fact(second, false),
            fact(send, false),
            fact(receive, false),
        ]);
        assert_eq!(collapsed.len(), 4);
    }

    /// A `{0, 0}` peak persisted before the gateway held funds would otherwise
    /// never advance while the margin stays at or below zero, so the ratio
    /// would read zero forever -- the gateway attacked from its first forward.
    #[test]
    fn a_zero_asset_peak_re_anchors_once_the_gateway_holds_funds() {
        let empty = DrawdownPeak {
            peak_cumulative_margin_msat: 0,
            assets_at_peak_msat: 0,
        };
        let anchored = advance_peak(Some(empty), -500, Amount::from_msats(100_000));
        assert_eq!(anchored.peak_cumulative_margin_msat, 0);
        assert_eq!(anchored.assets_at_peak_msat, 100_000);
        assert!((drawdown_pct(&anchored, -500) - 0.5).abs() < f64::EPSILON);

        // Still nothing to anchor to: leave it alone rather than recording a
        // second zero.
        assert_eq!(advance_peak(Some(empty), -500, Amount::ZERO), empty);

        // A non-zero denominator is never re-anchored by this rule.
        let real = DrawdownPeak {
            peak_cumulative_margin_msat: 1_000,
            assets_at_peak_msat: 5_000,
        };
        assert_eq!(advance_peak(Some(real), 500, Amount::from_msats(1)), real);
    }

    #[test]
    fn exposure_counts_ecash_open_positions_and_the_new_forward() {
        let limit = Amount::from_msats(1_000);
        assert!(!exposure_exceeded(
            Amount::from_msats(500),
            300,
            Amount::from_msats(200),
            limit
        ));
        assert!(exposure_exceeded(
            Amount::from_msats(500),
            300,
            Amount::from_msats(201),
            limit
        ));
        assert!(exposure_exceeded(
            Amount::from_msats(u64::MAX),
            1,
            Amount::ZERO,
            limit
        ));
    }
}
