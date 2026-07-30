use std::collections::BTreeMap;
use std::fmt::Debug;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::{ConsensusItem, ConsensusUnixTime, CurrentFeeConsensus};
use fedimint_core::module::{Amounts, CoreConsensusVersion, ModuleConsensusVersion};
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::util::BoxStream;
use fedimint_core::{
    NumPeers, OutPoint, PeerId, TransactionId, apply, async_trait_maybe_send, impl_db_lookup,
    impl_db_record,
};
use fedimint_logging::LOG_CONSENSUS;
use fedimint_server_core::migration::{
    DynModuleHistoryItem, DynServerDbMigrationFn, IServerDbMigrationContext,
};
use futures::StreamExt;
use serde::Serialize;
use tracing::warn;

use crate::db::DbKeyPrefix;

pub const MODULE_FEE_CONSENSUS_LOOKBACK_SECS: u64 = 4 * 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemPrefix;

impl_db_record!(
    key = AcceptedItemKey,
    value = AcceptedItem,
    db_prefix = DbKeyPrefix::AcceptedItem,
    notify_on_modify = false,
);
impl_db_lookup!(key = AcceptedItemKey, query_prefix = AcceptedItemPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl_db_record!(
    key = AcceptedTransactionKey,
    value = Vec<ModuleInstanceId>,
    db_prefix = DbKeyPrefix::AcceptedTransaction,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = AcceptedTransactionKey,
    query_prefix = AcceptedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomeKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomePrefix;

impl_db_record!(
    key = SignedSessionOutcomeKey,
    value = SignedSessionOutcome,
    db_prefix = DbKeyPrefix::SignedSessionOutcome,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = SignedSessionOutcomeKey,
    query_prefix = SignedSessionOutcomePrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsPrefix;

impl_db_record!(
    key = AlephUnitsKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::AlephUnits,
    notify_on_modify = false,
);
impl_db_lookup!(key = AlephUnitsKey, query_prefix = AlephUnitsPrefix);

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleConsensusVersionVoteKey {
    pub module_instance_id: ModuleInstanceId,
    pub peer_id: PeerId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleConsensusVersionVotePrefix {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleConsensusVersionVoteFullPrefix;

impl_db_record!(
    key = ModuleConsensusVersionVoteKey,
    value = ModuleConsensusVersion,
    db_prefix = DbKeyPrefix::ModuleConsensusVersionVote,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ModuleConsensusVersionVoteKey,
    query_prefix = ModuleConsensusVersionVotePrefix
);

impl_db_lookup!(
    key = ModuleConsensusVersionVoteKey,
    query_prefix = ModuleConsensusVersionVoteFullPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleConsensusVersionVotingActivationKey {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleConsensusVersionVotingActivationPrefix;

impl_db_record!(
    key = ModuleConsensusVersionVotingActivationKey,
    value = ModuleConsensusVersion,
    db_prefix = DbKeyPrefix::ModuleConsensusVersionVotingActivation,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ModuleConsensusVersionVotingActivationKey,
    query_prefix = ModuleConsensusVersionVotingActivationPrefix
);

pub async fn active_module_consensus_version<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    module_instance_id: ModuleInstanceId,
    num_peers: NumPeers,
    initial_version: ModuleConsensusVersion,
    legacy_consensus_version_votes: BTreeMap<PeerId, ModuleConsensusVersion>,
) -> ModuleConsensusVersion
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    let core_consensus_version_votes = dbtx
        .find_by_prefix(&ModuleConsensusVersionVotePrefix { module_instance_id })
        .await
        .map(|(key, version)| (key.peer_id, version))
        .collect::<BTreeMap<PeerId, ModuleConsensusVersion>>()
        .await;

    active_module_consensus_version_from_votes(
        num_peers,
        initial_version,
        legacy_consensus_version_votes,
        core_consensus_version_votes,
    )
}

fn active_module_consensus_version_from_votes(
    num_peers: NumPeers,
    initial_version: ModuleConsensusVersion,
    mut legacy_consensus_version_votes: BTreeMap<PeerId, ModuleConsensusVersion>,
    core_consensus_version_votes: BTreeMap<PeerId, ModuleConsensusVersion>,
) -> ModuleConsensusVersion {
    for (peer_id, version) in core_consensus_version_votes {
        legacy_consensus_version_votes.insert(peer_id, version);
    }

    let mut versions = legacy_consensus_version_votes
        .values()
        .copied()
        .collect::<Vec<ModuleConsensusVersion>>();

    assert!(
        versions.len() <= num_peers.total(),
        "module consensus version votes exceed peer count"
    );

    while versions.len() < num_peers.total() {
        versions.push(initial_version);
    }

    assert_eq!(versions.len(), num_peers.total());

    versions.sort_unstable();

    assert!(versions.first() <= versions.last());

    versions[num_peers.max_evil()]
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct CoreConsensusVersionVoteKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct CoreConsensusVersionVotePrefix;

impl_db_record!(
    key = CoreConsensusVersionVoteKey,
    value = CoreConsensusVersion,
    db_prefix = DbKeyPrefix::CoreConsensusVersionVote,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = CoreConsensusVersionVoteKey,
    query_prefix = CoreConsensusVersionVotePrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct CoreConsensusVersionVotingActivationKey;

#[derive(Debug, Encodable, Decodable)]
pub struct CoreConsensusVersionVotingActivationPrefix;

impl_db_record!(
    key = CoreConsensusVersionVotingActivationKey,
    value = CoreConsensusVersion,
    db_prefix = DbKeyPrefix::CoreConsensusVersionVotingActivation,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = CoreConsensusVersionVotingActivationKey,
    query_prefix = CoreConsensusVersionVotingActivationPrefix
);

/// The core consensus version currently active for the federation.
///
/// This is the version agreed on at DKG time, raised by the highest version a
/// threshold of peers has voted for.
pub async fn active_core_consensus_version<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    num_peers: NumPeers,
    initial_version: CoreConsensusVersion,
) -> CoreConsensusVersion
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    let votes = dbtx
        .find_by_prefix(&CoreConsensusVersionVotePrefix)
        .await
        .map(|(key, version)| (key.0, version))
        .collect::<BTreeMap<PeerId, CoreConsensusVersion>>()
        .await;

    active_core_consensus_version_from_votes(num_peers, initial_version, votes)
}

/// Aggregates per-peer core consensus version votes with the same threshold
/// rule [`active_module_consensus_version_from_votes`] uses for modules: peers
/// which have not voted count as voting for `initial_version`, and the active
/// version is the highest version at least `num_peers.threshold()` peers vote
/// for or above.
///
/// The result is monotonic. Per-peer votes may only ever increase (enforced
/// when the vote consensus item is processed) and `initial_version` is applied
/// as a hard floor here, so a vote can never lower the active version.
fn active_core_consensus_version_from_votes(
    num_peers: NumPeers,
    initial_version: CoreConsensusVersion,
    votes: BTreeMap<PeerId, CoreConsensusVersion>,
) -> CoreConsensusVersion {
    let mut versions = votes
        .values()
        .copied()
        .collect::<Vec<CoreConsensusVersion>>();

    assert!(
        versions.len() <= num_peers.total(),
        "core consensus version votes exceed peer count"
    );

    while versions.len() < num_peers.total() {
        versions.push(initial_version);
    }

    versions.sort_unstable();

    let threshold_version = *versions
        .get(num_peers.max_evil())
        .expect("versions has exactly one entry per peer");

    threshold_version.max(initial_version)
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AccruedFeesKey;

#[derive(Debug, Encodable, Decodable)]
pub struct AccruedFeesPrefix;

impl_db_record!(
    key = AccruedFeesKey,
    value = Amounts,
    db_prefix = DbKeyPrefix::AccruedFees,
    notify_on_modify = true,
);

impl_db_lookup!(key = AccruedFeesKey, query_prefix = AccruedFeesPrefix);

/// Fees the federation has charged and not yet paid out to guardians.
///
/// Multi-unit, so the ledger is independent of the asset a fee was charged in.
pub async fn accrued_fees<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> Amounts
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    dbtx.get_value(&AccruedFeesKey)
        .await
        .unwrap_or(Amounts::ZERO)
}

/// Credits `fees` to the accrued fee ledger.
///
/// On overflow the ledger is left unchanged rather than saturating, so it can
/// never credit more than was actually charged. Every peer processes the same
/// ordered transactions, so this decision is deterministic.
pub async fn accrue_fees(dbtx: &mut DatabaseTransaction<'_>, fees: &Amounts) {
    if *fees == Amounts::ZERO {
        return;
    }

    let accrued = accrued_fees(dbtx).await;

    let Some(accrued) = accrued.checked_add(fees) else {
        warn!(
            target: LOG_CONSENSUS,
            ?fees,
            "Accrued fee ledger overflow, leaving the ledger unchanged"
        );

        return;
    };

    dbtx.insert_entry(&AccruedFeesKey, &accrued).await;
}

/// Debits `amounts` from the accrued fee ledger, returning `false` and leaving
/// the ledger unchanged if it does not hold that much in every unit.
pub async fn debit_accrued_fees(dbtx: &mut DatabaseTransaction<'_>, amounts: &Amounts) -> bool {
    let Some(remaining) = accrued_fees(dbtx).await.checked_sub(amounts) else {
        return false;
    };

    dbtx.insert_entry(&AccruedFeesKey, &remaining).await;

    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IRawDatabaseExt as _};
    use fedimint_core::module::{
        AmountUnit, Amounts, CoreConsensusVersion, ModuleConsensusVersion,
    };
    use fedimint_core::{Amount, NumPeers, PeerId};

    use super::{
        accrue_fees, accrued_fees, active_core_consensus_version_from_votes,
        active_module_consensus_version_from_votes, debit_accrued_fees,
    };

    fn test_db() -> Database {
        MemDatabase::new().into_database()
    }

    fn custom(unit: u64, msats: u64) -> Amounts {
        Amounts::new_custom(AmountUnit::new_custom(unit), Amount::from_msats(msats))
    }

    #[tokio::test]
    async fn accrued_fees_accumulate_per_unit() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(1000)).await;
        accrue_fees(&mut dbtx.to_ref_nc(), &custom(7, 42)).await;
        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(500)).await;

        let expected = Amounts::new_bitcoin_msats(1500)
            .checked_add(&custom(7, 42))
            .expect("no overflow");

        assert_eq!(accrued_fees(&mut dbtx.to_ref_nc()).await, expected);
    }

    #[tokio::test]
    async fn accruing_zero_fees_is_a_no_op() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::ZERO).await;

        assert_eq!(accrued_fees(&mut dbtx.to_ref_nc()).await, Amounts::ZERO);
    }

    #[tokio::test]
    async fn debit_rejects_more_than_accrued() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(1000)).await;

        assert!(
            !debit_accrued_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(1001)).await,
            "debit beyond the accrued balance must be rejected"
        );
        assert_eq!(
            accrued_fees(&mut dbtx.to_ref_nc()).await,
            Amounts::new_bitcoin_msats(1000),
            "a rejected debit must leave the ledger unchanged"
        );

        assert!(debit_accrued_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(400)).await);
        assert_eq!(
            accrued_fees(&mut dbtx.to_ref_nc()).await,
            Amounts::new_bitcoin_msats(600)
        );
    }

    #[tokio::test]
    async fn debit_rejects_units_the_ledger_does_not_hold() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(1000)).await;

        assert!(
            !debit_accrued_fees(&mut dbtx.to_ref_nc(), &custom(7, 1)).await,
            "a unit the ledger holds nothing of must not be debitable"
        );
        assert_eq!(
            accrued_fees(&mut dbtx.to_ref_nc()).await,
            Amounts::new_bitcoin_msats(1000)
        );
    }

    #[tokio::test]
    async fn accrue_leaves_ledger_unchanged_on_overflow() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        let huge = Amounts::new_bitcoin_msats(u64::MAX);
        accrue_fees(&mut dbtx.to_ref_nc(), &huge).await;
        accrue_fees(&mut dbtx.to_ref_nc(), &Amounts::new_bitcoin_msats(1)).await;

        assert_eq!(
            accrued_fees(&mut dbtx.to_ref_nc()).await,
            huge,
            "an overflowing accrual must not credit anything"
        );
    }

    #[test]
    fn active_module_consensus_version_merges_legacy_and_core_votes() {
        let initial = ModuleConsensusVersion::new(1, 0);
        let legacy = BTreeMap::from([
            (PeerId::from(0), ModuleConsensusVersion::new(2, 0)),
            (PeerId::from(1), ModuleConsensusVersion::new(2, 0)),
            (PeerId::from(2), ModuleConsensusVersion::new(2, 0)),
            (PeerId::from(3), ModuleConsensusVersion::new(1, 0)),
        ]);
        let core = BTreeMap::from([(PeerId::from(3), ModuleConsensusVersion::new(2, 0))]);

        assert_eq!(
            active_module_consensus_version_from_votes(NumPeers::from(4), initial, legacy, core),
            ModuleConsensusVersion::new(2, 0)
        );
    }

    #[test]
    fn active_core_consensus_version_defaults_to_config_version() {
        assert_eq!(
            active_core_consensus_version_from_votes(
                NumPeers::from(4),
                CoreConsensusVersion::new(2, 1),
                BTreeMap::new(),
            ),
            CoreConsensusVersion::new(2, 1)
        );
    }

    #[test]
    fn active_core_consensus_version_requires_threshold() {
        let initial = CoreConsensusVersion::new(2, 1);

        // Two out of four peers is below the threshold of three.
        assert_eq!(
            active_core_consensus_version_from_votes(
                NumPeers::from(4),
                initial,
                BTreeMap::from([
                    (PeerId::from(0), CoreConsensusVersion::new(2, 2)),
                    (PeerId::from(1), CoreConsensusVersion::new(2, 2)),
                ]),
            ),
            initial
        );

        // Three out of four peers reach the threshold.
        assert_eq!(
            active_core_consensus_version_from_votes(
                NumPeers::from(4),
                initial,
                BTreeMap::from([
                    (PeerId::from(0), CoreConsensusVersion::new(2, 2)),
                    (PeerId::from(1), CoreConsensusVersion::new(2, 2)),
                    (PeerId::from(2), CoreConsensusVersion::new(2, 2)),
                ]),
            ),
            CoreConsensusVersion::new(2, 2)
        );

        // A threshold only counts for the highest version all of them agree on.
        assert_eq!(
            active_core_consensus_version_from_votes(
                NumPeers::from(4),
                initial,
                BTreeMap::from([
                    (PeerId::from(0), CoreConsensusVersion::new(3, 0)),
                    (PeerId::from(1), CoreConsensusVersion::new(2, 2)),
                    (PeerId::from(2), CoreConsensusVersion::new(2, 2)),
                    (PeerId::from(3), CoreConsensusVersion::new(2, 2)),
                ]),
            ),
            CoreConsensusVersion::new(2, 2)
        );
    }

    #[test]
    fn active_core_consensus_version_never_decreases() {
        let initial = CoreConsensusVersion::new(2, 2);

        // Votes below the config version must not lower the active version.
        assert_eq!(
            active_core_consensus_version_from_votes(
                NumPeers::from(4),
                initial,
                BTreeMap::from([
                    (PeerId::from(0), CoreConsensusVersion::new(2, 0)),
                    (PeerId::from(1), CoreConsensusVersion::new(2, 0)),
                    (PeerId::from(2), CoreConsensusVersion::new(2, 0)),
                    (PeerId::from(3), CoreConsensusVersion::new(2, 0)),
                ]),
            ),
            initial
        );

        // Neither may they lower a version that has already been voted active.
        let mut votes = BTreeMap::from([
            (PeerId::from(0), CoreConsensusVersion::new(2, 3)),
            (PeerId::from(1), CoreConsensusVersion::new(2, 3)),
            (PeerId::from(2), CoreConsensusVersion::new(2, 3)),
        ]);

        assert_eq!(
            active_core_consensus_version_from_votes(NumPeers::from(4), initial, votes.clone()),
            CoreConsensusVersion::new(2, 3)
        );

        votes.insert(PeerId::from(3), CoreConsensusVersion::new(2, 0));

        assert_eq!(
            active_core_consensus_version_from_votes(NumPeers::from(4), initial, votes),
            CoreConsensusVersion::new(2, 3)
        );
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct CoreUnixTimeVoteKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct CoreUnixTimeVotePrefix;

impl_db_record!(
    key = CoreUnixTimeVoteKey,
    value = ConsensusUnixTime,
    db_prefix = DbKeyPrefix::CoreUnixTimeVote,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = CoreUnixTimeVoteKey,
    query_prefix = CoreUnixTimeVotePrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct ConsensusUnixTimeKey;

#[derive(Debug, Encodable, Decodable)]
pub struct ConsensusUnixTimePrefix;

impl_db_record!(
    key = ConsensusUnixTimeKey,
    value = ConsensusUnixTime,
    db_prefix = DbKeyPrefix::ConsensusUnixTime,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ConsensusUnixTimeKey,
    query_prefix = ConsensusUnixTimePrefix
);

pub async fn consensus_unix_time<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> ConsensusUnixTime
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    dbtx.get_value(&ConsensusUnixTimeKey)
        .await
        .unwrap_or_default()
}

pub async fn consensus_unix_time_from_votes<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    num_peers: NumPeers,
) -> ConsensusUnixTime
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    let mut times = dbtx
        .find_by_prefix(&CoreUnixTimeVotePrefix)
        .await
        .map(|entry| entry.1)
        .collect::<Vec<ConsensusUnixTime>>()
        .await;

    times.sort_unstable();
    times.reverse();

    assert!(times.last() <= times.first());

    times
        .get(num_peers.threshold() - 1)
        .copied()
        .unwrap_or_default()
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusVoteKey {
    pub module_instance_id: ModuleInstanceId,
    pub peer_id: PeerId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusVotePrefix {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusVoteFullPrefix;

impl_db_record!(
    key = ModuleFeeConsensusVoteKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::ModuleFeeConsensusVote,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ModuleFeeConsensusVoteKey,
    query_prefix = ModuleFeeConsensusVotePrefix
);

impl_db_lookup!(
    key = ModuleFeeConsensusVoteKey,
    query_prefix = ModuleFeeConsensusVoteFullPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusDesiredKey {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusDesiredPrefix;

impl_db_record!(
    key = ModuleFeeConsensusDesiredKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::ModuleFeeConsensusDesired,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ModuleFeeConsensusDesiredKey,
    query_prefix = ModuleFeeConsensusDesiredPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusScheduleKey {
    pub module_instance_id: ModuleInstanceId,
    pub active_since: ConsensusUnixTime,
    pub sequence: u64,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusSchedulePrefix {
    pub module_instance_id: ModuleInstanceId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ModuleFeeConsensusScheduleFullPrefix;

impl_db_record!(
    key = ModuleFeeConsensusScheduleKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::ModuleFeeConsensusSchedule,
    notify_on_modify = true,
);

impl_db_lookup!(
    key = ModuleFeeConsensusScheduleKey,
    query_prefix = ModuleFeeConsensusSchedulePrefix
);

impl_db_lookup!(
    key = ModuleFeeConsensusScheduleKey,
    query_prefix = ModuleFeeConsensusScheduleFullPrefix
);

pub async fn current_module_fee_consensus<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    module_instance_id: ModuleInstanceId,
    initial_fee_consensus: Vec<u8>,
) -> CurrentFeeConsensus
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    dbtx.find_by_prefix(&ModuleFeeConsensusSchedulePrefix { module_instance_id })
        .await
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .max_by_key(|(key, _)| (key.active_since, key.sequence))
        .map_or(
            CurrentFeeConsensus {
                active_since: ConsensusUnixTime::default(),
                fee_consensus: initial_fee_consensus,
            },
            |(key, fee_consensus)| CurrentFeeConsensus {
                active_since: key.active_since,
                fee_consensus,
            },
        )
}

pub async fn module_fee_consensus_schedules<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    module_instance_id: ModuleInstanceId,
    current_time: ConsensusUnixTime,
    initial_fee_consensus: Vec<u8>,
) -> Vec<CurrentFeeConsensus>
where
    for<'tx> DatabaseTransaction<'tx, Cap>: IDatabaseTransactionOpsCore,
{
    let cutoff = ConsensusUnixTime(
        current_time
            .0
            .saturating_sub(MODULE_FEE_CONSENSUS_LOOKBACK_SECS),
    );
    let mut stored_schedules = dbtx
        .find_by_prefix(&ModuleFeeConsensusSchedulePrefix { module_instance_id })
        .await
        .collect::<Vec<_>>()
        .await;

    stored_schedules.sort_by_key(|(key, _)| (key.active_since, key.sequence));

    let previous_schedule = stored_schedules
        .iter()
        .rev()
        .find(|(key, _)| key.active_since < cutoff)
        .map_or(
            CurrentFeeConsensus {
                fee_consensus: initial_fee_consensus,
                active_since: ConsensusUnixTime::default(),
            },
            |(key, fee_consensus)| CurrentFeeConsensus {
                fee_consensus: fee_consensus.clone(),
                active_since: key.active_since,
            },
        );

    let mut schedules = vec![previous_schedule];
    schedules.extend(
        stored_schedules
            .into_iter()
            .filter_map(|(key, fee_consensus)| {
                (cutoff <= key.active_since).then_some(CurrentFeeConsensus {
                    fee_consensus,
                    active_since: key.active_since,
                })
            }),
    );

    schedules
}

pub fn get_global_database_migrations() -> BTreeMap<DatabaseVersion, DynServerDbMigrationFn> {
    BTreeMap::new()
}

/// A concrete implementation of [`IServerDbMigrationContext`] APIs
/// available for server-module db migrations.
pub struct ServerDbMigrationContext;

#[apply(async_trait_maybe_send!)]
impl IServerDbMigrationContext for ServerDbMigrationContext {
    async fn get_module_history_stream<'s, 'tx>(
        &'s self,
        module_instance_id: ModuleInstanceId,
        dbtx: &'s mut DatabaseTransaction<'tx>,
    ) -> BoxStream<'s, DynModuleHistoryItem>
    where
        'tx: 's,
    {
        dbtx.ensure_global().expect("Dbtx must be global");

        // Items of the currently ongoing session, that have already been processed. We
        // have to query them in full first and collect them into a vector so we don't
        // hold two references to the dbtx at the same time.
        let active_session_items = dbtx
            .find_by_prefix(&AcceptedItemPrefix)
            .await
            .map(|(_, item)| item)
            .collect::<Vec<_>>()
            .await;

        let stream =
            dbtx.find_by_prefix(&SignedSessionOutcomePrefix)
                .await
                // Transform the session stream into an accepted item stream
                .flat_map(|(_, signed_session_outcome): (_, SignedSessionOutcome)| {
                    futures::stream::iter(signed_session_outcome.session_outcome.items)
                })
                // Append the accepted items from the current session after all the signed session
                // items have been processed
                .chain(futures::stream::iter(active_session_items))
                .flat_map(move |item| {
                    let history_items =
                        match item.item {
                            ConsensusItem::Transaction(tx) => {
                                let txid = tx.tx_hash();
                                let input_items = tx.inputs.into_iter().filter_map(|input| {
                                    (input.module_instance_id() == module_instance_id)
                                        .then_some(DynModuleHistoryItem::Input(input))
                                });

                                let output_items = tx.outputs.into_iter().zip(0..).filter_map(
                                    |(output, out_idx)| {
                                        (output.module_instance_id() == module_instance_id)
                                            .then_some(DynModuleHistoryItem::Output(
                                                output,
                                                OutPoint { txid, out_idx },
                                            ))
                                    },
                                );

                                input_items.chain(output_items).collect::<Vec<_>>()
                            }
                            ConsensusItem::Module(mci) => {
                                if mci.module_instance_id() == module_instance_id {
                                    vec![DynModuleHistoryItem::ConsensusItem(mci)]
                                } else {
                                    vec![]
                                }
                            }
                            ConsensusItem::ModuleConsensusVersion(_)
                            | ConsensusItem::CoreConsensusVersion(_)
                            | ConsensusItem::CoreUnixTime(_)
                            | ConsensusItem::ModuleFeeConsensus(_) => vec![],
                            ConsensusItem::Default { .. } => {
                                unreachable!("We never save unknown CIs on the server side")
                            }
                        };
                    futures::stream::iter(history_items)
                });

        Box::pin(stream)
    }
}
