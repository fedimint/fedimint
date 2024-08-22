mod recovery_history_tracker;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_client::module::init::recovery::{RecoveryFromHistory, RecoveryFromHistoryCommon};
use fedimint_client::module::init::ClientModuleRecoverArgs;
use fedimint_client::module::recovery::{DynModuleBackup, ModuleBackup};
use fedimint_client::module::{ClientContext, ClientDbTxContext};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::{LOG_CLIENT_MODULE_WALLET, LOG_CLIENT_RECOVERY};
use fedimint_wallet_common::{WalletInput, WalletInputV0};
use futures::Future;
use tracing::{debug, trace, warn};

use self::recovery_history_tracker::ConsensusPegInTweakIdxesUsedTracker;
use crate::client_db::{
    NextPegInTweakIndexKey, PegInTweakIndexData, PegInTweakIndexKey, RecoveryFinalizedKey,
    RecoveryStateKey, TweakIdx,
};
use crate::{WalletClientInit, WalletClientModule, WalletClientModuleData};

#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub enum WalletModuleBackup {
    V0(WalletModuleBackupV0),
    V1(WalletModuleBackupV1),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl IntoDynInstance for WalletModuleBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}

impl ModuleBackup for WalletModuleBackup {}

impl WalletModuleBackup {
    pub fn new_v1(
        session_count: u64,
        next_tweak_idx: TweakIdx,
        already_claimed_tweak_idxes: BTreeSet<TweakIdx>,
    ) -> WalletModuleBackup {
        WalletModuleBackup::V1(WalletModuleBackupV1 {
            session_count,
            next_tweak_idx,
            already_claimed_tweak_idxes,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct WalletModuleBackupV0 {
    pub session_count: u64,
    pub next_tweak_idx: TweakIdx,
}

#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct WalletModuleBackupV1 {
    pub session_count: u64,
    pub next_tweak_idx: TweakIdx,
    pub already_claimed_tweak_idxes: BTreeSet<TweakIdx>,
}

#[derive(Debug, Clone, Decodable, Encodable)]
pub struct WalletRecoveryStateV0 {
    snapshot: Option<WalletModuleBackup>,
    next_unused_idx_from_backup: TweakIdx,
    new_start_idx: Option<TweakIdx>,
    tweak_idxes_with_pegins: Option<BTreeSet<TweakIdx>>,
    tracker: ConsensusPegInTweakIdxesUsedTracker,
}

#[derive(Debug, Clone, Decodable, Encodable)]
pub struct WalletRecoveryStateV1 {
    snapshot: Option<WalletModuleBackup>,
    next_unused_idx_from_backup: TweakIdx,
    // If `Some` - backup contained information about which tweak idxes were already claimed (the
    // set can still be empty). If `None` - backup version did not contain that information.
    already_claimed_tweak_idxes_from_backup: Option<BTreeSet<TweakIdx>>,
    new_start_idx: Option<TweakIdx>,
    tweak_idxes_with_pegins: Option<BTreeSet<TweakIdx>>,
    tracker: ConsensusPegInTweakIdxesUsedTracker,
}

#[derive(Debug, Clone, Decodable, Encodable)]
pub enum WalletRecoveryState {
    V0(WalletRecoveryStateV0),
    V1(WalletRecoveryStateV1),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

/// Wallet client module recovery implementation
///
/// First, history of Federation is scanned for expected peg-in addresses being
/// used to find any peg-ins in a perfectly private way.
///
/// Then from that point (`TweakIdx`) Bitcoin node is queried for any peg-ins
/// that might have happened on chain, but not were claimed yet, up to a certain
/// gap limit.
///
/// Eventually last known used `TweakIdx `is moved a bit forward, and that's the
/// new point a client will use for new peg-ins.
#[derive(Clone, Debug)]
pub struct WalletRecovery {
    state: WalletRecoveryStateV1,
    data: WalletClientModuleData,
    btc_rpc: DynBitcoindRpc,
}

#[apply(async_trait_maybe_send!)]
impl RecoveryFromHistory for WalletRecovery {
    type Init = WalletClientInit;

    async fn new(
        init: &WalletClientInit,
        args: &ClientModuleRecoverArgs<Self::Init>,
        snapshot: Option<&WalletModuleBackup>,
    ) -> anyhow::Result<(Self, u64)> {
        trace!(target: LOG_CLIENT_MODULE_WALLET, "Starting new recovery");
        let rpc_config = init
            .0
            .clone()
            .unwrap_or(WalletClientModule::get_rpc_config(args.cfg()));

        let btc_rpc = create_bitcoind(&rpc_config, TaskGroup::new().make_handle())?;

        let data = WalletClientModuleData {
            cfg: args.cfg().clone(),
            module_root_secret: args.module_root_secret().clone(),
        };

        #[allow(clippy::single_match_else)]
        let (
            next_unused_idx_from_backup,
            start_session_idx,
            already_claimed_tweak_idxes_from_backup,
        ) = match snapshot.as_ref() {
            Some(WalletModuleBackup::V0(backup)) => {
                debug!(target: LOG_CLIENT_MODULE_WALLET, ?backup, "Restoring starting from an existing backup (v0)");

                (
                    backup.next_tweak_idx,
                    backup.session_count.saturating_sub(1),
                    None,
                )
            }
            Some(WalletModuleBackup::V1(backup)) => {
                debug!(target: LOG_CLIENT_MODULE_WALLET, ?backup, "Restoring starting from an existing backup (v1)");

                (
                    backup.next_tweak_idx,
                    backup.session_count.saturating_sub(1),
                    Some(backup.already_claimed_tweak_idxes.clone()),
                )
            }
            _ => {
                debug!(target: LOG_CLIENT_MODULE_WALLET, "Restoring without an existing backup");
                (TweakIdx(0), 0, None)
            }
        };

        // fetch consensus height first
        let session_count = args
            .context()
            .global_api()
            .session_count()
            .await?
            // In case something is off, at least don't panic due to start not being before end
            .max(start_session_idx);

        debug!(target: LOG_CLIENT_MODULE_WALLET, next_unused_tweak_idx = ?next_unused_idx_from_backup, "Scanning federation history for used peg-in addresses");

        Ok((
            WalletRecovery {
                state: WalletRecoveryStateV1 {
                    snapshot: snapshot.cloned(),
                    new_start_idx: None,
                    tweak_idxes_with_pegins: None,
                    next_unused_idx_from_backup,
                    already_claimed_tweak_idxes_from_backup,
                    tracker: ConsensusPegInTweakIdxesUsedTracker::new(
                        next_unused_idx_from_backup,
                        start_session_idx,
                        session_count,
                        &data,
                    ),
                },
                data,
                btc_rpc,
            },
            start_session_idx,
        ))
    }

    async fn load_dbtx(
        init: &WalletClientInit,
        dbtx: &mut DatabaseTransaction<'_>,
        args: &ClientModuleRecoverArgs<Self::Init>,
    ) -> anyhow::Result<Option<(Self, RecoveryFromHistoryCommon)>> {
        trace!(target: LOG_CLIENT_MODULE_WALLET, "Loading recovery state");
        let rpc_config = init
            .0
            .clone()
            .unwrap_or(WalletClientModule::get_rpc_config(args.cfg()));

        let btc_rpc = create_bitcoind(&rpc_config, TaskGroup::new().make_handle())?;

        let data = WalletClientModuleData {
            cfg: args.cfg().clone(),
            module_root_secret: args.module_root_secret().clone(),
        };
        Ok(dbtx.get_value(&RecoveryStateKey)
            .await
            .and_then(|(state, common)| {
                if let WalletRecoveryState::V1(state) = state {
                    Some((state, common))
                } else {
                    warn!(target: LOG_CLIENT_RECOVERY, "Found unknown version recovery state. Ignoring");
                    None
                }
            })
            .map(|(state, common)| {
                (
                    WalletRecovery {
                        state,
                        data,
                        btc_rpc,
                    },
                    common,
                )
            }))
    }

    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    ) {
        trace!(target: LOG_CLIENT_MODULE_WALLET, "Storing recovery state");
        dbtx.insert_entry(
            &RecoveryStateKey,
            &(WalletRecoveryState::V1(self.state.clone()), common.clone()),
        )
        .await;
    }

    async fn delete_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) {
        dbtx.remove_entry(&RecoveryStateKey).await;
    }

    async fn load_finalized(dbtx: &mut DatabaseTransaction<'_>) -> Option<bool> {
        dbtx.get_value(&RecoveryFinalizedKey).await
    }

    async fn store_finalized(dbtx: &mut DatabaseTransaction<'_>, state: bool) {
        dbtx.insert_entry(&RecoveryFinalizedKey, &state).await;
    }

    async fn handle_input(
        &mut self,
        _client_ctx: &ClientContext<WalletClientModule>,
        _idx: usize,
        input: &WalletInput,
        session_idx: u64,
    ) -> anyhow::Result<()> {
        let script_pubkey = match input {
            WalletInput::V0(WalletInputV0(ref input)) => &input.tx_output().script_pubkey,
            WalletInput::Default {
                variant: _,
                bytes: _,
            } => {
                return Ok(());
            }
        };

        self.state
            .tracker
            .handle_script(&self.data, script_pubkey, session_idx);

        Ok(())
    }

    async fn pre_finalize(&mut self) -> anyhow::Result<()> {
        let data = &self.data;
        let btc_rpc = &self.btc_rpc;
        // Due to lifetime in async context issue, this one is cloned and wrapped in a
        // mutex
        let tracker = &Arc::new(Mutex::new(self.state.tracker.clone()));

        debug!(target: LOG_CLIENT_MODULE_WALLET,
            next_unused_tweak_idx = ?self.state.next_unused_idx_from_backup,
            "Scanning blockchain for used peg-in addresses");
        let RecoverScanOutcome { last_used_idx: _, new_start_idx, tweak_idxes_with_pegins}
            = recover_scan_idxes_for_activity(
                if self.state.already_claimed_tweak_idxes_from_backup.is_some() {
                    // If the backup contains list of already claimed tweak_idexes, we can just scan
                    // the blockchain addresses starting from tweakidx `0`, without loosing too much privacy,
                    // as we will skip all the idxes that had peg-ins already
                    TweakIdx(0)
                } else {
                    // If backup didn't have it, we just start from the last derived address from backup (or 0 otherwise).
                    self.state.next_unused_idx_from_backup
                },
                &self.state.tracker.used_tweak_idxes()
                    .union(&self.state.already_claimed_tweak_idxes_from_backup.clone().unwrap_or_default())
                    .copied().collect(),
                |cur_tweak_idx: TweakIdx|
                async move {

                    let (script, address, _tweak_key, _operation_id) =
                    data.derive_peg_in_script(cur_tweak_idx);

                    // Randomly query for the decoy before or after our own address
                    let use_decoy_before_real_query : bool = rand::random();
                    let decoy = tracker.lock().expect("locking failed").pop_decoy();

                    let use_decoy = || async {
                        if let Some(decoy) = decoy.as_ref() {
                            btc_rpc.watch_script_history(decoy).await?;
                            let _ = btc_rpc.get_script_history(decoy).await?;
                        }
                        Ok::<_, anyhow::Error>(())
                    };

                    if use_decoy_before_real_query {
                        use_decoy().await?;
                    }
                    btc_rpc.watch_script_history(&script).await?;
                    let history = btc_rpc.get_script_history(&script).await?;

                    if !use_decoy_before_real_query {
                        use_decoy().await?;
                    }

                    debug!(target: LOG_CLIENT_MODULE_WALLET, %cur_tweak_idx, %address, history_len=history.len(), "Checked address");

                    Ok(history)
                }).await?;

        self.state.new_start_idx = Some(new_start_idx);
        self.state.tweak_idxes_with_pegins = Some(tweak_idxes_with_pegins);

        Ok(())
    }

    async fn finalize_dbtx(
        &self,
        dbtx: &mut ClientDbTxContext<'_, '_, WalletClientModule>,
    ) -> anyhow::Result<()> {
        let now = fedimint_core::time::now();

        let mut tweak_idx = TweakIdx(0);

        let new_start_idx = self
            .state
            .new_start_idx
            .expect("Must have new_star_idx already set by previous steps");

        let tweak_idxes_with_pegins = self
            .state
            .tweak_idxes_with_pegins
            .clone()
            .expect("Must be set by previous steps");

        debug!(target: LOG_CLIENT_MODULE_WALLET, ?new_start_idx, "Finalizing recovery");

        while tweak_idx < new_start_idx {
            let (_script, _address, _tweak_key, operation_id) =
                self.data.derive_peg_in_script(tweak_idx);
            dbtx.module_dbtx()
                .insert_new_entry(
                    &PegInTweakIndexKey(tweak_idx),
                    &PegInTweakIndexData {
                        creation_time: now,
                        next_check_time: if tweak_idxes_with_pegins.contains(&tweak_idx) {
                            // The addresses that were already used before, or didn't seem to
                            // contain anything don't need automatic
                            // peg-in attempt, and can be re-attempted
                            // manually if needed.
                            Some(now)
                        } else {
                            None
                        },
                        last_check_time: None,
                        operation_id,
                        claimed: vec![],
                    },
                )
                .await;
            tweak_idx = tweak_idx.next();
        }

        dbtx.module_dbtx()
            .insert_new_entry(&NextPegInTweakIndexKey, &new_start_idx)
            .await;
        Ok(())
    }
}

/// We will check this many addresses after last actually used
/// one before we give up
pub(crate) const RECOVER_MAX_GAP: u64 = 10;
/// New client will start deriving new addresses from last used one
/// plus that many indexes. This should be less than
/// `MAX_GAP`, but more than 0: We want to make sure we detect
/// deposits that might have been made after multiple successive recoveries,
/// but we want also to avoid accidental address re-use.
pub(crate) const RECOVER_NUM_IDX_ADD_TO_LAST_USED: u64 = 8;

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct RecoverScanOutcome {
    pub(crate) last_used_idx: Option<TweakIdx>,
    pub(crate) new_start_idx: TweakIdx,
    pub(crate) tweak_idxes_with_pegins: BTreeSet<TweakIdx>,
}

/// A part of `WalletClientInit::recover` extracted out to be easy to
/// test, as a side-effect free.
pub(crate) async fn recover_scan_idxes_for_activity<F, FF, T>(
    previous_next_unused_idx: TweakIdx,
    used_tweak_idxes: &BTreeSet<TweakIdx>,
    check_addr_history: F,
) -> anyhow::Result<RecoverScanOutcome>
where
    F: Fn(TweakIdx) -> FF,
    FF: Future<Output = anyhow::Result<Vec<T>>>,
{
    let mut last_used_idx = previous_next_unused_idx.prev();

    let mut cur_tweak_idx = previous_next_unused_idx;
    let mut tweak_idxes_with_pegins = BTreeSet::new();

    let new_start_idx = loop {
        let gap_since_last_used = cur_tweak_idx - last_used_idx.unwrap_or_default();

        if RECOVER_MAX_GAP <= gap_since_last_used {
            break last_used_idx
                .unwrap_or_default()
                .advance(RECOVER_NUM_IDX_ADD_TO_LAST_USED);
        }

        if used_tweak_idxes.contains(&cur_tweak_idx) {
            debug!(target: LOG_CLIENT_MODULE_WALLET,
                tweak_idx=%cur_tweak_idx,
                "Skipping checking history of an address, as it was previously used");
            last_used_idx = Some(cur_tweak_idx);
        } else {
            let history = check_addr_history(cur_tweak_idx).await?;

            if !history.is_empty() {
                last_used_idx = Some(cur_tweak_idx);
                tweak_idxes_with_pegins.insert(cur_tweak_idx);
            }
        }
        cur_tweak_idx = cur_tweak_idx.next();
    };

    Ok(RecoverScanOutcome {
        last_used_idx,
        new_start_idx,
        tweak_idxes_with_pegins,
    })
}
