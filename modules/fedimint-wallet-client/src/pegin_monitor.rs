use std::cmp;
use std::time::{Duration, SystemTime};

use anyhow::anyhow;
use bitcoin::ScriptBuf;
use fedimint_api_client::api::DynModuleApi;
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_client_module::module::{ClientContext, OutPointRange};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _,
};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::module::{serde_json, Amounts};
use fedimint_core::task::sleep;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{BitcoinHash, TransactionId, secp256k1, time};
use fedimint_logging::LOG_CLIENT_MODULE_WALLET;
use fedimint_wallet_common::txoproof::PegInProof;
use fedimint_wallet_common::{WalletCommonInit, WalletInput};
use futures::StreamExt as _;
use secp256k1::Keypair;
use tokio::sync::watch;
use tracing::{debug, instrument, trace, warn};

use crate::api::WalletFederationApi as _;
use crate::client_db::{
    ClaimedPegInData, ClaimedPegInKey, PegInTweakIndexData, PegInTweakIndexKey,
    PegInTweakIndexPrefix, TweakIdx,
};
use crate::events::{DepositConfirmed, ReceivePaymentEvent};
use crate::{
    WalletClientModule, WalletClientModuleData, WalletOperationMeta, WalletOperationMetaVariant,
};

/// A helper struct meant to combined data from all addresses/records
/// into a single struct with all actionable data.
#[derive(Debug, Clone)]
struct NextActions {
    /// Current time
    now: SystemTime,
    /// Index keys due for a check
    due: Vec<(PegInTweakIndexKey, PegInTweakIndexData)>,
    /// Nearest key that is not due yet
    next: Option<SystemTime>,
}

impl NextActions {
    pub fn new() -> Self {
        Self {
            now: time::now(),
            due: vec![],
            next: None,
        }
    }
}

impl NextActions {
    /// Calculate next actions from the database
    async fn from_db_state(db: &Database) -> Self {
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&PegInTweakIndexPrefix)
            .await
            .fold(NextActions::new(), |state, (key, val)| async {
                state.fold(key, val)
            })
            .await
    }

    /// Combine current state with another record
    pub fn fold(mut self, key: PegInTweakIndexKey, val: PegInTweakIndexData) -> Self {
        if let Some(next_check_time) = val.next_check_time {
            if next_check_time < self.now {
                self.due.push((key, val));
            }

            self.next = match self.next {
                Some(existing) => Some(existing.min(next_check_time)),
                None => Some(next_check_time),
            };
        }
        self
    }
}

/// A deposit monitoring task
///
/// On the high level it maintains a list of derived addresses with some info
/// like when is the next time to check for deposits on them.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_peg_in_monitor(
    client_ctx: ClientContext<WalletClientModule>,
    db: Database,
    btc_rpc: DynBitcoindRpc,
    module_api: DynModuleApi,
    data: WalletClientModuleData,
    pegin_claimed_sender: watch::Sender<()>,
    mut wakeup_receiver: watch::Receiver<()>,
) {
    let min_sleep: Duration = if is_running_in_test_env() {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(30)
    };

    loop {
        if let Err(err) = check_for_deposits(
            &db,
            &data,
            &btc_rpc,
            &module_api,
            &client_ctx,
            &pegin_claimed_sender,
        )
        .await
        {
            warn!(target: LOG_CLIENT_MODULE_WALLET, error = %err.fmt_compact_anyhow(), "Error checking for deposits");
            continue;
        }

        let now = time::now();
        let next_wakeup = NextActions::from_db_state(&db).await.next.unwrap_or_else(||
            /* for simplicity just wake up every hour, even when there's no need */
              now + Duration::from_secs(60 * 60));
        let next_wakeup_duration = next_wakeup
            .duration_since(now)
            .unwrap_or_default()
            .max(min_sleep);
        debug!(target: LOG_CLIENT_MODULE_WALLET, sleep_msecs=%next_wakeup_duration.as_millis(), "Sleep after completing due checks");
        tokio::select! {
            () = sleep(next_wakeup_duration) => {
                debug!(target: LOG_CLIENT_MODULE_WALLET, "Woken up by a scheduled wakeup");
            },
            res = wakeup_receiver.changed() => {
                debug!(target: LOG_CLIENT_MODULE_WALLET, "Woken up by a signal");
                if res.is_err() {
                    debug!(target: LOG_CLIENT_MODULE_WALLET,  "Terminating peg-in monitor");
                    return;
                }
            }
        }
    }
}

async fn check_for_deposits(
    db: &Database,
    data: &WalletClientModuleData,
    btc_rpc: &DynBitcoindRpc,
    module_api: &DynModuleApi,
    client_ctx: &ClientContext<WalletClientModule>,
    pengin_claimed_sender: &watch::Sender<()>,
) -> Result<(), anyhow::Error> {
    let due = NextActions::from_db_state(db).await.due;
    trace!(target: LOG_CLIENT_MODULE_WALLET, ?due, "Checking for deposists");
    for (due_key, due_val) in due {
        check_and_claim_idx_pegins(
            data,
            due_key,
            btc_rpc,
            module_api,
            db,
            client_ctx,
            due_val,
            pengin_claimed_sender,
        )
        .await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn check_and_claim_idx_pegins(
    data: &WalletClientModuleData,
    due_key: PegInTweakIndexKey,
    btc_rpc: &DynBitcoindRpc,
    module_api: &DynModuleApi,
    db: &Database,
    client_ctx: &ClientContext<WalletClientModule>,
    due_val: PegInTweakIndexData,
    pengin_claimed_sender: &watch::Sender<()>,
) -> Result<(), anyhow::Error> {
    let now = time::now();
    match check_idx_pegins(data, due_key.0, btc_rpc, module_api, db, client_ctx).await {
        Ok(outcomes) => {
            let next_check_time = CheckOutcome::retry_delay_vec(&outcomes, due_val.creation_time)
                .map(|duration| now + duration);
            db
                .autocommit(
                    |dbtx, _| {
                        Box::pin(async {
                            let claimed_now = CheckOutcome::get_claimed_now_outpoints(&outcomes);

                            let claimed_sender = pengin_claimed_sender.clone();
                            dbtx.on_commit(move || {
                                claimed_sender.send_replace(());
                            });

                            let peg_in_tweak_index_data = PegInTweakIndexData {
                                next_check_time,
                                last_check_time: Some(now),
                                claimed: [due_val.claimed.clone(), claimed_now].concat(),
                                ..due_val
                            };
                            trace!(
                                target: LOG_CLIENT_MODULE_WALLET,
                                tweak_idx=%due_key.0,
                                due_in_secs=?next_check_time.map(|next_check_time| next_check_time.duration_since(now).unwrap_or_default().as_secs()),
                                data=?peg_in_tweak_index_data,
                                "Updating"
                            );
                            dbtx
                                .insert_entry(&due_key, &peg_in_tweak_index_data)
                                .await;

                            Ok::<_, anyhow::Error>(())
                        })
                    },
                    None,
                )
                .await?;
        }
        Err(err) => {
            debug!(target: LOG_CLIENT_MODULE_WALLET, err = %err.fmt_compact_anyhow(), tweak_idx=%due_key.0, "Error checking tweak_idx");
        }
    }
    Ok(())
}

/// Outcome of checking a single deposit Bitcoin transaction output
///
/// For every address there can be multiple outcomes (`Vec<Self>`).
#[derive(Copy, Clone, Debug)]
enum CheckOutcome {
    /// There's a tx pending (needs more confirmation)
    Pending { num_blocks_needed: u64 },
    /// A state machine was created to claim the peg-in
    Claimed { outpoint: bitcoin::OutPoint },

    /// A peg-in transaction was already claimed (state machine created) in the
    /// past
    AlreadyClaimed,
}

impl CheckOutcome {
    /// Desired retry delay for a single outcome
    ///
    /// None means "no need to check anymore".
    fn retry_delay(self) -> Option<Duration> {
        match self {
            // Check again in time proportional to the expected block confirmation time
            CheckOutcome::Pending { num_blocks_needed } => {
                if is_running_in_test_env() {
                    // In tests, we basically mine all blocks right away
                    Some(Duration::from_millis(1))
                } else {
                    Some(Duration::from_secs(60 * num_blocks_needed))
                }
            }
            // Once anything has been claimed, there's no reason to claim again automatically,
            // and it's undesirable due to privacy reasons.
            // Users can possibly update the underlying record via other means to force a check on
            // demand.
            CheckOutcome::Claimed { .. } | CheckOutcome::AlreadyClaimed => None,
        }
    }

    /// Desired retry delay for a bunch of outcomes.
    ///
    /// This time is intended to be persisted in the database.
    ///
    /// None means "no need to check anymore".
    fn retry_delay_vec(outcomes: &[CheckOutcome], creation_time: SystemTime) -> Option<Duration> {
        // If the address was allocated, but nothing was ever received or even detected
        // on it yet, check again in time proportional to the age of the
        // address.
        if outcomes.is_empty() {
            if is_running_in_test_env() {
                // When testing we usually send deposits right away, so check more aggressively.
                return Some(Duration::from_millis(100));
            }
            let now = time::now();
            let age = now.duration_since(creation_time).unwrap_or_default();
            return Some(age / 10);
        }

        // The delays is the minimum retry delay.
        let mut min = None;

        for outcome in outcomes {
            min = match (min, outcome.retry_delay()) {
                (None, time) => time,
                (Some(min), None) => Some(min),
                (Some(min), Some(time)) => Some(cmp::min(min, time)),
            };
        }

        min
    }

    fn get_claimed_now_outpoints(outcomes: &[CheckOutcome]) -> Vec<bitcoin::OutPoint> {
        let mut res = vec![];
        for outcome in outcomes {
            if let CheckOutcome::Claimed { outpoint } = outcome {
                res.push(*outpoint);
            }
        }

        res
    }
}

/// Query via btc rpc for a history of an address derived with `tweak_idx` and
/// claim any peg-ins that are ready.
///
/// Return a list of [`CheckOutcome`]s for each matching output.
#[instrument(target = LOG_CLIENT_MODULE_WALLET, skip_all, fields(tweak_idx))]
async fn check_idx_pegins(
    data: &WalletClientModuleData,
    tweak_idx: TweakIdx,
    btc_rpc: &DynBitcoindRpc,
    module_rpc: &DynModuleApi,
    db: &Database,
    client_ctx: &ClientContext<WalletClientModule>,
) -> Result<Vec<CheckOutcome>, anyhow::Error> {
    let current_consensus_block_count = module_rpc.fetch_consensus_block_count().await?;
    let (script, address, tweak_key, operation_id) = data.derive_peg_in_script(tweak_idx);
    btc_rpc.watch_script_history(&script).await?;

    let history = btc_rpc.get_script_history(&script).await?;

    debug!(target: LOG_CLIENT_MODULE_WALLET, %address, num_txes=history.len(), "Got history of a peg-in address");

    let mut outcomes = vec![];

    for (transaction, out_idx) in filter_onchain_deposit_outputs(history.into_iter(), &script) {
        let txid = transaction.compute_txid();
        let outpoint = bitcoin::OutPoint {
            txid,
            vout: out_idx,
        };

        let claimed_peg_in_key = ClaimedPegInKey {
            peg_in_index: tweak_idx,
            btc_out_point: outpoint,
        };

        if db
            .begin_transaction_nc()
            .await
            .get_value(&claimed_peg_in_key)
            .await
            .is_some()
        {
            debug!(target: LOG_CLIENT_MODULE_WALLET, %txid, %out_idx, "Already claimed");
            outcomes.push(CheckOutcome::AlreadyClaimed);
            continue;
        }
        let finality_delay = u64::from(data.cfg.finality_delay);

        let tx_block_count =
            if let Some(tx_block_height) = btc_rpc.get_tx_block_height(&txid).await? {
                tx_block_height.saturating_add(1)
            } else {
                outcomes.push(CheckOutcome::Pending {
                    num_blocks_needed: finality_delay,
                });
                debug!(target:LOG_CLIENT_MODULE_WALLET, %txid, %out_idx,"In the mempool");
                continue;
            };

        let num_blocks_needed = tx_block_count.saturating_sub(current_consensus_block_count);

        if 0 < num_blocks_needed {
            outcomes.push(CheckOutcome::Pending { num_blocks_needed });
            debug!(target: LOG_CLIENT_MODULE_WALLET, %txid, %out_idx, %num_blocks_needed, %finality_delay, %tx_block_count, %current_consensus_block_count, "Needs more confirmations");
            continue;
        }

        debug!(target: LOG_CLIENT_MODULE_WALLET, %txid, %out_idx, %finality_delay, %tx_block_count, %current_consensus_block_count, "Ready to claim");

        let tx_out_proof = btc_rpc.get_txout_proof(txid).await?;
        let federation_knows_utxo = module_rpc.is_utxo_confirmed(outpoint).await?;

        claim_peg_in(
            client_ctx,
            tweak_idx,
            tweak_key,
            &transaction,
            operation_id,
            outpoint,
            tx_out_proof,
            federation_knows_utxo,
        )
        .await?;
        outcomes.push(CheckOutcome::Claimed { outpoint });
    }
    Ok(outcomes)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn claim_peg_in(
    client_ctx: &ClientContext<WalletClientModule>,
    tweak_idx: TweakIdx,
    tweak_key: Keypair,
    transaction: &bitcoin::Transaction,
    address_operation_id: OperationId,
    out_point: bitcoin::OutPoint,
    tx_out_proof: TxOutProof,
    federation_knows_utxo: bool,
) -> anyhow::Result<()> {
    /// Returns the claim transactions output range if a claim happened or
    /// `None` otherwise if the deposit was smaller than the deposit fee.
    async fn claim_peg_in_inner(
        client_ctx: &ClientContext<WalletClientModule>,
        dbtx: &mut DatabaseTransaction<'_>,
        btc_transaction: &bitcoin::Transaction,
        out_idx: u32,
        tweak_key: Keypair,
        txout_proof: TxOutProof,
        address_operation_id: OperationId,
        receive_operation_id: OperationId,
        federation_knows_utxo: bool,
    ) -> Option<(OutPointRange, bitcoin::Amount)> {
        let pegin_proof = PegInProof::new(
            txout_proof,
            btc_transaction.clone(),
            out_idx,
            tweak_key.public_key(),
        )
        .expect("TODO: handle API returning faulty proofs");

        let amount = pegin_proof.tx_output().value.into();
        let btc_amount = pegin_proof.tx_output().value;
        let wallet_input = if federation_knows_utxo {
            WalletInput::new_v1(&pegin_proof)
        } else {
            WalletInput::new_v0(pegin_proof)
        };

        let client_input = ClientInput::<WalletInput> {
            input: wallet_input,
            keys: vec![tweak_key],
            amounts: Amounts::new_bitcoin(amount),
        };

        if amount <= client_ctx.self_ref().cfg().fee_consensus.peg_in_abs {
            warn!(target: LOG_CLIENT_MODULE_WALLET, "We won't claim a deposit lower than the deposit fee");
            return None;
        }

        let txid = btc_transaction.compute_txid();

        client_ctx
            .log_event(
                dbtx,
                DepositConfirmed {
                    txid,
                    out_idx,
                    amount,
                },
            )
            .await;

        client_ctx
            .log_event(
                dbtx,
                ReceivePaymentEvent {
                    operation_id: address_operation_id,
                    receive_operation_id,
                    amount,
                    txid,
                },
            )
            .await;

        Some((
            client_ctx
                .claim_inputs(
                    dbtx,
                    ClientInputBundle::new_no_sm(vec![client_input]),
                    receive_operation_id,
                )
                .await
                .expect("Cannot claim input, additional funding needed"),
            btc_amount,
        ))
    }

    let tx_out_proof = &tx_out_proof;

    debug!(target: LOG_CLIENT_MODULE_WALLET, %out_point, "Claiming a peg-in");

    // Generate a new operation ID for this specific deposit claim
    let receive_operation_id = OperationId::new_random();

    client_ctx
        .module_db()
        .autocommit(
            |dbtx, _| {
                Box::pin(async {
                    let maybe_claim_result = claim_peg_in_inner(
                        client_ctx,
                        dbtx,
                        transaction,
                        out_point.vout,
                        tweak_key,
                        tx_out_proof.clone(),
                        address_operation_id,
                        receive_operation_id,
                        federation_knows_utxo,
                    )
                    .await;

                    let claimed_pegin_data = if let Some((change_range, btc_amount)) = maybe_claim_result {
                        let claim_txid = change_range.txid();
                        let change: Vec<_> = change_range.into_iter().collect();

                        client_ctx
                            .manual_operation_start_dbtx(
                                dbtx,
                                receive_operation_id,
                                WalletCommonInit::KIND.as_str(),
                                WalletOperationMeta {
                                    variant: WalletOperationMetaVariant::ReceiveDeposit {
                                        address_operation_id,
                                        tweak_idx,
                                        btc_out_point: out_point,
                                        amount: btc_amount,
                                        claim_txid,
                                        change: change.clone(),
                                    },
                                    extra_meta: serde_json::Value::Null,
                                },
                                vec![],
                            )
                            .await?;

                        ClaimedPegInData {
                            claim_txid,
                            change,
                        }
                    } else {
                        ClaimedPegInData {
                            claim_txid: TransactionId::from_byte_array([0; 32]),
                            change: vec![],
                        }
                    };

                    dbtx.insert_entry(
                        &ClaimedPegInKey {
                            peg_in_index: tweak_idx,
                            btc_out_point: out_point,
                        },
                        &claimed_pegin_data,
                    )
                    .await;

                    Ok(())
                })
            },
            Some(100),
        )
        .await
        .map_err(|e| match e {
            AutocommitError::CommitFailed {
                last_error,
                attempts,
            } => anyhow!("Failed to commit after {attempts} attempts: {last_error}"),
            AutocommitError::ClosureError { error, .. } => error,
        })?;

    Ok(())
}

pub(crate) fn filter_onchain_deposit_outputs<'a>(
    tx_iter: impl Iterator<Item = bitcoin::Transaction> + 'a,
    out_script: &'a ScriptBuf,
) -> impl Iterator<Item = (bitcoin::Transaction, u32)> + 'a {
    tx_iter.flat_map(move |tx| {
        tx.output
            .clone()
            .into_iter()
            .enumerate()
            .filter_map(move |(out_idx, tx_out)| {
                if &tx_out.script_pubkey == out_script {
                    Some((tx.clone(), out_idx as u32))
                } else {
                    None
                }
            })
    })
}
