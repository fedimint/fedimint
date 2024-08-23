use std::time::Duration;
use std::{cmp, ops};

use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiVersion, ModuleCommon};
use fedimint_core::session_outcome::{AcceptedItem, SessionStatus};
use fedimint_core::task::{MaybeSend, MaybeSync, ShuttingDownError, TaskGroup};
use fedimint_core::transaction::Transaction;
use fedimint_core::{apply, async_trait_maybe_send, OutPoint};
use fedimint_logging::LOG_CLIENT_RECOVERY;
use futures::{Stream, StreamExt as _};
use rand::{thread_rng, Rng as _};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use super::{ClientModuleInit, ClientModuleRecoverArgs};
use crate::module::recovery::RecoveryProgress;
use crate::module::{ClientContext, ClientDbTxContext, ClientModule};

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
/// Common state tracked during recovery from history
pub struct RecoveryFromHistoryCommon {
    start_session: u64,
    next_session: u64,
    end_session: u64,
}

impl RecoveryFromHistoryCommon {
    pub fn new(start_session: u64, next_session: u64, end_session: u64) -> Self {
        Self {
            start_session,
            next_session,
            end_session,
        }
    }
}

/// Module specific logic for [`ClientModuleRecoverArgs::recover_from_history`]
///
/// See [`ClientModuleRecoverArgs::recover_from_history`] for more information.
#[apply(async_trait_maybe_send!)]
pub trait RecoveryFromHistory: std::fmt::Debug + MaybeSend + MaybeSync + Clone {
    /// [`ClientModuleInit`] of this recovery logic.
    type Init: ClientModuleInit;

    /// New empty state to start recovery from, and session number to start from
    async fn new(
        init: &Self::Init,
        args: &ClientModuleRecoverArgs<Self::Init>,
        snapshot: Option<&<<Self::Init as ClientModuleInit>::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<(Self, u64)>;

    /// Try to load the existing state previously stored with
    /// [`RecoveryFromHistory::store_dbtx`].
    ///
    /// Storing and restoring progress is used to save progress and
    /// continue recovery if it was previously terminated before completion.
    async fn load_dbtx(
        init: &Self::Init,
        dbtx: &mut DatabaseTransaction<'_>,
        args: &ClientModuleRecoverArgs<Self::Init>,
    ) -> anyhow::Result<Option<(Self, RecoveryFromHistoryCommon)>>;

    /// Store the current recovery state in the database
    ///
    /// See [`Self::load_dbtx`].
    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    );

    /// Delete the recovery state from the database
    ///
    /// See [`Self::load_dbtx`].
    async fn delete_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>);

    /// Read the finalization status
    ///
    /// See [`Self::load_dbtx`].
    async fn load_finalized(dbtx: &mut DatabaseTransaction<'_>) -> Option<bool>;

    /// Store finalization status
    ///
    /// See [`Self::load_finalized`].
    async fn store_finalized(dbtx: &mut DatabaseTransaction<'_>, state: bool);

    /// Handle session outcome, adjusting the current state
    ///
    /// It is expected that most implementations don't need to override this
    /// function, and override more granular ones instead (e.g.
    /// [`Self::handle_input`] and/or [`Self::handle_output`]).
    ///
    /// The default implementation will loop through items in the
    /// `session.items` and forward them one by one to respective functions
    /// (see [`Self::handle_transaction`]).
    async fn handle_session(
        &mut self,
        client_ctx: &ClientContext<<Self::Init as ClientModuleInit>::Module>,
        session_idx: u64,
        session_items: &Vec<AcceptedItem>,
    ) -> anyhow::Result<()> {
        for accepted_item in session_items {
            if let ConsensusItem::Transaction(ref transaction) = accepted_item.item {
                self.handle_transaction(client_ctx, transaction, session_idx)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handle session outcome, adjusting the current state
    ///
    /// It is expected that most implementations don't need to override this
    /// function, and override more granular ones instead (e.g.
    /// [`Self::handle_input`] and/or [`Self::handle_output`]).
    ///
    /// The default implementation will loop through inputs and outputs
    /// of the transaction, filter and downcast ones matching current module
    /// and forward them one by one to respective functions
    /// (e.g. [`Self::handle_input`], [`Self::handle_output`]).
    async fn handle_transaction(
        &mut self,
        client_ctx: &ClientContext<<Self::Init as ClientModuleInit>::Module>,
        transaction: &Transaction,
        session_idx: u64,
    ) -> anyhow::Result<()> {
        trace!(
            target: LOG_CLIENT_RECOVERY,
            tx_hash = %transaction.tx_hash(),
            input_num = transaction.inputs.len(),
            output_num = transaction.outputs.len(),
            "processing transaction"
        );

        for (idx, input) in transaction.inputs.iter().enumerate() {
            trace!(
                target: LOG_CLIENT_RECOVERY,
                tx_hash = %transaction.tx_hash(),
                idx,
                module_id = input.module_instance_id(),
                "found transaction input"
            );

            if let Some(own_input) = client_ctx.input_from_dyn(input) {
                self.handle_input(client_ctx, idx, own_input, session_idx)
                    .await?;
            }
        }

        for (out_idx, output) in transaction.outputs.iter().enumerate() {
            trace!(
                target: LOG_CLIENT_RECOVERY,
                tx_hash = %transaction.tx_hash(),
                idx = out_idx,
                module_id = output.module_instance_id(),
                "found transaction output"
            );

            if let Some(own_output) = client_ctx.output_from_dyn(output) {
                let out_point = OutPoint {
                    txid: transaction.tx_hash(),
                    out_idx: out_idx as u64,
                };

                self.handle_output(client_ctx, out_point, own_output, session_idx)
                    .await?;
            }
        }

        Ok(())
    }

    /// Handle transaction input, adjusting the current state
    ///
    /// Default implementation does nothing.
    async fn handle_input(
        &mut self,
        _client_ctx: &ClientContext<<Self::Init as ClientModuleInit>::Module>,
        _idx: usize,
        _input: &<<<Self::Init as ClientModuleInit>::Module as ClientModule>::Common as ModuleCommon>::Input,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Handle transaction output, adjusting the current state
    ///
    /// Default implementation does nothing.
    async fn handle_output(
        &mut self,
        _client_ctx: &ClientContext<<Self::Init as ClientModuleInit>::Module>,
        _out_point: OutPoint,
        _output: &<<<Self::Init as ClientModuleInit>::Module as ClientModule>::Common as ModuleCommon>::Output,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Called before `finalize_dbtx`, to allow final state changes outside
    /// of retriable database transaction.
    async fn pre_finalize(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Finalize the recovery converting the tracked state to final
    /// changes in the database.
    ///
    /// This is the only place during recovery where module gets a chance to
    /// create state machines, etc. and that's why `dbtx` is of
    /// [`ClientDbTxContext`] type.
    ///
    /// Notably this function is running in a database-autocommit wrapper, so
    /// might be called again on database commit failure.
    async fn finalize_dbtx(
        &self,
        dbtx: &mut ClientDbTxContext<'_, '_, <Self::Init as ClientModuleInit>::Module>,
    ) -> anyhow::Result<()>;
}

impl<Init> ClientModuleRecoverArgs<Init>
where
    Init: ClientModuleInit,
{
    /// Run recover of a module from federation consensus history
    ///
    /// It is expected that most modules will implement their recovery
    /// by following Federation consensus history to restore their
    /// state. This function implement such a recovery by being generic
    /// over [`RecoveryFromHistory`] trait, which provides module-specific
    /// parts of recovery logic.
    pub async fn recover_from_history<Recovery>(
        &self,
        init: &Init,
        snapshot: Option<&<<Init as ClientModuleInit>::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<()>
    where
        Recovery: RecoveryFromHistory<Init = Init> + std::fmt::Debug,
    {
        /// Fetch epochs in a given range and send them over `sender`
        ///
        /// Since WASM's `spawn` does not support join handles, we indicate
        /// errors via `sender` itself.
        fn fetch_block_stream<'a>(
            api: DynGlobalApi,
            core_api_version: ApiVersion,
            decoders: ModuleDecoderRegistry,
            epoch_range: ops::Range<u64>,
            task_group: TaskGroup,
        ) -> impl futures::Stream<Item = Result<(u64, Vec<AcceptedItem>), ShuttingDownError>> + 'a
        {
            // How many request for blocks to run in parallel (streaming).
            const PARALLISM_LEVEL: usize = 64;
            const VERSION_THAT_INTRODUCED_GET_SESSION_STATUS: ApiVersion =
                ApiVersion { major: 0, minor: 1 };

            futures::stream::iter(epoch_range.clone())
                .map(move |session_idx| {
                    let api = api.clone();
                    let decoders = decoders.clone();
                    let task_group = task_group.clone();

                    Box::pin(async move {
                        // NOTE: Each block is fetched in a spawned task. This avoids a footgun
                        // of stuff in streams not making any progress when the stream itself
                        // is not being polled, and possibly can increase the fetching performance.
                        task_group.spawn_cancellable("recovery fetch block", async move {

                            info!(session_idx, "Fetching epoch");

                            let mut retry_sleep = Duration::from_millis(10);
                            let block = loop {
                                trace!(target: LOG_CLIENT_RECOVERY, session_idx, "Awaiting signed block");

                                let items_res = if core_api_version < VERSION_THAT_INTRODUCED_GET_SESSION_STATUS {
                                    api.await_block(session_idx, &decoders).await.map(|s| s.items)
                                } else {
                                    api.get_session_status(session_idx, &decoders).await.map(|s| match s {
                                        SessionStatus::Initial => panic!("Federation missing session that existed when we started recovery"),
                                        SessionStatus::Pending(items) => items,
                                        SessionStatus::Complete(s) => s.items,
                                    })
                                };

                                match items_res {
                                    Ok(block) => {
                                        debug!(target: LOG_CLIENT_RECOVERY, session_idx, "Got signed session");
                                        break block
                                    },
                                    Err(e) => {
                                        const MAX_SLEEP: Duration = Duration::from_secs(120);

                                        warn!(target: LOG_CLIENT_RECOVERY, e = %e, session_idx, "Error trying to fetch signed block");
                                        // We don't want PARALLISM_LEVEL tasks hammering Federation
                                        // with requests, so max sleep is significant
                                        if retry_sleep <= MAX_SLEEP {
                                            retry_sleep = retry_sleep
                                                + thread_rng().gen_range(Duration::ZERO..=retry_sleep);
                                        }
                                        fedimint_core::runtime::sleep(cmp::min(retry_sleep, MAX_SLEEP))
                                            .await;
                                    }
                                }
                            };

                            (session_idx, block)
                        }).await.expect("Can't fail")
                    })
                })
                .buffered(PARALLISM_LEVEL)
        }

        /// Make enough progress to justify saving a state snapshot

        async fn make_progress<'a, Init, Recovery: RecoveryFromHistory<Init = Init>>(
            client_ctx: &ClientContext<<Init as ClientModuleInit>::Module>,
            common_state: &mut RecoveryFromHistoryCommon,
            state: &mut Recovery,
            block_stream: &mut (impl Stream<Item = Result<(u64, Vec<AcceptedItem>), ShuttingDownError>>
                      + Unpin),
        ) -> anyhow::Result<()>
        where
            Init: ClientModuleInit,
        {
            /// the amount of blocks after which we save progress in the
            /// database (return from this function)
            ///
            /// TODO: Instead of a fixed range of session
            /// indexes, make the loop time-based, so the amount of
            /// progress we can loose on termination is time-bound,
            /// and thus more adaptive.
            const PROGRESS_SNAPSHOT_BLOCKS: u64 = 10;

            let block_range = common_state.next_session
                ..cmp::min(
                    common_state
                        .next_session
                        .wrapping_add(PROGRESS_SNAPSHOT_BLOCKS),
                    common_state.end_session,
                );

            debug!(
                target: LOG_CLIENT_RECOVERY,
                ?block_range,
                "Processing blocks"
            );

            for _ in block_range {
                let Some(res) = block_stream.next().await else {
                    break;
                };

                let (session_idx, accepted_items) = res?;

                assert_eq!(common_state.next_session, session_idx);
                state
                    .handle_session(client_ctx, session_idx, &accepted_items)
                    .await?;

                common_state.next_session += 1;
            }

            Ok(())
        }

        let db = self.db();
        let client_ctx = self.context();

        if Recovery::load_finalized(&mut db.begin_transaction_nc().await)
            .await
            .unwrap_or_default()
        {
            // In rare circumstances, the finalization could complete, yet the completion
            // of `recover` function not yet persisted in the database. So
            // it's possible that `recovery` would be called again on an
            // already finalized state. Because of this we store a
            // finalization marker in the same dbtx as the finalization itself, detect this
            // here and exit early.
            //
            // Example sequence how this happens (if `finalize_dbtx` didn't exist):
            //
            // 0. module recovery is complete and progress saved to the db
            // 1. `dbtx` with finalization commits, progress deleted, completing recovery on
            //    the client module side
            // 2. client crashes/gets terminated (tricky corner case)
            // 3. client starts again
            // 4. client never observed/persisted that the module finished recovery, so
            //    calls module recovery again
            // 5. module doesn't see progress, starts recovery again, eventually completes
            //    again and moves to finalization
            // 6. module runs finalization again and probably fails because it's actually
            //    not idempotent and doesn't expect the already existing state.
            warn!("Previously finalized, exiting");
            return Ok(());
        }
        let current_session_count = client_ctx.global_api().session_count().await?;
        debug!(target: LOG_CLIENT_RECOVERY, session_count = current_session_count, "Current session count");

        let (mut state, mut common_state) =
            // TODO: if load fails (e.g. module didn't migrate an existing recovery state and failed to decode it),
            // we could just ... start from scratch? at least being able to force this behavior might be useful
            if let Some((state, common_state)) = Recovery::load_dbtx(init, &mut db.begin_transaction_nc().await, self).await? {
                (state, common_state)
            } else {
                let (state, start_session) = Recovery::new(init, self, snapshot).await?;

                debug!(target: LOG_CLIENT_RECOVERY, start_session, "Recovery start session");
                (state,
                RecoveryFromHistoryCommon {
                    start_session,
                    next_session: start_session,
                    end_session: current_session_count + 1,
                })
            };

        let block_stream_session_range = common_state.next_session..common_state.end_session;
        debug!(target: LOG_CLIENT_RECOVERY, range = ?block_stream_session_range, "Starting block streaming");

        let mut block_stream = fetch_block_stream(
            self.api().clone(),
            *self.core_api_version(),
            client_ctx.decoders(),
            block_stream_session_range,
            self.task_group().clone(),
        );
        let client_ctx = self.context();

        while common_state.next_session < common_state.end_session {
            make_progress(
                &client_ctx,
                &mut common_state,
                &mut state,
                &mut block_stream,
            )
            .await?;

            let mut dbtx = db.begin_transaction().await;
            state.store_dbtx(&mut dbtx.to_ref_nc(), &common_state).await;
            dbtx.commit_tx().await;

            self.update_recovery_progress(RecoveryProgress {
                complete: (common_state.next_session - common_state.start_session)
                    .try_into()
                    .unwrap_or(u32::MAX),
                total: (common_state.end_session - common_state.start_session)
                    .try_into()
                    .unwrap_or(u32::MAX),
            });
        }

        state.pre_finalize().await?;

        let mut dbtx = db.begin_transaction().await;
        state.store_dbtx(&mut dbtx.to_ref_nc(), &common_state).await;
        dbtx.commit_tx().await;

        debug!(
            target: LOG_CLIENT_RECOVERY,
            ?state,
            "Finalizing restore"
        );

        client_ctx
            .clone()
            .module_autocommit_2(
                |dbtx, _| {
                    let state = state.clone();
                    {
                        Box::pin(async move {
                            state.delete_dbtx(&mut dbtx.module_dbtx()).await;
                            state.finalize_dbtx(dbtx).await?;
                            Recovery::store_finalized(&mut dbtx.module_dbtx(), true).await;

                            Ok(())
                        })
                    }
                },
                None,
            )
            .await?;

        Ok(())
    }
}
