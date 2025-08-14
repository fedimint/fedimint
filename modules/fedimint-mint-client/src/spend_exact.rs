use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, ensure};
use async_stream::stream;
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{State, StateTransition};
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{ClientModule, DynGlobalClientContext};
use fedimint_core::core::OperationId;
use fedimint_core::db::AutocommitError;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::CommonModuleInit;
use fedimint_core::{Amount, TieredCounts, TieredMulti, apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT_MODULE_MINT;
use fedimint_mint_common::config::FeeConsensus;
use fedimint_mint_common::{MintCommonInit, MintOutput};
use futures::{StreamExt, pin_mut, stream};
use serde::Serialize;
use tokio::pin;
use tracing::{debug, error, trace};

use crate::output::{NoteIssuanceRequest, par_finalize_notes};
use crate::{
    MintClientContext, MintClientModule, MintClientStateMachines, MintOperationMeta,
    MintOperationMetaVariant, NotesSelector, SpendExactState, SpendableNote,
};

impl MintClientModule {
    /// Spend notes with exact denominations. The function takes a `TieredMulti`
    /// argument specifying exactly how many notes per denomination to return.
    ///
    /// The function spawns a state machine that either finishes immediately if
    /// the correct notes are already available, or starts a reissuance process
    /// to get the exact denominations. The resulting notes are returned via
    /// the [`Self::subscribe_spend_notes_with_exact_denominations`] function's
    /// final success state.
    ///
    /// *Note that other than [`Self::spend_notes_with_selector`] this function
    /// does not keep track of the notes. If you don't use them they are "lost"
    /// (can always be recovered from operation, but someone needs to do that).*
    #[allow(clippy::too_many_lines)]
    pub async fn spend_notes_with_exact_denominations<M: Serialize>(
        &self,
        requested_denominations: TieredCounts,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        ensure!(
            !requested_denominations.is_empty(),
            "Cannot request zero notes"
        );

        let extra_meta = serde_json::to_value(extra_meta).expect(
            "MintClientModule::spend_notes_with_exact_denominations extra_meta is serializable",
        );

        let operation_id = OperationId::new_random();

        // If we already have the right denominations, return immediately
        let spend_res: anyhow::Result<()> = self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let extra_meta = extra_meta.clone();
                    let requested_denominations = requested_denominations.clone();
                    Box::pin(async move {
                        let available_notes = Self::select_notes(
                            dbtx,
                            &SelectNotesWithExactDenominations::new(requested_denominations.clone()),
                            requested_denominations.total_amount(),
                            self.cfg.fee_consensus
                        ).await?;

                        for (amount, note) in available_notes.iter_items() {
                            trace!(target: LOG_CLIENT_MODULE_MINT, %amount, %note, "Spending note as exact denomination spend");
                            MintClientModule::delete_spendable_note(&self.client_ctx, dbtx, amount, note).await;
                        }

                        self.client_ctx.manual_operation_start_dbtx(
                            dbtx,
                            operation_id,
                            MintClientModule::kind().as_str(),
                            MintOperationMeta {
                                variant: MintOperationMetaVariant::SpendExact {
                                    requested_denominations: requested_denominations.clone(),
                                    change_outpoints: None,
                                },
                                amount: available_notes.total_amount(),
                                extra_meta,
                            },
                            vec![
                                self.client_ctx.make_dyn(MintClientStateMachines::SpendExact(
                                    SpendExactStateMachine {
                                        operation_id,
                                        state: SpendExactStates::Created(SpendExactStateCreated::DenominationsAvailable(SpendExactStateSuccess {
                                            notes: available_notes,
                                        })),
                                    },
                                )),
                            ]
                        ).await?;
                        Ok(())
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { .. } => {
                    panic!("Infinite retries exhausted")
                }
            });

        match spend_res {
            Ok(()) => {
                debug!(target: LOG_CLIENT_MODULE_MINT, "Spend notes with exact denominations succeeded");
                return Ok(operation_id);
            }
            Err(e) => {
                debug!(target: LOG_CLIENT_MODULE_MINT, ?e, "Spend notes with exact denominations failed, trying reissuing");
            }
        }

        // If we don't have the correct notes, try to reissue existing notes into the
        // correct denominations
        let transaction_builder = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let requested_denominations = requested_denominations.clone();
                    Box::pin(async move {
                        let mut outputs = Vec::with_capacity(requested_denominations.count_items());
                        let mut note_issuance_requests =
                            Vec::with_capacity(requested_denominations.count_items());
                        for (amount, count) in requested_denominations.iter() {
                            for _ in 0..count {
                                let note_secret = self.new_note_secret(amount, dbtx).await;
                                let (issuance_request, blind_nonce) =
                                    NoteIssuanceRequest::new(&self.secp, &note_secret);
                                outputs.push(ClientOutput {
                                    output: MintOutput::new_v0(amount, blind_nonce),
                                    amount,
                                });
                                note_issuance_requests.push((amount, issuance_request));
                            }
                        }

                        let output_bundle = ClientOutputBundle::new(
                            outputs,
                            vec![ClientOutputSM {
                                state_machines: Arc::new(move |out_point_range: OutPointRange| {
                                    assert_eq!(
                                        out_point_range.count(),
                                        note_issuance_requests.len()
                                    );

                                    let requested_notes_requests = note_issuance_requests
                                        .clone()
                                        .into_iter()
                                        .zip(out_point_range)
                                        .map(|((amount, request), out_point)| {
                                            (out_point.out_idx, (amount, request))
                                        })
                                        .collect::<BTreeMap<_, _>>();

                                    vec![MintClientStateMachines::SpendExact(
                                        SpendExactStateMachine {
                                            operation_id,
                                            state: SpendExactStates::Created(
                                                SpendExactStateCreated::NeedsReissuing(
                                                    SpendExactStateReissuing {
                                                        requested_notes_outpoints: out_point_range,
                                                        requested_notes_requests,
                                                    },
                                                ),
                                            ),
                                        },
                                    )]
                                }),
                            }],
                        );
                        Result::<_, anyhow::Error>::Ok(
                            TransactionBuilder::new()
                                .with_outputs(self.client_ctx.make_client_outputs(output_bundle)),
                        )
                    })
                },
                None,
            )
            .await
            .expect("Can't fail");

        // FIXME: why can't I finalize and submit inside the DB transaction?
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                move |change_range: OutPointRange| MintOperationMeta {
                    variant: MintOperationMetaVariant::SpendExact {
                        requested_denominations: requested_denominations.clone(),
                        change_outpoints: Some(change_range),
                    },
                    amount: requested_denominations.total_amount(),
                    extra_meta: extra_meta.clone(),
                },
                transaction_builder,
            )
            .await?;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a spend exact operation started
    /// with [`MintClientModule::spend_notes_with_exact_denominations`].
    pub async fn subscribe_spend_notes_with_exact_denominations(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<SpendExactState>> {
        let operation = self.mint_operation(operation_id).await?;

        let MintOperationMetaVariant::SpendExact {
            change_outpoints, ..
        } = operation.meta::<MintOperationMeta>().variant
        else {
            bail!("Operation is not a spend exact operation");
        };

        let notifier = self.notifier.clone();
        let ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                let stream = notifier
                    .subscribe(operation_id)
                    .await
                    .filter_map(|state| async {
                        let MintClientStateMachines::SpendExact(state) = state else {
                            return None;
                        };
                        Some(state)
                    });

                pin_mut!(stream);

                while let Some(state) = stream.next().await {
                    match state.state {
                        SpendExactStates::Reissuing(_) => {
                            yield SpendExactState::Reissuing;
                        },
                        SpendExactStates::Success(success) => {
                            if let Some(change_outpoints) = &change_outpoints {
                                trace!(target: LOG_CLIENT_MODULE_MINT, "Awaiting reissue-exact change: {:?}", change_outpoints);
                                ctx.await_primary_module_outputs(
                                    operation_id,
                                    change_outpoints.into_iter().collect()
                                ).await.expect("Must await outputs");
                            } else {
                                trace!(target: LOG_CLIENT_MODULE_MINT, "No reissue-exact change outpoints to await");
                            }

                            yield SpendExactState::Success(success.notes);
                            break;
                        },
                        SpendExactStates::Failure(error) => {
                            yield SpendExactState::Failed(error);
                            break;
                        }
                        SpendExactStates::Created(_) => {
                            // Will be followed by one of the other states immediately, no need to even consider it.
                        }
                    }
                }
            }
        }))
    }
}

struct SelectNotesWithExactDenominations(TieredCounts);

impl SelectNotesWithExactDenominations {
    pub fn new(requested_denominations: TieredCounts) -> Self {
        assert!(
            !requested_denominations.is_empty(),
            "Cannot request zero notes"
        );
        Self(requested_denominations)
    }
}

#[apply(async_trait_maybe_send!)]
impl<Note: Send> NotesSelector<Note> for SelectNotesWithExactDenominations {
    async fn select_notes(
        &self,
        #[cfg(not(target_family = "wasm"))] stream: impl futures::Stream<Item = (Amount, Note)> + Send,
        #[cfg(target_family = "wasm")] stream: impl futures::Stream<Item = (Amount, Note)>,
        requested_amount: Amount,
        _fee_consensus: FeeConsensus,
    ) -> anyhow::Result<TieredMulti<Note>> {
        assert_eq!(self.0.total_amount(), requested_amount, "Amount mismatch");
        let mut notes = TieredMulti::default();

        pin!(stream);
        while let Some((amount, note)) = stream.next().await {
            if notes.tier_count(amount) < self.0.get(amount) {
                notes.push(amount, note);
            }
        }

        ensure!(
            self.0 == notes.summary(),
            "Could not select notes with exact denominations. Requested denominations: {:?}. Selected denominations: {:?}",
            self.0,
            notes.summary(),
        );

        Ok(notes)
    }
}

/// State machine for spending notes with exact denominations
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SpendExactStateMachine {
    pub operation_id: OperationId,
    pub state: SpendExactStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SpendExactStates {
    /// We can't spawn a final state machine due to SM executor limitations, so
    /// we add the created step even though it's not really needed
    Created(SpendExactStateCreated),
    /// We're waiting for reissuance to complete
    Reissuing(SpendExactStateReissuing),
    /// Reissuance completed successfully
    Success(SpendExactStateSuccess),
    /// Transaction was rejected
    Failure(String),
}

/// Intermediary state since we can't spawn a final state like `Success`. See
/// [`SpendExactStates::Created`].
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SpendExactStateCreated {
    NeedsReissuing(SpendExactStateReissuing),
    DenominationsAvailable(SpendExactStateSuccess),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SpendExactStateReissuing {
    /// Notes that the user requested, these will be returned in the
    /// [`SpendExactStateSuccess`] state
    pub(crate) requested_notes_outpoints: OutPointRange,
    /// `out_idx -> (denomination, issuance_request)`
    pub(crate) requested_notes_requests: BTreeMap<u64, (Amount, NoteIssuanceRequest)>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct SpendExactStateSuccess {
    /// The final notes with exact denominations
    pub notes: TieredMulti<SpendableNote>,
}

impl State for SpendExactStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            SpendExactStates::Created(_) => {
                vec![StateTransition::new(
                    std::future::ready(()),
                    move |_dbtx, (), old_state: SpendExactStateMachine| {
                        Box::pin(async move {
                            let new_state = match old_state.state {
                                SpendExactStates::Created(
                                    SpendExactStateCreated::DenominationsAvailable(success),
                                ) => SpendExactStates::Success(success),
                                SpendExactStates::Created(
                                    SpendExactStateCreated::NeedsReissuing(reissuing),
                                ) => SpendExactStates::Reissuing(reissuing),
                                _ => panic!("Invalid previous state"),
                            };
                            SpendExactStateMachine {
                                operation_id: old_state.operation_id,
                                state: new_state,
                            }
                        })
                    },
                )]
            }
            SpendExactStates::Reissuing(reissuing) => {
                reissuing.transitions(self.operation_id, context, global_context)
            }
            SpendExactStates::Success(_) | SpendExactStates::Failure(_) => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl SpendExactStateReissuing {
    fn transitions(
        &self,
        operation_id: OperationId,
        context: &MintClientContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<SpendExactStateMachine>> {
        let global_context = global_context.clone();
        let context_transition = context.clone();
        let context_trigger = context.clone();
        let txid = self.requested_notes_outpoints.txid;
        let requested_notes_outpoints = self.requested_notes_outpoints;
        let requested_notes_requests = self.requested_notes_requests.clone();
        vec![StateTransition::new(
            async move {
                global_context.await_tx_accepted(txid).await?;

                let blind_sig_shares = stream::iter(requested_notes_outpoints)
                    .then(move |out_point| {
                        let requested_notes_requests_inner = requested_notes_requests.clone();
                        let context_inner = context_trigger.clone();
                        async move {
                            let (amount, request) = requested_notes_requests_inner
                                .get(&out_point.out_idx)
                                .expect("Outpoint should have a request");
                            let shares = context_inner
                                .await_note_signature_shares(out_point, *amount, request)
                                .await;

                            (out_point.out_idx, shares)
                        }
                    })
                    .collect::<Vec<_>>()
                    .await;

                Result::<_, String>::Ok(blind_sig_shares)
            },
            move |_dbtx, result, old_state: SpendExactStateMachine| {
                let context_inner = context_transition.clone();
                Box::pin(async move {
                    let SpendExactStates::Reissuing(SpendExactStateReissuing {
                        requested_notes_requests,
                        ..
                    }) = &old_state.state
                    else {
                        panic!("Expected Reissuing state");
                    };

                    let blind_sig_shares = match result {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Failed to get blind signature shares: {e}");

                            return SpendExactStateMachine {
                                operation_id,
                                state: SpendExactStates::Failure(format!(
                                    "Failed to get blind signature shares: {e}"
                                )),
                            };
                        }
                    };

                    let notes = par_finalize_notes(
                        &context_inner.tbs_pks,
                        blind_sig_shares,
                        requested_notes_requests,
                    )
                    .into_iter()
                    .collect();

                    SpendExactStateMachine {
                        operation_id,
                        state: SpendExactStates::Success(SpendExactStateSuccess { notes }),
                    }
                })
            },
        )]
    }
}
