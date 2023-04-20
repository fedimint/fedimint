mod db;
/// State machines for mint inputs
mod input;
/// State machines for out-of-band transmitted e-cash notes
mod oob;
/// State machines for mint outputs
mod output;

use std::cmp::Ordering;
use std::fmt::Formatter;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use async_stream::stream;
use bitcoin_hashes::Hash;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{
    ClientModule, DynPrimaryClientModule, IClientModule, PrimaryClientModule,
};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{
    apply, async_trait_maybe_send, Amount, OutPoint, Tiered, TieredMulti, TieredSummary,
    TransactionId,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::MintClientConfig;
pub use fedimint_mint_common::*;
use futures::{pin_mut, StreamExt};
use secp256k1::{All, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use tbs::AggregatePublicKey;
use thiserror::Error;
use tracing::debug;

use crate::db::{NextECashNoteIndexKey, NoteKey, NoteKeyPrefix};
use crate::input::{
    MintInputCommon, MintInputStateCreated, MintInputStateMachine, MintInputStates,
};
use crate::oob::{MintOOBStateMachine, MintOOBStates, MintOOBStatesCreated};
use crate::output::{
    MintOutputCommon, MintOutputStateMachine, MintOutputStates, MintOutputStatesCreated,
    MultiNoteIssuanceRequest, NoteIssuanceRequest,
};

const MINT_E_CASH_TYPE_CHILD_ID: ChildId = ChildId(0);

#[apply(async_trait_maybe_send!)]
pub trait MintClientExt {
    /// Try to reissue e-cash notes received from a third party to receive them
    /// in our wallet. The progress and outcome can be observed using
    /// [`MintClientExt::subscribe_reissue_external_notes_updates`].
    async fn reissue_external_notes(
        &self,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<OperationId>;

    /// Subscribe to updates on the progress of a reissue operation started with
    /// [`MintClientExt::reissue_external_notes`].
    async fn subscribe_reissue_external_notes_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<ReissueExternalNotesState>>;

    /// Fetches and removes notes of *at least* amount `min_amount` from the
    /// wallet to be sent to the recipient out of band. These spends can be
    /// canceled by calling [`MintClientExt::try_cancel_spend_notes`] as long as
    /// the recipient hasn't reissued the e-cash notes themselves yet.
    ///
    /// The client will also automatically attempt to cancel the operation after
    /// `try_cancel_after` time has passed. This is a safety mechanism to avoid
    /// users forgetting about failed out-of-band transactions. The timeout
    /// should be chosen such that the recipient (who is potentially offline at
    /// the time of receiving the e-cash notes) had a reasonable timeframe to
    /// come online and reissue the notes themselves.
    async fn spend_notes(
        &self,
        min_amount: Amount,
        try_cancel_after: Duration,
    ) -> anyhow::Result<(OperationId, TieredMulti<SpendableNote>)>;

    /// Try to cancel a spend operation started with
    /// [`MintClientExt::spend_notes`]. If the e-cash notes have already been
    /// spent this operation will fail which can be observed using
    /// [`MintClientExt::subscribe_spend_notes_updates`].
    async fn try_cancel_spend_notes(&self, operation_id: OperationId);

    /// Subscribe to updates on the progress of a raw e-cash spend operation
    /// started with [`MintClientExt::spend_notes`].
    async fn subscribe_spend_notes_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<SpendOOBState>>;
}

/// The high-level state of a reissue operation started with
/// [`MintClientExt::reissue_external_notes`].
#[derive(Debug, Clone)]
pub enum ReissueExternalNotesState {
    /// The operation has been created and is waiting to be accepted by the
    /// federation.
    Created,
    /// We are waiting for blind signatures to arrive but can already assume the
    /// transaction to be successful.
    Issuing,
    /// The operation has been completed successfully.
    Done,
    /// Some error happened and the operation failed.
    Failed(String),
}

/// The high-level state of a raw e-cash spend operation started with
/// [`MintClientExt::spend_notes`].
pub enum SpendOOBState {
    /// The e-cash has been selected and given to the caller
    Created,
    /// The user requested a cancellation of the operation, we are waiting for
    /// the outcome of the cancel transaction.
    UserCanceledProcessing,
    /// The user-requested cancellation was successful, we got all our money
    /// back.
    UserCanceledSuccess,
    /// The user-requested cancellation failed, the e-cash notes have been spent
    /// by someone else already.
    UserCanceledFailure,
    /// We tried to cancel the operation automatically after the timeout but
    /// failed, indicating the recipient reissued the e-cash to themselves,
    /// making the out-of-band spend **successful**.
    Success,
    /// We tried to cancel the operation automatically after the timeout and
    /// succeeded, indicating the recipient did not reissue the e-cash to
    /// themselves, meaning the out-of-band spend **failed**.
    Refunded,
}

#[apply(async_trait_maybe_send!)]
impl MintClientExt for Client {
    async fn reissue_external_notes(
        &self,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<OperationId> {
        let (mint_client_instance, mint_client) = mint_client(self);

        let operation_id: OperationId = notes.consensus_hash().into_inner();
        if self.get_operation(operation_id).await.is_some() {
            bail!("We already reissued these notes");
        }

        let mint_input = mint_client
            .create_input_from_notes(operation_id, notes)
            .await?;

        let tx = TransactionBuilder::new().with_input(mint_input.into_dyn(mint_client_instance));

        let operation_meta_gen = |txid| MintMeta::Reissuance {
            out_point: OutPoint { txid, out_idx: 0 },
        };

        self.finalize_and_submit_transaction(
            operation_id,
            MintCommonGen::KIND.as_str(),
            operation_meta_gen,
            tx,
        )
        .await
        .expect("Transactions can only fail if the operation already exists, which we checked previously");

        Ok(operation_id)
    }

    async fn subscribe_reissue_external_notes_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<ReissueExternalNotesState>> {
        let out_point = match mint_operation(self, operation_id).await? {
            MintMeta::Reissuance { out_point } => out_point,
            _ => bail!("Operation is not a reissuance"),
        };

        let (_, mint_client) = mint_client(self);

        let tx_accepted_future = self
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(out_point.txid);
        let output_finalized_future = mint_client.await_output_finalized(operation_id, out_point);

        Ok(Box::pin(stream! {
            yield ReissueExternalNotesState::Created;

            match tx_accepted_future.await {
                Ok(()) => {
                    yield ReissueExternalNotesState::Issuing;
                },
                Err(()) => {
                    yield ReissueExternalNotesState::Failed("Transaction not accepted".to_string());
                }
            }

            match output_finalized_future.await {
                Ok(_) => {
                    yield ReissueExternalNotesState::Done;
                },
                Err(e) => {
                    yield ReissueExternalNotesState::Failed(e.to_string());
                },
            }
        }))
    }

    async fn spend_notes(
        &self,
        min_amount: Amount,
        try_cancel_after: Duration,
    ) -> anyhow::Result<(OperationId, TieredMulti<SpendableNote>)> {
        let (mint_client_instance, mint_client) = mint_client(self);

        self.db()
            .autocommit(
                |dbtx| {
                    Box::pin(async move {
                        let (operation_id, states, notes) = mint_client
                            .spend_notes_oob(
                                &mut dbtx.with_module_prefix(mint_client_instance),
                                min_amount,
                                try_cancel_after,
                            )
                            .await?;

                        let dyn_states = states
                            .into_iter()
                            .map(|s| s.into_dyn(mint_client_instance))
                            .collect();

                        self.add_state_machines(dbtx, dyn_states).await?;
                        self.add_operation_log_entry(
                            dbtx,
                            operation_id,
                            MintCommonGen::KIND.as_str(),
                            MintMeta::SpendOOB,
                        )
                        .await;

                        Ok((operation_id, notes))
                    })
                },
                Some(100),
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow!("Commit to DB failed: {last_error}")
                }
            })
    }

    async fn try_cancel_spend_notes(&self, operation_id: OperationId) {
        let (_, mint_client) = mint_client(self);

        // TODO: make robust by writing to the DB, this can fail
        let _ = mint_client.cancel_oob_payment_bc.send(operation_id);
    }

    async fn subscribe_spend_notes_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<SpendOOBState>> {
        if !matches!(
            mint_operation(self, operation_id).await?,
            MintMeta::SpendOOB
        ) {
            bail!("Operation is not a out-of-band spend");
        };

        let tx_subscription = self.transaction_updates(operation_id).await;
        let refund_future = mint_client(self).1.await_spend_oob_refund(operation_id);

        // TODO: check if operation exists and is a spend operation
        Ok(Box::pin(stream! {
            yield SpendOOBState::Created;

            let refund = refund_future.await;
            if refund.user_triggered {
                yield SpendOOBState::UserCanceledProcessing;
                match tx_subscription.await_tx_accepted(refund.transaction_id).await {
                    Ok(()) => {
                        yield SpendOOBState::UserCanceledSuccess;
                    },
                    Err(()) => {
                        yield SpendOOBState::UserCanceledFailure;
                    }
                }
            } else {
                match tx_subscription.await_tx_accepted(refund.transaction_id).await {
                    Ok(()) => {
                        yield SpendOOBState::Refunded;
                    },
                    Err(()) => {
                        yield SpendOOBState::Success;
                    }
                }
            }
        }))
    }
}

fn mint_client(client: &Client) -> (ModuleInstanceId, &MintClientModule) {
    let mint_client_instance = client
        .get_first_instance(&MintCommonGen::KIND)
        .expect("No mint module attached to client");

    let mint_client = client
        .get_module_client::<MintClientModule>(mint_client_instance)
        .expect("Instance ID exists, we just fetched it");

    (mint_client_instance, mint_client)
}

async fn mint_operation(client: &Client, operation_id: OperationId) -> anyhow::Result<MintMeta> {
    let operation = client
        .get_operation(operation_id)
        .await
        .ok_or(anyhow!("Operation not found"))?;

    if operation.operation_type() != MintCommonGen::KIND.as_str() {
        bail!("Operation is not a mint operation");
    }

    Ok(operation.meta())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MintMeta {
    Reissuance { out_point: OutPoint },
    SpendOOB,
}

#[derive(Debug, Clone)]
pub struct MintClientGen;

impl ExtendsCommonModuleGen for MintClientGen {
    type Common = MintCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for MintClientGen {
    type Module = MintClientModule;
    type Config = MintClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        let (cancel_oob_payment_bc, _) = tokio::sync::broadcast::channel(16);
        Ok(MintClientModule {
            cfg,
            secret: module_root_secret,
            secp: Secp256k1::new(),
            notifier,
            cancel_oob_payment_bc,
        })
    }

    async fn init_primary(
        &self,
        cfg: Self::Config,
        db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        Ok(self
            .init(cfg, db, module_root_secret, notifier)
            .await?
            .into())
    }
}

#[derive(Debug)]
pub struct MintClientModule {
    cfg: MintClientConfig,
    secret: DerivableSecret,
    secp: Secp256k1<All>,
    notifier: ModuleNotifier<DynGlobalClientContext, MintClientStateMachines>,
    cancel_oob_payment_bc: tokio::sync::broadcast::Sender<OperationId>,
}

// TODO: wrap in Arc
#[derive(Debug, Clone)]
pub struct MintClientContext {
    pub mint_decoder: Decoder,
    pub mint_keys: Tiered<AggregatePublicKey>,
    pub cancel_oob_payment_bc: tokio::sync::broadcast::Sender<OperationId>,
}

impl MintClientContext {
    fn subscribe_cancel_oob_payment(&self) -> tokio::sync::broadcast::Receiver<OperationId> {
        self.cancel_oob_payment_bc.subscribe()
    }
}

impl Context for MintClientContext {}

impl ClientModule for MintClientModule {
    type Common = MintModuleTypes;
    type ModuleStateMachineContext = MintClientContext;
    type States = MintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        MintClientContext {
            mint_decoder: self.decoder(),
            mint_keys: self.cfg.tbs_pks.clone(),
            cancel_oob_payment_bc: self.cancel_oob_payment_bc.clone(),
        }
    }

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.0.total_amount(),
            // FIXME: prevent overflows
            fee: self.cfg.fee_consensus.note_spend_abs * (input.0.count_items() as u64),
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.0.total_amount(),
            fee: self.cfg.fee_consensus.note_issuance_abs * (output.0.count_items() as u64),
        }
    }
}

#[apply(async_trait_maybe_send)]
impl PrimaryClientModule for MintClientModule {
    async fn create_sufficient_input(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<ClientInput<MintInput, MintClientStateMachines>> {
        self.create_input(dbtx, operation_id, min_amount).await
    }

    async fn create_exact_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> ClientOutput<MintOutput, MintClientStateMachines> {
        // FIXME: don't hardcode notes per denomination
        self.create_output(dbtx, operation_id, 2, amount).await
    }
}

impl MintClientModule {
    /// Returns the number of held e-cash notes per denomination
    pub async fn get_wallet_summary(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> TieredSummary {
        dbtx.find_by_prefix(&NoteKeyPrefix)
            .await
            .fold(
                TieredSummary::default(),
                |mut acc, (key, _note)| async move {
                    acc.inc(key.amount, 1);
                    acc
                },
            )
            .await
    }

    // TODO: put "notes per denomination" default into cfg
    /// Creates a mint output with exactly the given `amount`, issuing e-cash
    /// notes such that the client holds `notes_per_denomination` notes of each
    /// e-cash note denomination held.
    pub async fn create_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        notes_per_denomination: u16,
        amount: Amount,
    ) -> ClientOutput<MintOutput, MintClientStateMachines> {
        let mut amount_requests: Vec<((Amount, NoteIssuanceRequest), (Amount, BlindNonce))> =
            Vec::new();
        let denominations = TieredSummary::represent_amount(
            amount,
            &self.get_wallet_summary(dbtx).await,
            &self.cfg.tbs_pks,
            notes_per_denomination,
        );
        for (amt, num) in denominations.iter() {
            for _ in 0..num {
                let (request, blind_nonce) = self.new_ecash_note(amt, dbtx).await;
                amount_requests.push(((amt, request), (amt, blind_nonce)));
            }
        }
        let (note_issuance, sig_req): (MultiNoteIssuanceRequest, MintOutput) =
            amount_requests.into_iter().unzip();

        let state_generator = Arc::new(move |txid, out_idx| {
            vec![MintClientStateMachines::Output(MintOutputStateMachine {
                common: MintOutputCommon {
                    operation_id,
                    out_point: OutPoint { txid, out_idx },
                },
                state: MintOutputStates::Created(MintOutputStatesCreated {
                    note_issuance: note_issuance.clone(),
                }),
            })]
        });

        debug!(
            %amount,
            notes = %sig_req.0.count_items(),
            tiers = ?sig_req.0.iter_tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        ClientOutput {
            output: sig_req,
            state_machines: state_generator,
        }
    }

    /// Wait for the e-cash notes to be retrieved. If this is not possible
    /// because another terminal state was reached an error describing the
    /// failure is returned.
    pub async fn await_output_finalized(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                let MintClientStateMachines::Output(state) = state else { return None };

                if state.common.out_point != out_point {
                    return None;
                }

                match state.state {
                    MintOutputStates::Succeeded(_) => Some(Ok(())),
                    MintOutputStates::Aborted(_) => Some(Err(anyhow!("Transaction was rejected"))),
                    MintOutputStates::Failed(failed) => Some(Err(anyhow!(
                        "Failed to finalize transaction: {}",
                        failed.error
                    ))),
                    _ => None,
                }
            });
        pin_mut!(stream);

        stream.next_or_pending().await
    }

    // FIXME: use lazy e-cash note loading implemented in #2183
    /// Creates a mint input of at least `min_amount`.
    pub async fn create_input(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<ClientInput<MintInput, MintClientStateMachines>> {
        let spendable_selected_notes = Self::select_notes(dbtx, min_amount).await?;

        for (amount, note) in spendable_selected_notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.note.0,
            })
            .await;
        }

        self.create_input_from_notes(operation_id, spendable_selected_notes)
            .await
    }

    /// Create a mint input from external, potentially untrusted notes
    pub async fn create_input_from_notes(
        &self,
        operation_id: OperationId,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<ClientInput<MintInput, MintClientStateMachines>> {
        if let Some((amt, invalid_note)) = notes.iter_items().find(|(amt, note)| {
            let Some(mint_key) = self.cfg.tbs_pks.get(*amt) else {return true;};
            !note.note.verify(mint_key.0)
        }) {
            return Err(anyhow!(
                "Invalid note in input: amt={} note={:?}",
                amt,
                invalid_note
            ));
        }

        let (spend_keys, selected_notes) = notes
            .iter_items()
            .map(|(amt, spendable_note)| (spendable_note.spend_key, (amt, spendable_note.note)))
            .unzip();

        let sm_gen = Arc::new(move |txid, input_idx| {
            vec![MintClientStateMachines::Input(MintInputStateMachine {
                common: MintInputCommon {
                    operation_id,
                    txid,
                    input_idx,
                },
                state: MintInputStates::Created(MintInputStateCreated {
                    notes: notes.clone(),
                }),
            })]
        });

        Ok(ClientInput {
            input: MintInput(selected_notes),
            keys: spend_keys,
            state_machines: sm_gen,
        })
    }

    async fn spend_notes_oob(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        min_amount: Amount,
        try_cancel_after: Duration,
    ) -> anyhow::Result<(
        OperationId,
        Vec<MintClientStateMachines>,
        TieredMulti<SpendableNote>,
    )> {
        let spendable_selected_notes = Self::select_notes(dbtx, min_amount).await?;

        let operation_id = spendable_selected_notes.consensus_hash().into_inner();

        for (amount, note) in spendable_selected_notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.note.0,
            })
            .await;
        }

        let state_machines = vec![MintClientStateMachines::OOB(MintOOBStateMachine {
            operation_id,
            state: MintOOBStates::Created(MintOOBStatesCreated {
                notes: spendable_selected_notes.clone(),
                timeout: fedimint_core::time::now() + try_cancel_after,
            }),
        })];

        Ok((operation_id, state_machines, spendable_selected_notes))
    }

    pub async fn await_spend_oob_refund(&self, operation_id: OperationId) -> SpendOOBRefund {
        Box::pin(
            self.notifier
                .subscribe(operation_id)
                .await
                .filter_map(|state| async move {
                    let MintClientStateMachines::OOB(state) = state else { return None };

                    match state.state {
                        MintOOBStates::TimeoutRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: false,
                            transaction_id: refund.refund_txid,
                        }),
                        MintOOBStates::UserRefund(refund) => Some(SpendOOBRefund {
                            user_triggered: true,
                            transaction_id: refund.refund_txid,
                        }),
                        MintOOBStates::Created(_) => None,
                    }
                }),
        )
        .next_or_pending()
        .await
    }

    /// Select notes with total amount of *at least* `amount`. If more than
    /// requested amount of notes are returned it was because exact change
    /// couldn't be made, and the next smallest amount will be returned.
    ///
    /// The caller can request change from the federation.
    async fn select_notes(
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        amount: Amount,
    ) -> Result<TieredMulti<SpendableNote>, InsufficientBalanceError> {
        let note_stream = dbtx
            .find_by_prefix_sorted_descending(&NoteKeyPrefix)
            .await
            .map(|(key, note)| (key.amount, note));
        select_notes_from_stream(note_stream, amount).await
    }

    async fn get_next_note_index(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        amount: Amount,
    ) -> NoteIndex {
        NoteIndex(
            dbtx.get_value(&NextECashNoteIndexKey(amount))
                .await
                .unwrap_or(0),
        )
    }

    /// Derive the note `DerivableSecret` from the Mint's `secret` the `amount`
    /// tier and `note_idx`
    ///
    /// Static to help re-use in other places, that don't have a whole [`Self`]
    /// available
    pub fn new_note_secret_static(
        secret: &DerivableSecret,
        amount: Amount,
        note_idx: NoteIndex,
    ) -> DerivableSecret {
        assert_eq!(secret.level(), 1);
        debug!(?secret, %amount, %note_idx, "Deriving new mint note");
        secret
            .child_key(MINT_E_CASH_TYPE_CHILD_ID) // TODO: cache
            .child_key(ChildId(amount.msats))
            .child_key(ChildId(note_idx.as_u64()))
            .child_key(ChildId(amount.msats))
    }

    async fn new_note_secret(
        &self,
        amount: Amount,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> DerivableSecret {
        let new_idx = self.get_next_note_index(dbtx, amount).await;
        dbtx.insert_entry(&NextECashNoteIndexKey(amount), &new_idx.next().as_u64())
            .await;
        Self::new_note_secret_static(&self.secret, amount, new_idx)
    }

    pub async fn new_ecash_note(
        &self,
        amount: Amount,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> (NoteIssuanceRequest, BlindNonce) {
        let secret = self.new_note_secret(amount, dbtx).await;
        NoteIssuanceRequest::new(&self.secp, secret)
    }
}

pub struct SpendOOBRefund {
    pub user_triggered: bool,
    pub transaction_id: TransactionId,
}

// We are using a greedy algorithm to select notes. We start with the largest
// then proceed to the lowest tiers/denominations.
// But there is a catch: we don't know if there are enough notes in the lowest
// tiers, so we need to save a big note in case the sum of the following
// small notes are not enough.
pub async fn select_notes_from_stream<Note>(
    stream: impl futures::Stream<Item = (Amount, Note)>,
    requested_amount: Amount,
) -> Result<TieredMulti<Note>, InsufficientBalanceError> {
    if requested_amount == Amount::ZERO {
        return Ok(TieredMulti::default());
    }
    let mut stream = Box::pin(stream);
    let mut selected = vec![];
    // This is the big note we save in case the sum of the following small notes are
    // not sufficient to cover the pending amount
    // The tuple is (amount, note, checkpoint), where checkpoint is the index where
    // the note should be inserted on the selected vector if it is needed
    let mut last_big_note_checkpoint: Option<(Amount, Note, usize)> = None;
    let mut pending_amount = requested_amount;
    let mut previous_amount: Option<Amount> = None; // used to assert descending order
    loop {
        if let Some((note_amount, note)) = stream.next().await {
            assert!(
                previous_amount.map_or(true, |previous| previous >= note_amount),
                "notes are not sorted in descending order"
            );
            previous_amount = Some(note_amount);
            match note_amount.cmp(&pending_amount) {
                Ordering::Less => {
                    // keep adding notes until we have enough
                    pending_amount -= note_amount;
                    selected.push((note_amount, note))
                }
                Ordering::Greater => {
                    // probably we don't need this big note, but we'll keep it in case the
                    // following small notes don't add up to the
                    // requested amount
                    last_big_note_checkpoint = Some((note_amount, note, selected.len()));
                }
                Ordering::Equal => {
                    // exactly enough notes, return
                    selected.push((note_amount, note));
                    return Ok(selected.into_iter().collect());
                }
            }
        } else {
            assert!(pending_amount > Amount::ZERO);
            if let Some((big_note_amount, big_note, checkpoint)) = last_big_note_checkpoint {
                // the sum of the small notes don't add up to the pending amount, remove
                // them
                selected.truncate(checkpoint);
                // and use the big note to cover it
                selected.push((big_note_amount, big_note));
                // so now we have enough to cover the requested amount, return
                return Ok(selected.into_iter().collect());
            } else {
                let total_amount = requested_amount - pending_amount;
                // not enough notes, return
                return Err(InsufficientBalanceError {
                    requested_amount,
                    total_amount,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Error)]
pub struct InsufficientBalanceError {
    pub requested_amount: Amount,
    pub total_amount: Amount,
}

impl std::fmt::Display for InsufficientBalanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Insufficient balance: requested {} but only {} available",
            self.requested_amount, self.total_amount
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Output(MintOutputStateMachine),
    Input(MintInputStateMachine),
    OOB(MintOOBStateMachine),
}

impl IntoDynInstance for MintClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for MintClientStateMachines {
    type ModuleContext = MintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            MintClientStateMachines::Output(issuance_state) => {
                sm_enum_variant_translation!(
                    issuance_state.transitions(context, global_context),
                    MintClientStateMachines::Output
                )
            }
            MintClientStateMachines::Input(redemption_state) => {
                sm_enum_variant_translation!(
                    redemption_state.transitions(context, global_context),
                    MintClientStateMachines::Input
                )
            }
            MintClientStateMachines::OOB(oob_state) => {
                sm_enum_variant_translation!(
                    oob_state.transitions(context, global_context),
                    MintClientStateMachines::OOB
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Output(issuance_state) => issuance_state.operation_id(),
            MintClientStateMachines::Input(redemption_state) => redemption_state.operation_id(),
            MintClientStateMachines::OOB(oob_state) => oob_state.operation_id(),
        }
    }
}

/// A [`Note`] with associated secret key that allows to proof ownership (spend
/// it)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableNote {
    pub note: Note,
    pub spend_key: KeyPair,
}

/// An index used to deterministically derive [`Note`]s
///
/// We allow converting it to u64 and incrementing it, but
/// messing with it should be somewhat restricted to prevent
/// silly errors.
#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Encodable,
    Decodable,
    Default,
    PartialOrd,
    Ord,
)]
pub struct NoteIndex(u64);

impl NoteIndex {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    // Private. If it turns out it is useful outside,
    // we can relax and convert to `From<u64>`
    // Actually used in tests RN, so cargo complains in non-test builds.
    #[allow(unused)]
    fn from_u64(v: u64) -> Self {
        Self(v)
    }

    pub fn advance(&mut self) {
        *self = self.next()
    }
}

impl std::fmt::Display for NoteIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::{Amount, Tiered, TieredMulti, TieredSummary};
    use itertools::Itertools;

    use crate::select_notes_from_stream;

    #[test_log::test(tokio::test)]
    async fn select_notes_avg_test() {
        let max_amount = Amount::from_sats(1000000);
        let tiers = Tiered::gen_denominations(max_amount);
        let tiered =
            TieredSummary::represent_amount::<()>(max_amount, &Default::default(), &tiers, 3);

        let mut total_notes = 0;
        for multiplier in 1..100 {
            let stream = reverse_sorted_note_stream(tiered.iter().collect());
            let select =
                select_notes_from_stream(stream, Amount::from_sats(multiplier * 1000)).await;
            total_notes += select.unwrap().into_iter_items().count();
        }
        assert_eq!(total_notes / 100, 10);
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_exact_amount_with_minimum_notes() {
        let f = || {
            reverse_sorted_note_stream(vec![
                (Amount::from_sats(1), 10),
                (Amount::from_sats(5), 10),
                (Amount::from_sats(20), 10),
            ])
        };
        assert_eq!(
            select_notes_from_stream(f(), Amount::from_sats(7))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(1), 2), (Amount::from_sats(5), 1)])
        );
        assert_eq!(
            select_notes_from_stream(f(), Amount::from_sats(20))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 1)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_next_smallest_amount_if_exact_change_cannot_be_made() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(5), 5),
            (Amount::from_sats(20), 5),
        ]);
        assert_eq!(
            select_notes_from_stream(stream, Amount::from_sats(7))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(5), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_uses_big_note_if_small_amounts_are_not_sufficient() {
        let stream = reverse_sorted_note_stream(vec![
            (Amount::from_sats(1), 3),
            (Amount::from_sats(5), 3),
            (Amount::from_sats(20), 2),
        ]);
        assert_eq!(
            select_notes_from_stream(stream, Amount::from_sats(39))
                .await
                .unwrap(),
            notes(vec![(Amount::from_sats(20), 2)])
        );
    }

    #[test_log::test(tokio::test)]
    async fn select_notes_returns_error_if_amount_is_too_large() {
        let stream = reverse_sorted_note_stream(vec![(Amount::from_sats(10), 1)]);
        let error = select_notes_from_stream(stream, Amount::from_sats(100))
            .await
            .unwrap_err();
        assert_eq!(error.total_amount, Amount::from_sats(10));
    }

    fn reverse_sorted_note_stream(
        notes: Vec<(Amount, usize)>,
    ) -> impl futures::Stream<Item = (Amount, String)> {
        futures::stream::iter(
            notes
                .into_iter()
                // We are creating `number` dummy notes of `amount` value
                .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
                .sorted()
                .rev(),
        )
    }

    fn notes(notes: Vec<(Amount, usize)>) -> TieredMulti<String> {
        notes
            .into_iter()
            .flat_map(|(amount, number)| vec![(amount, "dummy note".into()); number])
            .collect()
    }
}
