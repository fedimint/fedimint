#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

#[cfg(feature = "cli")]
mod cli;
mod client_db;
mod ecash;
mod event;
mod input;
mod issuance;
mod output;
mod recovery;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use client_db::{SpendableNoteAmountPrefix, SpendableNotePrefix};
use event::NoteSpent;
use fedimint_client::db::ClientMigrationFn;
use fedimint_client::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, OutPointRange};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::rand::{thread_rng, Rng};
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, PeerId, TransactionId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::config::{client_denominations, FeeConsensus, MintClientConfig};
use fedimint_mintv2_common::{MintCommonInit, MintInput, MintModuleTypes, MintOutput, Note, KIND};
use futures::{pin_mut, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tbs::AggregatePublicKey;
use thiserror::Error;

use crate::client_db::SpendableNoteKey;
pub use crate::ecash::ECash;
use crate::input::{InputSMCommon, InputSMState, InputStateMachine};
use crate::issuance::NoteIssuanceRequest;
use crate::output::{MintOutputStateMachine, OutputSMCommon, OutputSMState};
use crate::recovery::MintRecovery;

const TARGET_PER_DENOMINATION: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct SpendableNote {
    pub amount: Amount,
    pub keypair: Keypair,
    pub signature: tbs::Signature,
}

impl SpendableNote {
    fn nonce(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn note(&self) -> Note {
        Note {
            amount: self.amount,
            nonce: self.nonce(),
            signature: self.signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MintOperationMeta {
    Send {
        ecash: String,
        custom_meta: Value,
    },
    Reissue {
        txid: TransactionId,
        amount: Amount,
        custom_meta: Value,
    },
    Receive {
        txid: TransactionId,
        ecash: String,
        custom_meta: Value,
    },
}

#[derive(Debug, Clone)]
pub struct MintClientInit;

impl ModuleInit for MintClientInit {
    type Common = MintCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for MintClientInit {
    type Module = MintClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(MintClientModule {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            root_secret: args.module_root_secret().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
        })
    }

    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        snapshot: Option<&<Self::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<()> {
        args.recover_from_history::<MintRecovery>(self, snapshot)
            .await
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientMigrationFn> {
        BTreeMap::new()
    }
}

#[derive(Debug)]
pub struct MintClientModule {
    federation_id: FederationId,
    cfg: MintClientConfig,
    root_secret: DerivableSecret,
    notifier: ModuleNotifier<MintClientStateMachines>,
    client_ctx: ClientContext<Self>,
}

#[derive(Debug, Clone)]
pub struct MintClientContext {
    client_ctx: ClientContext<MintClientModule>,
    tbs_agg_pks: BTreeMap<Amount, AggregatePublicKey>,
    tbs_pks: BTreeMap<Amount, BTreeMap<PeerId, tbs::PublicKeyShare>>,
    root_secret: DerivableSecret,
}

impl Context for MintClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for MintClientModule {
    type Init = MintClientInit;
    type Common = MintModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = MintClientContext;
    type States = MintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        MintClientContext {
            client_ctx: self.client_ctx.clone(),
            tbs_agg_pks: self.cfg.tbs_agg_pks.clone(),
            tbs_pks: self.cfg.tbs_pks.clone(),
            root_secret: self.root_secret.clone(),
        }
    }

    fn input_fee(
        &self,
        amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    fn output_fee(
        &self,
        amount: Amount,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }

    fn supports_being_primary(&self) -> bool {
        true
    }

    async fn create_final_inputs_and_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        mut input_amount: Amount,
        mut output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<MintInput, MintClientStateMachines>,
        ClientOutputBundle<MintOutput, MintClientStateMachines>,
    )> {
        let funding_notes = self
            .select_funding_input(dbtx, output_amount.saturating_sub(input_amount))
            .await
            .context("Insufficent funds")?;

        for note in &funding_notes {
            self.remove_spendable_note(dbtx, note).await;
        }

        input_amount += funding_notes.iter().map(|input| input.amount).sum();

        output_amount += funding_notes
            .iter()
            .map(|input| self.cfg.fee_consensus.fee(input.amount))
            .sum();

        assert!(output_amount <= input_amount);

        let (input_notes, output_amounts) = self
            .rebalance(dbtx, &self.cfg.fee_consensus, input_amount - output_amount)
            .await;

        for note in &input_notes {
            self.remove_spendable_note(dbtx, note).await;
        }

        input_amount += input_notes.iter().map(|note| note.amount).sum();

        output_amount += input_notes
            .iter()
            .map(|note| self.cfg.fee_consensus.fee(note.amount))
            .sum();

        output_amount += output_amounts
            .iter()
            .map(|amount| *amount + self.cfg.fee_consensus.fee(*amount))
            .sum();

        assert!(output_amount <= input_amount);

        let mut spendable_notes = funding_notes
            .into_iter()
            .chain(input_notes)
            .collect::<Vec<SpendableNote>>();

        // We sort the notes by amount to minimize the leaked information.
        spendable_notes.sort_by_key(|note| note.amount);

        let input_bundle = self.create_input_bundle(operation_id, spendable_notes);

        let mut amounts = represent_amount_with_fees(
            input_amount.saturating_sub(output_amount),
            self.cfg.fee_consensus.clone(),
        )
        .into_iter()
        .chain(output_amounts)
        .collect::<Vec<Amount>>();

        // We sort the amounts to minimize the leaked information.
        amounts.sort();

        let output_bundle = self.create_output_bundle(operation_id, amounts);

        Ok((input_bundle, output_bundle))
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        outpoint: OutPoint,
    ) -> anyhow::Result<()> {
        self.await_output_sm_success(operation_id, outpoint).await
    }

    async fn get_balance(&self, dbtx: &mut DatabaseTransaction<'_>) -> Amount {
        self.get_count_by_denomination_dbtx(dbtx)
            .await
            .into_iter()
            .map(|(amount, count)| amount.mul_u64(count))
            .sum()
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(
            self.notifier
                .subscribe_all_operations()
                .filter_map(|state| async move {
                    match state {
                        MintClientStateMachines::Output(MintOutputStateMachine {
                            state: OutputSMState::Pending | OutputSMState::Success,
                            ..
                        })
                        | MintClientStateMachines::Input(InputStateMachine {
                            state: InputSMState::Pending,
                            ..
                        }) => Some(()),
                        _ => None,
                    }
                }),
        )
    }
}

impl MintClientModule {
    async fn select_funding_input(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        mut excess_output: Amount,
    ) -> Option<Vec<SpendableNote>> {
        let mut selected_notes = Vec::new();
        let mut target_notes = Vec::new();
        let mut excess_notes = Vec::new();

        for amount in client_denominations().rev() {
            let notes_amount = dbtx
                .find_by_prefix(&SpendableNoteAmountPrefix(amount))
                .await
                .map(|entry| entry.0 .0)
                .collect::<Vec<SpendableNote>>()
                .await;

            target_notes.extend(notes_amount.iter().take(TARGET_PER_DENOMINATION).cloned());

            if notes_amount.len() > 2 * TARGET_PER_DENOMINATION {
                for note in notes_amount.into_iter().skip(TARGET_PER_DENOMINATION) {
                    let note_value = note
                        .amount
                        .checked_sub(self.cfg.fee_consensus.fee(note.amount))
                        .expect("All our notes are economical");

                    excess_output = excess_output.saturating_sub(note_value);

                    selected_notes.push(note);
                }
            } else {
                excess_notes.extend(notes_amount.into_iter().skip(TARGET_PER_DENOMINATION));
            }
        }

        if excess_output == Amount::ZERO {
            return Some(selected_notes);
        }

        for note in excess_notes.into_iter().chain(target_notes) {
            let note_value = note
                .amount
                .checked_sub(self.cfg.fee_consensus.fee(note.amount))
                .expect("All our notes are economical");

            excess_output = excess_output.saturating_sub(note_value);

            selected_notes.push(note);

            if excess_output == Amount::ZERO {
                return Some(selected_notes);
            }
        }

        None
    }

    async fn rebalance(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        fee_consensus: &FeeConsensus,
        mut excess_input: Amount,
    ) -> (Vec<SpendableNote>, Vec<Amount>) {
        let n_denominations = self.get_count_by_denomination_dbtx(dbtx).await;

        let mut notes = dbtx
            .find_by_prefix_sorted_descending(&SpendableNotePrefix)
            .await
            .map(|entry| entry.0 .0);

        let mut input_notes = Vec::new();
        let mut output_amounts = Vec::new();

        for amount in client_denominations() {
            let n_amount = n_denominations.get(&amount).copied().unwrap_or(0);

            let n_missing = TARGET_PER_DENOMINATION.saturating_sub(n_amount as usize);

            for _ in 0..n_missing {
                match excess_input.checked_sub(amount + fee_consensus.fee(amount)) {
                    Some(remaining_excess) => excess_input = remaining_excess,
                    None => match notes.next().await {
                        Some(note) => {
                            if note.amount <= amount + fee_consensus.fee(amount) {
                                break;
                            }

                            excess_input += note.amount - (amount + fee_consensus.fee(amount));

                            input_notes.push(note);
                        }
                        None => break,
                    },
                }

                output_amounts.push(amount);
            }
        }

        (input_notes, output_amounts)
    }

    fn create_input_bundle(
        &self,
        operation_id: OperationId,
        notes: Vec<SpendableNote>,
    ) -> ClientInputBundle<MintInput, MintClientStateMachines> {
        ClientInputBundle::new(
            notes
                .iter()
                .map(|spendable_note| ClientInput {
                    input: MintInput::new_v0(spendable_note.note()),
                    keys: vec![spendable_note.keypair],
                    amount: spendable_note.amount,
                })
                .collect(),
            vec![ClientInputSM {
                state_machines: Arc::new(move |range: OutPointRange| {
                    vec![MintClientStateMachines::Input(InputStateMachine {
                        common: InputSMCommon {
                            operation_id,
                            txid: range.txid(),
                            spendable_notes: notes.clone(),
                        },
                        state: InputSMState::Pending,
                    })]
                }),
            }],
        )
    }

    fn create_output_bundle(
        &self,
        operation_id: OperationId,
        requested_amounts: Vec<Amount>,
    ) -> ClientOutputBundle<MintOutput, MintClientStateMachines> {
        let issuance_requests = requested_amounts
            .into_iter()
            .map(|amount| NoteIssuanceRequest::new(amount, thread_rng().gen()))
            .collect::<Vec<NoteIssuanceRequest>>();

        ClientOutputBundle::new(
            issuance_requests
                .iter()
                .map(|request| ClientOutput {
                    output: request.output(&self.root_secret),
                    amount: request.amount,
                })
                .collect(),
            vec![ClientOutputSM {
                state_machines: Arc::new(move |range: OutPointRange| {
                    vec![MintClientStateMachines::Output(MintOutputStateMachine {
                        common: OutputSMCommon {
                            operation_id,
                            range: Some(range),
                            issuance_requests: issuance_requests.clone(),
                        },
                        state: OutputSMState::Pending,
                    })]
                }),
            }],
        )
    }

    async fn await_output_sm_success(
        &self,
        operation_id: OperationId,
        outpoint: OutPoint,
    ) -> anyhow::Result<()> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async {
                let MintClientStateMachines::Output(state) = state else {
                    return None;
                };

                if !state.common.range?.into_iter().contains(&outpoint) {
                    return None;
                }

                match state.state {
                    OutputSMState::Pending => None,
                    OutputSMState::Success => Some(Ok(())),
                    OutputSMState::Aborted => Some(Err(anyhow!("Transaction was rejected"))),
                    OutputSMState::Failure => Some(Err(anyhow!("Failed to finalize notes",))),
                }
            });

        pin_mut!(stream);

        stream.next_or_pending().await
    }

    /// Count the ECash notes in the client's database by denomination.
    pub async fn get_count_by_denomination(&self) -> BTreeMap<Amount, u64> {
        self.get_count_by_denomination_dbtx(
            &mut self.client_ctx.module_db().begin_transaction_nc().await,
        )
        .await
    }

    async fn get_count_by_denomination_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> BTreeMap<Amount, u64> {
        dbtx.find_by_prefix(&SpendableNotePrefix)
            .await
            .fold(BTreeMap::new(), |mut acc, entry| async move {
                acc.entry(entry.0 .0.amount)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);

                acc
            })
            .await
    }

    /// Send ECash for the given amount with an optional description. The amount
    /// will be rounded up to a multiple of 1024 msats which is the smallest
    /// denomination used throughout the client. If the rounded amount cannot
    /// be covered with the ecash notes in the client's database and the offline
    /// argument is set to false the client will create a transaction to
    /// reissue the required denominations. It is safe to cancel the send
    /// method call before the reissue is complete in which case the reissued
    /// notes are returned to the regular balance. To cancel a succesful ecash
    /// send simply receive it yourself.
    pub async fn send(
        &self,
        amount: Amount,
        memo: Option<String>,
        offline: bool,
        custom_meta: Value,
    ) -> Result<ECash, SendECashError> {
        let amount = round_to_multiple(amount, client_denominations().next().unwrap());

        if let Some(ecash) = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    Box::pin(self.send_ecash_dbtx(dbtx, amount, memo.clone(), custom_meta.clone()))
                },
                Some(100),
            )
            .await
            .expect("Failed to commit dbtx after 100 retries")
        {
            return Ok(ecash);
        }

        if offline {
            return Err(SendECashError::RequiresReissue);
        }

        self.client_ctx
            .global_api()
            .session_count()
            .await
            .map_err(|_| SendECashError::Offline)?;

        let operation_id = OperationId::new_random();

        let output = self.create_output_bundle(operation_id, represent_amount(amount));
        let output = self.client_ctx.make_client_outputs(output);

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                |range| MintOperationMeta::Reissue {
                    txid: range.txid(),
                    amount,
                    custom_meta: custom_meta.clone(),
                },
                TransactionBuilder::new().with_outputs(output),
            )
            .await
            .map_err(|_| SendECashError::InsufficientBalance)?;

        for outpoint in range.into_iter() {
            self.await_output_sm_success(operation_id, outpoint)
                .await
                .map_err(|_| SendECashError::Failure)?;
        }

        Box::pin(self.send(amount, memo, offline, custom_meta)).await
    }

    async fn send_ecash_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        mut remaining_amount: Amount,
        memo: Option<String>,
        custom_meta: Value,
    ) -> Result<Option<ECash>, Infallible> {
        let mut stream = dbtx
            .find_by_prefix_sorted_descending(&SpendableNotePrefix)
            .await
            .map(|entry| entry.0 .0);

        let mut notes = vec![];

        while let Some(spendable_note) = stream.next().await {
            remaining_amount = match remaining_amount.checked_sub(spendable_note.amount) {
                Some(amount) => amount,
                None => continue,
            };

            notes.push(spendable_note);
        }

        drop(stream);

        if remaining_amount != Amount::ZERO {
            return Ok(None);
        }

        for spendable_note in &notes {
            self.remove_spendable_note(dbtx, &spendable_note).await;
        }

        let ecash = ECash::new(self.federation_id.clone(), notes, memo);

        self.client_ctx
            .add_operation_log_entry_dbtx(
                dbtx,
                OperationId::new_random(),
                MintCommonInit::KIND.as_str(),
                MintOperationMeta::Send {
                    ecash: ecash.encode_base58(),
                    custom_meta,
                },
            )
            .await;

        Ok(Some(ecash))
    }

    /// Receive the ECash by reissuing the notes and return the total amount of
    /// the ecash reissued. This method is idempotent. If the client is
    /// currently offline and the offline arguement is set to false the
    /// method will return an error. If you want to construct a reissue
    /// transaction now regardless if your are online or not to receive the
    /// ecash automatically as soon as you go online again set the offline
    /// argument to true instead.
    pub async fn receive(
        &self,
        ecash: ECash,
        offline: bool,
        custom_meta: Value,
    ) -> Result<Amount, ReceiveECashError> {
        let operation_id = OperationId::from_encodable(&ecash);

        if self.client_ctx.operation_exists(operation_id).await {
            self.client_ctx
                .transaction_updates(operation_id)
                .await
                .await_any_tx_accepted()
                .await
                .map_err(|_| ReceiveECashError::AlreadySpent)?;

            return Ok(ecash.amount());
        }

        if ecash.mint() != Some(self.federation_id) {
            return Err(ReceiveECashError::WrongFederation);
        }

        if ecash
            .notes()
            .iter()
            .any(|note| note.amount < self.cfg.fee_consensus.base_fee())
        {
            return Err(ReceiveECashError::UneconomicalDenomination);
        }

        if !offline {
            self.client_ctx
                .global_api()
                .session_count()
                .await
                .map_err(|_| ReceiveECashError::Offline)?;
        }

        let input = self.create_input_bundle(operation_id, ecash.notes());
        let input = self.client_ctx.make_client_inputs(input);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                |range| MintOperationMeta::Receive {
                    txid: range.txid(),
                    ecash: ecash.encode_base58(),
                    custom_meta: custom_meta.clone(),
                },
                TransactionBuilder::new().with_inputs(input),
            )
            .await
            .expect("Receiving ecash requires additional funds");

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_any_tx_accepted()
            .await
            .map_err(|_| ReceiveECashError::AlreadySpent)?;

        Ok(ecash.amount())
    }

    async fn remove_spendable_note(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        spendable_note: &SpendableNote,
    ) {
        self.client_ctx
            .log_event(
                dbtx,
                NoteSpent {
                    nonce: spendable_note.nonce(),
                },
            )
            .await;

        dbtx.remove_entry(&SpendableNoteKey(spendable_note.clone()))
            .await
            .expect("Must deleted existing spendable note");
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendECashError {
    #[error("The client needs to reiusse notes but the offline arguemnt is set to false")]
    RequiresReissue,
    #[error("We need to reissue notes but the client is offline")]
    Offline,
    #[error("The clients balance is insufficient")]
    InsufficientBalance,
    #[error("A non-recoverable error has occured")]
    Failure,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ReceiveECashError {
    #[error("The ECash is from a different federation")]
    WrongFederation,
    #[error("The client is offline")]
    Offline,
    #[error("ECash contains an uneconomical denomination")]
    UneconomicalDenomination,
    #[error("ECash has already been spent")]
    AlreadySpent,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Input(InputStateMachine),
    Output(MintOutputStateMachine),
}

impl IntoDynInstance for MintClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for MintClientStateMachines {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            MintClientStateMachines::Input(redemption_state) => {
                sm_enum_variant_translation!(
                    redemption_state.transitions(context, global_context),
                    MintClientStateMachines::Input
                )
            }
            MintClientStateMachines::Output(issuance_state) => {
                sm_enum_variant_translation!(
                    issuance_state.transitions(context, global_context),
                    MintClientStateMachines::Output
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Input(redemption_state) => redemption_state.operation_id(),
            MintClientStateMachines::Output(issuance_state) => issuance_state.operation_id(),
        }
    }
}

fn round_to_multiple(amount: Amount, min_denomiation: Amount) -> Amount {
    Amount::from_msats(amount.msats.next_multiple_of(min_denomiation.msats))
}

fn represent_amount_with_fees(
    mut remaining_amount: Amount,
    fee_consensus: FeeConsensus,
) -> Vec<Amount> {
    let mut amounts = Vec::new();

    // Add denominations with a greedy algorithm
    for amount in client_denominations().rev() {
        let n_add = remaining_amount / (amount + fee_consensus.fee(amount));

        amounts.extend(std::iter::repeat(amount).take(n_add as usize));

        remaining_amount -= n_add * (amount + fee_consensus.fee(amount));
    }

    // We sort the notes by amount to minimize the leaked information.
    amounts.sort();

    amounts
}

fn represent_amount(mut remaining_amount: Amount) -> Vec<Amount> {
    let mut amounts = Vec::new();

    // Add denominations with a greedy algorithm
    for amount in client_denominations().rev() {
        let n_add = remaining_amount / amount;

        amounts.extend(std::iter::repeat(amount).take(n_add as usize));

        remaining_amount -= n_add * amount;
    }

    amounts
}
