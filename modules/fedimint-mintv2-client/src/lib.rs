#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]

mod api;
#[cfg(feature = "cli")]
mod cli;
mod client_db;
mod ecash;
mod event;
mod input;
pub mod issuance;
mod output;
mod receive;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use bitcoin_hashes::sha256;
use client_db::{RecoveryState, RecoveryStateKey, SpendableNoteAmountPrefix, SpendableNotePrefix};
pub use event::*;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::ClientModule;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client_module::module::recovery::{NoModuleBackup, RecoveryProgress};
use fedimint_client_module::module::{
    ClientContext, OutPointRange, PrimaryModulePriority, PrimaryModuleSupport,
};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{Amount, OutPoint, PeerId, TransactionId, apply, async_trait_maybe_send};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::config::{FeeConsensus, MintClientConfig, client_denominations};
use fedimint_mintv2_common::{
    Denomination, KIND, MintCommonInit, MintInput, MintModuleTypes, MintOutput, Note, RecoveryItem,
};
use futures::{StreamExt, pin_mut};
use itertools::Itertools;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tbs::AggregatePublicKey;
use thiserror::Error;

use crate::api::MintV2ModuleApi;
use crate::client_db::SpendableNoteKey;
pub use crate::ecash::ECash;
use crate::input::{InputSMCommon, InputSMState, InputStateMachine};
use crate::issuance::NoteIssuanceRequest;
use crate::output::{MintOutputStateMachine, OutputSMCommon, OutputSMState};
use crate::receive::ReceiveStateMachine;

const TARGET_PER_DENOMINATION: usize = 3;
const SLICE_SIZE: u64 = 10000;
const PARALLEL_HASH_REQUESTS: usize = 10;
const PARALLEL_SLICE_REQUESTS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct SpendableNote {
    pub denomination: Denomination,
    pub keypair: Keypair,
    pub signature: tbs::Signature,
}

impl SpendableNote {
    pub fn amount(&self) -> Amount {
        self.denomination.amount()
    }
}

impl SpendableNote {
    fn nonce(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn note(&self) -> Note {
        Note {
            denomination: self.denomination,
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

    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        _snapshot: Option<&NoModuleBackup>,
    ) -> anyhow::Result<()> {
        let mut state = if let Some(state) = args
            .db()
            .begin_transaction_nc()
            .await
            .get_value(&RecoveryStateKey)
            .await
        {
            state
        } else {
            RecoveryState {
                next_index: 0,
                total_items: args.module_api().fetch_recovery_count().await?,
                requests: BTreeMap::new(),
                nonces: BTreeSet::new(),
            }
        };

        if state.next_index == state.total_items {
            return Ok(());
        }

        let peer_selector = PeerSelector::new(args.api().all_peers().clone());

        let mut recovery_stream = futures::stream::iter(
            (state.next_index..state.total_items).step_by(SLICE_SIZE as usize),
        )
        .map(|start| {
            let api = args.module_api().clone();
            let end = std::cmp::min(start + SLICE_SIZE, state.total_items);

            async move { (start, end, api.fetch_recovery_slice_hash(start, end).await) }
        })
        .buffered(PARALLEL_HASH_REQUESTS)
        .map(|(start, end, hash)| {
            download_slice_with_hash(
                args.module_api().clone(),
                peer_selector.clone(),
                start,
                end,
                hash,
            )
        })
        .buffered(PARALLEL_SLICE_REQUESTS);

        let tweak_grind_seed = args.module_root_secret().to_random_bytes::<32>();

        loop {
            let items = recovery_stream
                .next()
                .await
                .expect("mintv2 recovery stream finished before recovery is complete");

            for item in &items {
                match item {
                    RecoveryItem::Output {
                        denomination,
                        nonce_hash,
                        tweak,
                    } => {
                        if !issuance::check_tweak(*tweak, tweak_grind_seed) {
                            continue;
                        }
                        let output_secret = issuance::output_secret(
                            *denomination,
                            *tweak,
                            args.module_root_secret(),
                        );

                        if !issuance::check_nonce(&output_secret, *nonce_hash) {
                            continue;
                        }

                        let computed_nonce_hash = issuance::nonce(&output_secret).consensus_hash();

                        // Ignore possible duplicate nonces
                        if !state.nonces.insert(computed_nonce_hash) {
                            continue;
                        }

                        state.requests.insert(
                            computed_nonce_hash,
                            NoteIssuanceRequest::new(*denomination, *tweak),
                        );
                    }
                    RecoveryItem::Input { nonce_hash } => {
                        state.requests.remove(nonce_hash);
                        state.nonces.remove(nonce_hash);
                    }
                }
            }

            state.next_index += items.len() as u64;

            let mut dbtx = args.db().begin_transaction().await;

            dbtx.insert_entry(&RecoveryStateKey, &state).await;

            if state.next_index == state.total_items {
                let state_machines = args
                    .context()
                    .map_dyn(vec![MintClientStateMachines::Output(
                        MintOutputStateMachine {
                            common: OutputSMCommon {
                                operation_id: OperationId::new_random(),
                                range: None,
                                issuance_requests: state.requests.into_values().collect(),
                            },
                            state: OutputSMState::Pending,
                        },
                    )])
                    .collect();

                args.context()
                    .add_state_machines_dbtx(&mut dbtx.to_ref_nc(), state_machines)
                    .await
                    .expect("state machine is valid");

                dbtx.commit_tx().await;

                return Ok(());
            }

            dbtx.commit_tx().await;

            args.update_recovery_progress(RecoveryProgress {
                complete: state.next_index.try_into().unwrap_or(u32::MAX),
                total: state.total_items.try_into().unwrap_or(u32::MAX),
            });
        }
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

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
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
    tbs_agg_pks: BTreeMap<Denomination, AggregatePublicKey>,
    tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, tbs::PublicKeyShare>>,
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
        amounts: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amounts.get_bitcoin()),
        ))
    }

    fn output_fee(
        &self,
        amounts: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amounts.get_bitcoin()),
        ))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }

    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::selected(PrimaryModulePriority::HIGH, [AmountUnit::BITCOIN])
    }

    async fn create_final_inputs_and_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        unit: AmountUnit,
        mut input_amount: Amount,
        mut output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<MintInput, MintClientStateMachines>,
        ClientOutputBundle<MintOutput, MintClientStateMachines>,
    )> {
        if unit != AmountUnit::BITCOIN {
            anyhow::bail!("Module can only handle Bitcoin");
        }

        let funding_notes = self
            .select_funding_input(dbtx, output_amount.saturating_sub(input_amount))
            .await
            .context("Insufficcent funds")?;

        for note in &funding_notes {
            self.remove_spendable_note(dbtx, note).await;
        }

        input_amount += funding_notes.iter().map(SpendableNote::amount).sum();

        output_amount += funding_notes
            .iter()
            .map(|input| self.cfg.fee_consensus.fee(input.amount()))
            .sum();

        assert!(output_amount <= input_amount);

        let (input_notes, output_amounts) = self
            .rebalance(dbtx, &self.cfg.fee_consensus, input_amount - output_amount)
            .await;

        for note in &input_notes {
            self.remove_spendable_note(dbtx, note).await;
        }

        input_amount += input_notes.iter().map(SpendableNote::amount).sum();

        output_amount += input_notes
            .iter()
            .map(|note| self.cfg.fee_consensus.fee(note.amount()))
            .sum();

        output_amount += output_amounts
            .iter()
            .map(|denomination| {
                denomination.amount() + self.cfg.fee_consensus.fee(denomination.amount())
            })
            .sum();

        assert!(output_amount <= input_amount);

        let mut spendable_notes = funding_notes
            .into_iter()
            .chain(input_notes)
            .collect::<Vec<SpendableNote>>();

        // We sort the notes by denomination to minimize the leaked information.
        spendable_notes.sort_by_key(|note| note.denomination);

        let input_bundle = Self::create_input_bundle(operation_id, spendable_notes, false);

        let mut denominations = represent_amount_with_fees(
            input_amount.saturating_sub(output_amount),
            &self.cfg.fee_consensus,
        )
        .into_iter()
        .chain(output_amounts)
        .collect::<Vec<Denomination>>();

        // We sort the amounts to minimize the leaked information.
        denominations.sort();

        let output_bundle = self.create_output_bundle(operation_id, denominations);

        Ok((input_bundle, output_bundle))
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        outpoint: OutPoint,
    ) -> anyhow::Result<()> {
        self.await_output_sm_success(operation_id, outpoint).await
    }

    async fn get_balance(&self, dbtx: &mut DatabaseTransaction<'_>, unit: AmountUnit) -> Amount {
        if unit != AmountUnit::BITCOIN {
            return Amount::ZERO;
        }
        self.get_count_by_denomination_dbtx(dbtx)
            .await
            .into_iter()
            .map(|(denomination, count)| denomination.amount().mul_u64(count))
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
                .map(|entry| entry.0.0)
                .collect::<Vec<SpendableNote>>()
                .await;

            target_notes.extend(notes_amount.iter().take(TARGET_PER_DENOMINATION).cloned());

            if notes_amount.len() > 2 * TARGET_PER_DENOMINATION {
                for note in notes_amount.into_iter().skip(TARGET_PER_DENOMINATION) {
                    let note_fee = self.cfg.fee_consensus.fee(note.amount());

                    let note_value = note
                        .amount()
                        .checked_sub(note_fee)
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
            let note_amount = note.amount();
            let note_value = note_amount
                .checked_sub(self.cfg.fee_consensus.fee(note_amount))
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
        fee: &FeeConsensus,
        mut excess_input: Amount,
    ) -> (Vec<SpendableNote>, Vec<Denomination>) {
        let n_denominations = self.get_count_by_denomination_dbtx(dbtx).await;

        let mut notes = dbtx
            .find_by_prefix_sorted_descending(&SpendableNotePrefix)
            .await
            .map(|entry| entry.0.0);

        let mut input_notes = Vec::new();
        let mut output_denominations = Vec::new();

        for d in client_denominations() {
            let n_denomination = n_denominations.get(&d).copied().unwrap_or(0);

            let n_missing = TARGET_PER_DENOMINATION.saturating_sub(n_denomination as usize);

            for _ in 0..n_missing {
                match excess_input.checked_sub(d.amount() + fee.fee(d.amount())) {
                    Some(remaining_excess) => excess_input = remaining_excess,
                    None => match notes.next().await {
                        Some(note) => {
                            if note.amount() <= d.amount() + fee.fee(d.amount()) {
                                break;
                            }

                            excess_input += note.amount() - (d.amount() + fee.fee(d.amount()));

                            input_notes.push(note);
                        }
                        None => break,
                    },
                }

                output_denominations.push(d);
            }
        }

        (input_notes, output_denominations)
    }

    fn create_input_bundle(
        operation_id: OperationId,
        notes: Vec<SpendableNote>,
        include_receive_sm: bool,
    ) -> ClientInputBundle<MintInput, MintClientStateMachines> {
        let inputs = notes
            .iter()
            .map(|spendable_note| ClientInput {
                input: MintInput::new_v0(spendable_note.note()),
                keys: vec![spendable_note.keypair],
                amounts: Amounts::new_bitcoin(spendable_note.amount()),
            })
            .collect();

        let input_sms = vec![ClientInputSM {
            state_machines: Arc::new(move |range: OutPointRange| {
                let mut sms = vec![MintClientStateMachines::Input(InputStateMachine {
                    common: InputSMCommon {
                        operation_id,
                        txid: range.txid(),
                        spendable_notes: notes.clone(),
                    },
                    state: InputSMState::Pending,
                })];

                if include_receive_sm {
                    sms.push(MintClientStateMachines::Receive(ReceiveStateMachine {
                        operation_id,
                        txid: range.txid(),
                        state: crate::receive::ReceiveSMState::Pending,
                    }));
                }

                sms
            }),
        }];

        ClientInputBundle::new(inputs, input_sms)
    }

    fn create_output_bundle(
        &self,
        operation_id: OperationId,
        requested_denominations: Vec<Denomination>,
    ) -> ClientOutputBundle<MintOutput, MintClientStateMachines> {
        let issuance_requests = requested_denominations
            .into_iter()
            .map(|d| NoteIssuanceRequest::new(d, issuance::grind_tweak(&self.root_secret)))
            .collect::<Vec<NoteIssuanceRequest>>();

        let outputs = issuance_requests
            .iter()
            .map(|request| ClientOutput {
                output: request.output(&self.root_secret),
                amounts: Amounts::new_bitcoin(request.denomination.amount()),
            })
            .collect();

        let output_sms = vec![ClientOutputSM {
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
        }];

        ClientOutputBundle::new(outputs, output_sms)
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

    /// Count the `ECash` notes in the client's database by denomination.
    pub async fn get_count_by_denomination(&self) -> BTreeMap<Denomination, u64> {
        self.get_count_by_denomination_dbtx(
            &mut self.client_ctx.module_db().begin_transaction_nc().await,
        )
        .await
    }

    async fn get_count_by_denomination_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> BTreeMap<Denomination, u64> {
        dbtx.find_by_prefix(&SpendableNotePrefix)
            .await
            .fold(BTreeMap::new(), |mut acc, entry| async move {
                acc.entry(entry.0.0.denomination)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);

                acc
            })
            .await
    }

    /// Send `ECash` for the given amount with an optional description. The
    /// amount will be rounded up to a multiple of 1024 msats which is the
    /// smallest denomination used throughout the client. If the rounded
    /// amount cannot be covered with the ecash notes in the client's
    /// database and the offline argument is set to false the client will
    /// create a transaction to reissue the required denominations. It is
    /// safe to cancel the send method call before the reissue is complete
    /// in which case the reissued notes are returned to the regular
    /// balance. To cancel a successful ecash send simply receive it
    /// yourself.
    pub async fn send(
        &self,
        amount: Amount,
        memo: Option<String>,
        offline: bool,
        custom_meta: Value,
    ) -> Result<ECash, SendECashError> {
        let amount = round_to_multiple(amount, client_denominations().next().unwrap().amount());

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
        let cm = custom_meta.clone();

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                move |range| MintOperationMeta::Reissue {
                    txid: range.txid(),
                    amount,
                    custom_meta: cm.clone(),
                },
                TransactionBuilder::new().with_outputs(output),
            )
            .await
            .map_err(|_| SendECashError::InsufficientBalance)?;

        for outpoint in range {
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
            .map(|entry| entry.0.0);

        let mut notes = vec![];

        while let Some(spendable_note) = stream.next().await {
            remaining_amount = match remaining_amount.checked_sub(spendable_note.amount()) {
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
            self.remove_spendable_note(dbtx, spendable_note).await;
        }

        let ecash = ECash::new(self.federation_id, notes, memo);
        let amount = ecash.amount();
        let operation_id = OperationId::new_random();

        self.client_ctx
            .add_operation_log_entry_dbtx(
                dbtx,
                operation_id,
                MintCommonInit::KIND.as_str(),
                MintOperationMeta::Send {
                    ecash: ecash.encode_base32(),
                    custom_meta,
                },
            )
            .await;

        self.client_ctx
            .log_event(
                dbtx,
                SendPaymentEvent {
                    operation_id,
                    amount,
                },
            )
            .await;

        Ok(Some(ecash))
    }

    /// Receive the `ECash` by reissuing the notes and return the total amount
    /// of the ecash reissued. This method is idempotent. If the client is
    /// currently offline and the offline argument is set to false the
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
            .any(|note| note.amount() < self.cfg.fee_consensus.base_fee())
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

        let input = Self::create_input_bundle(operation_id, ecash.notes(), true);
        let input = self.client_ctx.make_client_inputs(input);
        let ec = ecash.encode_base32();

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                MintCommonInit::KIND.as_str(),
                move |range| MintOperationMeta::Receive {
                    txid: range.txid(),
                    ecash: ec.clone(),
                    custom_meta: custom_meta.clone(),
                },
                TransactionBuilder::new().with_inputs(input),
            )
            .await
            .expect("Receiving ecash requires additional funds");

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                ReceivePaymentEvent {
                    operation_id,
                    amount: ecash.amount(),
                },
            )
            .await;

        dbtx.commit_tx().await;

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_any_tx_accepted()
            .await
            .map_err(|_| ReceiveECashError::AlreadySpent)?;

        for outpoint in range {
            self.await_output_sm_success(operation_id, outpoint)
                .await
                .map_err(|_| ReceiveECashError::Failure)?;
        }

        Ok(ecash.amount())
    }

    async fn remove_spendable_note(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        spendable_note: &SpendableNote,
    ) {
        dbtx.remove_entry(&SpendableNoteKey(spendable_note.clone()))
            .await
            .expect("Must deleted existing spendable note");
    }
}

#[derive(Clone)]
struct PeerSelector {
    latency: Arc<RwLock<BTreeMap<PeerId, Duration>>>,
}

impl PeerSelector {
    fn new(peers: BTreeSet<PeerId>) -> Self {
        let latency = peers
            .into_iter()
            .map(|peer| (peer, Duration::ZERO))
            .collect();

        Self {
            latency: Arc::new(RwLock::new(latency)),
        }
    }

    /// Pick 2 peers at random, return the one with lower latency
    fn choose_peer(&self) -> PeerId {
        let latency = self.latency.read().unwrap();

        let peer_a = latency.iter().choose(&mut thread_rng()).unwrap();
        let peer_b = latency.iter().choose(&mut thread_rng()).unwrap();

        if peer_a.1 <= peer_b.1 {
            *peer_a.0
        } else {
            *peer_b.0
        }
    }

    // Update with exponential moving average (α = 0.1)
    fn report(&self, peer: PeerId, duration: Duration) {
        self.latency
            .write()
            .unwrap()
            .entry(peer)
            .and_modify(|latency| *latency = *latency * 9 / 10 + duration * 1 / 10)
            .or_insert(duration);
    }

    fn remove(&self, peer: PeerId) {
        self.latency.write().unwrap().remove(&peer);
    }
}

/// Download a slice with hash verification and peer selection
async fn download_slice_with_hash(
    module_api: DynModuleApi,
    peer_selector: PeerSelector,
    start: u64,
    end: u64,
    expected_hash: sha256::Hash,
) -> Vec<RecoveryItem> {
    const TIMEOUT: Duration = Duration::from_secs(3);

    loop {
        let peer = peer_selector.choose_peer();
        let start_time = fedimint_core::time::now();

        if let Ok(data) = module_api
            .fetch_recovery_slice(peer, TIMEOUT, start, end)
            .await
        {
            let elapsed = fedimint_core::time::now()
                .duration_since(start_time)
                .unwrap_or_default();

            peer_selector.report(peer, elapsed);

            if data.consensus_hash::<sha256::Hash>() == expected_hash {
                return data;
            }

            peer_selector.remove(peer);
        } else {
            let elapsed = fedimint_core::time::now()
                .duration_since(start_time)
                .unwrap_or_default();

            peer_selector.report(peer, elapsed);
        }
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendECashError {
    #[error("The client needs to reiusse notes but the offline argument is set to false")]
    RequiresReissue,
    #[error("We need to reissue notes but the client is offline")]
    Offline,
    #[error("The clients balance is insufficient")]
    InsufficientBalance,
    #[error("A non-recoverable error has occurred")]
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
    #[error("A non-recoverable error has occurred")]
    Failure,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MintClientStateMachines {
    Input(InputStateMachine),
    Output(MintOutputStateMachine),
    Receive(ReceiveStateMachine),
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
            MintClientStateMachines::Receive(receive_state) => {
                sm_enum_variant_translation!(
                    receive_state.transitions(context, global_context),
                    MintClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            MintClientStateMachines::Input(redemption_state) => redemption_state.operation_id(),
            MintClientStateMachines::Output(issuance_state) => issuance_state.operation_id(),
            MintClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
        }
    }
}

fn round_to_multiple(amount: Amount, min_denomiation: Amount) -> Amount {
    Amount::from_msats(amount.msats.next_multiple_of(min_denomiation.msats))
}

fn represent_amount_with_fees(
    mut remaining_amount: Amount,
    fee_consensus: &FeeConsensus,
) -> Vec<Denomination> {
    let mut denominations = Vec::new();

    // Add denominations with a greedy algorithm
    for denomination in client_denominations().rev() {
        let n_add =
            remaining_amount / (denomination.amount() + fee_consensus.fee(denomination.amount()));

        denominations.extend(std::iter::repeat_n(denomination, n_add as usize));

        remaining_amount -=
            n_add * (denomination.amount() + fee_consensus.fee(denomination.amount()));
    }

    // We sort the notes by amount to minimize the leaked information.
    denominations.sort();

    denominations
}

fn represent_amount(mut remaining_amount: Amount) -> Vec<Denomination> {
    let mut denominations = Vec::new();

    // Add denominations with a greedy algorithm
    for denomination in client_denominations().rev() {
        let n_add = remaining_amount / denomination.amount();

        denominations.extend(std::iter::repeat_n(denomination, n_add as usize));

        remaining_amount -= n_add * denomination.amount();
    }

    denominations
}
