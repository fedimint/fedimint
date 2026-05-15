#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub use fedimint_walletv2_common as common;

mod api;
#[cfg(feature = "cli")]
mod cli;
mod db;
pub mod events;
mod receive_sm;
mod send_sm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use db::{NextOutputIndexKey, ValidAddressIndexKey, ValidAddressIndexPrefix};
use events::{ReceivePaymentEvent, SendPaymentEvent};
use fedimint_api_client::api::{DynModuleApi, FederationResult};
use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, OutPointRange};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::sm_enum_variant_translation;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{TaskGroup, TaskHandle, block_in_place, sleep};
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_CLIENT_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletClientConfig;
use fedimint_walletv2_common::{
    KIND, StandardScript, TxInfo, WalletCommonInit, WalletInput, WalletInputV0, WalletModuleTypes,
    WalletOutput, WalletOutputV0, descriptor, is_potential_receive,
};
use futures::StreamExt;
use receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use secp256k1::Keypair;
use send_sm::{SendSMCommon, SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator as _;
use thiserror::Error;
use tracing::{debug, warn};

/// Number of output info entries to scan per batch.
const SLICE_SIZE: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Send(SendMeta),
    Receive(ReceiveMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMeta {
    pub change_outpoint_range: OutPointRange,
    pub address: Address<NetworkUnchecked>,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveMeta {
    pub change_outpoint_range: OutPointRange,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

/// The final state of an operation sending bitcoin onchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalSendOperationState {
    /// The transaction was successful.
    Success(bitcoin::Txid),
    /// The funding transaction was aborted.
    Aborted,
    /// A programming error has occurred or the federation is malicious.
    Failure,
}

/// The final state of an operation claiming an onchain deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalReceiveState {
    /// The deposit was successfully claimed.
    Success,
    /// The federation rejected the claim transaction.
    Aborted(String),
}

/// Result of a single pass of [`WalletClientModule::check_outputs`].
#[derive(Debug, Clone)]
struct CheckOutputsProgress {
    /// `(operation_id, script)` for each claim submitted during this pass.
    submitted: Vec<(OperationId, ScriptBuf)>,
    /// True if the federation returned a non-empty slice, meaning there are
    /// likely more outputs to scan immediately; false if the slice was empty
    /// and the caller should back off before retrying.
    more_outputs: bool,
}

#[derive(Debug, Clone)]
pub struct WalletClientModule {
    root_secret: DerivableSecret,
    cfg: WalletClientConfig,
    notifier: ModuleNotifier<WalletClientStateMachines>,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    pub client_ctx: ClientContext<WalletClientModule>,
}

impl Context for WalletClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for WalletClientModule {
    type Init = WalletClientInit;
    type Common = WalletModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = WalletClientContext;
    type States = WalletClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        WalletClientContext {
            client_ctx: self.client_ctx.clone(),
        }
    }

    fn input_fee(
        &self,
        amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        amount
            .get(&AmountUnit::BITCOIN)
            .map(|a| Amounts::new_bitcoin(self.cfg.fee_consensus.fee(*a)))
    }

    fn output_fee(
        &self,
        amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        amount
            .get(&AmountUnit::BITCOIN)
            .map(|a| Amounts::new_bitcoin(self.cfg.fee_consensus.fee(*a)))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct WalletClientInit;

impl ModuleInit for WalletClientInit {
    type Common = WalletCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for WalletClientInit {
    type Module = WalletClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let module = WalletClientModule {
            root_secret: args.module_root_secret().clone(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
        };

        Ok(module)
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(db::DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

impl WalletClientModule {
    /// Returns the Bitcoin network for this federation.
    pub fn get_network(&self) -> bitcoin::Network {
        self.cfg.network
    }

    /// Fetch the total value of bitcoin controlled by the federation.
    pub async fn total_value(&self) -> FederationResult<bitcoin::Amount> {
        self.module_api
            .federation_wallet()
            .await
            .map(|tx_out| tx_out.map_or(bitcoin::Amount::ZERO, |tx_out| tx_out.value))
    }

    /// Fetch the consensus block count of the federation.
    pub async fn block_count(&self) -> FederationResult<u64> {
        self.module_api.consensus_block_count().await
    }

    /// Fetch the current consensus feerate.
    pub async fn feerate(&self) -> FederationResult<Option<u64>> {
        self.module_api.consensus_feerate().await
    }

    /// Fetch information on the chain of pending bitcoin transactions.
    async fn pending_tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.module_api.pending_tx_chain().await
    }

    /// Display log of bitcoin transactions.
    async fn tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.module_api.tx_chain().await
    }

    /// Fetch the current fee required to send an onchain payment.
    pub async fn send_fee(&self) -> Result<bitcoin::Amount, SendError> {
        self.module_api
            .send_fee()
            .await
            .map_err(|e| SendError::FederationError(e.to_string()))?
            .ok_or(SendError::NoConsensusFeerateAvailable)
    }

    /// Send an onchain payment with the given fee.
    pub async fn send(
        &self,
        address: Address<NetworkUnchecked>,
        value: bitcoin::Amount,
        fee: Option<bitcoin::Amount>,
    ) -> Result<OperationId, SendError> {
        if !address.is_valid_for_network(self.cfg.network) {
            return Err(SendError::WrongNetwork);
        }

        if value < self.cfg.dust_limit {
            return Err(SendError::DustValue);
        }

        let fee = match fee {
            Some(value) => value,
            None => self
                .module_api
                .send_fee()
                .await
                .map_err(|e| SendError::FederationError(e.to_string()))?
                .ok_or(SendError::NoConsensusFeerateAvailable)?,
        };

        let operation_id = OperationId::new_random();

        let destination = StandardScript::from_address(&address.clone().assume_checked())
            .ok_or(SendError::UnsupportedAddress)?;

        let client_output = ClientOutput::<WalletOutput> {
            output: WalletOutput::V0(WalletOutputV0 {
                destination,
                value,
                fee,
            }),
            amounts: Amounts::new_bitcoin(Amount::from_sats((value + fee).to_sat())),
        };

        let client_output_sm = ClientOutputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Send(SendStateMachine {
                    common: SendSMCommon {
                        operation_id,
                        outpoint: OutPoint {
                            txid: range.txid(),
                            out_idx: 0,
                        },
                        value,
                        fee,
                    },
                    state: SendSMState::Funding,
                })]
            }),
        };

        let client_output_bundle = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        let address_clone = address.clone();

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Send(SendMeta {
                        change_outpoint_range,
                        address: address_clone.clone(),
                        value,
                        fee,
                    })
                },
                TransactionBuilder::new().with_outputs(client_output_bundle),
            )
            .await
            .map_err(|_| SendError::InsufficientFunds)?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                SendPaymentEvent {
                    operation_id,
                    address,
                    value,
                    fee,
                },
            )
            .await;

        dbtx.commit_tx().await;

        Ok(operation_id)
    }

    /// Await the final state of the send operation.
    pub async fn await_final_send_operation_state(
        &self,
        operation_id: OperationId,
    ) -> FinalSendOperationState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            let Some(WalletClientStateMachines::Send(state)) = stream.next().await else {
                panic!("stream must produce a terminal send state");
            };

            match state.state {
                SendSMState::Funding => {}
                SendSMState::Success(txid) => return FinalSendOperationState::Success(txid),
                SendSMState::Aborted(..) => return FinalSendOperationState::Aborted,
                SendSMState::Failure => return FinalSendOperationState::Failure,
            }
        }
    }

    /// Await the final state of the receive operation.
    pub async fn await_final_receive_operation_state(
        &self,
        operation_id: OperationId,
    ) -> FinalReceiveState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            let Some(WalletClientStateMachines::Receive(state)) = stream.next().await else {
                panic!("stream must produce a terminal receive state");
            };

            match state.state {
                ReceiveSMState::Funding => {}
                ReceiveSMState::Success => return FinalReceiveState::Success,
                ReceiveSMState::Aborted(reason) => return FinalReceiveState::Aborted(reason),
            }
        }
    }

    /// Drive the deposit scanner until a claim for `address` is submitted,
    /// then block until that claim's state machine reaches a terminal state.
    ///
    /// Forward-looking: only awaits deposits submitted *during this call*. If
    /// the address was claimed in a previous session, this won't surface that
    /// history — the funds are already in the user's balance.
    pub async fn await_receive(
        &self,
        address: Address<NetworkUnchecked>,
    ) -> anyhow::Result<FinalReceiveState> {
        let script = address.assume_checked().script_pubkey();
        // Foreground caller — no shared shutdown signal, so use a fresh group
        // whose handle never reports shutting-down. The group is dropped when
        // this function returns.
        let task_group = TaskGroup::new();
        let handle = task_group.make_handle();

        loop {
            let progress = self.check_outputs(&handle).await?;

            for (operation_id, claim_script) in progress.submitted {
                if claim_script == script {
                    return Ok(self.await_final_receive_operation_state(operation_id).await);
                }
            }

            if !progress.more_outputs {
                sleep(fedimint_walletv2_common::sleep_duration()).await;
            }
        }
    }

    /// Returns the next unused receive address, polling until the initial
    /// address derivation has completed.
    pub async fn receive(&self) -> Address {
        loop {
            if let Some(entry) = self
                .db
                .begin_transaction_nc()
                .await
                .find_by_prefix_sorted_descending(&ValidAddressIndexPrefix)
                .await
                .next()
                .await
            {
                return self.derive_address(entry.0.0);
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    fn derive_address(&self, index: u64) -> Address {
        descriptor(
            &self.cfg.bitcoin_pks,
            &self.derive_tweak(index).public_key().consensus_hash(),
        )
        .address(self.cfg.network)
    }

    fn derive_tweak(&self, index: u64) -> Keypair {
        self.root_secret
            .child_key(ChildId(index))
            .to_secp_key(secp256k1::SECP256K1)
    }

    /// Find the next valid index starting from (and including) `start_index`.
    ///
    /// Returns `None` if the task group begins shutting down before a valid
    /// index is found — `block_in_place` itself cannot be interrupted, so we
    /// poll the task handle each iteration so this CPU-bound loop doesn't
    /// hold up shutdown for the duration of the search.
    #[allow(clippy::maybe_infinite_iter)]
    fn next_valid_index(&self, start_index: u64, handle: &TaskHandle) -> Option<u64> {
        let pks_hash = self.cfg.bitcoin_pks.consensus_hash();

        block_in_place(|| {
            (start_index..)
                .take_while(|_| !handle.is_shutting_down())
                .find(|i| is_potential_receive(&self.derive_address(*i).script_pubkey(), &pks_hash))
        })
    }

    /// Issue ecash for an unspent output with a given fee.
    ///
    /// Submission and event logging happen inside the caller-supplied `dbtx`
    /// so that the caller can atomically advance `NextOutputIndexKey` in the
    /// same commit. Returns the `OperationId` of the receive operation on
    /// success — callers can use it to await the receive state machine's
    /// terminal state. Returns an error if the transaction cannot be
    /// assembled locally — most commonly because the remaining value after
    /// `receive_fee` is too small to cover the mint module's output fee.
    /// Federation acceptance is tracked by the receive state machine and
    /// does not block this call.
    async fn receive_output(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        output_index: u64,
        value: bitcoin::Amount,
        address_index: u64,
        fee: bitcoin::Amount,
    ) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();

        let client_input = ClientInput::<WalletInput> {
            input: WalletInput::V0(WalletInputV0 {
                output_index,
                fee,
                tweak: self.derive_tweak(address_index).public_key(),
            }),
            keys: vec![self.derive_tweak(address_index)],
            amounts: Amounts::new_bitcoin(Amount::from_sats((value - fee).to_sat())),
        };

        let client_input_sm = ClientInputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        txid: range.txid(),
                        value,
                        fee,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_input_bundle = self.client_ctx.make_client_inputs(ClientInputBundle::new(
            vec![client_input],
            vec![client_input_sm],
        ));

        self.client_ctx
            .finalize_and_submit_transaction_dbtx(
                dbtx,
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Receive(ReceiveMeta {
                        change_outpoint_range,
                        value,
                        fee,
                    })
                },
                TransactionBuilder::new().with_inputs(client_input_bundle),
            )
            .await?;

        self.client_ctx
            .log_event(
                dbtx,
                ReceivePaymentEvent {
                    operation_id,
                    address: self.derive_address(address_index).as_unchecked().clone(),
                    value,
                    fee,
                },
            )
            .await;

        Ok(operation_id)
    }

    /// Spawn a background task that scans the federation's deposit log and
    /// claims any deposits that land on this client's addresses.
    ///
    /// Opt-in: not called from [`ClientModuleInit::init`]. Stateful apps that
    /// want continuous auto-claiming should spawn this once at startup;
    /// one-shot callers (e.g. CLI) can use [`Self::await_receive`] instead,
    /// which drives its own scan loop for the duration of a single wait.
    pub fn spawn_output_scanner(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();
        let handle = task_group.make_handle();

        task_group.spawn_cancellable_with_span(client_span.clone(), "output-scanner", async move {
            let mut dbtx = module.db.begin_transaction().await;

            if dbtx
                .find_by_prefix(&ValidAddressIndexPrefix)
                .await
                .next()
                .await
                .is_none()
                && let Some(idx) = module.next_valid_index(0, &handle)
            {
                dbtx.insert_new_entry(&ValidAddressIndexKey(idx), &()).await;
            }

            dbtx.commit_tx().await;

            loop {
                match module.check_outputs(&handle).await {
                    Ok(progress) => {
                        if progress.more_outputs {
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(target: LOG_CLIENT_MODULE_WALLETV2, "Failed to fetch outputs: {e}");
                    }
                }

                sleep(fedimint_walletv2_common::sleep_duration()).await;
            }
        });
    }

    #[allow(clippy::too_many_lines)]
    async fn check_outputs(&self, handle: &TaskHandle) -> anyhow::Result<CheckOutputsProgress> {
        // Read both values from a single snapshot and drop the read-only
        // dbtx before the RPC and loop run, so we don't pin a snapshot
        // across the federation round-trips and inner write transactions.
        let (next_output_index, mut valid_indices) = {
            let mut dbtx = self.db.begin_transaction_nc().await;

            let next_output_index = dbtx.get_value(&NextOutputIndexKey).await.unwrap_or(0);

            let valid_indices: Vec<u64> = dbtx
                .find_by_prefix(&ValidAddressIndexPrefix)
                .await
                .map(|entry| entry.0.0)
                .collect()
                .await;

            (next_output_index, valid_indices)
        };

        let mut address_map: BTreeMap<ScriptBuf, u64> = valid_indices
            .iter()
            .map(|&i| (self.derive_address(i).script_pubkey(), i))
            .collect();

        let mut submitted: Vec<(OperationId, ScriptBuf)> = Vec::new();

        let outputs = self
            .module_api
            .output_info_slice(next_output_index, next_output_index + SLICE_SIZE)
            .await?;

        let returned_num = outputs.len();
        let mut matched_num: usize = 0;

        for output in &outputs {
            // If this output landed on our current highest derived address,
            // pre-compute the next valid index but DON'T persist it yet — it
            // gets written in the same commit as the matching cursor advance
            // below, so a cancellation or congestion early-return can't leave
            // a phantom address ahead of the deposit that triggered it.
            let new_valid_index = match address_map.get(&output.script) {
                Some(&address_index)
                    if address_index
                        == valid_indices
                            .last()
                            .copied()
                            .expect("we have at least one address index") =>
                {
                    // If shutdown is signaled mid-search, bail out without
                    // committing anything — we'll resume on the next start.
                    let Some(idx) = self.next_valid_index(address_index + 1, handle) else {
                        return Ok(CheckOutputsProgress {
                            submitted,
                            more_outputs: false,
                        });
                    };
                    Some(idx)
                }
                _ => None,
            };

            if let Some(&address_index) = address_map.get(&output.script)
                && !output.spent
            {
                // In order to not overpay on fees we choose to wait,
                // the congestion will clear up within a few blocks.
                if self.module_api.pending_tx_chain().await?.len() >= 3 {
                    return Ok(CheckOutputsProgress {
                        submitted,
                        more_outputs: false,
                    });
                }

                matched_num += 1;

                let receive_fee = self
                    .module_api
                    .receive_fee()
                    .await?
                    .ok_or(anyhow!("No consensus feerate is available"))?;

                if output.value > receive_fee {
                    // Submit the claim, extend the address watermark (if any),
                    // and advance the scan cursor in the same commit so
                    // cancellation between them cannot cause a duplicate claim
                    // or a phantom valid index on restart.
                    let mut dbtx = self.db.begin_transaction().await;

                    let result = self
                        .receive_output(
                            &mut dbtx.to_ref_nc(),
                            output.index,
                            output.value,
                            address_index,
                            receive_fee,
                        )
                        .await;

                    match result {
                        Ok(operation_id) => {
                            if let Some(idx) = new_valid_index {
                                dbtx.insert_entry(&ValidAddressIndexKey(idx), &()).await;
                            }

                            dbtx.insert_entry(&NextOutputIndexKey, &(output.index + 1))
                                .await;

                            dbtx.commit_tx_result().await?;

                            if let Some(idx) = new_valid_index {
                                valid_indices.push(idx);
                                address_map.insert(self.derive_address(idx).script_pubkey(), idx);
                            }

                            submitted.push((operation_id, output.script.clone()));

                            continue;
                        }
                        Err(err) => {
                            // The receive's dbtx goes out of scope
                            // uncommitted; control falls through to the
                            // unconditional cursor advance below so we skip
                            // past this output instead of looping on it
                            // forever.
                            warn!(
                                target: LOG_CLIENT_MODULE_WALLETV2,
                                output_index = output.index,
                                value_sat = output.value.to_sat(),
                                err = %err.fmt_compact_anyhow(),
                                "Output not economical to claim, advancing past it",
                            );
                        }
                    }
                }
            }

            let mut dbtx = self.db.begin_transaction().await;

            if let Some(idx) = new_valid_index {
                dbtx.insert_entry(&ValidAddressIndexKey(idx), &()).await;
            }

            dbtx.insert_entry(&NextOutputIndexKey, &(output.index + 1))
                .await;

            dbtx.commit_tx_result().await?;

            if let Some(idx) = new_valid_index {
                valid_indices.push(idx);
                address_map.insert(self.derive_address(idx).script_pubkey(), idx);
            }
        }

        debug!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            next_output_index,
            returned_num,
            matched_num,
            valid_indices_num = valid_indices.len(),
            "Scanning for outputs"
        );

        Ok(CheckOutputsProgress {
            submitted,
            more_outputs: !outputs.is_empty(),
        })
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendError {
    #[error("Address is from a different network than the federation.")]
    WrongNetwork,
    #[error("The value is too small")]
    DustValue,
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
    #[error("The client does not have sufficient funds to send the payment")]
    InsufficientFunds,
    #[error("Unsupported address type")]
    UnsupportedAddress,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WalletClientStateMachines {
    Send(send_sm::SendStateMachine),
    Receive(receive_sm::ReceiveStateMachine),
}

impl State for WalletClientStateMachines {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            WalletClientStateMachines::Send(sm) => sm_enum_variant_translation!(
                sm.transitions(context, global_context),
                WalletClientStateMachines::Send
            ),
            WalletClientStateMachines::Receive(sm) => sm_enum_variant_translation!(
                sm.transitions(context, global_context),
                WalletClientStateMachines::Receive
            ),
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            WalletClientStateMachines::Send(sm) => sm.operation_id(),
            WalletClientStateMachines::Receive(sm) => sm.operation_id(),
        }
    }
}

impl IntoDynInstance for WalletClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
