#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{anyhow, ensure};
use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use db::{NextDepositIndexKey, ValidAddressIndexKey, ValidAddressIndexPrefix};
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
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::{Amount, TransactionId, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_CLIENT_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletClientConfig;
use fedimint_walletv2_common::{
    DestinationScript, TransactionInfo, WalletCommonInit, WalletInput, WalletInputV0,
    WalletModuleTypes, WalletOutput, WalletOutputV0, descriptor, is_valid_script,
};
use futures::StreamExt;
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

mod api;
mod cli;
mod db;
pub mod events;
mod receive_sm;
mod send_sm;

use events::{ReceivePaymentEvent, SendPaymentEvent};
use receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use send_sm::{SendSMCommon, SendSMState, SendStateMachine};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Send(SendMeta),
    Receive(ReceiveMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMeta {
    pub change_outpoint_range: OutPointRange,
    pub address: Address<NetworkUnchecked>,
    pub amount: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveMeta {
    pub change_outpoint_range: OutPointRange,
    pub amount: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

/// The final state of an operation sending bitcoin on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalSendOperationState {
    /// The transaction was successful.
    Success(bitcoin::Txid),
    /// The funding transaction was aborted.
    Aborted,
    /// A programming error has occurred or the federation is malicious.
    Failure,
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
    const KIND: Option<ModuleKind> = None;
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

        module.spawn_deposit_scanner(args.task_group());

        Ok(module)
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

impl WalletClientModule {
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

    /// Fetch information on the chain of bitcoin transactions that are
    /// currently still pending.
    async fn pending_transaction_chain(&self) -> FederationResult<Vec<TransactionInfo>> {
        self.module_api.pending_transaction_chain().await
    }

    /// Display log of bitcoin transactions.
    async fn transaction_chain(&self, n: usize) -> FederationResult<Vec<TransactionInfo>> {
        self.module_api.transaction_chain(n).await
    }

    /// Fetch the current fee required to send an on-chain payment.
    pub async fn send_fee(&self) -> Result<bitcoin::Amount, SendError> {
        self.module_api
            .send_fee()
            .await
            .map_err(|e| SendError::FederationError(e.to_string()))?
            .ok_or(SendError::NoConsensusFeerateAvailable)
    }

    /// Send an on-chain payment with the given fee.
    pub async fn send(
        &self,
        address: Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        fee: Option<bitcoin::Amount>,
    ) -> Result<OperationId, SendError> {
        if !address.is_valid_for_network(self.cfg.network) {
            return Err(SendError::WrongNetwork);
        }

        if amount < self.cfg.dust_limit {
            return Err(SendError::DustAmount);
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

        let client_output = ClientOutput::<WalletOutput> {
            output: WalletOutput::V0(WalletOutputV0 {
                destination: DestinationScript::from_address(&address.clone().assume_checked()),
                value: amount,
                fee,
            }),
            amounts: Amounts::new_bitcoin(Amount::from_sats((amount + fee).to_sat())),
        };

        let client_output_sm = ClientOutputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Send(SendStateMachine {
                    common: SendSMCommon {
                        operation_id,
                        outpoint: range.into_iter().next().expect("must have one output"),
                        amount,
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

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Send(SendMeta {
                        change_outpoint_range,
                        address: address.clone(),
                        amount,
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
                    amount,
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

    /// Returns the next unused address.
    pub async fn receive(&self) -> Address {
        if let Some(entry) = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&ValidAddressIndexPrefix)
            .await
            .next()
            .await
        {
            self.derive_address(entry.0.0)
        } else {
            self.derive_address(self.next_valid_index(0))
        }
    }

    fn derive_address(&self, index: u64) -> Address {
        descriptor(
            &self.cfg.bitcoin_pks,
            Some(&self.derive_tweak(index).public_key().consensus_hash()),
        )
        .address(self.cfg.network)
    }

    fn derive_tweak(&self, index: u64) -> Keypair {
        self.root_secret
            .child_key(ChildId(index))
            .to_secp_key(secp256k1::SECP256K1)
    }

    /// Find the next valid index starting from (and including) `start_index`.
    #[allow(clippy::maybe_infinite_iter)]
    fn next_valid_index(&self, start_index: u64) -> u64 {
        let pks_hash = self.cfg.bitcoin_pks.consensus_hash();

        (start_index..)
            .find(|i| is_valid_script(&self.derive_address(*i).script_pubkey(), &pks_hash))
            .expect("Will always find a valid index")
    }

    /// Issue ecash for an unspent deposit with a given fee.
    async fn receive_deposit(
        &self,
        deposit_index: u64,
        amount: bitcoin::Amount,
        address_index: u64,
        fee: bitcoin::Amount,
    ) -> (OperationId, TransactionId) {
        let operation_id = OperationId::new_random();

        let client_input = ClientInput::<WalletInput> {
            input: WalletInput::V0(WalletInputV0 {
                deposit_index,
                fee,
                tweak: self.derive_tweak(address_index).public_key(),
            }),
            keys: vec![self.derive_tweak(address_index)],
            amounts: Amounts::new_bitcoin(Amount::from_sats((amount - fee).to_sat())),
        };

        let client_input_sm = ClientInputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        txid: range.txid(),
                        amount,
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

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Receive(ReceiveMeta {
                        change_outpoint_range,
                        amount,
                        fee,
                    })
                },
                TransactionBuilder::new().with_inputs(client_input_bundle),
            )
            .await
            .expect("Input amount is sufficient to finalize transaction");

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                ReceivePaymentEvent {
                    operation_id,
                    amount,
                    fee,
                },
            )
            .await;

        dbtx.commit_tx().await;

        (operation_id, range.txid())
    }

    fn spawn_deposit_scanner(&self, task_group: &TaskGroup) {
        let module = self.clone();

        task_group.spawn_cancellable("deposit-scanner", async move {
            module.receive().await;

            let mut dbtx = module.db.begin_transaction().await;

            if dbtx
                .find_by_prefix(&ValidAddressIndexPrefix)
                .await
                .next()
                .await
                .is_none()
            {
                dbtx.insert_new_entry(&ValidAddressIndexKey(module.next_valid_index(0)), &())
                    .await;
            }

            dbtx.commit_tx().await;

            loop {
                match module.check_deposits().await {
                    Ok(count) => {
                        if count == 100 {
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(target: LOG_CLIENT_MODULE_WALLETV2, "Failed to fetch deposits: {e}");
                    }
                }

                sleep(fedimint_walletv2_common::sleep_duration()).await;
            }
        });
    }

    async fn check_deposits(&self) -> anyhow::Result<usize> {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let next_deposit_index = dbtx.get_value(&NextDepositIndexKey).await.unwrap_or(0);

        let valid_indices: Vec<u64> = dbtx
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        let address_map: BTreeMap<ScriptBuf, u64> = valid_indices
            .iter()
            .map(|&i| (self.derive_address(i).script_pubkey(), i))
            .collect();

        let mut added_address_index = false;

        let deposit_range = self
            .module_api
            .deposit_range(next_deposit_index, next_deposit_index + 100)
            .await?;

        info!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            "Scanning for deposits..."
        );

        for (offset, tx_out) in deposit_range.deposits.iter().enumerate() {
            let deposit_index = next_deposit_index + offset as u64;

            if let Some(&address_index) = address_map.get(&tx_out.script_pubkey) {
                let receive_fee = self
                    .module_api
                    .receive_fee()
                    .await?
                    .ok_or(anyhow!("No consensus feerate is available"))?;

                info!(
                    target: LOG_CLIENT_MODULE_WALLETV2,
                    deposit_index,
                    value_sats = tx_out.value.to_sat(),
                    "Found matching deposit, claiming..."
                );

                if tx_out.value >= receive_fee + bitcoin::Amount::from_sat(100)
                    && !deposit_range.spent.contains(&deposit_index)
                {
                    let (operation_id, txid) = self
                        .receive_deposit(deposit_index, tx_out.value, address_index, receive_fee)
                        .await;

                    let result = self
                        .client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(txid)
                        .await;

                    ensure!(
                        result.is_ok(),
                        "Claim transaction for deposit {deposit_index} was rejected"
                    );
                }

                let mut dbtx = self.db.begin_transaction().await;

                dbtx.insert_entry(&NextDepositIndexKey, &(deposit_index + 1))
                    .await;

                let next_address_index = valid_indices
                    .last()
                    .copied()
                    .expect("we have at least one address index");

                // If we used the highest valid index, add the next valid one
                if address_index == next_address_index && !added_address_index {
                    dbtx.insert_entry(
                        &ValidAddressIndexKey(self.next_valid_index(address_index + 1)),
                        &(),
                    )
                    .await;

                    info!(
                        target: LOG_CLIENT_MODULE_WALLETV2,
                        "Adding next valid address index"
                    );

                    added_address_index = true;
                }

                dbtx.commit_tx_result().await?;
            }
        }

        Ok(deposit_range.deposits.len())
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendError {
    #[error("Address is from a different network then the federation.")]
    WrongNetwork,
    #[error("The amount is to small to be send on-chain")]
    DustAmount,
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
    #[error("The client does not have sufficicent funds to send the payment")]
    InsufficientFunds,
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
