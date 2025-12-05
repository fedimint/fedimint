#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt::Debug;

use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use db::AddressCounterKey;
use fedimint_api_client::api::{DynModuleApi, FederationResult};
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule, OutPointRange};
use fedimint_client_module::sm::{Context, DynState, State, StateTransition};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_walletv2_common::config::WalletClientConfig;
use fedimint_walletv2_common::esplora_api::{DynEsploraConnection, RealEsploraConnection};
use fedimint_walletv2_common::{
    descriptor, DestinationScript, ReceiveFee, SendFee, TransactionInfo, WalletCommonInit,
    WalletInput, WalletInputV0, WalletModuleTypes, WalletOutput, WalletOutputV0,
};
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod api;
mod cli;
mod db;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalOperationState {
    /// The operation has been successful.
    Success,
    /// The operation has been aborted due to a change of the consensus feerate.
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentDeposit {
    /// The amount that has been deposited.
    pub value: bitcoin::Amount,
    /// If the deposit has been confirmed this is the number of additional
    /// confirmations required until the ecash for the deposit can be claimed.
    pub confirmations_required: Option<u64>,
    /// The bitcoin outpoint.
    pub outpoint: bitcoin::OutPoint,
    /// The index of the address this deposit was made to.
    pub index: u64,
}

#[derive(Debug)]
pub struct WalletClientModule {
    root_secret: DerivableSecret,
    cfg: WalletClientConfig,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
    esplora_rpc: DynEsploraConnection,
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    pub decoder: Decoder,
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
            decoder: self.decoder(),
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

#[derive(Debug, Clone)]
pub struct WalletClientInit {
    pub esplora_connection: DynEsploraConnection,
}

impl Default for WalletClientInit {
    fn default() -> Self {
        Self {
            esplora_connection: DynEsploraConnection::from(RealEsploraConnection),
        }
    }
}

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
        Ok(WalletClientModule {
            root_secret: args.module_root_secret().clone(),
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
            esplora_rpc: self.esplora_connection.clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

/// Methods for operator to retrieve information about the wallet state.
pub struct WalletInfoApi(DynModuleApi);

impl WalletInfoApi {
    /// Fetch the total value of bitcoin controlled by the federation.
    pub async fn total_value(&self) -> FederationResult<bitcoin::Amount> {
        self.0
            .federation_wallet()
            .await
            .map(|tx_out| tx_out.map_or(bitcoin::Amount::ZERO, |tx_out| tx_out.value))
    }

    /// Fetch the consensus block count of the federation.
    pub async fn block_count(&self) -> FederationResult<u64> {
        self.0.consensus_block_count().await
    }

    /// Fetch the current consensus feerate.
    pub async fn feerate(&self) -> FederationResult<Option<u64>> {
        self.0.consensus_feerate().await
    }

    /// Fetch information on the chain of bitcoin transactions that are
    /// currently still pending.
    pub async fn pending_transaction_chain(&self) -> FederationResult<Vec<TransactionInfo>> {
        self.0.pending_transaction_chain().await
    }

    /// Retrieve info for a bitcoin transaction by index.
    pub async fn transaction(&self, index: u64) -> FederationResult<Option<TransactionInfo>> {
        self.0.transaction_info(index).await
    }

    /// Display log of bitcoin transactions.
    pub async fn transaction_chain(
        &self,
        n_transactions: usize,
    ) -> FederationResult<Vec<TransactionInfo>> {
        self.0.transaction_chain(n_transactions).await
    }
}

impl WalletClientModule {
    /// Methods for operator to retrieve information about the wallet state.
    pub fn info(&self) -> WalletInfoApi {
        WalletInfoApi(self.module_api.clone())
    }

    /// Fetch the current fee required to send an on-chain payment.
    pub async fn send_fee(&self) -> Result<bitcoin::Amount, SendError> {
        self.module_api
            .send_fee()
            .await
            .map_err(|e| SendError::FederationError(e.to_string()))?
            .ok_or(SendError::NoConsensusFeerateAvailable)
            .map(|fee| fee.value)
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

        let send_fee = self
            .module_api
            .send_fee()
            .await
            .map_err(|e| SendError::FederationError(e.to_string()))?
            .ok_or(SendError::NoConsensusFeerateAvailable)?;

        let send_fee = match fee {
            Some(value) => {
                if value < send_fee.value {
                    return Err(SendError::InsufficientFee);
                }

                SendFee {
                    index: send_fee.index,
                    value,
                }
            }
            None => send_fee,
        };

        let operation_id = OperationId::new_random();

        let client_output = ClientOutput::<WalletOutput> {
            output: WalletOutput::V0(WalletOutputV0 {
                destination: DestinationScript::from_address(&address.clone().assume_checked()),
                value: amount,
                fee: send_fee.clone(),
            }),
            amounts: Amounts::new_bitcoin(Amount::from_sats((amount + send_fee.value).to_sat())),
        };

        let client_output_bundle = self
            .client_ctx
            .make_client_outputs(ClientOutputBundle::new_no_sm(vec![client_output]));

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Send(SendMeta {
                        change_outpoint_range,
                        address: address.clone(),
                        amount,
                        fee: send_fee.value,
                    })
                },
                TransactionBuilder::new().with_outputs(client_output_bundle),
            )
            .await
            .map_err(|_| SendError::InsufficientFunds)?;

        Ok(operation_id)
    }

    /// Await the final operation state of a send or receive operation.
    pub async fn await_final_operation_state(
        &self,
        operation_id: OperationId,
    ) -> FinalOperationState {
        match self
            .client_ctx
            .transaction_updates(operation_id)
            .await
            .await_any_tx_accepted()
            .await
        {
            Ok(()) => FinalOperationState::Success,
            Err(..) => FinalOperationState::Aborted,
        }
    }

    /// Increment the address counter and return the new highest index.
    pub async fn increment_address_index(&self) -> u64 {
        let mut dbtx = self.db.begin_transaction().await;

        let index = dbtx.get_value(&AddressCounterKey).await.unwrap_or(0);

        dbtx.insert_entry(&AddressCounterKey, &(index + 1)).await;

        dbtx.commit_tx().await;

        index
    }

    /// Return the number of all previously derived addresses.
    pub async fn address_count(&self) -> u64 {
        self.db
            .begin_transaction()
            .await
            .get_value(&AddressCounterKey)
            .await
            .unwrap_or(0)
    }

    /// Derive address for an index.
    pub fn derive_address(&self, index: u64) -> Address {
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

    fn default_esplora_server(&self) -> Option<SafeUrl> {
        let url = match self.cfg.network {
            Network::Bitcoin => "https://blockstream.info/api/",
            Network::Testnet => "https://blockstream.info/testnet/api/",
            Network::Signet => "https://blockstream.info/signet/api/",
            _ => return None,
        };

        Some(SafeUrl::parse(url).expect("Failed to parse default esplora server"))
    }

    /// Check an address for unspent deposits and return the deposits in
    /// descending order by value. If no esplora api is set and the network is
    /// either Mainnet, Testnet 3 or Signet the client will default to the
    /// blockstream api.
    pub async fn check_address_for_deposits(
        &self,
        index: u64,
        esplora: Option<SafeUrl>,
    ) -> Result<Vec<UnspentDeposit>, CheckError> {
        let esplora = match esplora {
            Some(esplora) => esplora,
            None => self
                .default_esplora_server()
                .ok_or(CheckError::NoEsploraDefault)?,
        };

        let consensus_block_height = self
            .info()
            .block_count()
            .await
            .map_err(|e| CheckError::FederationError(e.to_string()))?
            .saturating_sub(1);

        let mut deposits = self
            .esplora_rpc
            .get_address_utxo(esplora, self.derive_address(index))
            .await
            .map_err(|e| CheckError::EsploraError(e.to_string()))?
            .into_iter()
            .map(|utxo| UnspentDeposit {
                value: bitcoin::Amount::from_sat(utxo.value),
                confirmations_required: utxo
                    .status
                    .block_height
                    .map(|block_height| block_height.saturating_sub(consensus_block_height)),
                outpoint: bitcoin::OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                index,
            })
            .collect::<Vec<UnspentDeposit>>();

        deposits.sort_by_key(|d| d.value);

        deposits.reverse();

        let unspent_outpoints = self
            .module_api
            .filter_unspent_outpoints(&deposits.iter().map(|d| d.outpoint).collect())
            .await
            .map_err(|e| CheckError::FederationError(e.to_string()))?;

        let unspent_deposits = deposits
            .into_iter()
            .filter(|d| unspent_outpoints.contains(&d.outpoint))
            .collect();

        Ok(unspent_deposits)
    }

    /// Fetch the current fee required to issue ecash for an unspent deposit.
    pub async fn receive_fee(&self) -> Result<bitcoin::Amount, ReceiveError> {
        self.module_api
            .receive_fee()
            .await
            .map_err(|e| ReceiveError::FederationError(e.to_string()))?
            .ok_or(ReceiveError::NoConsensusFeerateAvailable)
            .map(|fee| fee.value)
    }

    /// Issue ecash for an unspent deposit with a given fee.
    pub async fn receive(
        &self,
        unspent_deposit: UnspentDeposit,
        fee: Option<bitcoin::Amount>,
    ) -> Result<OperationId, ReceiveError> {
        let receive_fee = self
            .module_api
            .receive_fee()
            .await
            .map_err(|e| ReceiveError::FederationError(e.to_string()))?
            .ok_or(ReceiveError::NoConsensusFeerateAvailable)?;

        let receive_fee = match fee {
            Some(value) => {
                if value < receive_fee.value {
                    return Err(ReceiveError::InsufficientFee);
                }

                ReceiveFee {
                    index: receive_fee.index,
                    value,
                }
            }
            None => receive_fee,
        };

        if unspent_deposit.value < receive_fee.value + bitcoin::Amount::from_sat(100) {
            return Err(ReceiveError::DustDeposit);
        }

        let operation_id = OperationId::new_random();

        let client_input = ClientInput::<WalletInput> {
            input: WalletInput::V0(WalletInputV0 {
                outpoint: unspent_deposit.outpoint,
                fee: receive_fee.clone(),
                tweak: self.derive_tweak(unspent_deposit.index).public_key(),
            }),
            keys: vec![self.derive_tweak(unspent_deposit.index)],
            amounts: Amounts::new_bitcoin(Amount::from_sats(
                (unspent_deposit.value - receive_fee.value).to_sat(),
            )),
        };

        let client_input_bundle = self
            .client_ctx
            .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input]));

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Receive(ReceiveMeta {
                        change_outpoint_range,
                        amount: unspent_deposit.value,
                        fee: receive_fee.value,
                    })
                },
                TransactionBuilder::new().with_inputs(client_input_bundle),
            )
            .await
            .expect("Input amount is sufficient to finalize transaction");

        Ok(operation_id)
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
    #[error("The currently required fee exceeds the specified fee")]
    InsufficientFee,
    #[error("The client does not have sufficicent funds to send the payment")]
    InsufficientFunds,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum CheckError {
    #[error("There is no default esplora server for this network")]
    NoEsploraDefault,
    #[error("Esplora returned an error: {0}")]
    EsploraError(String),
    #[error("Federation returned an error: {0}")]
    FederationError(String),
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
    #[error("The currently required fee exceeds the specified fee")]
    InsufficientFee,
    #[error("The unspent deposit cannot be claimed with the given fee without additional funds")]
    DustDeposit,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WalletClientStateMachines {}

impl State for WalletClientStateMachines {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        unreachable!()
    }

    fn operation_id(&self) -> OperationId {
        unreachable!()
    }
}

impl IntoDynInstance for WalletClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
