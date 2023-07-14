pub mod api;

mod deposit;
mod withdraw;

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, bail, ensure};
use async_stream::stream;
use bitcoin::{Address, Network};
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, MultiApiVersion,
    TransactionItemAmount,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint};
use fedimint_wallet_common::config::WalletClientConfig;
use fedimint_wallet_common::tweakable::Tweakable;
pub use fedimint_wallet_common::*;
use futures::{Stream, StreamExt};
use miniscript::ToPublicKey;
use rand::{thread_rng, Rng};
use secp256k1::{All, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::api::WalletFederationApi;
use crate::deposit::{CreatedDepositState, DepositStateMachine, DepositStates};
use crate::withdraw::{CreatedWithdrawState, WithdrawStateMachine, WithdrawStates};

#[apply(async_trait_maybe_send!)]
pub trait WalletClientExt {
    async fn get_deposit_address(
        &self,
        valid_until: SystemTime,
    ) -> anyhow::Result<(OperationId, Address)>;

    async fn subscribe_deposit_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<DepositState>>;

    /// Fetches the fees that would need to be paid to make the withdraw request
    /// using [`WalletClientExt::withdraw`] work *right now*.
    ///
    /// Note that we do not receive a guarantee that these fees will be valid in
    /// the future, thus even the next second using these fees *may* fail.
    /// The caller should be prepared to retry with a new fee estimate.
    async fn get_withdraw_fee(
        &self,
        address: bitcoin::Address,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<PegOutFees>;

    /// Attempt to withdraw a given `amount` of Bitcoin to a destination
    /// `address`. The caller has to supply the fee rate to be used which can be
    /// fetched using [`WalletClientExt::get_withdraw_fee`] and should be
    /// acknowledged by the user since it can be unexpectedly high.
    async fn withdraw(
        &self,
        address: bitcoin::Address,
        amount: bitcoin::Amount,
        fee: PegOutFees,
    ) -> anyhow::Result<OperationId>;

    async fn subscribe_withdraw_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<WithdrawState>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum DepositState {
    WaitingForTransaction,
    WaitingForConfirmation,
    Confirmed,
    // TODO: add amount
    Claimed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum WithdrawState {
    Created,
    Succeeded(bitcoin::Txid),
    Failed(String),
    // TODO: track refund
    // Refunded,
    // RefundFailed(String),
}

#[apply(async_trait_maybe_send!)]
impl WalletClientExt for Client {
    async fn get_deposit_address(
        &self,
        valid_until: SystemTime,
    ) -> anyhow::Result<(OperationId, Address)> {
        let (wallet_client, instance) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        let (operation_id, address) = self
            .db()
            .autocommit(
                |dbtx| {
                    Box::pin(async move {
                        let (operation_id, sm, address) =
                            wallet_client.get_deposit_address(valid_until);
                        // Begin watching the script address
                        wallet_client
                            .rpc
                            .watch_script_history(&address.script_pubkey())
                            .await?;

                        self.add_state_machines(dbtx, vec![DynState::from_typed(instance.id, sm)])
                            .await?;
                        self.operation_log()
                            .add_operation_log_entry(
                                dbtx,
                                operation_id,
                                WalletCommonGen::KIND.as_str(),
                                WalletOperationMeta::Deposit {
                                    address: address.clone(),
                                    expires_at: valid_until,
                                },
                            )
                            .await;

                        Ok((operation_id, address))
                    })
                },
                Some(100),
            )
            .await
            .map_err(|e| match e {
                AutocommitError::CommitFailed {
                    last_error,
                    attempts,
                } => last_error.context(format!("Failed to commit after {attempts} attempts")),
                AutocommitError::ClosureError { error, .. } => error,
            })?;

        Ok((operation_id, address))
    }

    async fn subscribe_deposit_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<DepositState>> {
        let (wallet_client, _) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        let operation_log_entry = self
            .operation_log()
            .get_operation(operation_id)
            .await
            .ok_or(anyhow!("Operation not found"))?;

        if operation_log_entry.operation_type() != WalletCommonGen::KIND.as_str() {
            bail!("Operation is not a wallet operation");
        }

        let operation_meta = operation_log_entry.meta::<WalletOperationMeta>();

        if !matches!(operation_meta, WalletOperationMeta::Deposit { .. }) {
            bail!("Operation is not a deposit operation");
        }

        let mut operation_stream = wallet_client.notifier.subscribe(operation_id).await;
        let tx_subscriber = self.transaction_updates(operation_id).await;

        Ok(
            operation_log_entry.outcome_or_updates(self.db(), operation_id, || {
                stream! {
                    match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::Created(_)) => {
                            yield DepositState::WaitingForTransaction;
                        },
                        Some(DepositStates::TimedOut(_)) => {
                            yield DepositState::Failed("Deposit timed out".to_string());
                            return;
                        }
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    }

                    match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::WaitingForConfirmations(_)) => {
                            yield DepositState::WaitingForConfirmation;
                        },
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    }

                    let claiming = match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::Claiming(claiming)) => claiming,
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    };
                    yield DepositState::Confirmed;

                    if let Err(e) = tx_subscriber.await_tx_accepted(claiming.transaction_id).await {
                        yield DepositState::Failed(format!("Failed to claim: {e:?}"));
                        return;
                    }

                    if let Some(out_point) = claiming.change.as_ref() {
                        self.await_primary_module_output(operation_id, *out_point)
                            .await
                            .expect("Cannot fail if tx was accepted and federation is honest");
                    }
                    yield DepositState::Claimed;
                }
            }),
        )
    }

    async fn get_withdraw_fee(
        &self,
        address: Address,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<PegOutFees> {
        let (wallet_client, _) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        wallet_client.get_withdraw_fees(address, amount).await
    }

    async fn withdraw(
        &self,
        address: Address,
        amount: bitcoin::Amount,
        fee: PegOutFees,
    ) -> anyhow::Result<OperationId> {
        let (wallet_client, instance) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        let operation_id = OperationId(thread_rng().gen());

        let withdraw_output = wallet_client
            .create_withdraw_output(operation_id, address.clone(), amount, fee.clone())
            .await?;
        let tx_builder =
            TransactionBuilder::new().with_output(withdraw_output.into_dyn(instance.id));

        self.finalize_and_submit_transaction(
            operation_id,
            WalletCommonGen::KIND.as_str(),
            move |_, change| WalletOperationMeta::Withdraw {
                address: address.clone(),
                amount,
                fee: fee.clone(),
                change,
            },
            tx_builder,
        )
        .await?;

        Ok(operation_id)
    }

    async fn subscribe_withdraw_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<WithdrawState>> {
        let (wallet_client, _) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        let operation = self
            .operation_log()
            .get_operation(operation_id)
            .await
            .ok_or(anyhow!("Operation not found"))?;

        if operation.operation_type() != WalletCommonGen::KIND.as_str() {
            bail!("Operation is not a wallet operation");
        }

        let operation_meta = operation.meta::<WalletOperationMeta>();

        let WalletOperationMeta::Withdraw { change, .. } = operation_meta else {
            bail!("Operation is not a withdraw operation");
        };

        let mut operation_stream = wallet_client.notifier.subscribe(operation_id).await;

        Ok(
            operation.outcome_or_updates(self.db(), operation_id, move || {
                stream! {
                    match next_withdraw_state(&mut operation_stream).await {
                        Some(WithdrawStates::Created(_)) => {
                            yield WithdrawState::Created;
                        },
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    }

                    // TODO: get rid of awaiting change here, there has to be a better way to make tests deterministic
                    if let Some(change_out_point) = change {
                        // Swallowing potential errors since the transaction failing  is handled by
                        // output outcome fetching already
                        let _ = self
                            .await_primary_module_output(operation_id, change_out_point)
                            .await;
                    }

                    match next_withdraw_state(&mut operation_stream).await {
                        Some(WithdrawStates::Aborted(inner)) => {
                            yield WithdrawState::Failed(inner.error);
                        },
                        Some(WithdrawStates::Success(inner)) => {
                            yield WithdrawState::Succeeded(inner.txid);
                        },
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => {},
                    }
                }
            }),
        )
    }
}

async fn next_deposit_state<S>(stream: &mut S) -> Option<DepositStates>
where
    S: Stream<Item = WalletClientStates> + Unpin,
{
    loop {
        if let WalletClientStates::Deposit(ds) = stream.next().await? {
            return Some(ds.state);
        }
        tokio::task::yield_now().await;
    }
}

async fn next_withdraw_state<S>(stream: &mut S) -> Option<WithdrawStates>
where
    S: Stream<Item = WalletClientStates> + Unpin,
{
    loop {
        if let WalletClientStates::Withdraw(ds) = stream.next().await? {
            return Some(ds.state);
        }
        tokio::task::yield_now().await;
    }
}

#[derive(Debug, Clone, Default)]
// TODO: should probably move to DB
pub struct WalletClientGen(pub Option<BitcoinRpcConfig>);

impl WalletClientGen {
    pub fn new(rpc: BitcoinRpcConfig) -> Self {
        Self(Some(rpc))
    }
}

impl ExtendsCommonModuleGen for WalletClientGen {
    type Common = WalletCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for WalletClientGen {
    type Module = WalletClientModule;
    type Config = WalletClientConfig;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conficts")
    }

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        _api_version: ApiVersion,
        _module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        _api: DynGlobalApi,
        module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module> {
        let rpc_config = self
            .0
            .clone()
            .unwrap_or(default_esplora_server(cfg.network));
        Ok(WalletClientModule {
            cfg,
            module_api,
            notifier,
            rpc: create_bitcoind(&rpc_config, TaskGroup::new().make_handle())?,
        })
    }
}

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    let url = match network {
        Network::Bitcoin => Url::parse("https://blockstream.info/api/")
            .expect("Failed to parse default esplora server"),
        Network::Testnet => Url::parse("https://blockstream.info/testnet/api/")
            .expect("Failed to parse default esplora server"),
        Network::Regtest => {
            Url::parse("http://127.0.0.1:50002/").expect("Failed to parse default esplora server")
        }
        Network::Signet => Url::parse("https://mutinynet.com/api/")
            .expect("Failed to parse default esplora server"),
    };
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Deposit {
        address: bitcoin::Address,
        expires_at: SystemTime,
    },
    Withdraw {
        address: bitcoin::Address,
        #[serde(with = "bitcoin::util::amount::serde::as_sat")]
        amount: bitcoin::Amount,
        fee: PegOutFees,
        change: Option<OutPoint>,
    },
}

#[derive(Debug)]
pub struct WalletClientModule {
    cfg: WalletClientConfig,
    module_api: DynModuleApi,
    notifier: ModuleNotifier<DynGlobalClientContext, WalletClientStates>,
    rpc: DynBitcoindRpc,
}

impl ClientModule for WalletClientModule {
    type Common = WalletModuleTypes;
    type ModuleStateMachineContext = WalletClientContext;
    type States = WalletClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {
        WalletClientContext {
            rpc: self.rpc.clone(),
            wallet_descriptor: self.cfg.peg_in_descriptor.clone(),
            wallet_decoder: self.decoder(),
            secp: Default::default(),
        }
    }

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: Amount::from_sats(input.0.tx_output().value),
            fee: self.cfg.fee_consensus.peg_in_abs,
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.amount().into(),
            fee: self.cfg.fee_consensus.peg_out_abs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    rpc: DynBitcoindRpc,
    wallet_descriptor: PegInDescriptor,
    wallet_decoder: Decoder,
    secp: Secp256k1<All>,
}

impl Context for WalletClientContext {}

impl WalletClientModule {
    pub fn get_network(&self) -> Network {
        self.cfg.network
    }

    pub fn get_deposit_address(
        &self,
        valid_until: SystemTime,
    ) -> (OperationId, WalletClientStates, Address) {
        // TODO: derive from root secret
        // TODO: don't use global secp context
        let tweak_key = KeyPair::new(secp256k1::SECP256K1, &mut thread_rng());
        let x_only_pk = tweak_key.public_key().to_x_only_pubkey();
        let operation_id = OperationId(x_only_pk.serialize());

        let address = self
            .cfg
            .peg_in_descriptor
            .tweak(&x_only_pk, secp256k1::SECP256K1)
            .address(self.cfg.network)
            .unwrap();

        let deposit_sm = WalletClientStates::Deposit(DepositStateMachine {
            operation_id,
            state: DepositStates::Created(CreatedDepositState {
                tweak_key,
                timeout_at: valid_until,
            }),
        });

        (operation_id, deposit_sm, address)
    }

    pub async fn get_withdraw_fees(
        &self,
        address: bitcoin::Address,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<PegOutFees> {
        check_address(&address, self.cfg.network)?;

        self.module_api
            .fetch_peg_out_fees(&address, amount)
            .await?
            .ok_or(anyhow!("Federation didn't return peg-out fees"))
    }

    pub async fn create_withdraw_output(
        &self,
        operation_id: OperationId,
        address: bitcoin::Address,
        amount: bitcoin::Amount,
        fees: PegOutFees,
    ) -> anyhow::Result<ClientOutput<WalletOutput, WalletClientStates>> {
        check_address(&address, self.cfg.network)?;

        let output = WalletOutput::PegOut(PegOut {
            recipient: address,
            amount,
            fees,
        });

        let sm_gen = move |txid, out_idx| {
            vec![WalletClientStates::Withdraw(WithdrawStateMachine {
                operation_id,
                state: WithdrawStates::Created(CreatedWithdrawState {
                    fm_outpoint: OutPoint { txid, out_idx },
                }),
            })]
        };

        Ok(ClientOutput::<WalletOutput, WalletClientStates> {
            output,
            state_machines: Arc::new(sm_gen),
        })
    }
}

fn check_address(address: &Address, network: Network) -> anyhow::Result<()> {
    ensure!(
        address.is_valid_for_network(network),
        "Address isn't compatible with the federation's network: {network:?}"
    );

    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum WalletClientStates {
    Deposit(DepositStateMachine),
    Withdraw(WithdrawStateMachine),
}

impl IntoDynInstance for WalletClientStates {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for WalletClientStates {
    type ModuleContext = WalletClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            WalletClientStates::Deposit(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    WalletClientStates::Deposit
                )
            }
            WalletClientStates::Withdraw(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    WalletClientStates::Withdraw
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            WalletClientStates::Deposit(sm) => sm.operation_id(),
            WalletClientStates::Withdraw(sm) => sm.operation_id(),
        }
    }
}
