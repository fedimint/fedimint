#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod api;

pub mod client_db;
mod deposit;
mod withdraw;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, bail, ensure, Context as AnyhowContext};
use async_stream::stream;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use client_db::DbKeyPrefix;
use fedimint_api_client::api::DynModuleApi;
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::bitcoin_migration::checked_address_to_unchecked_address;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{
    AutocommitError, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint};
use fedimint_wallet_common::config::{FeeConsensus, WalletClientConfig};
use fedimint_wallet_common::tweakable::Tweakable;
pub use fedimint_wallet_common::*;
use futures::{Stream, StreamExt};
use rand::{thread_rng, Rng};
use secp256k1::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::api::WalletFederationApi;
use crate::client_db::NextPegInTweakIndexKey;
use crate::deposit::{CreatedDepositState, DepositStateMachine, DepositStates};
use crate::withdraw::{CreatedWithdrawState, WithdrawStateMachine, WithdrawStates};

const WALLET_TWEAK_CHILD_ID: ChildId = ChildId(0);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinTransactionData {
    /// The bitcoin transaction is saved as soon as we see it so the transaction
    /// can be re-transmitted if it's evicted from the mempool.
    pub btc_transaction: bitcoin::Transaction,
    /// Index of the deposit output
    pub out_idx: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum DepositState {
    WaitingForTransaction,
    WaitingForConfirmation(BitcoinTransactionData),
    Confirmed(BitcoinTransactionData),
    Claimed(BitcoinTransactionData),
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
pub struct WalletClientInit(pub Option<BitcoinRpcConfig>);

impl WalletClientInit {
    pub fn new(rpc: BitcoinRpcConfig) -> Self {
        Self(Some(rpc))
    }
}

impl ModuleInit for WalletClientInit {
    type Common = WalletCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut wallet_client_items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::NextPegInTweakIndex => {
                    if let Some(index) = dbtx.get_value(&NextPegInTweakIndexKey).await {
                        wallet_client_items
                            .insert("NextPegInTweakIndex".to_string(), Box::new(index));
                    }
                }
            }
        }

        Box::new(wallet_client_items.into_iter())
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
        let rpc_config = self
            .0
            .clone()
            .unwrap_or(WalletClientModule::get_rpc_config(args.cfg()));

        // FIXME: reactivate key derivation once we implement recovery
        let random_root_secret = {
            let (key, salt): ([u8; 32], [u8; 32]) = thread_rng().gen();
            DerivableSecret::new_root(&key, &salt)
        };

        Ok(WalletClientModule {
            cfg: args.cfg().clone(),
            module_root_secret: random_root_secret,
            module_api: args.module_api().clone(),
            notifier: args.notifier().clone(),
            rpc: create_bitcoind(&rpc_config, TaskGroup::new().make_handle())?,
            client_ctx: args.context(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOperationMeta {
    pub variant: WalletOperationMetaVariant,
    pub extra_meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletOperationMetaVariant {
    Deposit {
        address: bitcoin::Address<NetworkUnchecked>,
        expires_at: SystemTime,
    },
    Withdraw {
        address: bitcoin::Address<NetworkUnchecked>,
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        amount: bitcoin::Amount,
        fee: PegOutFees,
        change: Vec<OutPoint>,
    },
}

#[derive(Debug)]
pub struct WalletClientModule {
    cfg: WalletClientConfig,
    module_root_secret: DerivableSecret,
    module_api: DynModuleApi,
    notifier: ModuleNotifier<WalletClientStates>,
    rpc: DynBitcoindRpc,
    client_ctx: ClientContext<Self>,
}

impl ClientModule for WalletClientModule {
    type Init = WalletClientInit;
    type Common = WalletModuleTypes;
    type Backup = NoModuleBackup;
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

    fn input_fee(&self, _input: &<Self::Common as ModuleCommon>::Input) -> Option<Amount> {
        Some(self.cfg.fee_consensus.peg_in_abs)
    }

    fn output_fee(&self, _output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        Some(self.cfg.fee_consensus.peg_out_abs)
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
    fn get_rpc_config(cfg: &WalletClientConfig) -> BitcoinRpcConfig {
        if let Ok(rpc_config) = BitcoinRpcConfig::get_defaults_from_env_vars() {
            // TODO: Wallet client cannot support bitcoind RPC until the bitcoin dep is
            // updated to 0.30
            if rpc_config.kind == "bitcoind" {
                cfg.default_bitcoin_rpc.clone()
            } else {
                rpc_config
            }
        } else {
            cfg.default_bitcoin_rpc.clone()
        }
    }

    pub fn get_network(&self) -> Network {
        self.cfg.network
    }

    pub fn get_fee_consensus(&self) -> FeeConsensus {
        self.cfg.fee_consensus
    }

    pub async fn get_deposit_address_inner(
        &self,
        valid_until: SystemTime,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (OperationId, WalletClientStates, Address) {
        let deposit_idx = get_next_peg_in_tweak_child_id(dbtx).await;
        let (secret_tweak_key, _, address, operation_id) =
            Self::derive_deposit_address_static(&self.cfg, &self.module_root_secret, deposit_idx);

        let deposit_sm = WalletClientStates::Deposit(DepositStateMachine {
            operation_id,
            state: DepositStates::Created(CreatedDepositState {
                tweak_key: secret_tweak_key,
                timeout_at: valid_until,
            }),
        });

        (operation_id, deposit_sm, address)
    }

    fn derive_deposit_address_static(
        cfg: &WalletClientConfig,
        module_root_secret: &DerivableSecret,
        idx: ChildId,
    ) -> (
        secp256k1::KeyPair,
        secp256k1::PublicKey,
        Address,
        OperationId,
    ) {
        let secret_tweak_key = module_root_secret
            .child_key(WALLET_TWEAK_CHILD_ID)
            .child_key(idx)
            .to_secp_key(secp256k1::SECP256K1);

        let public_tweak_key = secret_tweak_key.public_key();

        let address = cfg
            .peg_in_descriptor
            .tweak(&public_tweak_key, secp256k1::SECP256K1)
            .address(cfg.network)
            .unwrap();

        // TODO: make hash?
        let operation_id = OperationId(public_tweak_key.x_only_public_key().0.serialize());

        (secret_tweak_key, public_tweak_key, address, operation_id)
    }

    /// Fetches the fees that would need to be paid to make the withdraw request
    /// using [`Self::withdraw`] work *right now*.
    ///
    /// Note that we do not receive a guarantee that these fees will be valid in
    /// the future, thus even the next second using these fees *may* fail.
    /// The caller should be prepared to retry with a new fee estimate.
    pub async fn get_withdraw_fees(
        &self,
        address: bitcoin::Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<PegOutFees> {
        check_address(&address, self.cfg.network)?;

        self.module_api
            .fetch_peg_out_fees(&address.assume_checked(), amount)
            .await?
            .context("Federation didn't return peg-out fees")
    }

    pub fn create_withdraw_output(
        &self,
        operation_id: OperationId,
        address: bitcoin::Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        fees: PegOutFees,
    ) -> anyhow::Result<ClientOutput<WalletOutput, WalletClientStates>> {
        check_address(&address, self.cfg.network)?;

        let output = WalletOutput::new_v0_peg_out(address, amount, fees);

        let amount = output.maybe_v0_ref().expect("v0 output").amount().into();

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
            amount,
            state_machines: Arc::new(sm_gen),
        })
    }

    pub async fn get_deposit_address<M: Serialize + MaybeSend + MaybeSync>(
        &self,
        valid_until: SystemTime,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, Address)> {
        let extra_meta = serde_json::to_value(extra_meta).expect("extra meta is serializable");

        let (operation_id, address) = self
            .client_ctx
            .module_autocommit(
                |dbtx, _| {
                    let extra_meta_inner = extra_meta.clone();
                    Box::pin(async {
                        let (operation_id, sm, address) = self
                            .get_deposit_address_inner(valid_until, &mut dbtx.module_dbtx())
                            .await;

                        // Begin watching the script address
                        self.rpc
                            .watch_script_history(&address.script_pubkey())
                            .await?;

                        dbtx.add_state_machines(vec![self.client_ctx.make_dyn_state(sm)])
                            .await?;

                        dbtx.add_operation_log_entry(
                            operation_id,
                            WalletCommonInit::KIND.as_str(),
                            WalletOperationMeta {
                                variant: WalletOperationMetaVariant::Deposit {
                                    address: checked_address_to_unchecked_address(&address),
                                    expires_at: valid_until,
                                },
                                extra_meta: extra_meta_inner,
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

    pub async fn subscribe_deposit_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<DepositState>> {
        let operation_log_entry = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .with_context(|| anyhow!("Operation not found: {}", operation_id.fmt_short()))?;

        if operation_log_entry.operation_module_kind() != WalletCommonInit::KIND.as_str() {
            bail!("Operation is not a wallet operation");
        }

        let operation_meta = operation_log_entry.meta::<WalletOperationMeta>();

        if !matches!(
            operation_meta.variant,
            WalletOperationMetaVariant::Deposit { .. }
        ) {
            bail!("Operation is not a deposit operation");
        }

        let mut operation_stream = self.notifier.subscribe(operation_id).await;
        let tx_subscriber = self.client_ctx.transaction_updates(operation_id).await;

        let client_ctx = self.client_ctx.clone();
        Ok(
            operation_log_entry.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
                stream! {

                    match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::Created(_)) => {
                            yield DepositState::WaitingForTransaction;
                        },
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    }

                    let tx_data = match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::WaitingForConfirmations(inner)) => {
                            let tx_data = BitcoinTransactionData { btc_transaction: inner.btc_transaction, out_idx: inner.out_idx };
                            yield DepositState::WaitingForConfirmation(tx_data.clone());
                            tx_data
                        },
                        Some(DepositStates::TimedOut(_)) => {
                            yield DepositState::Failed("Deposit timed out".to_string());
                            return;
                        },
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    };

                    let claiming = match next_deposit_state(&mut operation_stream).await {
                        Some(DepositStates::Claiming(claiming)) => claiming,
                        Some(s) => {
                            panic!("Unexpected state {s:?}")
                        },
                        None => return,
                    };
                    yield DepositState::Confirmed(tx_data.clone());

                    if let Err(e) = tx_subscriber.await_tx_accepted(claiming.transaction_id).await {
                        yield DepositState::Failed(format!("Failed to claim: {e:?}"));
                        return;
                    }


                    client_ctx.await_primary_module_outputs(operation_id, claiming.change)
                        .await
                        .expect("Cannot fail if tx was accepted and federation is honest");

                    yield DepositState::Claimed(tx_data.clone());
                }
            }),
        )
    }

    /// Attempt to withdraw a given `amount` of Bitcoin to a destination
    /// `address`. The caller has to supply the fee rate to be used which can be
    /// fetched using [`Self::get_withdraw_fees`] and should be
    /// acknowledged by the user since it can be unexpectedly high.
    pub async fn withdraw<M: Serialize + MaybeSend + MaybeSync>(
        &self,
        address: bitcoin::Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        fee: PegOutFees,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        {
            let operation_id = OperationId(thread_rng().gen());

            let withdraw_output =
                self.create_withdraw_output(operation_id, address.clone(), amount, fee)?;
            let tx_builder = TransactionBuilder::new()
                .with_output(self.client_ctx.make_client_output(withdraw_output));

            let extra_meta =
                serde_json::to_value(extra_meta).expect("Failed to serialize extra meta");
            self.client_ctx
                .finalize_and_submit_transaction(
                    operation_id,
                    WalletCommonInit::KIND.as_str(),
                    |_, change| WalletOperationMeta {
                        variant: WalletOperationMetaVariant::Withdraw {
                            address: address.clone(),
                            amount,
                            fee,
                            change,
                        },
                        extra_meta: extra_meta.clone(),
                    },
                    tx_builder,
                )
                .await?;

            Ok(operation_id)
        }
    }

    pub async fn subscribe_withdraw_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<WithdrawState>> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .with_context(|| anyhow!("Operation not found: {}", operation_id.fmt_short()))?;

        if operation.operation_module_kind() != WalletCommonInit::KIND.as_str() {
            bail!("Operation is not a wallet operation");
        }

        let operation_meta = operation.meta::<WalletOperationMeta>();

        let WalletOperationMetaVariant::Withdraw { change, .. } = operation_meta.variant else {
            bail!("Operation is not a withdraw operation");
        };

        let mut operation_stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(
            operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
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

                        // Swallowing potential errors since the transaction failing  is handled by
                        // output outcome fetching already
                        let _ = client_ctx
                            .await_primary_module_outputs(operation_id, change)
                            .await;


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

fn check_address(address: &Address<NetworkUnchecked>, network: Network) -> anyhow::Result<()> {
    ensure!(
        address.is_valid_for_network(network),
        "Address isn't compatible with the federation's network: {network:?}"
    );

    Ok(())
}

/// Returns the child index to derive the next peg-in tweak key from.
async fn get_next_peg_in_tweak_child_id(dbtx: &mut DatabaseTransaction<'_>) -> ChildId {
    let index = dbtx.get_value(&NextPegInTweakIndexKey).await.unwrap_or(0);
    dbtx.insert_entry(&NextPegInTweakIndexKey, &(index + 1))
        .await;
    ChildId(index)
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WalletClientStates {
    Deposit(DepositStateMachine),
    Withdraw(WithdrawStateMachine),
}

impl IntoDynInstance for WalletClientStates {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for WalletClientStates {
    type ModuleContext = WalletClientContext;

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
