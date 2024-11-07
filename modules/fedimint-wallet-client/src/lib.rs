#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod api;
#[cfg(feature = "cli")]
mod cli;

mod backup;

pub mod client_db;
/// Legacy, state-machine based peg-ins, replaced by `pegin_monitor`
/// but retained for time being to ensure existing peg-ins complete.
mod deposit;
/// Peg-in monitor: a task monitoring deposit addresses for peg-ins.
mod pegin_monitor;
mod withdraw;

use std::collections::BTreeMap;
use std::future;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, bail, ensure, Context as AnyhowContext};
use async_stream::stream;
use backup::WalletModuleBackup;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::{All, Secp256k1, SECP256K1};
use bitcoin::{Address, Network, ScriptBuf};
use client_db::{DbKeyPrefix, PegInTweakIndexKey, TweakIdx};
use fedimint_api_client::api::DynModuleApi;
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use fedimint_client::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client::module::{ClientContext, ClientModule, IClientModule, IdxRange};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::util::backoff_util::background_backoff;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, runtime, secp256k1, Amount, OutPoint,
    TransactionId,
};
use fedimint_logging::LOG_CLIENT_MODULE_WALLET;
use fedimint_wallet_common::config::{FeeConsensus, WalletClientConfig};
use fedimint_wallet_common::tweakable::Tweakable;
pub use fedimint_wallet_common::*;
use futures::{Stream, StreamExt};
use rand::{thread_rng, Rng};
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tokio::sync::watch;
use tracing::{debug, instrument};

use crate::api::WalletFederationApi;
use crate::backup::WalletRecovery;
use crate::client_db::{
    ClaimedPegInData, ClaimedPegInKey, ClaimedPegInPrefix, NextPegInTweakIndexKey,
    PegInTweakIndexData, PegInTweakIndexPrefix, RecoveryFinalizedKey,
};
use crate::deposit::DepositStateMachine;
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
pub enum DepositStateV1 {
    WaitingForTransaction,
    WaitingForConfirmation(BitcoinTransactionData),
    Confirmed(BitcoinTransactionData),
    Claimed(BitcoinTransactionData),
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum DepositStateV2 {
    WaitingForTransaction,
    WaitingForConfirmation {
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        btc_deposited: bitcoin::Amount,
        btc_out_point: bitcoin::OutPoint,
    },
    Confirmed {
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        btc_deposited: bitcoin::Amount,
        btc_out_point: bitcoin::OutPoint,
    },
    Claimed {
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        btc_deposited: bitcoin::Amount,
        btc_out_point: bitcoin::OutPoint,
    },
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
                DbKeyPrefix::PegInTweakIndex => {
                    push_db_pair_items!(
                        dbtx,
                        PegInTweakIndexPrefix,
                        PegInTweakIndexKey,
                        PegInTweakIndexData,
                        wallet_client_items,
                        "Peg-In Tweak Index"
                    );
                }
                DbKeyPrefix::ClaimedPegIn => {
                    push_db_pair_items!(
                        dbtx,
                        ClaimedPegInPrefix,
                        ClaimedPegInKey,
                        ClaimedPegInData,
                        wallet_client_items,
                        "Claimed Peg-In"
                    );
                }
                DbKeyPrefix::RecoveryFinalized => {
                    if let Some(val) = dbtx.get_value(&RecoveryFinalizedKey).await {
                        wallet_client_items.insert("RecoveryFinalized".to_string(), Box::new(val));
                    }
                }
                DbKeyPrefix::RecoveryState => {}
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
        let data = WalletClientModuleData {
            cfg: args.cfg().clone(),
            module_root_secret: args.module_root_secret().clone(),
        };

        let rpc_config = self
            .0
            .clone()
            .unwrap_or(WalletClientModule::get_rpc_config(args.cfg()));

        let db = args.db().clone();

        let btc_rpc = create_bitcoind(&rpc_config, TaskGroup::new().make_handle())?;
        let module_api = args.module_api().clone();

        let (pegin_claimed_sender, pegin_claimed_receiver) = watch::channel(());
        let (pegin_monitor_wakeup_sender, pegin_monitor_wakeup_receiver) = watch::channel(());

        Ok(WalletClientModule {
            db,
            data,
            module_api,
            notifier: args.notifier().clone(),
            rpc: btc_rpc,
            client_ctx: args.context(),
            pegin_monitor_wakeup_sender,
            pegin_monitor_wakeup_receiver,
            pegin_claimed_receiver,
            pegin_claimed_sender,
            task_group: args.task_group().clone(),
            admin_auth: args.admin_auth().cloned(),
        })
    }

    /// Wallet recovery
    ///
    /// Query bitcoin rpc for history of addresses from last known used
    /// addresses (or index 0) until MAX_GAP unused ones.
    ///
    /// Notably does not persist the progress of addresses being queried,
    /// because it is not expected that it would take long enough to bother.
    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        snapshot: Option<&<Self::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<()> {
        args.recover_from_history::<WalletRecovery>(self, snapshot)
            .await
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
        address: Address<NetworkUnchecked>,
        /// Added in 0.4.2, can be `None` for old deposits or `Some` for ones
        /// using the pegin monitor. The value is the child index of the key
        /// used to generate the address, so we can re-generate the secret key
        /// from our root secret.
        #[serde(default)]
        tweak_idx: Option<TweakIdx>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<SystemTime>,
    },
    Withdraw {
        address: Address<NetworkUnchecked>,
        #[serde(with = "bitcoin::amount::serde::as_sat")]
        amount: bitcoin::Amount,
        fee: PegOutFees,
        change: Vec<OutPoint>,
    },

    RbfWithdraw {
        rbf: Rbf,
        change: Vec<OutPoint>,
    },
}

/// The non-resource, just plain-data parts of [`WalletClientModule`]
#[derive(Debug, Clone)]
pub struct WalletClientModuleData {
    cfg: WalletClientConfig,
    module_root_secret: DerivableSecret,
}

impl WalletClientModuleData {
    fn derive_deposit_address(
        &self,
        idx: TweakIdx,
    ) -> (Keypair, secp256k1::PublicKey, Address, OperationId) {
        let idx = ChildId(idx.0);

        let secret_tweak_key = self
            .module_root_secret
            .child_key(WALLET_TWEAK_CHILD_ID)
            .child_key(idx)
            .to_secp_key(fedimint_core::secp256k1::SECP256K1);

        let public_tweak_key = secret_tweak_key.public_key();

        let address = self
            .cfg
            .peg_in_descriptor
            .tweak(&public_tweak_key, bitcoin::secp256k1::SECP256K1)
            .address(self.cfg.network)
            .unwrap();

        // TODO: make hash?
        let operation_id = OperationId(public_tweak_key.x_only_public_key().0.serialize());

        (secret_tweak_key, public_tweak_key, address, operation_id)
    }

    fn derive_peg_in_script(
        &self,
        idx: TweakIdx,
    ) -> (ScriptBuf, bitcoin::Address, Keypair, OperationId) {
        let (secret_tweak_key, _, address, operation_id) = self.derive_deposit_address(idx);

        (
            self.cfg
                .peg_in_descriptor
                .tweak(&secret_tweak_key.public_key(), SECP256K1)
                .script_pubkey(),
            address,
            secret_tweak_key,
            operation_id,
        )
    }
}

#[derive(Debug)]
pub struct WalletClientModule {
    data: WalletClientModuleData,
    db: Database,
    module_api: DynModuleApi,
    notifier: ModuleNotifier<WalletClientStates>,
    rpc: DynBitcoindRpc,
    client_ctx: ClientContext<Self>,
    /// Updated to wake up pegin monitor
    pegin_monitor_wakeup_sender: watch::Sender<()>,
    pegin_monitor_wakeup_receiver: watch::Receiver<()>,
    /// Called every time a peg-in was claimed
    pegin_claimed_sender: watch::Sender<()>,
    pegin_claimed_receiver: watch::Receiver<()>,
    task_group: TaskGroup,
    admin_auth: Option<ApiAuth>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for WalletClientModule {
    type Init = WalletClientInit;
    type Common = WalletModuleTypes;
    type Backup = WalletModuleBackup;
    type ModuleStateMachineContext = WalletClientContext;
    type States = WalletClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {
        WalletClientContext {
            rpc: self.rpc.clone(),
            wallet_descriptor: self.cfg().peg_in_descriptor.clone(),
            wallet_decoder: self.decoder(),
            secp: Secp256k1::default(),
        }
    }

    async fn start(&self) {
        self.task_group.spawn_cancellable("peg-in monitor", {
            let client_ctx = self.client_ctx.clone();
            let db = self.db.clone();
            let btc_rpc = self.rpc.clone();
            let module_api = self.module_api.clone();
            let data = self.data.clone();
            let pegin_claimed_sender = self.pegin_claimed_sender.clone();
            let pegin_monitor_wakeup_receiver = self.pegin_monitor_wakeup_receiver.clone();
            pegin_monitor::run_peg_in_monitor(
                client_ctx,
                db,
                btc_rpc,
                module_api,
                data,
                pegin_claimed_sender,
                pegin_monitor_wakeup_receiver,
            )
        });
    }

    fn supports_backup(&self) -> bool {
        true
    }

    async fn backup(&self) -> anyhow::Result<backup::WalletModuleBackup> {
        // fetch consensus height first
        let session_count = self.client_ctx.global_api().session_count().await?;

        let mut dbtx = self.db.begin_transaction_nc().await;
        let next_pegin_tweak_idx = dbtx
            .get_value(&NextPegInTweakIndexKey)
            .await
            .unwrap_or_default();
        let claimed = dbtx
            .find_by_prefix(&PegInTweakIndexPrefix)
            .await
            .filter_map(|(k, v)| async move {
                if v.claimed.is_empty() {
                    None
                } else {
                    Some(k.0)
                }
            })
            .collect()
            .await;
        Ok(backup::WalletModuleBackup::new_v1(
            session_count,
            next_pegin_tweak_idx,
            claimed,
        ))
    }

    fn input_fee(
        &self,
        _amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg().fee_consensus.peg_in_abs)
    }

    fn output_fee(
        &self,
        _amount: Amount,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        Some(self.cfg().fee_consensus.peg_out_abs)
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    rpc: DynBitcoindRpc,
    wallet_descriptor: PegInDescriptor,
    wallet_decoder: Decoder,
    secp: Secp256k1<All>,
}

impl Context for WalletClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

impl WalletClientModule {
    fn cfg(&self) -> &WalletClientConfig {
        &self.data.cfg
    }

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
        self.cfg().network
    }

    pub fn get_fee_consensus(&self) -> FeeConsensus {
        self.cfg().fee_consensus
    }

    async fn allocate_deposit_address_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> (OperationId, Address, TweakIdx) {
        dbtx.ensure_isolated().expect("Must be isolated db");

        let tweak_idx = get_next_peg_in_tweak_child_id(dbtx).await;
        let (_secret_tweak_key, _, address, operation_id) =
            self.data.derive_deposit_address(tweak_idx);

        let now = fedimint_core::time::now();

        dbtx.insert_new_entry(
            &PegInTweakIndexKey(tweak_idx),
            &PegInTweakIndexData {
                creation_time: now,
                next_check_time: Some(now),
                last_check_time: None,
                operation_id,
                claimed: vec![],
            },
        )
        .await;

        (operation_id, address, tweak_idx)
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
        check_address(&address, self.cfg().network)?;

        self.module_api
            .fetch_peg_out_fees(&address.assume_checked(), amount)
            .await?
            .context("Federation didn't return peg-out fees")
    }

    /// Returns a summary of the wallet's coins
    pub async fn get_wallet_summary(&self) -> anyhow::Result<WalletSummary> {
        Ok(self.module_api.fetch_wallet_summary().await?)
    }

    pub fn create_withdraw_output(
        &self,
        operation_id: OperationId,
        address: &bitcoin::Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        fees: PegOutFees,
    ) -> anyhow::Result<ClientOutputBundle<WalletOutput, WalletClientStates>> {
        check_address(address, self.cfg().network)?;

        let output = WalletOutput::new_v0_peg_out(address.clone(), amount, fees);

        let amount = output.maybe_v0_ref().expect("v0 output").amount().into();

        let sm_gen = move |txid, out_idxs: IdxRange| {
            assert_eq!(out_idxs.count(), 1);
            let out_idx = out_idxs.start();
            vec![WalletClientStates::Withdraw(WithdrawStateMachine {
                operation_id,
                state: WithdrawStates::Created(CreatedWithdrawState {
                    fm_outpoint: OutPoint { txid, out_idx },
                }),
            })]
        };

        Ok(ClientOutputBundle::new(
            vec![ClientOutput::<WalletOutput> { output, amount }],
            vec![ClientOutputSM::<WalletClientStates> {
                state_machines: Arc::new(sm_gen),
            }],
        ))
    }

    pub fn create_rbf_withdraw_output(
        &self,
        operation_id: OperationId,
        rbf: &Rbf,
    ) -> anyhow::Result<ClientOutputBundle<WalletOutput, WalletClientStates>> {
        let output = WalletOutput::new_v0_rbf(rbf.fees, rbf.txid);

        let amount = output.maybe_v0_ref().expect("v0 output").amount().into();

        let sm_gen = move |txid, out_idxs: IdxRange| {
            assert_eq!(out_idxs.count(), 1);
            let out_idx = out_idxs.start();
            vec![WalletClientStates::Withdraw(WithdrawStateMachine {
                operation_id,
                state: WithdrawStates::Created(CreatedWithdrawState {
                    fm_outpoint: OutPoint { txid, out_idx },
                }),
            })]
        };

        Ok(ClientOutputBundle::new(
            vec![ClientOutput::<WalletOutput> { output, amount }],
            vec![ClientOutputSM::<WalletClientStates> {
                state_machines: Arc::new(sm_gen),
            }],
        ))
    }

    /// Allocates a deposit address that is controlled by the federation.
    ///
    /// This is an EXPERT ONLY method intended for power users such as Lightning
    /// gateways allocating liquidity, and we discourage exposing peg-in
    /// functionality to everyday users of a Fedimint wallet due to the
    /// following two limitations:
    ///
    /// The transaction sending to this address needs to be smaller than 40KB in
    /// order for the peg-in to be claimable. If the transaction is too large,
    /// funds will be lost.
    ///
    /// In the future, federations will also enforce a minimum peg-in amount to
    /// prevent accumulation of dust UTXOs. Peg-ins under this minimum cannot be
    /// claimed and funds will be lost.
    ///
    /// Everyday users should rely on Lightning to move funds into the
    /// federation.
    pub async fn allocate_deposit_address_expert_only<M>(
        &self,
        extra_meta: M,
    ) -> anyhow::Result<(OperationId, Address, TweakIdx)>
    where
        M: Serialize + MaybeSend + MaybeSync,
    {
        let extra_meta_value =
            serde_json::to_value(extra_meta).expect("Failed to serialize extra meta");
        let (operation_id, address, tweak_idx) = self
            .db
            .autocommit(
                move |dbtx, _| {
                    let extra_meta_value_inner = extra_meta_value.clone();
                    Box::pin(async move {
                        let (operation_id, address, tweak_idx) = self
                            .allocate_deposit_address_inner(dbtx)
                            .await;

                        self.client_ctx.manual_operation_start_dbtx(
                            dbtx,
                            operation_id,
                            WalletCommonInit::KIND.as_str(),
                            WalletOperationMeta {
                                variant: WalletOperationMetaVariant::Deposit {
                                    // TODO(bitcoin 0.32): use as_unchecked
                                    address: address.to_string().parse().expect("can be parsed"),
                                    tweak_idx: Some(tweak_idx),
                                    expires_at: None,
                                },
                                extra_meta: extra_meta_value_inner,
                            },
                            vec![]
                        ).await?;

                        debug!(target: LOG_CLIENT_MODULE_WALLET, %tweak_idx, %address, "Derived a new deposit address");

                        // Begin watching the script address
                        self.rpc
                            .watch_script_history(&address.script_pubkey())
                            .await?;

                        let sender = self.pegin_monitor_wakeup_sender.clone();
                        dbtx.on_commit(move || {
                            let _ = sender.send(());
                        });

                        Ok((operation_id, address, tweak_idx))
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

        Ok((operation_id, address, tweak_idx))
    }

    /// Returns a stream of updates about an ongoing deposit operation created
    /// with [`WalletClientModule::allocate_deposit_address_expert_only`].
    /// Returns an error for old deposit operations created prior to the 0.4
    /// release and not driven to completion yet. This should be rare enough
    /// that an indeterminate state is ok here.
    pub async fn subscribe_deposit(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<DepositStateV2>> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .with_context(|| anyhow!("Operation not found: {}", operation_id.fmt_short()))?;

        if operation.operation_module_kind() != WalletCommonInit::KIND.as_str() {
            bail!("Operation is not a wallet operation");
        }

        let operation_meta = operation.meta::<WalletOperationMeta>();

        let WalletOperationMetaVariant::Deposit {
            address, tweak_idx, ..
        } = operation_meta.variant
        else {
            bail!("Operation is not a deposit operation");
        };

        // The old deposit operations don't have tweak_idx set
        let Some(tweak_idx) = tweak_idx else {
            // In case we are dealing with an old deposit that still uses state machines we
            // don't have the logic here anymore to subscribe to updates. We can still read
            // the final state though if it reached any.
            let outcome_v1 = operation
                .outcome::<DepositStateV1>()
                .context("Old pending deposit, can't subscribe to updates")?;

            let outcome_v2 = match outcome_v1 {
                DepositStateV1::Claimed(tx_info) => DepositStateV2::Claimed {
                    btc_deposited: tx_info.btc_transaction.output[tx_info.out_idx as usize].value,
                    btc_out_point: bitcoin::OutPoint {
                        txid: tx_info.btc_transaction.compute_txid(),
                        vout: tx_info.out_idx,
                    },
                },
                DepositStateV1::Failed(error) => DepositStateV2::Failed(error),
                _ => bail!("Non-final outcome in operation log"),
            };

            return Ok(UpdateStreamOrOutcome::Outcome(outcome_v2));
        };

        Ok(self.client_ctx.outcome_or_updates(&operation, operation_id, || {
            let stream_rpc = self.rpc.clone();
            let stream_cient_ctx = self.client_ctx.clone();
            let stream_script_pub_key = address.assume_checked().script_pubkey();

            stream! {
                yield DepositStateV2::WaitingForTransaction;

                retry(
                    "subscribe script history",
                    background_backoff(),
                    || stream_rpc.watch_script_history(&stream_script_pub_key)
                ).await.expect("Will never give up");
                let (btc_out_point, btc_deposited) = retry(
                    "fetch history",
                    background_backoff(),
                    || async {
                        let history = stream_rpc.get_script_history(&stream_script_pub_key).await?;
                        history.first().and_then(|tx| {
                            let (out_idx, amount) = tx.output
                                .iter()
                                .enumerate()
                                .find_map(|(idx, output)| (output.script_pubkey == stream_script_pub_key).then_some((idx, output.value)))?;
                            let txid = tx.compute_txid();

                            Some((
                                bitcoin::OutPoint {
                                    txid,
                                    vout: out_idx as u32,
                                },
                                amount
                            ))
                        }).context("No deposit transaction found")
                    }
                ).await.expect("Will never give up");

                yield DepositStateV2::WaitingForConfirmation {
                    btc_deposited,
                    btc_out_point
                };

                let claim_data = stream_cient_ctx.module_db().wait_key_exists(&ClaimedPegInKey {
                    peg_in_index: tweak_idx,
                    btc_out_point,
                }).await;

                yield DepositStateV2::Confirmed {
                    btc_deposited,
                    btc_out_point
                };

                match stream_cient_ctx.await_primary_module_outputs(operation_id, claim_data.change).await {
                    Ok(_) => yield DepositStateV2::Claimed {
                        btc_deposited,
                        btc_out_point
                    },
                    Err(e) => yield DepositStateV2::Failed(e.to_string())
                }
            }
        }))
    }

    pub async fn find_tweak_idx_by_operation_id(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<TweakIdx> {
        Ok(self
            .client_ctx
            .module_db()
            .clone()
            .begin_transaction_nc()
            .await
            .find_by_prefix(&PegInTweakIndexPrefix)
            .await
            .filter(|(_k, v)| future::ready(v.operation_id == operation_id))
            .next()
            .await
            .ok_or_else(|| anyhow::format_err!("OperationId not found"))?
            .0
             .0)
    }

    pub async fn get_pegin_tweak_idx(
        &self,
        tweak_idx: TweakIdx,
    ) -> anyhow::Result<PegInTweakIndexData> {
        self.client_ctx
            .module_db()
            .clone()
            .begin_transaction_nc()
            .await
            .get_value(&PegInTweakIndexKey(tweak_idx))
            .await
            .ok_or_else(|| anyhow::format_err!("TweakIdx not found"))
    }

    pub async fn get_claimed_pegins(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        tweak_idx: TweakIdx,
    ) -> Vec<(
        bitcoin::OutPoint,
        TransactionId,
        Vec<fedimint_core::OutPoint>,
    )> {
        let outpoints = dbtx
            .get_value(&PegInTweakIndexKey(tweak_idx))
            .await
            .map(|v| v.claimed)
            .unwrap_or_default();

        let mut res = vec![];

        for outpoint in outpoints {
            let claimed_peg_in_data = dbtx
                .get_value(&ClaimedPegInKey {
                    peg_in_index: tweak_idx,
                    btc_out_point: outpoint,
                })
                .await
                .expect("Must have a corresponding claim record");
            res.push((
                outpoint,
                claimed_peg_in_data.claim_txid,
                claimed_peg_in_data.change,
            ));
        }

        res
    }

    /// Like [`Self::recheck_pegin_address`] but by `operation_id`
    pub async fn recheck_pegin_address_by_op_id(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<()> {
        let tweak_idx = self.find_tweak_idx_by_operation_id(operation_id).await?;

        self.recheck_pegin_address(tweak_idx).await
    }

    /// Schedule given address for immediate re-check for deposits
    pub async fn recheck_pegin_address(&self, tweak_idx: TweakIdx) -> anyhow::Result<()> {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let db_key = PegInTweakIndexKey(tweak_idx);
                        let db_val = dbtx
                            .get_value(&db_key)
                            .await
                            .ok_or_else(|| anyhow::format_err!("DBKey not found"))?;

                        dbtx.insert_entry(
                            &db_key,
                            &PegInTweakIndexData {
                                next_check_time: Some(fedimint_core::time::now()),
                                ..db_val
                            },
                        )
                        .await;

                        let sender = self.pegin_monitor_wakeup_sender.clone();
                        dbtx.on_commit(move || {
                            let _ = sender.send(());
                        });

                        Ok::<_, anyhow::Error>(())
                    })
                },
                Some(100),
            )
            .await?;

        Ok(())
    }

    /// Await for num deposit by [`OperationId`]
    pub async fn await_num_deposit_by_operation_id(
        &self,
        operation_id: OperationId,
        num_deposits: usize,
    ) -> anyhow::Result<()> {
        let tweak_idx = self.find_tweak_idx_by_operation_id(operation_id).await?;
        self.await_num_deposits(tweak_idx, num_deposits).await
    }

    #[instrument(skip_all, fields(tweak_idx=?tweak_idx, num_deposists=num_deposits))]
    pub async fn await_num_deposits(
        &self,
        tweak_idx: TweakIdx,
        num_deposits: usize,
    ) -> anyhow::Result<()> {
        let operation_id = self.get_pegin_tweak_idx(tweak_idx).await?.operation_id;

        let mut receiver = self.pegin_claimed_receiver.clone();
        let mut backoff = backoff_util::aggressive_backoff();

        loop {
            let pegins = self
                .get_claimed_pegins(
                    &mut self.client_ctx.module_db().begin_transaction_nc().await,
                    tweak_idx,
                )
                .await;

            if pegins.len() < num_deposits {
                debug!(target: LOG_CLIENT_MODULE_WALLET, has=pegins.len(), "Not enough deposits");
                self.recheck_pegin_address(tweak_idx).await?;
                runtime::sleep(backoff.next().unwrap_or_default()).await;
                receiver.changed().await?;
                continue;
            }

            debug!(target: LOG_CLIENT_MODULE_WALLET, has=pegins.len(), "Enough deposits detected");

            for (_outpoint, transaction_id, change) in pegins {
                debug!(target: LOG_CLIENT_MODULE_WALLET, out_points=?change, "Ensuring deposists claimed");
                let tx_subscriber = self.client_ctx.transaction_updates(operation_id).await;

                if let Err(e) = tx_subscriber.await_tx_accepted(transaction_id).await {
                    bail!("{}", e);
                }

                debug!(target: LOG_CLIENT_MODULE_WALLET, out_points=?change, "Ensuring outputs claimed");
                self.client_ctx
                    .await_primary_module_outputs(operation_id, change)
                    .await
                    .expect("Cannot fail if tx was accepted and federation is honest");
            }

            return Ok(());
        }
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
                self.create_withdraw_output(operation_id, &address, amount, fee)?;
            let tx_builder = TransactionBuilder::new()
                .with_outputs(self.client_ctx.make_client_outputs(withdraw_output));

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

    /// Attempt to increase the fee of a onchain withdraw transaction using
    /// replace by fee (RBF).
    /// This can prevent transactions from getting stuck
    /// in the mempool
    #[deprecated(
        since = "0.4.0",
        note = "RBF withdrawals are rejected by the federation"
    )]
    pub async fn rbf_withdraw<M: Serialize + MaybeSync + MaybeSend>(
        &self,
        rbf: Rbf,
        extra_meta: M,
    ) -> anyhow::Result<OperationId> {
        let operation_id = OperationId(thread_rng().gen());

        let withdraw_output = self.create_rbf_withdraw_output(operation_id, &rbf)?;
        let tx_builder = TransactionBuilder::new()
            .with_outputs(self.client_ctx.make_client_outputs(withdraw_output));

        let extra_meta = serde_json::to_value(extra_meta).expect("Failed to serialize extra meta");
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                |_, change| WalletOperationMeta {
                    variant: WalletOperationMetaVariant::RbfWithdraw {
                        rbf: rbf.clone(),
                        change,
                    },
                    extra_meta: extra_meta.clone(),
                },
                tx_builder,
            )
            .await?;

        Ok(operation_id)
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

        let (WalletOperationMetaVariant::Withdraw { change, .. }
        | WalletOperationMetaVariant::RbfWithdraw { change, .. }) = operation_meta.variant
        else {
            bail!("Operation is not a withdraw operation");
        };

        let mut operation_stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(self
            .client_ctx
            .outcome_or_updates(&operation, operation_id, || {
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
            }))
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
async fn get_next_peg_in_tweak_child_id(dbtx: &mut DatabaseTransaction<'_>) -> TweakIdx {
    let index = dbtx
        .get_value(&NextPegInTweakIndexKey)
        .await
        .unwrap_or_default();
    dbtx.insert_entry(&NextPegInTweakIndexKey, &(index.next()))
        .await;
    index
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

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::backup::{
        recover_scan_idxes_for_activity, RecoverScanOutcome, RECOVER_NUM_IDX_ADD_TO_LAST_USED,
    };

    #[allow(clippy::too_many_lines)] // shut-up clippy, it's a test
    #[tokio::test(flavor = "multi_thread")]
    async fn sanity_test_recover_inner() {
        {
            let last_checked = AtomicBool::new(false);
            let last_checked = &last_checked;
            assert_eq!(
                recover_scan_idxes_for_activity(
                    TweakIdx(0),
                    &BTreeSet::new(),
                    |cur_idx| async move {
                        Ok(match cur_idx {
                            TweakIdx(9) => {
                                last_checked.store(true, Ordering::SeqCst);
                                vec![]
                            }
                            TweakIdx(10) => panic!("Shouldn't happen"),
                            TweakIdx(11) => {
                                vec![0usize] /* just for type inference */
                            }
                            _ => vec![],
                        })
                    }
                )
                .await
                .unwrap(),
                RecoverScanOutcome {
                    last_used_idx: None,
                    new_start_idx: TweakIdx(RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                    tweak_idxes_with_pegins: BTreeSet::from([])
                }
            );
            assert!(last_checked.load(Ordering::SeqCst));
        }

        {
            let last_checked = AtomicBool::new(false);
            let last_checked = &last_checked;
            assert_eq!(
                recover_scan_idxes_for_activity(
                    TweakIdx(0),
                    &BTreeSet::from([TweakIdx(1), TweakIdx(2)]),
                    |cur_idx| async move {
                        Ok(match cur_idx {
                            TweakIdx(1) => panic!("Shouldn't happen: already used (1)"),
                            TweakIdx(2) => panic!("Shouldn't happen: already used (2)"),
                            TweakIdx(11) => {
                                last_checked.store(true, Ordering::SeqCst);
                                vec![]
                            }
                            TweakIdx(12) => panic!("Shouldn't happen"),
                            TweakIdx(13) => {
                                vec![0usize] /* just for type inference */
                            }
                            _ => vec![],
                        })
                    }
                )
                .await
                .unwrap(),
                RecoverScanOutcome {
                    last_used_idx: Some(TweakIdx(2)),
                    new_start_idx: TweakIdx(2 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                    tweak_idxes_with_pegins: BTreeSet::from([])
                }
            );
            assert!(last_checked.load(Ordering::SeqCst));
        }

        {
            let last_checked = AtomicBool::new(false);
            let last_checked = &last_checked;
            assert_eq!(
                recover_scan_idxes_for_activity(
                    TweakIdx(10),
                    &BTreeSet::new(),
                    |cur_idx| async move {
                        Ok(match cur_idx {
                            TweakIdx(10) => vec![()],
                            TweakIdx(19) => {
                                last_checked.store(true, Ordering::SeqCst);
                                vec![]
                            }
                            TweakIdx(20) => panic!("Shouldn't happen"),
                            _ => vec![],
                        })
                    }
                )
                .await
                .unwrap(),
                RecoverScanOutcome {
                    last_used_idx: Some(TweakIdx(10)),
                    new_start_idx: TweakIdx(10 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                    tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(10)])
                }
            );
            assert!(last_checked.load(Ordering::SeqCst));
        }

        assert_eq!(
            recover_scan_idxes_for_activity(TweakIdx(0), &BTreeSet::new(), |cur_idx| async move {
                Ok(match cur_idx {
                    TweakIdx(6 | 15) => vec![()],
                    _ => vec![],
                })
            })
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: Some(TweakIdx(15)),
                new_start_idx: TweakIdx(15 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(6), TweakIdx(15)])
            }
        );
        assert_eq!(
            recover_scan_idxes_for_activity(TweakIdx(10), &BTreeSet::new(), |cur_idx| async move {
                Ok(match cur_idx {
                    TweakIdx(8) => {
                        vec![()] /* for type inference only */
                    }
                    TweakIdx(9) => {
                        panic!("Shouldn't happen")
                    }
                    _ => vec![],
                })
            })
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: None,
                new_start_idx: TweakIdx(9 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([])
            }
        );
        assert_eq!(
            recover_scan_idxes_for_activity(TweakIdx(10), &BTreeSet::new(), |cur_idx| async move {
                Ok(match cur_idx {
                    TweakIdx(9) => panic!("Shouldn't happen"),
                    TweakIdx(15) => vec![()],
                    _ => vec![],
                })
            })
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: Some(TweakIdx(15)),
                new_start_idx: TweakIdx(15 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(15)])
            }
        );
    }
}
