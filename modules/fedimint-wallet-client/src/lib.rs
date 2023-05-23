pub mod api;

mod deposit;

use std::time::SystemTime;

use anyhow::{anyhow, bail};
use async_stream::stream;
use bitcoin::{Address, Network};
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::util::BoxStream;
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_wallet_common::config::WalletClientConfig;
use fedimint_wallet_common::tweakable::Tweakable;
pub use fedimint_wallet_common::*;
use futures::{Stream, StreamExt};
use miniscript::ToPublicKey;
use rand::thread_rng;
use secp256k1::{All, KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};

use crate::deposit::{CreatedDepositState, DepositStateMachine, DepositStates};

#[apply(async_trait_maybe_send!)]
pub trait WalletClientExt {
    async fn get_deposit_address(
        &self,
        valid_until: SystemTime,
    ) -> anyhow::Result<(OperationId, Address)>;

    async fn subscribe_deposit_updates(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<BoxStream<DepositState>>;
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

                        self.add_state_machines(dbtx, vec![DynState::from_typed(instance.id, sm)])
                            .await?;
                        self.add_operation_log_entry(
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
    ) -> anyhow::Result<BoxStream<DepositState>> {
        let (wallet_client, _) =
            self.get_first_module::<WalletClientModule>(&WalletCommonGen::KIND);

        let operation_log_entry = self
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

        Ok(Box::pin(stream! {
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
        }))
    }
}

async fn next_deposit_state<S>(stream: &mut S) -> Option<DepositStates>
where
    S: Stream<Item = WalletClientStates> + Unpin,
{
    match stream.next().await? {
        WalletClientStates::Deposit(ds) => Some(ds.state),
    }
}

#[derive(Debug, Clone)]
pub struct WalletClientGen;

impl ExtendsCommonModuleGen for WalletClientGen {
    type Common = WalletCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for WalletClientGen {
    type Module = WalletClientModule;
    type Config = WalletClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        _module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        _api: DynGlobalApi,
        _module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module> {
        Ok(WalletClientModule { cfg, notifier })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Deposit {
        address: bitcoin::Address,
        expires_at: SystemTime,
    },
}

#[derive(Debug)]
pub struct WalletClientModule {
    cfg: WalletClientConfig,
    notifier: ModuleNotifier<DynGlobalClientContext, WalletClientStates>,
}

impl ClientModule for WalletClientModule {
    type Common = WalletModuleTypes;
    type ModuleStateMachineContext = WalletClientContext;
    type States = WalletClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {
        WalletClientContext {
            esplora_server: "http://127.0.0.1:50002".to_string(),
            wallet_descriptor: self.cfg.peg_in_descriptor.clone(),
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
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    esplora_server: String,
    wallet_descriptor: PegInDescriptor,
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
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum WalletClientStates {
    Deposit(DepositStateMachine),
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
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            WalletClientStates::Deposit(sm) => sm.operation_id(),
        }
    }
}
