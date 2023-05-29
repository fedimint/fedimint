pub mod receive;

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_stream::stream;
use bitcoin_hashes::Hash;
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State};
use fedimint_client::{
    sm_enum_variant_translation, Client, DynGlobalClientContext, UpdateStreamOrOutcome,
};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ExtendsCommonModuleGen, TransactionItemAmount};
use fedimint_core::{apply, async_trait_maybe_send, Amount, TransactionId};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{
    ln_operation, LightningCommonGen, LightningGateway, LightningModuleTypes, LightningOutput, KIND,
};
use futures::StreamExt;
use lightning::routing::gossip::RoutingFees;
use secp256k1::{KeyPair, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use self::receive::{
    GatewayReceiveCommon, GatewayReceiveStateMachine, GatewayReceiveStates, Htlc,
    HtlcInterceptedState, ReceiveError,
};
use crate::gatewaylnrpc::GetNodeInfoResponse;
use crate::lnrpc_client::ILnRpcClient;

const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

/// The high-level state of a reissue operation started with
/// [`LightningClientExt::intercept_htlc`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayExtReceiveStates {
    HtlcIntercepted,
    Funding,
    Preimage(Preimage),
    RefundSuccess(TransactionId),
    RefundError(String),
    FundingFailed(String),
    InvalidHtlc(ReceiveError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GatewayMeta {
    Pay,
}

#[apply(async_trait_maybe_send!)]
pub trait GatewayClientExt {
    /// Attempt fulfill HTLC by buying preimage from  federation
    async fn gateway_intercept_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId>;

    /// Subscribe to update to lightning receive
    async fn gateway_subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtReceiveStates>>;

    /// Register gateway with federation
    async fn register_with_federation(&self) -> anyhow::Result<()>;
}

#[apply(async_trait_maybe_send!)]
impl GatewayClientExt for Client {
    /// Pays a LN invoice with our available funds
    async fn gateway_intercept_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId> {
        let (_, instance) = self.get_first_module::<GatewayClientModule>(&KIND);

        self.db()
            .autocommit(
                |dbtx| {
                    let htlc_clone = htlc.clone();
                    Box::pin(async move {
                        let operation_id = OperationId(htlc.payment_hash.into_inner());

                        let state_machines = vec![GatewayClientStateMachines::Receive(
                            GatewayReceiveStateMachine {
                                common: GatewayReceiveCommon { operation_id },
                                state: GatewayReceiveStates::HtlcIntercepted(
                                    HtlcInterceptedState { htlc: htlc_clone },
                                ),
                            },
                        )];

                        let dyn_states = state_machines
                            .into_iter()
                            .map(|s| s.into_dyn(instance.id))
                            .collect();

                        self.add_state_machines(dbtx, dyn_states).await?;
                        self.add_operation_log_entry(
                            dbtx,
                            operation_id,
                            KIND.as_str(),
                            GatewayMeta::Pay,
                        )
                        .await;

                        Ok(operation_id)
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

    async fn gateway_subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtReceiveStates>> {
        let (gateway, _instance) = self.get_first_module::<GatewayClientModule>(&KIND);
        let operation = ln_operation(self, operation_id).await?;

        Ok(operation.outcome_or_updates(self.db(), operation_id, || {
            stream! {
                yield GatewayExtReceiveStates::HtlcIntercepted;

                let mut stream = gateway.notifier.subscribe(operation_id).await;
                let state = loop {
                    if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            GatewayReceiveStates::FundingOffer(_) => break GatewayExtReceiveStates::Funding,
                            GatewayReceiveStates::InvalidHtlc(e) => break GatewayExtReceiveStates::InvalidHtlc(e),
                            GatewayReceiveStates::FundingFailed(e) => break GatewayExtReceiveStates::FundingFailed(e),
                            _ => {}
                        }
                    }
                };
                yield state;

                let state = loop {
                    if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            GatewayReceiveStates::Preimage(preimage) => break GatewayExtReceiveStates::Preimage(preimage),
                            // FIXME: do we need something here to actually wait for the ecash to arrive???
                            GatewayReceiveStates::RefundSuccess(txid) => break GatewayExtReceiveStates::RefundSuccess(txid),
                            GatewayReceiveStates::RefundError(e) => break GatewayExtReceiveStates::RefundError(e),
                            GatewayReceiveStates::FundingFailed(e) => break GatewayExtReceiveStates::FundingFailed(e),
                            _ => {}
                        }
                    }
                };
                yield state;
            }
        }))
    }

    /// Register this gateway with the federation
    async fn register_with_federation(&self) -> anyhow::Result<()> {
        let (gateway, instance) = self.get_first_module::<GatewayClientModule>(&KIND);
        let route_hints = vec![];
        let config = gateway.to_gateway_registration_info(route_hints, GW_ANNOUNCEMENT_TTL);
        instance.api.register_gateway(&config).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientGen {
    pub lightning_client: Arc<dyn ILnRpcClient>,
    pub timelock_delta: u64,
    pub api: Url,
    pub mint_channel_id: u64,
    pub fees: RoutingFees,
}

impl ExtendsCommonModuleGen for GatewayClientGen {
    type Common = LightningCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for GatewayClientGen {
    type Module = GatewayClientModule;
    type Config = LightningClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        let GetNodeInfoResponse { pub_key, alias: _ } = self.lightning_client.info().await?;
        let node_pub_key =
            PublicKey::from_slice(&pub_key).map_err(|e| anyhow!("Invalid node pubkey {}", e))?;
        Ok(GatewayClientModule {
            cfg,
            notifier,
            redeem_key: module_root_secret
                .child_key(ChildId(0))
                .to_secp_key(&Secp256k1::new()),
            node_pub_key,
            lightning_client: self.lightning_client.clone(),
            timelock_delta: self.timelock_delta,
            api: self.api.clone(),
            mint_channel_id: self.mint_channel_id,
            fees: self.fees,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GatewayClientContext {
    lnrpc: Arc<dyn ILnRpcClient>,
    redeem_key: bitcoin::KeyPair,
    timelock_delta: u64,
    secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    pub ln_decoder: Decoder,
}

impl Context for GatewayClientContext {}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum GatewayError {
    #[error("Gateway canceled the contract")]
    Canceled(Option<TransactionId>),
    #[error("Unrecoverable error occurred in the gateway")]
    Failed,
}

#[derive(Debug)]
pub struct GatewayClientModule {
    cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<DynGlobalClientContext, GatewayClientStateMachines>,
    redeem_key: KeyPair,
    node_pub_key: PublicKey,
    timelock_delta: u64,
    // FIXME: this is used for gateway registration
    // Should this happen inside or outside the client?
    api: Url,
    mint_channel_id: u64,
    fees: RoutingFees,
    lightning_client: Arc<dyn ILnRpcClient>,
}

impl ClientModule for GatewayClientModule {
    type Common = LightningModuleTypes;
    type ModuleStateMachineContext = GatewayClientContext;
    type States = GatewayClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        Self::ModuleStateMachineContext {
            lnrpc: self.lightning_client.clone(),
            redeem_key: self.redeem_key,
            timelock_delta: self.timelock_delta,
            secp: secp256k1_zkp::Secp256k1::new(),
            ln_decoder: self.decoder(),
        }
    }

    fn input_amount(
        &self,
        input: &<Self::Common as fedimint_core::module::ModuleCommon>::Input,
    ) -> fedimint_core::module::TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.contract_input,
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as fedimint_core::module::ModuleCommon>::Output,
    ) -> fedimint_core::module::TransactionItemAmount {
        match output {
            LightningOutput::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.cfg.fee_consensus.contract_output,
            },
            LightningOutput::Offer(_) | LightningOutput::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        }
    }
}

impl GatewayClientModule {
    pub fn to_gateway_registration_info(
        &self,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
    ) -> LightningGateway {
        LightningGateway {
            mint_channel_id: self.mint_channel_id,
            mint_pub_key: self.redeem_key.x_only_public_key().0,
            node_pub_key: self.node_pub_key,
            api: self.api.clone(),
            route_hints,
            valid_until: fedimint_core::time::now() + time_to_live,
            fees: self.fees,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayClientStateMachines {
    Receive(GatewayReceiveStateMachine),
}

impl IntoDynInstance for GatewayClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachines {
    type ModuleContext = GatewayClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match self {
            GatewayClientStateMachines::Receive(receive_state) => {
                sm_enum_variant_translation!(
                    receive_state.transitions(context, global_context),
                    GatewayClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        match self {
            GatewayClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
        }
    }
}
