pub mod pay;

use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, OperationId, State};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, Client, DynGlobalClientContext};
use fedimint_core::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, ExtendsCommonModuleGen, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_ln_client::contracts::ContractId;
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::incoming::{
    FundingOfferState, IncomingSmCommon, IncomingSmError, IncomingSmStates, IncomingStateMachine,
};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{
    create_incoming_contract_output, ln_operation, LightningClientContext, LightningCommonGen,
    LightningGateway, LightningModuleTypes, LightningOutput, KIND,
};
use futures::StreamExt;
use lightning::routing::gossip::RoutingFees;
use secp256k1::{KeyPair, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use url::Url;

use self::pay::{GatewayPayCommon, GatewayPayInvoice, GatewayPayStateMachine, GatewayPayStates};
use crate::db::FederationRegistrationKey;
use crate::gatewaylnrpc::{GetNodeInfoResponse, InterceptHtlcRequest};
use crate::lnrpc_client::ILnRpcClient;

pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);
pub const INITIAL_REGISTER_BACKOFF_DURATION: Duration = Duration::from_secs(15);

/// The high-level state of a reissue operation started with
/// [`GatewayClientExt::gateway_pay_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayExtPayStates {
    Created,
    Preimage {
        preimage: Preimage,
    },
    Success {
        preimage: Preimage,
        outpoint: OutPoint,
    },
    Canceled,
    Fail,
    OfferDoesNotExist {
        contract_id: ContractId,
    },
}

/// The high-level state of an intercepted HTLC operation started with
/// [`GatewayClientExt::gateway_handle_intercepted_htlc`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayExtReceiveStates {
    Funding,
    Preimage(Preimage),
    RefundSuccess(OutPoint),
    RefundError(String),
    FundingFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GatewayMeta {
    Pay,
    Receive,
}

#[apply(async_trait_maybe_send!)]
pub trait GatewayClientExt {
    /// Pay lightning invoice on behalf of federation user
    async fn gateway_pay_bolt11_invoice(
        &self,
        contract_id: ContractId,
    ) -> anyhow::Result<OperationId>;

    /// Subscribe to update to lightning payment
    async fn gateway_subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtPayStates>>;

    /// Register gateway with federation
    async fn register_with_federation(
        &self,
        gateway_api: Url,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
        gateway_id: secp256k1::PublicKey,
    ) -> anyhow::Result<()>;

    /// Attempt fulfill HTLC by buying preimage from the federation
    async fn gateway_handle_intercepted_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId>;

    /// Subscribe to updates when the gateway is handling an intercepted HTLC
    async fn gateway_subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtReceiveStates>>;
}

#[apply(async_trait_maybe_send!)]
impl GatewayClientExt for Client {
    /// Pays a LN invoice with our available funds
    async fn gateway_pay_bolt11_invoice(
        &self,
        contract_id: ContractId,
    ) -> anyhow::Result<OperationId> {
        let (_, instance) = self.get_first_module::<GatewayClientModule>(&KIND);

        self.db()
            .autocommit(
                |dbtx| {
                    Box::pin(async move {
                        let operation_id = OperationId(contract_id.into_inner());

                        let state_machines =
                            vec![GatewayClientStateMachines::Pay(GatewayPayStateMachine {
                                common: GatewayPayCommon { operation_id },
                                state: GatewayPayStates::PayInvoice(GatewayPayInvoice {
                                    contract_id,
                                }),
                            })];

                        let dyn_states = state_machines
                            .into_iter()
                            .map(|s| s.into_dyn(instance.id))
                            .collect();

                        self.add_state_machines(dbtx, dyn_states).await?;
                        self.operation_log()
                            .add_operation_log_entry(
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
                    anyhow::anyhow!("Commit to DB failed: {last_error}")
                }
            })
    }

    async fn gateway_subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtPayStates>> {
        let (gateway, _instance) = self.get_first_module::<GatewayClientModule>(&KIND);
        let operation = ln_operation(self, operation_id).await?;

        Ok(operation.outcome_or_updates(self.db(), operation_id, || {
            stream! {
                yield GatewayExtPayStates::Created;

                match gateway.await_paid_invoice(operation_id).await {
                    Ok((outpoint, preimage)) => {
                        yield GatewayExtPayStates::Preimage{ preimage: preimage.clone() };

                        if self.await_primary_module_output(operation_id, outpoint).await.is_ok() {
                            yield GatewayExtPayStates::Success{ preimage: preimage.clone(), outpoint };
                            return;
                        }

                        yield GatewayExtPayStates::Fail;
                    }
                    Err(error) => {
                        match error {
                            GatewayError::Canceled(cancel_txid) => {
                                if self.transaction_updates(operation_id).await.await_tx_accepted(cancel_txid).await.is_ok() {
                                    yield GatewayExtPayStates::Canceled;
                                    return;
                                }

                                yield GatewayExtPayStates::Fail;
                            }
                            GatewayError::OfferDoesNotExist(contract_id) => {
                                yield GatewayExtPayStates::OfferDoesNotExist { contract_id };
                            }
                            _ => {
                                yield GatewayExtPayStates::Fail;
                            }
                        }
                    }
                }
            }
        }))
    }

    /// Register this gateway with the federation
    async fn register_with_federation(
        &self,
        gateway_api: Url,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
        gateway_id: secp256k1::PublicKey,
    ) -> anyhow::Result<()> {
        let (gateway, _) = self.get_first_module::<GatewayClientModule>(&KIND);
        let registration_info = gateway.to_gateway_registration_info(
            route_hints,
            time_to_live,
            gateway_api,
            gateway_id,
        );

        let federation_id = self.get_config().federation_id;
        let mut dbtx = self.db().begin_transaction().await;
        gateway
            .register_with_federation(&mut dbtx, federation_id, registration_info)
            .await?;
        dbtx.commit_tx().await;
        Ok(())
    }

    /// Handles an intercepted HTLC by buying a preimage from the federation
    async fn gateway_handle_intercepted_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId> {
        let (gateway, instance) = self.get_first_module::<GatewayClientModule>(&KIND);
        let (operation_id, output) = gateway
            .create_funding_incoming_contract_output(htlc)
            .await?;
        let tx = TransactionBuilder::new().with_output(output.into_dyn(instance.id));
        let operation_meta_gen = |_: TransactionId, _: Option<OutPoint>| GatewayMeta::Receive;
        self.finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;
        Ok(operation_id)
    }

    async fn gateway_subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<'_, GatewayExtReceiveStates>> {
        let (gateway, _instance) = self.get_first_module::<GatewayClientModule>(&KIND);
        let operation = ln_operation(self, operation_id).await?;

        Ok(operation.outcome_or_updates(self.db(), operation_id, || {
            stream! {
                yield GatewayExtReceiveStates::Funding;

                let mut stream = gateway.notifier.subscribe(operation_id).await;
                let state = loop {
                    if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            IncomingSmStates::Preimage(preimage) => break GatewayExtReceiveStates::Preimage(preimage),
                            IncomingSmStates::RefundSubmitted(txid) => {
                                let out_point = OutPoint { txid, out_idx: 0};
                                match self.await_primary_module_output(operation_id, out_point).await {
                                    Ok(_) => break GatewayExtReceiveStates::RefundSuccess(out_point),
                                    Err(e) => break GatewayExtReceiveStates::RefundError(e.to_string()),
                                }
                            },
                            IncomingSmStates::FundingFailed(e) => break GatewayExtReceiveStates::FundingFailed(e),
                            _ => {}
                        }
                    }
                };
                yield state;
            }
        }))
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientGen {
    pub lightning_client: Arc<dyn ILnRpcClient>,
    pub timelock_delta: u64,
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

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        _api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        _api: DynGlobalApi,
        module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module> {
        let GetNodeInfoResponse { pub_key, alias: _ } = self.lightning_client.info().await?;
        let node_pub_key = PublicKey::from_slice(&pub_key)
            .map_err(|e| anyhow::anyhow!("Invalid node pubkey {}", e))?;
        Ok(GatewayClientModule {
            cfg,
            notifier,
            redeem_key: module_root_secret
                .child_key(ChildId(0))
                .to_secp_key(&Secp256k1::new()),
            node_pub_key,
            lightning_client: self.lightning_client.clone(),
            timelock_delta: self.timelock_delta,
            mint_channel_id: self.mint_channel_id,
            fees: self.fees,
            module_api,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientContext {
    lnrpc: Arc<dyn ILnRpcClient>,
    redeem_key: bitcoin::KeyPair,
    timelock_delta: u64,
    secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    pub ln_decoder: Decoder,
}

impl Context for GatewayClientContext {}

impl From<&GatewayClientContext> for LightningClientContext {
    fn from(ctx: &GatewayClientContext) -> Self {
        LightningClientContext {
            ln_decoder: ctx.ln_decoder.clone(),
            redeem_key: ctx.redeem_key,
        }
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum GatewayError {
    #[error("Gateway canceled the contract")]
    Canceled(TransactionId),
    #[error("Offer does not exist")]
    OfferDoesNotExist(ContractId),
    #[error("Unrecoverable error occurred in the gateway")]
    Failed,
}

#[derive(Debug)]
pub struct GatewayClientModule {
    cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<DynGlobalClientContext, GatewayClientStateMachines>,
    pub redeem_key: KeyPair,
    node_pub_key: PublicKey,
    timelock_delta: u64,
    mint_channel_id: u64,
    fees: RoutingFees,
    lightning_client: Arc<dyn ILnRpcClient>,
    module_api: DynModuleApi,
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
        api: Url,
        gateway_id: secp256k1::PublicKey,
    ) -> LightningGateway {
        LightningGateway {
            mint_channel_id: self.mint_channel_id,
            gateway_redeem_key: self.redeem_key.x_only_public_key().0,
            node_pub_key: self.node_pub_key,
            api,
            route_hints,
            valid_until: fedimint_core::time::now() + time_to_live,
            fees: self.fees,
            gateway_id,
        }
    }

    async fn register_with_federation(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        id: FederationId,
        registration: LightningGateway,
    ) -> anyhow::Result<()> {
        self.module_api.register_gateway(&registration).await?;
        dbtx.insert_entry(&FederationRegistrationKey { id }, &registration)
            .await;
        info!(
            "Successfully registered gateway {} with federation {}",
            registration.gateway_id, id
        );
        Ok(())
    }

    async fn await_paid_invoice(
        &self,
        operation_id: OperationId,
    ) -> Result<(OutPoint, Preimage), GatewayError> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            if let Some(GatewayClientStateMachines::Pay(state)) = stream.next().await {
                match state.state {
                    GatewayPayStates::Preimage(outpoint, preimage) => {
                        return Ok((outpoint, preimage))
                    }
                    GatewayPayStates::Canceled(cancel_outpoint, _) => {
                        return Err(GatewayError::Canceled(cancel_outpoint))
                    }
                    GatewayPayStates::OfferDoesNotExist(contract_id) => {
                        return Err(GatewayError::OfferDoesNotExist(contract_id))
                    }
                    GatewayPayStates::Failed => return Err(GatewayError::Failed),
                    _ => {}
                }
            }
        }
    }

    async fn create_funding_incoming_contract_output(
        &self,
        htlc: Htlc,
    ) -> Result<
        (
            OperationId,
            ClientOutput<LightningOutput, GatewayClientStateMachines>,
        ),
        IncomingSmError,
    > {
        let operation_id = OperationId(htlc.payment_hash.into_inner());
        let (incoming_output, contract_id) = create_incoming_contract_output(
            &self.module_api,
            htlc.payment_hash,
            htlc.outgoing_amount_msat,
            self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachines> {
            output: incoming_output,
            state_machines: Arc::new(move |txid, _| {
                vec![GatewayClientStateMachines::Receive(IncomingStateMachine {
                    common: IncomingSmCommon {
                        operation_id,
                        contract_id,
                    },
                    state: IncomingSmStates::FundingOffer(FundingOfferState { txid }),
                })]
            }),
        };
        Ok((operation_id, client_output))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayClientStateMachines {
    Pay(GatewayPayStateMachine),
    Receive(IncomingStateMachine),
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
            GatewayClientStateMachines::Pay(pay_state) => {
                sm_enum_variant_translation!(
                    pay_state.transitions(context, global_context),
                    GatewayClientStateMachines::Pay
                )
            }
            GatewayClientStateMachines::Receive(receive_state) => {
                sm_enum_variant_translation!(
                    receive_state.transitions(&context.into(), global_context),
                    GatewayClientStateMachines::Receive
                )
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        match self {
            GatewayClientStateMachines::Pay(pay_state) => pay_state.operation_id(),
            GatewayClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
        }
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Route htlc error")]
    RouteHtlcError,
}
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct Htlc {
    /// The HTLC payment hash.
    pub payment_hash: sha256::Hash,
    /// The incoming HTLC amount in millisatoshi.
    pub incoming_amount_msat: Amount,
    /// The outgoing HTLC amount in millisatoshi
    pub outgoing_amount_msat: Amount,
    /// The incoming HTLC expiry
    pub incoming_expiry: u32,
    /// The short channel id of the HTLC.
    pub short_channel_id: u64,
    /// The id of the incoming channel
    pub incoming_chan_id: u64,
    /// The index of the incoming htlc in the incoming channel
    pub htlc_id: u64,
}

impl TryFrom<InterceptHtlcRequest> for Htlc {
    type Error = anyhow::Error;

    fn try_from(s: InterceptHtlcRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_hash: sha256::Hash::from_slice(&s.payment_hash)?,
            incoming_amount_msat: Amount::from_msats(s.incoming_amount_msat),
            outgoing_amount_msat: Amount::from_msats(s.outgoing_amount_msat),
            incoming_expiry: s.incoming_expiry,
            short_channel_id: s.short_channel_id,
            incoming_chan_id: s.incoming_chan_id,
            htlc_id: s.htlc_id,
        })
    }
}
