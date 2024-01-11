pub mod complete;
pub mod pay;

use std::sync::Arc;
use std::time::Duration;

use anyhow::ensure;
use async_stream::stream;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::derivable_secret::ChildId;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::oplog::UpdateStreamOrOutcome;
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, AddStateMachinesError, DynGlobalClientContext};
use fedimint_core::api::DynModuleApi;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{AutocommitError, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ApiVersion, ModuleInit, MultiApiVersion, TransactionItemAmount};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, TransactionId};
use fedimint_ln_client::incoming::{
    FundingOfferState, IncomingSmCommon, IncomingSmError, IncomingSmStates, IncomingStateMachine,
};
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_client::{create_incoming_contract_output, LightningClientInit};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::{ContractId, Preimage};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{
    LightningClientContext, LightningCommonInit, LightningGateway, LightningGatewayAnnouncement,
    LightningModuleTypes, LightningOutput, LightningOutputV0, KIND,
};
use futures::StreamExt;
use lightning_invoice::RoutingFees;
use secp256k1::{KeyPair, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use self::complete::GatewayCompleteStateMachine;
use self::pay::{
    GatewayPayCommon, GatewayPayInvoice, GatewayPayStateMachine, GatewayPayStates,
    OutgoingPaymentError,
};
use crate::gateway_lnrpc::InterceptHtlcRequest;
use crate::state_machine::complete::{
    GatewayCompleteCommon, GatewayCompleteStates, WaitForPreimageState,
};
use crate::Gateway;

pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);
pub const INITIAL_REGISTER_BACKOFF_DURATION: Duration = Duration::from_secs(15);

/// The high-level state of a reissue operation started with
/// [`GatewayClientModule::gateway_pay_bolt11_invoice`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayExtPayStates {
    Created,
    Preimage {
        preimage: Preimage,
    },
    Success {
        preimage: Preimage,
        out_points: Vec<OutPoint>,
    },
    Canceled {
        error: OutgoingPaymentError,
    },
    Fail {
        error: OutgoingPaymentError,
        error_message: String,
    },
    OfferDoesNotExist {
        contract_id: ContractId,
    },
}

/// The high-level state of an intercepted HTLC operation started with
/// [`GatewayClientModule::gateway_handle_intercepted_htlc`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayExtReceiveStates {
    Funding,
    Preimage(Preimage),
    RefundSuccess {
        out_points: Vec<OutPoint>,
        error: IncomingSmError,
    },
    RefundError {
        error_message: String,
        error: IncomingSmError,
    },
    FundingFailed {
        error: IncomingSmError,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GatewayMeta {
    Pay,
    Receive,
}

#[derive(Debug, Clone)]
pub struct GatewayClientInit {
    pub timelock_delta: u64,
    pub mint_channel_id: u64,
    pub gateway: Gateway,
}

#[apply(async_trait_maybe_send!)]
impl ModuleInit for GatewayClientInit {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(vec![].into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for GatewayClientInit {
    type Module = GatewayClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(GatewayClientModule {
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            redeem_key: args
                .module_root_secret()
                .child_key(ChildId(0))
                .to_secp_key(&Secp256k1::new()),
            module_api: args.module_api().clone(),
            timelock_delta: self.timelock_delta,
            mint_channel_id: self.mint_channel_id,
            client_ctx: args.context(),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientContext {
    redeem_key: bitcoin::KeyPair,
    timelock_delta: u64,
    secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    pub ln_decoder: Decoder,
    notifier: ModuleNotifier<DynGlobalClientContext, GatewayClientStateMachines>,
    gateway: Gateway,
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

/// Client side Lightning module **for the gateway**.
///
/// For the client side Lightning module for normal clients,
/// see [`fedimint_ln_client::LightningClientModule`]
#[derive(Debug)]
pub struct GatewayClientModule {
    cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<DynGlobalClientContext, GatewayClientStateMachines>,
    pub redeem_key: KeyPair,
    timelock_delta: u64,
    mint_channel_id: u64,
    module_api: DynModuleApi,
    client_ctx: ClientContext<Self>,
    gateway: Gateway,
}

impl ClientModule for GatewayClientModule {
    type Init = LightningClientInit;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContext;
    type States = GatewayClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        Self::ModuleStateMachineContext {
            redeem_key: self.redeem_key,
            timelock_delta: self.timelock_delta,
            secp: secp256k1_zkp::Secp256k1::new(),
            ln_decoder: self.decoder(),
            notifier: self.notifier.clone(),
            gateway: self.gateway.clone(),
        }
    }

    fn input_amount(
        &self,
        input: &<Self::Common as fedimint_core::module::ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        let input = input.maybe_v0_ref()?;

        Some(TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.contract_input,
        })
    }

    fn output_amount(
        &self,
        output: &<Self::Common as fedimint_core::module::ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        let output = output.maybe_v0_ref()?;

        let amt = match output {
            LightningOutputV0::Contract(account_output) => TransactionItemAmount {
                amount: account_output.amount,
                fee: self.cfg.fee_consensus.contract_output,
            },
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => {
                TransactionItemAmount {
                    amount: Amount::ZERO,
                    fee: Amount::ZERO,
                }
            }
        };
        Some(amt)
    }
}

impl GatewayClientModule {
    pub fn to_gateway_registration_info(
        &self,
        route_hints: Vec<RouteHint>,
        ttl: Duration,
        api: SafeUrl,
        gateway_id: secp256k1::PublicKey,
        fees: RoutingFees,
        node_pub_key: PublicKey,
        lightning_alias: String,
        supports_private_payments: bool,
    ) -> LightningGatewayAnnouncement {
        LightningGatewayAnnouncement {
            info: LightningGateway {
                mint_channel_id: self.mint_channel_id,
                gateway_redeem_key: self.redeem_key.public_key(),
                node_pub_key,
                lightning_alias,
                api,
                route_hints,
                fees,
                gateway_id,
                supports_private_payments,
            },
            ttl,
            vetted: false,
        }
    }

    async fn register_with_federation_inner(
        &self,
        id: FederationId,
        registration: LightningGatewayAnnouncement,
    ) -> anyhow::Result<()> {
        self.module_api.register_gateway(&registration).await?;
        debug!(
            "Successfully registered gateway {} with federation {id}",
            registration.info.gateway_id
        );
        Ok(())
    }

    async fn create_funding_incoming_contract_output_from_htlc(
        &self,
        htlc: Htlc,
    ) -> Result<
        (
            OperationId,
            ClientOutput<LightningOutputV0, GatewayClientStateMachines>,
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

        let client_output = ClientOutput::<LightningOutputV0, GatewayClientStateMachines> {
            output: incoming_output,
            state_machines: Arc::new(move |txid, _| {
                vec![
                    GatewayClientStateMachines::Receive(IncomingStateMachine {
                        common: IncomingSmCommon {
                            operation_id,
                            contract_id,
                            payment_hash: htlc.payment_hash,
                        },
                        state: IncomingSmStates::FundingOffer(FundingOfferState { txid }),
                    }),
                    GatewayClientStateMachines::Complete(GatewayCompleteStateMachine {
                        common: GatewayCompleteCommon {
                            operation_id,
                            incoming_chan_id: htlc.incoming_chan_id,
                            htlc_id: htlc.htlc_id,
                        },
                        state: GatewayCompleteStates::WaitForPreimage(WaitForPreimageState),
                    }),
                ]
            }),
        };
        Ok((operation_id, client_output))
    }

    async fn create_funding_incoming_contract_output_from_swap(
        &self,
        swap: SwapParameters,
    ) -> Result<
        (
            OperationId,
            ClientOutput<LightningOutputV0, GatewayClientStateMachines>,
        ),
        IncomingSmError,
    > {
        let payment_hash = swap.payment_hash;
        let operation_id = OperationId(payment_hash.into_inner());
        let (incoming_output, contract_id) = create_incoming_contract_output(
            &self.module_api,
            payment_hash,
            swap.amount_msat,
            self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0, GatewayClientStateMachines> {
            output: incoming_output,
            state_machines: Arc::new(move |txid, _| {
                vec![GatewayClientStateMachines::Receive(IncomingStateMachine {
                    common: IncomingSmCommon {
                        operation_id,
                        contract_id,
                        payment_hash,
                    },
                    state: IncomingSmStates::FundingOffer(FundingOfferState { txid }),
                })]
            }),
        };
        Ok((operation_id, client_output))
    }

    /// Register gateway with federation
    pub async fn register_with_federation(
        &self,
        gateway_api: SafeUrl,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
        gateway_id: secp256k1::PublicKey,
        fees: RoutingFees,
        node_pub_key: PublicKey,
        lightning_alias: String,
        supports_private_payments: bool,
    ) -> anyhow::Result<()> {
        {
            let registration_info = self.to_gateway_registration_info(
                route_hints,
                time_to_live,
                gateway_api,
                gateway_id,
                fees,
                node_pub_key,
                lightning_alias,
                supports_private_payments,
            );

            let federation_id = self.client_ctx.get_config().global.federation_id();
            self.register_with_federation_inner(federation_id, registration_info)
                .await?;
            Ok(())
        }
    }

    /// Attempt fulfill HTLC by buying preimage from the federation
    pub async fn gateway_handle_intercepted_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId> {
        debug!("Handling intercepted HTLC {htlc:?}");
        let (operation_id, client_output) = self
            .create_funding_incoming_contract_output_from_htlc(htlc.clone())
            .await?;

        let output = ClientOutput {
            output: LightningOutput::V0(client_output.output),
            state_machines: client_output.state_machines,
        };

        let tx = TransactionBuilder::new().with_output(self.client_ctx.make_client_output(output));
        let operation_meta_gen = |_: TransactionId, _: Vec<OutPoint>| GatewayMeta::Receive;
        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;
        debug!(?operation_id, "Submitted transaction for HTLC {htlc:?}");
        Ok(operation_id)
    }

    /// Attempt buying preimage from this federation in order to fulfill a pay
    /// request in another federation served by this gateway. In direct swap
    /// scenario, the gateway DOES NOT send payment over the lightning network
    async fn gateway_handle_direct_swap(
        &self,
        swap_params: SwapParameters,
    ) -> anyhow::Result<OperationId> {
        debug!("Handling direct swap {swap_params:?}");
        let (operation_id, client_output) = self
            .create_funding_incoming_contract_output_from_swap(swap_params.clone())
            .await?;

        let tx = TransactionBuilder::new().with_output(self.client_ctx.make_client_output(
            ClientOutput {
                output: LightningOutput::V0(client_output.output),
                state_machines: client_output.state_machines,
            },
        ));
        let operation_meta_gen = |_: TransactionId, _: Vec<OutPoint>| GatewayMeta::Receive;
        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;
        debug!(
            ?operation_id,
            "Submitted transaction for direct swap {swap_params:?}"
        );
        Ok(operation_id)
    }

    /// Subscribe to updates when the gateway is handling an intercepted HTLC,
    /// or direct swap between federations
    pub async fn gateway_subscribe_ln_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<GatewayExtReceiveStates>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
            stream! {

                yield GatewayExtReceiveStates::Funding;

                let state = loop {
                    debug!("Getting next ln receive state for {operation_id}");
                    if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            IncomingSmStates::Preimage(preimage) =>{
                                debug!(?operation_id, "Received preimage");
                                break GatewayExtReceiveStates::Preimage(preimage)
                            },
                            IncomingSmStates::RefundSubmitted { out_points, error } => {
                                debug!(?operation_id, "Refund submitted for {out_points:?} {error}");
                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(_) => {
                                        debug!(?operation_id, "Refund success");
                                        break GatewayExtReceiveStates::RefundSuccess { out_points, error }
                                    },
                                    Err(e) => {
                                        warn!(?operation_id, "Got failure {e:?} while awaiting for refund outputs {out_points:?}");
                                        break GatewayExtReceiveStates::RefundError{ error_message: e.to_string(), error }
                                    },
                                }
                            },
                            IncomingSmStates::FundingFailed { error } => {
                                warn!(?operation_id, "Funding failed: {error:?}");
                                break GatewayExtReceiveStates::FundingFailed{ error }
                            },
                            other => {
                                debug!("Got state {other:?} while awaiting for output of {operation_id}");
                            }
                        }
                    }
                };
                yield state;
            }
        }))
    }

    /// Pay lightning invoice on behalf of federation user
    pub async fn gateway_pay_bolt11_invoice(
        &self,
        pay_invoice_payload: PayInvoicePayload,
    ) -> anyhow::Result<OperationId> {
        let payload = pay_invoice_payload.clone();

        self.gateway
            .execute_with_lightning_connection(|lnrpc, _, _, _| async move {
                if matches!(
                    pay_invoice_payload.payment_data,
                    PaymentData::PrunedInvoice { .. }
                ) {
                    ensure!(
                        lnrpc.supports_private_payments(),
                        "Private payments are not supported by the lightning node"
                    );
                }
                Ok(())
            })
            .await?;

        self.client_ctx
            .module_autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let operation_id = OperationId(payload.contract_id.into_inner());

                        let state_machines =
                            vec![GatewayClientStateMachines::Pay(GatewayPayStateMachine {
                                common: GatewayPayCommon { operation_id },
                                state: GatewayPayStates::PayInvoice(GatewayPayInvoice {
                                    pay_invoice_payload: payload.clone(),
                                }),
                            })];

                        let dyn_states = state_machines
                            .into_iter()
                            .map(|s| self.client_ctx.make_dyn(s))
                            .collect();

                            match dbtx.add_state_machines( dyn_states).await {
                                Ok(()) => {
                                    dbtx
                                        .add_operation_log_entry(
                                            operation_id,
                                            KIND.as_str(),
                                            GatewayMeta::Pay,
                                        )
                                        .await;
                                }
                                Err(AddStateMachinesError::StateAlreadyExists) => {
                                    info!("State machine for operation {operation_id} already exists, will not add a new one")
                                }
                                Err(other) => {
                                    anyhow::bail!("Failed to add state machines: {other:?}")
                                }
                            }
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

    pub async fn gateway_subscribe_ln_pay(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<GatewayExtPayStates>> {
        let mut stream = self.notifier.subscribe(operation_id).await;
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let client_ctx = self.client_ctx.clone();

        Ok(operation.outcome_or_updates(&self.client_ctx.global_db(), operation_id, || {
            stream! {
                yield GatewayExtPayStates::Created;

                loop {
                    debug!("Getting next ln pay state for {operation_id}");
                    if let Some(GatewayClientStateMachines::Pay(state)) = stream.next().await {
                        match state.state {
                            GatewayPayStates::Preimage(out_points, preimage) => {
                                yield GatewayExtPayStates::Preimage{ preimage: preimage.clone() };

                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(_) => {
                                        debug!(?operation_id, "Success");
                                        yield GatewayExtPayStates::Success{ preimage: preimage.clone(), out_points };
                                        return;

                                    }
                                    Err(e) => {
                                        warn!(?operation_id, "Got failure {e:?} while awaiting for outputs {out_points:?}");
                                        // TODO: yield something here?
                                    }
                                }
                            }
                            GatewayPayStates::Canceled { txid, contract_id, error } => {
                                debug!(?operation_id, "Trying to cancel contract {contract_id:?} due to {error:?}");
                                match client_ctx.transaction_updates(operation_id).await.await_tx_accepted(txid).await {
                                    Ok(()) => {
                                        debug!(?operation_id, "Canceled contract {contract_id:?} due to {error:?}");
                                        yield GatewayExtPayStates::Canceled{ error };
                                        return;
                                    }
                                    Err(e) => {
                                        warn!(?operation_id, "Got failure {e:?} while awaiting for transaction {txid} to be accepted for");
                                        yield GatewayExtPayStates::Fail { error, error_message: format!("Refund transaction {txid} was not accepted by the federation. OperationId: {operation_id} Error: {e:?}") };
                                    }
                                }
                            }
                            GatewayPayStates::OfferDoesNotExist(contract_id) => {
                                warn!("Yielding OfferDoesNotExist state for {operation_id} and contract {contract_id}");
                                yield GatewayExtPayStates::OfferDoesNotExist { contract_id };
                            }
                            GatewayPayStates::Failed{ error, error_message } => {
                                warn!("Yielding Fail state for {operation_id} due to {error:?} {error_message:?}");
                                yield GatewayExtPayStates::Fail{ error, error_message };
                            },
                            GatewayPayStates::PayInvoice(_) => {
                                debug!("Got initial state PayInvoice while awaiting for output of {operation_id}");
                            }
                            other => {
                                info!("Got state {other:?} while awaiting for output of {operation_id}");
                            }
                        }
                    } else {
                        warn!("Got None while getting next ln pay state for {operation_id}");
                    }
                }
            }
        }))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayClientStateMachines {
    Pay(GatewayPayStateMachine),
    Receive(IncomingStateMachine),
    Complete(GatewayCompleteStateMachine),
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
            GatewayClientStateMachines::Complete(complete_state) => {
                sm_enum_variant_translation!(
                    complete_state.transitions(context, global_context),
                    GatewayClientStateMachines::Complete
                )
            }
        }
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        match self {
            GatewayClientStateMachines::Pay(pay_state) => pay_state.operation_id(),
            GatewayClientStateMachines::Receive(receive_state) => receive_state.operation_id(),
            GatewayClientStateMachines::Complete(complete_state) => complete_state.operation_id(),
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

#[derive(Debug, Clone)]
pub struct SwapParameters {
    payment_hash: sha256::Hash,
    amount_msat: Amount,
}

impl TryFrom<PaymentData> for SwapParameters {
    type Error = anyhow::Error;

    fn try_from(s: PaymentData) -> Result<Self, Self::Error> {
        let payment_hash = s.payment_hash();
        let amount_msat = s
            .amount()
            .ok_or_else(|| anyhow::anyhow!("Amountless invoice cannot be used in direct swap"))?;
        Ok(Self {
            payment_hash,
            amount_msat,
        })
    }
}
