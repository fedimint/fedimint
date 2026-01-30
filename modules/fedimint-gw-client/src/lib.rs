mod complete;
pub mod events;
pub mod pay;

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey};
use complete::{GatewayCompleteCommon, GatewayCompleteStates, WaitForPreimageState};
use events::{IncomingPaymentStarted, OutgoingPaymentStarted};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::ClientHandleArc;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule, OutPointRange};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{
    AddStateMachinesError, DynGlobalClientContext, sm_enum_variant_translation,
};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{AutocommitError, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion};
use fedimint_core::util::{FmtCompact, SafeUrl, Spanned};
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send, secp256k1};
use fedimint_derive_secret::ChildId;
use fedimint_lightning::{
    InterceptPaymentRequest, InterceptPaymentResponse, LightningContext, LightningRpcError,
    PayInvoiceResponse,
};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::incoming::{
    FundingOfferState, IncomingSmCommon, IncomingSmError, IncomingSmStates, IncomingStateMachine,
};
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_client::{
    LightningClientContext, LightningClientInit, RealGatewayConnection,
    create_incoming_contract_output,
};
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, Preimage};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::{
    KIND, LightningCommonInit, LightningGateway, LightningGatewayAnnouncement,
    LightningModuleTypes, LightningOutput, LightningOutputV0, RemoveGatewayRequest,
    create_gateway_remove_message,
};
use fedimint_lnv2_common::GatewayApi;
use futures::StreamExt;
use lightning_invoice::RoutingFees;
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use self::complete::GatewayCompleteStateMachine;
use self::pay::{
    GatewayPayCommon, GatewayPayInvoice, GatewayPayStateMachine, GatewayPayStates,
    OutgoingPaymentError,
};

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
    pub federation_index: u64,
    pub lightning_manager: Arc<dyn IGatewayClientV1>,
}

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
                .to_secp_key(&fedimint_core::secp256k1::Secp256k1::new()),
            module_api: args.module_api().clone(),
            federation_index: self.federation_index,
            client_ctx: args.context(),
            lightning_manager: self.lightning_manager.clone(),
            connector_registry: args.connector_registry.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientContext {
    redeem_key: Keypair,
    secp: Secp256k1<All>,
    pub ln_decoder: Decoder,
    notifier: ModuleNotifier<GatewayClientStateMachines>,
    pub client_ctx: ClientContext<GatewayClientModule>,
    pub lightning_manager: Arc<dyn IGatewayClientV1>,
    pub connector_registry: ConnectorRegistry,
}

impl Context for GatewayClientContext {
    const KIND: Option<ModuleKind> = Some(fedimint_ln_common::KIND);
}

impl From<&GatewayClientContext> for LightningClientContext {
    fn from(ctx: &GatewayClientContext) -> Self {
        let gateway_conn = RealGatewayConnection {
            api: GatewayApi::new(None, ctx.connector_registry.clone()),
        };
        LightningClientContext {
            ln_decoder: ctx.ln_decoder.clone(),
            redeem_key: ctx.redeem_key,
            gateway_conn: Arc::new(gateway_conn),
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
    pub notifier: ModuleNotifier<GatewayClientStateMachines>,
    pub redeem_key: Keypair,
    federation_index: u64,
    module_api: DynModuleApi,
    client_ctx: ClientContext<Self>,
    pub lightning_manager: Arc<dyn IGatewayClientV1>,
    connector_registry: ConnectorRegistry,
}

#[async_trait::async_trait]
impl ClientModule for GatewayClientModule {
    type Init = LightningClientInit;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContext;
    type States = GatewayClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        Self::ModuleStateMachineContext {
            redeem_key: self.redeem_key,
            secp: Secp256k1::new(),
            ln_decoder: self.decoder(),
            notifier: self.notifier.clone(),
            client_ctx: self.client_ctx.clone(),
            lightning_manager: self.lightning_manager.clone(),
            connector_registry: self.connector_registry.clone(),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as fedimint_core::module::ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(self.cfg.fee_consensus.contract_input))
    }

    async fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(input.maybe_v0_ref()?.amount))
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        output: &<Self::Common as fedimint_core::module::ModuleCommon>::Output,
    ) -> Option<Amounts> {
        match output.maybe_v0_ref()? {
            LightningOutputV0::Contract(_) => {
                Some(Amounts::new_bitcoin(self.cfg.fee_consensus.contract_output))
            }
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => {
                Some(Amounts::ZERO)
            }
        }
    }

    async fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        let amount_btc = match output.maybe_v0_ref()? {
            LightningOutputV0::Contract(contract_output) => contract_output.amount,
            LightningOutputV0::Offer(_) | LightningOutputV0::CancelOutgoing { .. } => Amount::ZERO,
        };
        Some(Amounts::new_bitcoin(amount_btc))
    }
}

impl GatewayClientModule {
    fn to_gateway_registration_info(
        &self,
        route_hints: Vec<RouteHint>,
        ttl: Duration,
        fees: RoutingFees,
        lightning_context: LightningContext,
        api: SafeUrl,
        gateway_id: PublicKey,
    ) -> LightningGatewayAnnouncement {
        LightningGatewayAnnouncement {
            info: LightningGateway {
                federation_index: self.federation_index,
                gateway_redeem_key: self.redeem_key.public_key(),
                node_pub_key: lightning_context.lightning_public_key,
                lightning_alias: lightning_context.lightning_alias,
                api,
                route_hints,
                fees,
                gateway_id,
                supports_private_payments: lightning_context.lnrpc.supports_private_payments(),
            },
            ttl,
            vetted: false,
        }
    }

    async fn create_funding_incoming_contract_output_from_htlc(
        &self,
        htlc: Htlc,
    ) -> Result<
        (
            OperationId,
            Amount,
            ClientOutput<LightningOutputV0>,
            ClientOutputSM<GatewayClientStateMachines>,
            ContractId,
        ),
        IncomingSmError,
    > {
        let operation_id = OperationId(htlc.payment_hash.to_byte_array());
        let (incoming_output, amount, contract_id) = create_incoming_contract_output(
            &self.module_api,
            htlc.payment_hash,
            htlc.outgoing_amount_msat,
            &self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0> {
            output: incoming_output,
            amounts: Amounts::new_bitcoin(amount),
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachines> {
            state_machines: Arc::new(move |out_point_range: OutPointRange| {
                assert_eq!(out_point_range.count(), 1);
                vec![
                    GatewayClientStateMachines::Receive(IncomingStateMachine {
                        common: IncomingSmCommon {
                            operation_id,
                            contract_id,
                            payment_hash: htlc.payment_hash,
                        },
                        state: IncomingSmStates::FundingOffer(FundingOfferState {
                            txid: out_point_range.txid(),
                        }),
                    }),
                    GatewayClientStateMachines::Complete(GatewayCompleteStateMachine {
                        common: GatewayCompleteCommon {
                            operation_id,
                            payment_hash: htlc.payment_hash,
                            incoming_chan_id: htlc.incoming_chan_id,
                            htlc_id: htlc.htlc_id,
                        },
                        state: GatewayCompleteStates::WaitForPreimage(WaitForPreimageState),
                    }),
                ]
            }),
        };
        Ok((
            operation_id,
            amount,
            client_output,
            client_output_sm,
            contract_id,
        ))
    }

    async fn create_funding_incoming_contract_output_from_swap(
        &self,
        swap: SwapParameters,
    ) -> Result<
        (
            OperationId,
            ClientOutput<LightningOutputV0>,
            ClientOutputSM<GatewayClientStateMachines>,
        ),
        IncomingSmError,
    > {
        let payment_hash = swap.payment_hash;
        let operation_id = OperationId(payment_hash.to_byte_array());
        let (incoming_output, amount, contract_id) = create_incoming_contract_output(
            &self.module_api,
            payment_hash,
            swap.amount_msat,
            &self.redeem_key,
        )
        .await?;

        let client_output = ClientOutput::<LightningOutputV0> {
            output: incoming_output,
            amounts: Amounts::new_bitcoin(amount),
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachines> {
            state_machines: Arc::new(move |out_point_range| {
                assert_eq!(out_point_range.count(), 1);
                vec![GatewayClientStateMachines::Receive(IncomingStateMachine {
                    common: IncomingSmCommon {
                        operation_id,
                        contract_id,
                        payment_hash,
                    },
                    state: IncomingSmStates::FundingOffer(FundingOfferState {
                        txid: out_point_range.txid(),
                    }),
                })]
            }),
        };
        Ok((operation_id, client_output, client_output_sm))
    }

    /// Register gateway with federation
    pub async fn try_register_with_federation(
        &self,
        route_hints: Vec<RouteHint>,
        time_to_live: Duration,
        fees: RoutingFees,
        lightning_context: LightningContext,
        api: SafeUrl,
        gateway_id: PublicKey,
    ) {
        let registration_info = self.to_gateway_registration_info(
            route_hints,
            time_to_live,
            fees,
            lightning_context,
            api,
            gateway_id,
        );
        let gateway_id = registration_info.info.gateway_id;

        let federation_id = self
            .client_ctx
            .get_config()
            .await
            .global
            .calculate_federation_id();
        match self.module_api.register_gateway(&registration_info).await {
            Err(e) => {
                warn!(
                    e = %e.fmt_compact(),
                    "Failed to register gateway {gateway_id} with federation {federation_id}"
                );
            }
            _ => {
                info!(
                    "Successfully registered gateway {gateway_id} with federation {federation_id}"
                );
            }
        }
    }

    /// Attempts to remove a gateway's registration from the federation. Since
    /// removing gateway registrations is best effort, this does not return
    /// an error and simply emits a warning when the registration cannot be
    /// removed.
    pub async fn remove_from_federation(&self, gateway_keypair: Keypair) {
        // Removing gateway registrations is best effort, so just emit a warning if it
        // fails
        if let Err(e) = self.remove_from_federation_inner(gateway_keypair).await {
            let gateway_id = gateway_keypair.public_key();
            let federation_id = self
                .client_ctx
                .get_config()
                .await
                .global
                .calculate_federation_id();
            warn!("Failed to remove gateway {gateway_id} from federation {federation_id}: {e:?}");
        }
    }

    /// Retrieves the signing challenge from each federation peer. Since each
    /// peer maintains their own list of registered gateways, the gateway
    /// needs to provide a signature that is signed by the private key of the
    /// gateway id to remove the registration.
    async fn remove_from_federation_inner(&self, gateway_keypair: Keypair) -> anyhow::Result<()> {
        let gateway_id = gateway_keypair.public_key();
        let challenges = self
            .module_api
            .get_remove_gateway_challenge(gateway_id)
            .await;

        let fed_public_key = self.cfg.threshold_pub_key;
        let signatures = challenges
            .into_iter()
            .filter_map(|(peer_id, challenge)| {
                let msg = create_gateway_remove_message(fed_public_key, peer_id, challenge?);
                let signature = gateway_keypair.sign_schnorr(msg);
                Some((peer_id, signature))
            })
            .collect::<BTreeMap<_, _>>();

        let remove_gateway_request = RemoveGatewayRequest {
            gateway_id,
            signatures,
        };

        self.module_api.remove_gateway(remove_gateway_request).await;

        Ok(())
    }

    /// Attempt fulfill HTLC by buying preimage from the federation
    pub async fn gateway_handle_intercepted_htlc(&self, htlc: Htlc) -> anyhow::Result<OperationId> {
        debug!("Handling intercepted HTLC {htlc:?}");
        let (operation_id, amount, client_output, client_output_sm, contract_id) = self
            .create_funding_incoming_contract_output_from_htlc(htlc.clone())
            .await?;

        let output = ClientOutput {
            output: LightningOutput::V0(client_output.output),
            amounts: Amounts::new_bitcoin(amount),
        };

        let tx = TransactionBuilder::new().with_outputs(self.client_ctx.make_client_outputs(
            ClientOutputBundle::new(vec![output], vec![client_output_sm]),
        ));
        let operation_meta_gen = |_: OutPointRange| GatewayMeta::Receive;
        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;
        debug!(?operation_id, "Submitted transaction for HTLC {htlc:?}");
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        self.client_ctx
            .log_event(
                &mut dbtx,
                IncomingPaymentStarted {
                    contract_id,
                    payment_hash: htlc.payment_hash,
                    invoice_amount: htlc.outgoing_amount_msat,
                    contract_amount: amount,
                    operation_id,
                },
            )
            .await;
        dbtx.commit_tx().await;
        Ok(operation_id)
    }

    /// Attempt buying preimage from this federation in order to fulfill a pay
    /// request in another federation served by this gateway. In direct swap
    /// scenario, the gateway DOES NOT send payment over the lightning network
    pub async fn gateway_handle_direct_swap(
        &self,
        swap_params: SwapParameters,
    ) -> anyhow::Result<OperationId> {
        debug!("Handling direct swap {swap_params:?}");
        let (operation_id, client_output, client_output_sm) = self
            .create_funding_incoming_contract_output_from_swap(swap_params.clone())
            .await?;

        let output = ClientOutput {
            output: LightningOutput::V0(client_output.output),
            amounts: client_output.amounts,
        };
        let tx = TransactionBuilder::new().with_outputs(self.client_ctx.make_client_outputs(
            ClientOutputBundle::new(vec![output], vec![client_output_sm]),
        ));
        let operation_meta_gen = |_: OutPointRange| GatewayMeta::Receive;
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

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {

                yield GatewayExtReceiveStates::Funding;

                let state = loop {
                    debug!("Getting next ln receive state for {}", operation_id.fmt_short());
                    if let Some(GatewayClientStateMachines::Receive(state)) = stream.next().await {
                        match state.state {
                            IncomingSmStates::Preimage(preimage) =>{
                                debug!(?operation_id, "Received preimage");
                                break GatewayExtReceiveStates::Preimage(preimage)
                            },
                            IncomingSmStates::RefundSubmitted { out_points, error } => {
                                debug!(?operation_id, "Refund submitted for {out_points:?} {error}");
                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(()) => {
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
                                debug!("Got state {other:?} while awaiting for output of {}", operation_id.fmt_short());
                            }
                        }
                    }
                };
                yield state;
            }
        }))
    }

    /// For the given `OperationId`, this function will wait until the Complete
    /// state machine has finished or failed.
    pub async fn await_completion(&self, operation_id: OperationId) {
        let mut stream = self.notifier.subscribe(operation_id).await;
        loop {
            match stream.next().await {
                Some(GatewayClientStateMachines::Complete(state)) => match state.state {
                    GatewayCompleteStates::HtlcFinished => {
                        info!(%state, "LNv1 completion state machine finished");
                        return;
                    }
                    GatewayCompleteStates::Failure => {
                        error!(%state, "LNv1 completion state machine failed");
                        return;
                    }
                    _ => {
                        info!(%state, "Waiting for LNv1 completion state machine");
                        continue;
                    }
                },
                Some(GatewayClientStateMachines::Receive(state)) => {
                    info!(%state, "Waiting for LNv1 completion state machine");
                    continue;
                }
                Some(state) => {
                    warn!(%state, "Operation is not an LNv1 completion state machine");
                    return;
                }
                None => return,
            }
        }
    }

    /// Pay lightning invoice on behalf of federation user
    pub async fn gateway_pay_bolt11_invoice(
        &self,
        pay_invoice_payload: PayInvoicePayload,
    ) -> anyhow::Result<OperationId> {
        let payload = pay_invoice_payload.clone();
        self.lightning_manager
            .verify_pruned_invoice(pay_invoice_payload.payment_data)
            .await?;

        self.client_ctx.module_db()
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let operation_id = OperationId(payload.contract_id.to_byte_array());

                        self.client_ctx.log_event(dbtx, OutgoingPaymentStarted {
                            contract_id: payload.contract_id,
                            invoice_amount: payload.payment_data.amount().expect("LNv1 invoices should have an amount"),
                            operation_id,
                        }).await;

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

                            match self.client_ctx.add_state_machines_dbtx(dbtx, dyn_states).await {
                                Ok(()) => {
                                    self.client_ctx
                                        .add_operation_log_entry_dbtx(
                                            dbtx,
                                            operation_id,
                                            KIND.as_str(),
                                            GatewayMeta::Pay,
                                        )
                                        .await;
                                }
                                Err(AddStateMachinesError::StateAlreadyExists) => {
                                    info!("State machine for operation {} already exists, will not add a new one", operation_id.fmt_short());
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

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                yield GatewayExtPayStates::Created;

                loop {
                    debug!("Getting next ln pay state for {}", operation_id.fmt_short());
                    match stream.next().await { Some(GatewayClientStateMachines::Pay(state)) => {
                        match state.state {
                            GatewayPayStates::Preimage(out_points, preimage) => {
                                yield GatewayExtPayStates::Preimage{ preimage: preimage.clone() };

                                match client_ctx.await_primary_module_outputs(operation_id, out_points.clone()).await {
                                    Ok(()) => {
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
                                        yield GatewayExtPayStates::Fail { error, error_message: format!("Refund transaction {txid} was not accepted by the federation. OperationId: {} Error: {e:?}", operation_id.fmt_short()) };
                                    }
                                }
                            }
                            GatewayPayStates::OfferDoesNotExist(contract_id) => {
                                warn!("Yielding OfferDoesNotExist state for {} and contract {contract_id}", operation_id.fmt_short());
                                yield GatewayExtPayStates::OfferDoesNotExist { contract_id };
                            }
                            GatewayPayStates::Failed{ error, error_message } => {
                                warn!("Yielding Fail state for {} due to {error:?} {error_message:?}", operation_id.fmt_short());
                                yield GatewayExtPayStates::Fail{ error, error_message };
                            },
                            GatewayPayStates::PayInvoice(_) => {
                                debug!("Got initial state PayInvoice while awaiting for output of {}", operation_id.fmt_short());
                            }
                            other => {
                                info!("Got state {other:?} while awaiting for output of {}", operation_id.fmt_short());
                            }
                        }
                    } _ => {
                        warn!("Got None while getting next ln pay state for {}", operation_id.fmt_short());
                    }}
                }
            }
        }))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachines {
    Pay(GatewayPayStateMachine),
    Receive(IncomingStateMachine),
    Complete(GatewayCompleteStateMachine),
}

impl fmt::Display for GatewayClientStateMachines {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayClientStateMachines::Pay(pay) => {
                write!(f, "{pay}")
            }
            GatewayClientStateMachines::Receive(receive) => {
                write!(f, "{receive}")
            }
            GatewayClientStateMachines::Complete(complete) => {
                write!(f, "{complete}")
            }
        }
    }
}

impl IntoDynInstance for GatewayClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachines {
    type ModuleContext = GatewayClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
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

#[derive(Debug, Clone, Eq, PartialEq)]
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
    pub short_channel_id: Option<u64>,
    /// The id of the incoming channel
    pub incoming_chan_id: u64,
    /// The index of the incoming htlc in the incoming channel
    pub htlc_id: u64,
}

impl TryFrom<InterceptPaymentRequest> for Htlc {
    type Error = anyhow::Error;

    fn try_from(s: InterceptPaymentRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_hash: s.payment_hash,
            incoming_amount_msat: Amount::from_msats(s.amount_msat),
            outgoing_amount_msat: Amount::from_msats(s.amount_msat),
            incoming_expiry: s.expiry,
            short_channel_id: s.short_channel_id,
            incoming_chan_id: s.incoming_chan_id,
            htlc_id: s.htlc_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SwapParameters {
    pub payment_hash: sha256::Hash,
    pub amount_msat: Amount,
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

/// An interface between module implementation and the general `Gateway`
///
/// To abstract away and decouple the core gateway from the modules, the
/// interface between them is expressed as a trait. The gateway handles
/// operations that require Lightning node access or database access.
#[async_trait]
pub trait IGatewayClientV1: Debug + Send + Sync {
    /// Verifies that the supplied `preimage_auth` is the same as the
    /// `preimage_auth` that initiated the payment.
    ///
    /// If it is not, then this will return an error because this client is not
    /// authorized to receive the preimage.
    async fn verify_preimage_authentication(
        &self,
        payment_hash: sha256::Hash,
        preimage_auth: sha256::Hash,
        contract: OutgoingContractAccount,
    ) -> Result<(), OutgoingPaymentError>;

    /// Verify that the lightning node supports private payments if a pruned
    /// invoice is supplied.
    async fn verify_pruned_invoice(&self, payment_data: PaymentData) -> anyhow::Result<()>;

    /// Retrieves the federation's routing fees from the federation's config.
    async fn get_routing_fees(&self, federation_id: FederationId) -> Option<RoutingFees>;

    /// Retrieve a client given a federation ID, used for swapping ecash between
    /// federations.
    async fn get_client(&self, federation_id: &FederationId) -> Option<Spanned<ClientHandleArc>>;

    // Retrieve a client given an invoice.
    //
    // Checks if the invoice route hint last hop has source node id matching this
    // gateways node pubkey and if the short channel id matches one assigned by
    // this gateway to a connected federation. In this case, the gateway can
    // avoid paying the invoice over the lightning network and instead perform a
    // direct swap between the two federations.
    async fn get_client_for_invoice(
        &self,
        payment_data: PaymentData,
    ) -> Option<Spanned<ClientHandleArc>>;

    /// Pay a Lightning invoice using the gateway's lightning node.
    async fn pay(
        &self,
        payment_data: PaymentData,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError>;

    /// Use the gateway's lightning node to send a complete HTLC response.
    async fn complete_htlc(
        &self,
        htlc_response: InterceptPaymentResponse,
    ) -> Result<(), LightningRpcError>;

    /// Check if the gateway satisfy the LNv1 payment by funding an LNv2
    /// `IncomingContract`
    async fn is_lnv2_direct_swap(
        &self,
        payment_hash: sha256::Hash,
        amount: Amount,
    ) -> anyhow::Result<
        Option<(
            fedimint_lnv2_common::contracts::IncomingContract,
            ClientHandleArc,
        )>,
    >;
}
