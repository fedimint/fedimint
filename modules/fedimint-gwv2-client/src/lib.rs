mod api;
mod complete_sm;
pub mod events;
mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{anyhow, ensure};
use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::Message;
use events::{IncomingPaymentStarted, OutgoingPaymentStarted};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::ClientHandleArc;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule, OutPointRange};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::time::now;
use fedimint_core::util::Spanned;
use fedimint_core::{Amount, PeerId, apply, async_trait_maybe_send, secp256k1};
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::SendPaymentPayload;
use fedimint_lnv2_common::{
    LightningCommonInit, LightningInvoice, LightningModuleTypes, LightningOutput, LightningOutputV0,
};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use receive_sm::{ReceiveSMState, ReceiveStateMachine};
use secp256k1::schnorr::Signature;
use send_sm::{SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare};
use tracing::{info, warn};

use crate::api::GatewayFederationApi;
pub use crate::complete_sm::IncomingCircuitKey;
use crate::complete_sm::{
    CircuitCompleteSMCommon, CircuitCompleteStateMachine, CompleteSMState, CompleteStateMachine,
};
use crate::receive_sm::ReceiveSMCommon;
use crate::send_sm::SendSMCommon;

/// LNv2 CLTV Delta in blocks
pub const EXPIRATION_DELTA_MINIMUM_V2: u64 = 144;

fn incoming_circuit_operation_id(
    receive_operation_id: OperationId,
    circuit: IncomingCircuitKey,
) -> OperationId {
    OperationId::from_encodable(&(
        "gateway-lnv2-incoming-circuit",
        receive_operation_id,
        circuit,
    ))
}

fn is_legacy_completion_for_circuit(
    state: &GatewayClientStateMachinesV2,
    circuit: IncomingCircuitKey,
) -> bool {
    let IncomingCircuitKey {
        incoming_chan_id,
        htlc_id,
    } = circuit;
    matches!(
        state,
        GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
            common,
            ..
        }) if common.incoming_chan_id == incoming_chan_id && common.htlc_id == htlc_id
    )
}

fn legacy_completion_in_states(
    active: &[GatewayClientStateMachinesV2],
    inactive: &[GatewayClientStateMachinesV2],
    circuit: IncomingCircuitKey,
) -> bool {
    active
        .iter()
        .chain(inactive)
        .any(|state| is_legacy_completion_for_circuit(state, circuit))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum IncomingRelayPlan {
    Replay,
    AddCompletion,
    CreateReceiveAndCompletion,
}

fn incoming_relay_plan(
    receive_exists: bool,
    completion_exists: bool,
    legacy_completion_exists: bool,
) -> IncomingRelayPlan {
    if completion_exists || legacy_completion_exists {
        IncomingRelayPlan::Replay
    } else if receive_exists {
        IncomingRelayPlan::AddCompletion
    } else {
        IncomingRelayPlan::CreateReceiveAndCompletion
    }
}

fn operation_creation_failed_permanently(
    creation_failed: bool,
    operation_exists_after_failure: bool,
) -> bool {
    creation_failed && !operation_exists_after_failure
}

/// Identifies the role of an LNv2 gateway operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GatewayOperationMetaV2 {
    /// Metadata written before operation roles were distinguished.
    Legacy(()),
    /// Metadata written for a role-specific operation.
    Role {
        /// Role used when recovering active operations.
        role: GatewayOperationRoleV2,
    },
}

/// Role of an LNv2 gateway operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOperationRoleV2 {
    /// An outgoing payment operation.
    Send,
    /// A federation receive operation.
    Receive,
    /// An incoming Lightning circuit completion operation.
    CircuitCompletion,
}

impl GatewayOperationMetaV2 {
    /// Constructs metadata for `role`.
    pub fn role(role: GatewayOperationRoleV2) -> Self {
        Self::Role { role }
    }

    /// Returns whether shutdown must await Lightning circuit completion.
    pub fn waits_for_completion(&self) -> bool {
        matches!(
            self,
            Self::Legacy(())
                | Self::Role {
                    role: GatewayOperationRoleV2::CircuitCompletion
                }
        )
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientInitV2 {
    pub gateway: Arc<dyn IGatewayClientV2>,
}

impl ModuleInit for GatewayClientInitV2 {
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
impl ClientModuleInit for GatewayClientInitV2 {
    type Module = GatewayClientModuleV2;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(GatewayClientModuleV2 {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            module_api: args.module_api().clone(),
            keypair: args
                .module_root_secret()
                .clone()
                .to_secp_key(fedimint_core::secp256k1::SECP256K1),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientModuleV2 {
    pub federation_id: FederationId,
    pub cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesV2>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: Keypair,
    pub gateway: Arc<dyn IGatewayClientV2>,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextV2 {
    pub module: GatewayClientModuleV2,
    pub decoder: Decoder,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway: Arc<dyn IGatewayClientV2>,
}

impl Context for GatewayClientContextV2 {
    const KIND: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
}

impl ClientModule for GatewayClientModuleV2 {
    type Init = GatewayClientInitV2;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContextV2;
    type States = GatewayClientStateMachinesV2;

    fn context(&self) -> Self::ModuleStateMachineContext {
        GatewayClientContextV2 {
            module: self.clone(),
            decoder: self.decoder(),
            tpe_agg_pk: self.cfg.tpe_agg_pk,
            tpe_pks: self.cfg.tpe_pks.clone(),
            gateway: self.gateway.clone(),
        }
    }
    fn input_fee(
        &self,
        amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::new_bitcoin(
            self.cfg.fee_consensus.fee(amount.expect_only_bitcoin()),
        ))
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        let amount = match output.ensure_v0_ref().ok()? {
            LightningOutputV0::Outgoing(contract) => contract.amount,
            LightningOutputV0::Incoming(contract) => contract.commitment.amount,
        };

        Some(Amounts::new_bitcoin(self.cfg.fee_consensus.fee(amount)))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesV2 {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
    /// Legacy completion state retained to decode and resume combined receive
    /// operations created by older clients.
    Complete(CompleteStateMachine),
    /// Completes one incoming circuit independently of other circuits carrying
    /// the same payment hash and amount.
    CircuitComplete(CircuitCompleteStateMachine),
}

impl fmt::Display for GatewayClientStateMachinesV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayClientStateMachinesV2::Send(send) => {
                write!(f, "{send}")
            }
            GatewayClientStateMachinesV2::Receive(receive) => {
                write!(f, "{receive}")
            }
            GatewayClientStateMachinesV2::Complete(complete) => {
                write!(f, "{complete}")
            }
            GatewayClientStateMachinesV2::CircuitComplete(complete) => {
                write!(f, "{complete}")
            }
        }
    }
}

impl IntoDynInstance for GatewayClientStateMachinesV2 {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachinesV2 {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            GatewayClientStateMachinesV2::Send(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Send
                )
            }
            GatewayClientStateMachinesV2::Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Receive
                )
            }
            GatewayClientStateMachinesV2::Complete(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Complete
                )
            }
            GatewayClientStateMachinesV2::CircuitComplete(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::CircuitComplete
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            GatewayClientStateMachinesV2::Send(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Receive(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Complete(state) => state.operation_id(),
            GatewayClientStateMachinesV2::CircuitComplete(state) => state.operation_id(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub enum FinalReceiveState {
    Rejected,
    Success([u8; 32]),
    Refunded,
    Failure,
}

impl GatewayClientModuleV2 {
    pub async fn send_payment(
        &self,
        payload: SendPaymentPayload,
    ) -> anyhow::Result<Result<[u8; 32], Signature>> {
        let operation_start = now();

        // The operation id is equal to the contract id which also doubles as the
        // message signed by the gateway via the forfeit signature to forfeit
        // the gateways claim to a contract in case of cancellation. We only create a
        // forfeit signature after we have started the send state machine to
        // prevent replay attacks with a previously cancelled outgoing contract
        let operation_id = OperationId::from_encodable(&payload.contract.clone());

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(self.subscribe_send(operation_id).await);
        }

        // Since the following four checks may only fail due to client side
        // programming error we do not have to enable cancellation and can check
        // them before we start the state machine.
        ensure!(
            payload.contract.claim_pk == self.keypair.public_key(),
            "The outgoing contract is keyed to another gateway"
        );

        // This prevents DOS attacks where an attacker submits a different invoice.
        ensure!(
            secp256k1::SECP256K1
                .verify_schnorr(
                    &payload.auth,
                    &Message::from_digest(
                        *payload.invoice.consensus_hash::<sha256::Hash>().as_ref()
                    ),
                    &payload.contract.refund_pk.x_only_public_key().0,
                )
                .is_ok(),
            "Invalid auth signature for the invoice data"
        );

        // We need to check that the contract has been confirmed by the federation
        // before we start the state machine to prevent DOS attacks.
        let (contract_id, expiration) = self
            .module_api
            .outgoing_contract_expiration(payload.outpoint)
            .await
            .map_err(|_| anyhow!("The gateway can not reach the federation"))?
            .ok_or(anyhow!("The outgoing contract has not yet been confirmed"))?;

        ensure!(
            contract_id == payload.contract.contract_id(),
            "Contract Id returned by the federation does not match contract in request"
        );

        let (payment_hash, amount) = match &payload.invoice {
            LightningInvoice::Bolt11(invoice) => (
                invoice.payment_hash(),
                invoice
                    .amount_milli_satoshis()
                    .ok_or(anyhow!("Invoice is missing amount"))?,
            ),
        };

        ensure!(
            PaymentImage::Hash(*payment_hash) == payload.contract.payment_image,
            "The invoices payment hash does not match the contracts payment hash"
        );

        let min_contract_amount = self
            .gateway
            .min_contract_amount(&payload.federation_id, amount)
            .await?;

        let send_sm = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common: SendSMCommon {
                operation_id,
                outpoint: payload.outpoint,
                contract: payload.contract.clone(),
                max_delay: expiration.saturating_sub(EXPIRATION_DELTA_MINIMUM_V2),
                min_contract_amount,
                invoice: payload.invoice,
                claim_keypair: self.keypair,
            },
            state: SendSMState::Sending,
        });

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        self.client_ctx
            .manual_operation_start_dbtx(
                &mut dbtx.to_ref_nc(),
                operation_id,
                LightningCommonInit::KIND.as_str(),
                GatewayOperationMetaV2::role(GatewayOperationRoleV2::Send),
                vec![self.client_ctx.make_dyn_state(send_sm)],
            )
            .await
            .ok();

        self.client_ctx
            .log_event(
                &mut dbtx,
                OutgoingPaymentStarted {
                    operation_start,
                    outgoing_contract: payload.contract.clone(),
                    min_contract_amount,
                    invoice_amount: Amount::from_msats(amount),
                    max_delay: expiration.saturating_sub(EXPIRATION_DELTA_MINIMUM_V2),
                },
            )
            .await;
        dbtx.commit_tx().await;

        Ok(self.subscribe_send(operation_id).await)
    }

    pub async fn subscribe_send(&self, operation_id: OperationId) -> Result<[u8; 32], Signature> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Send(state)) = stream.next().await {
                match state.state {
                    SendSMState::Sending => {}
                    SendSMState::Claiming(claiming) => {
                        // This increases latency by one ordering and may eventually be removed;
                        // however, at the current stage of lnv2 we prioritize the verification of
                        // correctness above minimum latency.
                        assert!(
                            self.client_ctx
                                .await_primary_module_outputs(operation_id, claiming.outpoints)
                                .await
                                .is_ok(),
                            "Gateway Module V2 failed to claim outgoing contract with preimage"
                        );

                        return Ok(claiming.preimage);
                    }
                    SendSMState::Cancelled(cancelled) => {
                        warn!("Outgoing lightning payment is cancelled {:?}", cancelled);

                        let signature = self
                            .keypair
                            .sign_schnorr(state.common.contract.forfeit_message());

                        assert!(state.common.contract.verify_forfeit_signature(&signature));

                        return Err(signature);
                    }
                }
            }
        }
    }

    async fn legacy_completion_exists(
        &self,
        operation_id: OperationId,
        circuit: IncomingCircuitKey,
    ) -> bool {
        let active = self
            .client_ctx
            .get_own_operation_active_states(operation_id)
            .await
            .into_iter()
            .map(|(state, _)| state)
            .collect::<Vec<_>>();
        let inactive = self
            .client_ctx
            .get_own_operation_inactive_states(operation_id)
            .await
            .into_iter()
            .map(|(state, _)| state)
            .collect::<Vec<_>>();

        legacy_completion_in_states(&active, &inactive, circuit)
    }

    pub async fn relay_incoming_htlc(
        &self,
        payment_hash: sha256::Hash,
        incoming_chan_id: u64,
        htlc_id: u64,
        contract: IncomingContract,
        amount_msat: u64,
    ) -> anyhow::Result<()> {
        let operation_start = now();
        let receive_operation_id = OperationId::from_encodable(&contract);
        let circuit = IncomingCircuitKey {
            incoming_chan_id,
            htlc_id,
        };
        let completion_operation_id = incoming_circuit_operation_id(receive_operation_id, circuit);
        let receive_exists = self.client_ctx.operation_exists(receive_operation_id).await;
        let completion_exists = self
            .client_ctx
            .operation_exists(completion_operation_id)
            .await;
        let legacy_completion_exists = self
            .legacy_completion_exists(receive_operation_id, circuit)
            .await;
        let plan = incoming_relay_plan(receive_exists, completion_exists, legacy_completion_exists);
        if plan == IncomingRelayPlan::Replay {
            return Ok(());
        }

        let commitment = contract.commitment.clone();
        if plan == IncomingRelayPlan::CreateReceiveAndCompletion {
            let refund_keypair = self.keypair;
            let client_output = ClientOutput::<LightningOutput> {
                output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
                amounts: Amounts::new_bitcoin(contract.commitment.amount),
            };
            let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
                state_machines: Arc::new(move |range: OutPointRange| {
                    assert_eq!(range.count(), 1);

                    vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                        common: ReceiveSMCommon {
                            operation_id: receive_operation_id,
                            contract: contract.clone(),
                            outpoint: range.into_iter().next().unwrap(),
                            refund_keypair,
                        },
                        state: ReceiveSMState::Funding,
                    })]
                }),
            };

            let client_output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
                vec![client_output],
                vec![client_output_sm],
            ));
            let transaction = TransactionBuilder::new().with_outputs(client_output);

            let creation_result = self
                .client_ctx
                .finalize_and_submit_transaction(
                    receive_operation_id,
                    LightningCommonInit::KIND.as_str(),
                    |_| GatewayOperationMetaV2::role(GatewayOperationRoleV2::Receive),
                    transaction,
                )
                .await;
            if let Err(error) = creation_result {
                let operation_exists = self.client_ctx.operation_exists(receive_operation_id).await;
                if operation_creation_failed_permanently(true, operation_exists) {
                    return Err(error);
                }
            } else {
                let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
                self.client_ctx
                    .log_event(
                        &mut dbtx,
                        IncomingPaymentStarted {
                            operation_start,
                            incoming_contract_commitment: commitment,
                            invoice_amount: Amount::from_msats(amount_msat),
                        },
                    )
                    .await;
                dbtx.commit_tx().await;
            }
        }

        let completion =
            GatewayClientStateMachinesV2::CircuitComplete(CircuitCompleteStateMachine {
                common: CircuitCompleteSMCommon {
                    operation_id: completion_operation_id,
                    receive_operation_id,
                    payment_hash,
                    circuit,
                },
                state: CompleteSMState::Pending,
            });
        let creation_result = self
            .client_ctx
            .manual_operation_start(
                completion_operation_id,
                LightningCommonInit::KIND.as_str(),
                GatewayOperationMetaV2::role(GatewayOperationRoleV2::CircuitCompletion),
                vec![self.client_ctx.make_dyn_state(completion)],
            )
            .await;
        if let Err(error) = creation_result {
            let operation_exists = self
                .client_ctx
                .operation_exists(completion_operation_id)
                .await;
            if operation_creation_failed_permanently(true, operation_exists) {
                return Err(error);
            }
        }

        Ok(())
    }

    pub async fn relay_direct_swap(
        &self,
        contract: IncomingContract,
        amount_msat: u64,
    ) -> anyhow::Result<FinalReceiveState> {
        let operation_start = now();

        let operation_id = OperationId::from_encodable(&contract);

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(self.await_receive(operation_id).await);
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
            amounts: Amounts::new_bitcoin(contract.commitment.amount),
        };
        let commitment = contract.commitment.clone();
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |range| {
                assert_eq!(range.count(), 1);

                vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        contract: contract.clone(),
                        outpoint: range.into_iter().next().unwrap(),
                        refund_keypair,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        let transaction = TransactionBuilder::new().with_outputs(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |_| GatewayOperationMetaV2::role(GatewayOperationRoleV2::Receive),
                transaction,
            )
            .await?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        self.client_ctx
            .log_event(
                &mut dbtx,
                IncomingPaymentStarted {
                    operation_start,
                    incoming_contract_commitment: commitment,
                    invoice_amount: Amount::from_msats(amount_msat),
                },
            )
            .await;
        dbtx.commit_tx().await;

        Ok(self.await_receive(operation_id).await)
    }

    pub async fn await_receive(&self, operation_id: OperationId) -> FinalReceiveState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Receive(state)) = stream.next().await {
                match state.state {
                    ReceiveSMState::Funding => {}
                    ReceiveSMState::Rejected(..) => return FinalReceiveState::Rejected,
                    ReceiveSMState::Success(preimage) => {
                        return FinalReceiveState::Success(preimage);
                    }
                    ReceiveSMState::Refunding(out_points) => {
                        if self
                            .client_ctx
                            .await_primary_module_outputs(operation_id, out_points)
                            .await
                            .is_err()
                        {
                            return FinalReceiveState::Failure;
                        }

                        return FinalReceiveState::Refunded;
                    }
                    ReceiveSMState::Failure => return FinalReceiveState::Failure,
                }
            }
        }
    }

    /// Waits for a legacy combined receive operation or a circuit-completion
    /// operation to finish.
    ///
    /// `operation_id` must identify either a legacy operation containing
    /// [`GatewayClientStateMachinesV2::Complete`] or a role-specific operation
    /// containing [`GatewayClientStateMachinesV2::CircuitComplete`]. Both
    /// successful completion and a durable permanent outcome conflict terminate
    /// the wait.
    pub async fn await_completion(&self, operation_id: OperationId) {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            match stream.next().await {
                Some(GatewayClientStateMachinesV2::Complete(state)) => {
                    if matches!(
                        state.state,
                        CompleteSMState::Completed | CompleteSMState::CompletionFailed(_)
                    ) {
                        info!(%state, "LNv2 completion state machine finished");
                        return;
                    }

                    info!(%state, "Waiting for LNv2 completion state machine");
                }
                Some(GatewayClientStateMachinesV2::Receive(state)) => {
                    info!(%state, "Waiting for LNv2 completion state machine");
                    continue;
                }
                Some(GatewayClientStateMachinesV2::CircuitComplete(state)) => {
                    if matches!(
                        state.state,
                        CompleteSMState::Completed | CompleteSMState::CompletionFailed(_)
                    ) {
                        info!(%state, "LNv2 circuit completion state machine finished");
                        return;
                    }

                    info!(%state, "Waiting for LNv2 circuit completion state machine");
                }
                Some(state) => {
                    warn!(%state, "Operation is not an LNv2 completion state machine");
                    return;
                }
                None => return,
            }
        }
    }
}

/// An interface between module implementation and the general `Gateway`
///
/// To abstract away and decouple the core gateway from the modules, the
/// interface between the is expressed as a trait. The core gateway handles
/// LNv2 operations that require access to the database or lightning node.
#[async_trait]
pub trait IGatewayClientV2: Debug + Send + Sync {
    /// Uses the gateway's Lightning node to complete a payment.
    ///
    /// Implementations must absorb and retry every transient node or
    /// connectivity failure. They return `Err` only when Lightning has reached
    /// a permanent state that makes the requested outcome impossible. The
    /// future may block while retrying and must remain cancellation-safe.
    /// Completion state machines persist any returned error as terminal
    /// `CompletionFailed`.
    async fn complete_htlc(
        &self,
        htlc_response: InterceptPaymentResponse,
    ) -> Result<(), LightningRpcError>;

    /// Determines if the payment can be completed using a direct swap to
    /// another federation.
    ///
    /// A direct swap is determined by checking the gateway's connected
    /// lightning node against the invoice's payee lightning node. If they
    /// are the same, then the gateway can use another client to complete
    /// the payment be swapping ecash instead of a payment over the
    /// Lightning network.
    async fn is_direct_swap(
        &self,
        invoice: &Bolt11Invoice,
    ) -> anyhow::Result<Option<(IncomingContract, ClientHandleArc)>>;

    /// Initiates a payment over the Lightning network.
    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<[u8; 32], LightningRpcError>;

    /// Computes the minimum contract amount necessary for making an outgoing
    /// payment.
    ///
    /// The minimum contract amount must contain transaction fees to cover the
    /// gateway's transaction fee and optionally additional fee to cover the
    /// gateway's Lightning fee if the payment goes over the Lightning
    /// network.
    async fn min_contract_amount(
        &self,
        federation_id: &FederationId,
        amount: u64,
    ) -> anyhow::Result<Amount>;

    /// Check if this invoice was created using LNv1 and if the gateway is
    /// connected to the target federation.
    async fn is_lnv1_invoice(&self, invoice: &Bolt11Invoice) -> Option<Spanned<ClientHandleArc>>;

    /// Perform a swap from an LNv2 `OutgoingContract` to an LNv1
    /// `IncomingContract`
    async fn relay_lnv1_swap(
        &self,
        client: &ClientHandleArc,
        invoice: &Bolt11Invoice,
    ) -> anyhow::Result<FinalReceiveState>;
}

#[cfg(test)]
mod tests;
