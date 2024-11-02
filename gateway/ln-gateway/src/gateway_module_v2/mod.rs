mod api;
mod complete_sm;
mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, ensure};
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::Message;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{apply, async_trait_maybe_send, secp256k1, Amount, OutPoint, PeerId};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::SendPaymentPayload;
use fedimint_lnv2_common::{
    LightningCommonInit, LightningInvoice, LightningModuleTypes, LightningOutput, LightningOutputV0,
};
use futures::StreamExt;
use receive_sm::{ReceiveSMState, ReceiveStateMachine};
use secp256k1::schnorr::Signature;
use send_sm::{SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare};
use tracing::{info, warn};

use crate::gateway_module_v2::api::GatewayFederationApi;
use crate::gateway_module_v2::complete_sm::{
    CompleteSMCommon, CompleteSMState, CompleteStateMachine,
};
use crate::gateway_module_v2::receive_sm::ReceiveSMCommon;
use crate::gateway_module_v2::send_sm::SendSMCommon;
use crate::{Gateway, EXPIRATION_DELTA_MINIMUM_V2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayOperationMetaV2;

#[derive(Debug, Clone)]
pub struct GatewayClientInitV2 {
    pub gateway: Arc<Gateway>,
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
    pub gateway: Arc<Gateway>,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextV2 {
    pub module: GatewayClientModuleV2,
    pub decoder: Decoder,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway: Arc<Gateway>,
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
        amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    fn output_fee(
        &self,
        _amount: Amount,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        let amount = match output.ensure_v0_ref().ok()? {
            LightningOutputV0::Outgoing(contract) => contract.amount,
            LightningOutputV0::Incoming(contract) => contract.commitment.amount,
        };

        Some(self.cfg.fee_consensus.fee(amount))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesV2 {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
    Complete(CompleteStateMachine),
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
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            GatewayClientStateMachinesV2::Send(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Receive(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Complete(state) => state.operation_id(),
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
        let max_delay = self
            .module_api
            .outgoing_contract_expiration(&payload.contract.contract_id())
            .await
            .map_err(|_| anyhow!("The gateway can not reach the federation"))?
            .ok_or(anyhow!("The outgoing contract has not yet been confirmed"))?
            .saturating_sub(EXPIRATION_DELTA_MINIMUM_V2);

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
            .routing_info_v2(&payload.federation_id)
            .await?
            .ok_or(anyhow!("Routing Info not available"))?
            .send_fee_minimum
            .add_to(amount);

        let send_sm = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common: SendSMCommon {
                operation_id,
                contract: payload.contract.clone(),
                max_delay,
                min_contract_amount,
                invoice: payload.invoice,
                claim_keypair: self.keypair,
            },
            state: SendSMState::Sending,
        });

        self.client_ctx
            .manual_operation_start(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                GatewayOperationMetaV2,
                vec![self.client_ctx.make_dyn_state(send_sm)],
            )
            .await
            .ok();

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

    pub async fn relay_incoming_htlc(
        &self,
        payment_hash: sha256::Hash,
        incoming_chan_id: u64,
        htlc_id: u64,
        contract: IncomingContract,
    ) -> anyhow::Result<()> {
        let operation_id = OperationId::from_encodable(&contract);

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(());
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
            amount: contract.commitment.amount,
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |txid, out_idxs: std::ops::RangeInclusive<u64>| {
                assert_eq!(out_idxs.clone().count(), 1);
                let out_idx = *out_idxs.start();
                vec![
                    GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                        common: ReceiveSMCommon {
                            operation_id,
                            contract: contract.clone(),
                            out_point: OutPoint { txid, out_idx },
                            refund_keypair,
                        },
                        state: ReceiveSMState::Funding,
                    }),
                    GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
                        common: CompleteSMCommon {
                            operation_id,
                            payment_hash,
                            incoming_chan_id,
                            htlc_id,
                        },
                        state: CompleteSMState::Pending,
                    }),
                ]
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
                |_, _| GatewayOperationMetaV2,
                transaction,
            )
            .await?;

        Ok(())
    }

    pub async fn relay_direct_swap(
        &self,
        contract: IncomingContract,
    ) -> anyhow::Result<FinalReceiveState> {
        let operation_id = OperationId::from_encodable(&contract);

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(self.await_receive(operation_id).await);
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
            amount: contract.commitment.amount,
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |txid, out_idxs| {
                assert_eq!(out_idxs.clone().count(), 1);
                let out_idx = *out_idxs.start();
                vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        contract: contract.clone(),
                        out_point: OutPoint { txid, out_idx },
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
                |_, _| GatewayOperationMetaV2,
                transaction,
            )
            .await?;

        Ok(self.await_receive(operation_id).await)
    }

    async fn await_receive(&self, operation_id: OperationId) -> FinalReceiveState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Receive(state)) = stream.next().await {
                match state.state {
                    ReceiveSMState::Funding => {}
                    ReceiveSMState::Rejected(..) => return FinalReceiveState::Rejected,
                    ReceiveSMState::Success(preimage) => {
                        return FinalReceiveState::Success(preimage)
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

    /// For the given `OperationId`, this function will wait until the Complete
    /// state machine has finished or failed.
    pub async fn await_completion(&self, operation_id: OperationId) {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            match stream.next().await {
                Some(GatewayClientStateMachinesV2::Complete(state)) => {
                    if state.state == CompleteSMState::Completed {
                        info!(%state, "LNv2 completion state machine finished");
                        return;
                    }

                    info!(%state, "Waiting for LNv2 completion state machine");
                }
                Some(GatewayClientStateMachinesV2::Receive(state)) => {
                    info!(%state, "Waiting for LNv2 completion state machine");
                    continue;
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
