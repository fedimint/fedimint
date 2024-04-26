mod complete_sm;
mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::bitcoin_migration::{
    bitcoin29_to_bitcoin30_schnorr_signature, bitcoin30_to_bitcoin29_keypair,
    bitcoin30_to_bitcoin29_message,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, PeerId};
use fedimint_lnv2_client::CreateInvoicePayload;
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_lnv2_common::{
    LightningCommonInit, LightningModuleTypes, LightningOutput, LightningOutputV0,
};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use receive_sm::{ReceiveSMState, ReceiveStateMachine};
use secp256k1::schnorr::Signature;
use secp256k1::KeyPair;
use send_sm::{SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare};
use tracing::warn;

use crate::gateway_module_v2::complete_sm::{
    CompleteSMCommon, CompleteSMState, CompleteStateMachine,
};
use crate::gateway_module_v2::receive_sm::ReceiveSMCommon;
use crate::gateway_module_v2::send_sm::SendSMCommon;
use crate::Gateway;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayOperationMetaV2;

#[derive(Debug, Clone)]
pub struct GatewayClientInitV2 {
    pub gateway: Gateway,
}

impl ModuleInit for GatewayClientInitV2 {
    type Common = LightningCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

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
            keypair: bitcoin30_to_bitcoin29_keypair(
                args.module_root_secret()
                    .clone()
                    .to_secp_key(secp256k1_zkp::SECP256K1),
            ),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug)]
pub struct GatewayClientModuleV2 {
    pub federation_id: FederationId,
    pub cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesV2>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: KeyPair,
    pub gateway: Gateway,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextV2 {
    pub decoder: Decoder,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesV2>,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway: Gateway,
}

impl Context for GatewayClientContextV2 {}

impl ClientModule for GatewayClientModuleV2 {
    type Init = GatewayClientInitV2;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContextV2;
    type States = GatewayClientStateMachinesV2;

    fn context(&self) -> Self::ModuleStateMachineContext {
        GatewayClientContextV2 {
            decoder: self.decoder(),
            notifier: self.notifier.clone(),
            tpe_agg_pk: self.cfg.tpe_agg_pk,
            tpe_pks: self.cfg.tpe_pks.clone(),
            gateway: self.gateway.clone(),
        }
    }

    fn input_fee(&self, _input: &<Self::Common as ModuleCommon>::Input) -> Option<Amount> {
        Some(self.cfg.fee_consensus.input)
    }

    fn output_fee(&self, _output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        Some(self.cfg.fee_consensus.output)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesV2 {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
    Complete(CompleteStateMachine),
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
            GatewayClientStateMachinesV2::Receive(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Send(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Complete(state) => state.operation_id(),
        }
    }
}

impl GatewayClientModuleV2 {
    pub async fn start_send_state_machine(
        &self,
        operation_id: OperationId,
        max_delay: u64,
        min_contract_amount: Amount,
        invoice: Bolt11Invoice,
        contract: OutgoingContract,
    ) -> anyhow::Result<()> {
        let send_sm = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common: SendSMCommon {
                operation_id,
                contract: contract.clone(),
                max_delay,
                min_contract_amount,
                invoice,
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
    }

    pub async fn subscribe_send(
        &self,
        operation_id: OperationId,
        contract: OutgoingContract,
    ) -> Result<[u8; 32], Signature> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Send(state)) = stream.next().await {
                match state.state {
                    SendSMState::Sending => {}
                    SendSMState::Claiming(claiming) => return Ok(claiming.preimage),
                    SendSMState::Cancelled(cancelled) => {
                        warn!("Outgoing lightning payment is cancelled {:?}", cancelled);

                        let signature = self.keypair.sign_schnorr(bitcoin30_to_bitcoin29_message(
                            contract.forfeit_message(),
                        ));

                        assert!(contract.verify_forfeit_signature(
                            &bitcoin29_to_bitcoin30_schnorr_signature(signature)
                        ));

                        return Err(signature);
                    }
                }
            }
        }
    }

    pub async fn relay_incoming_htlc(
        &self,
        incoming_chan_id: u64,
        htlc_id: u64,
        payload: CreateInvoicePayload,
    ) -> anyhow::Result<()> {
        let operation_id = OperationId::from_encodable(payload.clone());

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(());
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachinesV2> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(payload.contract.clone())),
            amount: payload.contract.commitment.amount,
            state_machines: Arc::new(move |txid, out_idx| {
                vec![
                    GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                        common: ReceiveSMCommon {
                            operation_id,
                            contract: payload.contract.clone(),
                            out_point: OutPoint { txid, out_idx },
                            refund_keypair,
                        },
                        state: ReceiveSMState::Funding,
                    }),
                    GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
                        common: CompleteSMCommon {
                            operation_id,
                            incoming_chan_id,
                            htlc_id,
                        },
                        state: CompleteSMState::Pending,
                    }),
                ]
            }),
        };

        let client_output = self.client_ctx.make_client_output(client_output);
        let transaction = TransactionBuilder::new().with_output(client_output);

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
        payload: CreateInvoicePayload,
    ) -> anyhow::Result<[u8; 32]> {
        let operation_id = OperationId::from_encodable(payload.clone());

        if self.client_ctx.operation_exists(operation_id).await {
            return self
                .subscribe_receive(operation_id)
                .await
                .ok_or(anyhow!("The internal send failed"));
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachinesV2> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(payload.contract.clone())),
            amount: payload.contract.commitment.amount,
            state_machines: Arc::new(move |txid, out_idx| {
                vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        contract: payload.contract.clone(),
                        out_point: OutPoint { txid, out_idx },
                        refund_keypair,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_output(client_output);
        let transaction = TransactionBuilder::new().with_output(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |_, _| GatewayOperationMetaV2,
                transaction,
            )
            .await?;

        self.subscribe_receive(operation_id)
            .await
            .ok_or(anyhow!("The internal send failed"))
    }

    async fn subscribe_receive(&self, operation_id: OperationId) -> Option<[u8; 32]> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Receive(state)) = stream.next().await {
                match state.state {
                    ReceiveSMState::Funding => {}
                    ReceiveSMState::Rejected(..) => return None,
                    ReceiveSMState::Success(preimage) => return Some(preimage),
                    ReceiveSMState::Failure => return None,
                    ReceiveSMState::Refunding(..) => return None,
                }
            }
        }
    }
}
