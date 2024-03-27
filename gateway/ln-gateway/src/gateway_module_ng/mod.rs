mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::api::DynModuleApi;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, KeyPair, ModuleInstanceId, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, OutPoint, PeerId};
use fedimint_ln_common_ng::config::LightningClientConfig;
use fedimint_ln_common_ng::contracts::{IncomingContract, OutgoingContract};
use fedimint_ln_common_ng::{LightningCommonInit, LightningModuleTypes, LightningOutput};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use receive_sm::{ReceiveSMState, ReceiveStateMachine};
use secp256k1::schnorr::Signature;
use send_sm::{SendSMState, SendStateMachine, Sending};
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare};

use crate::Gateway;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayOperationMetaNG;

#[derive(Debug, Clone)]
pub struct GatewayClientInitNG {
    pub gateway: Gateway,
}

#[apply(async_trait_maybe_send!)]
impl ModuleInit for GatewayClientInitNG {
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
impl ClientModuleInit for GatewayClientInitNG {
    type Module = GatewayClientModuleNG;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(GatewayClientModuleNG {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            module_api: args.module_api().clone(),
            keypair: args
                .module_root_secret()
                .clone()
                .to_secp_key(secp256k1::SECP256K1),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug)]
pub struct GatewayClientModuleNG {
    pub federation_id: FederationId,
    pub cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesNG>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: KeyPair,
    pub gateway: Gateway,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextNG {
    pub decoder: Decoder,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway: Gateway,
}

impl Context for GatewayClientContextNG {}

impl ClientModule for GatewayClientModuleNG {
    type Init = GatewayClientInitNG;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContextNG;
    type States = GatewayClientStateMachinesNG;

    fn context(&self) -> Self::ModuleStateMachineContext {
        GatewayClientContextNG {
            decoder: self.decoder(),
            tpe_agg_pk: self.cfg.tpe_agg_pk,
            tpe_pks: self.cfg.tpe_pks.clone(),
            gateway: self.gateway.clone(),
        }
    }

    fn input_amount(
        &self,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.fee_consensus.contract_input,
        })
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        Some(TransactionItemAmount {
            amount: output.amount(),
            fee: self.cfg.fee_consensus.contract_output,
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesNG {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
}

impl IntoDynInstance for GatewayClientStateMachinesNG {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachinesNG {
    type ModuleContext = GatewayClientContextNG;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            GatewayClientStateMachinesNG::Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesNG::Receive
                )
            }
            GatewayClientStateMachinesNG::Send(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesNG::Send
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            GatewayClientStateMachinesNG::Receive(state) => state.operation_id(),
            GatewayClientStateMachinesNG::Send(state) => state.operation_id(),
        }
    }
}

impl GatewayClientModuleNG {
    pub async fn start_send_state_machine(
        &self,
        operation_id: OperationId,
        max_delay: u64,
        max_fee_msat: u64,
        invoice: Bolt11Invoice,
        contract: OutgoingContract,
    ) -> anyhow::Result<()> {
        let send_sm = GatewayClientStateMachinesNG::Send(SendStateMachine {
            operation_id,
            contract: contract.clone(),
            state: SendSMState::Sending(Sending {
                max_delay,
                max_fee_msat,
                invoice,
                claim_keypair: self.keypair,
            }),
        });

        self.client_ctx
            .manual_operation_start(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                GatewayOperationMetaNG,
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
            if let Some(GatewayClientStateMachinesNG::Send(state)) = stream.next().await {
                match state.state {
                    SendSMState::Sending(..) => {}
                    SendSMState::Claiming(preimage, ..) => return Ok(preimage),
                    SendSMState::Cancelled => {
                        return Err(self.keypair.sign_schnorr(contract.forfeit_message()))
                    }
                }
            }
        }
    }

    pub async fn start_receive_state_machine(
        &self,
        operation_id: OperationId,
        contract: IncomingContract,
    ) -> anyhow::Result<()> {
        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachinesNG> {
            output: LightningOutput::Incoming(contract.clone()),
            state_machines: Arc::new(move |txid, out_idx| {
                vec![GatewayClientStateMachinesNG::Receive(ReceiveStateMachine {
                    operation_id,
                    contract: contract.clone(),
                    out_point: OutPoint { txid, out_idx },
                    state: ReceiveSMState::Funding(refund_keypair),
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_output(client_output);
        let transaction = TransactionBuilder::new().with_output(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |_, _| GatewayOperationMetaNG,
                transaction,
            )
            .await?;

        Ok(())
    }

    pub async fn subscribe_receive(&self, operation_id: OperationId) -> Option<[u8; 32]> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesNG::Receive(state)) = stream.next().await {
                match state.state {
                    ReceiveSMState::Funding(..) => {}
                    ReceiveSMState::Rejected(..) => return None,
                    ReceiveSMState::Success(preimage) => return Some(preimage),
                    ReceiveSMState::Failure => return None,
                    ReceiveSMState::Refunding(..) => return None,
                }
            }
        }
    }
}
