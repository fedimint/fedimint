use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::OutPoint;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::Keypair;
use fedimint_lnv2_common::contracts::{IncomingContract, LightningContract};
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use tpe::AggregateDecryptionKey;
use tracing::instrument;

use crate::LightningClientContext;
use crate::api::LightningFederationApi;
use crate::db::OutpointContractKey;
use crate::events::ReceivePaymentEvent;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveStateMachine {
    pub common: ReceiveSMCommon,
    pub state: ReceiveSMState,
}

impl ReceiveStateMachine {
    pub fn update(&self, state: ReceiveSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveSMCommon {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub claim_keypair: Keypair,
    pub agg_decryption_key: AggregateDecryptionKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ReceiveSMState {
    Pending,
    Claiming(Vec<OutPoint>),
    Expired,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that waits on the receipt of a Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Pending -- incoming contract is confirmed --> Claiming
///     Pending -- decryption contract expires --> Expired
/// ```
impl State for ReceiveStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let ctx = context.clone();

        match &self.state {
            ReceiveSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            old_state,
                            ctx.clone(),
                            gc.clone(),
                            contract_confirmed,
                        ))
                    },
                )]
            }
            ReceiveSMState::Claiming(..) | ReceiveSMState::Expired => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl ReceiveStateMachine {
    #[instrument(target = LOG_CLIENT_MODULE_LNV2, skip(global_context))]
    async fn await_incoming_contract(
        contract: IncomingContract,
        global_context: DynGlobalClientContext,
    ) -> Option<OutPoint> {
        global_context
            .module_api()
            .await_incoming_contract(&contract.contract_id(), contract.commitment.expiration)
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: ReceiveStateMachine,
        context: LightningClientContext,
        global_context: DynGlobalClientContext,
        outpoint: Option<OutPoint>,
    ) -> ReceiveStateMachine {
        let Some(outpoint) = outpoint else {
            return old_state.update(ReceiveSMState::Expired);
        };

        // Store the contract for later amount lookup
        dbtx.module_tx()
            .insert_entry(
                &OutpointContractKey(outpoint),
                &LightningContract::Incoming(old_state.common.contract.clone()),
            )
            .await;

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Incoming(
                outpoint,
                old_state.common.agg_decryption_key,
            )),
            amounts: Amounts::new_bitcoin(old_state.common.contract.commitment.amount),
            keys: vec![old_state.common.claim_keypair],
        };

        let change_range = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed");

        // Log event when receive completes successfully
        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                ReceivePaymentEvent {
                    operation_id: old_state.common.operation_id,
                    amount: old_state.common.contract.commitment.amount,
                },
            )
            .await;

        old_state.update(ReceiveSMState::Claiming(change_range.into_iter().collect()))
    }
}
