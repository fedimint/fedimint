use std::sync::Arc;

use bitcoin::util::key::KeyPair;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::OutPoint;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::{LightningClientContext, LightningInput, Witness};
use tpe::AggregateDecryptionKey;

use crate::api::LnFederationApi;
use crate::LightningClientStateMachines;

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
    pub claim_keypair: KeyPair,
    pub agg_decryption_key: AggregateDecryptionKey,
}

#[allow(clippy::large_enum_variant)]
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
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        match &self.state {
            ReceiveSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            old_state,
                            gc.clone(),
                            contract_confirmed,
                        ))
                    },
                )]
            }
            ReceiveSMState::Claiming(..) => {
                vec![]
            }
            ReceiveSMState::Expired => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl ReceiveStateMachine {
    async fn await_incoming_contract(
        contract: IncomingContract,
        global_context: DynGlobalClientContext,
    ) -> bool {
        global_context
            .module_api()
            .await_incoming_contract(&contract.contract_id(), contract.commitment.expiration)
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: ReceiveStateMachine,
        global_context: DynGlobalClientContext,
        contract_confirmed: bool,
    ) -> ReceiveStateMachine {
        if !contract_confirmed {
            return old_state.update(ReceiveSMState::Expired);
        }

        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input: LightningInput {
                amount: old_state.common.contract.commitment.amount,
                witness: Witness::Incoming(
                    old_state.common.contract.contract_id(),
                    old_state.common.agg_decryption_key,
                ),
            },
            keys: vec![old_state.common.claim_keypair],
            state_machines: Arc::new(|_, _| vec![]),
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;

        old_state.update(ReceiveSMState::Claiming(out_points))
    }
}
