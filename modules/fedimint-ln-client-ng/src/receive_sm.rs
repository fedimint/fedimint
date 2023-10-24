use std::sync::Arc;

use bitcoin::util::key::KeyPair;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::OutPoint;
use fedimint_ln_common_ng::api::LnFederationApi;
use fedimint_ln_common_ng::contracts::IncomingContract;
use fedimint_ln_common_ng::{LightningClientContext, LightningInput, Witness};
use secp256k1_zkp::PublicKey;
use tpe::AggregateDecryptionKey;

use crate::LightningClientStateMachines;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ReceiveStateMachine {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub state: ReceiveSMState,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ReceiveSMState {
    Pending(Pending),
    Claiming(Vec<OutPoint>),
    Expired,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Pending {
    pub claim_keypair: KeyPair,
    pub agg_decryption_key: AggregateDecryptionKey,
}

impl State for ReceiveStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        match &self.state {
            ReceiveSMState::Pending(..) => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.contract.clone(), gc.clone()),
                    move |dbtx, refund_pk, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            old_state,
                            gc.clone(),
                            refund_pk,
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
        self.operation_id
    }
}

impl ReceiveStateMachine {
    async fn await_incoming_contract(
        contract: IncomingContract,
        global_context: DynGlobalClientContext,
    ) -> Option<PublicKey> {
        global_context
            .module_api()
            .await_incoming_contract(&contract.contract_key(), contract.commitment.expiration)
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        old_state: ReceiveStateMachine,
        global_context: DynGlobalClientContext,
        refund_pk: Option<PublicKey>,
    ) -> ReceiveStateMachine {
        let pending = match old_state.state {
            ReceiveSMState::Pending(created) => created,
            _ => panic!("Invalid prior state"),
        };

        if refund_pk.is_none() {
            return ReceiveStateMachine {
                operation_id: old_state.operation_id,
                contract: old_state.contract,
                state: ReceiveSMState::Expired,
            };
        }

        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input: LightningInput {
                amount: old_state.contract.commitment.amount,
                witness: Witness::Incoming(
                    old_state.contract.contract_key(),
                    pending.agg_decryption_key,
                ),
            },
            keys: vec![pending.claim_keypair],
            state_machines: Arc::new(|_, _| vec![]),
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;

        ReceiveStateMachine {
            operation_id: old_state.operation_id,
            contract: old_state.contract,
            state: ReceiveSMState::Claiming(out_points),
        }
    }
}
