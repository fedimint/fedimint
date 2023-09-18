use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::util::key::KeyPair;
use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_ln_common::contracts::incoming::IncomingContractAccount;
use fedimint_ln_common::contracts::DecryptedPreimage;
use fedimint_ln_common::LightningInput;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::LnFederationApi;
use crate::{LightningClientContext, LightningClientStateMachines};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that waits on the receipt of a Lightning payment.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     SubmittedOffer -- await transaction rejection --> Canceled
///     SubmittedOffer -- await invoice confirmation --> ConfirmedInvoice
///     ConfirmedInvoice -- await contract creation + decryption  --> Funded
///     ConfirmedInvoice -- await offer timeout --> Canceled
///     Funded -- await claim tx acceptance --> Success
///     Funded -- await claim tx rejection --> Canceled
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningReceiveStates {
    SubmittedOffer(LightningReceiveSubmittedOffer),
    Canceled(LightningReceiveError),
    ConfirmedInvoice(LightningReceiveConfirmedInvoice),
    Funded(LightningReceiveFunded),
    Success(TransactionId),
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveStateMachine {
    pub operation_id: OperationId,
    pub state: LightningReceiveStates,
}

impl State for LightningReceiveStateMachine {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            LightningReceiveStates::SubmittedOffer(submitted_offer) => {
                submitted_offer.transitions(self.operation_id, global_context)
            }
            LightningReceiveStates::Canceled(_) => {
                vec![]
            }
            LightningReceiveStates::ConfirmedInvoice(confirmed_invoice) => {
                confirmed_invoice.transitions(global_context)
            }
            LightningReceiveStates::Funded(funded) => {
                funded.transitions(self.operation_id, global_context)
            }
            LightningReceiveStates::Success(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveSubmittedOffer {
    pub offer_txid: TransactionId,
    pub invoice: Bolt11Invoice,
    pub payment_keypair: KeyPair,
}

#[derive(Error, Clone, Debug, Serialize, Deserialize, Encodable, Decodable, Eq, PartialEq)]
pub enum LightningReceiveError {
    #[error("Offer transaction was rejected")]
    Rejected,
    #[error("Incoming Lightning invoice was not paid within the timeout")]
    Timeout,
    #[error("Claim transaction was rejected")]
    ClaimRejected,
    #[error("The decrypted preimage was invalid")]
    InvalidPreimage,
}

impl LightningReceiveSubmittedOffer {
    fn transitions(
        &self,
        operation_id: OperationId,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let global_context = global_context.clone();
        let txid = self.offer_txid;
        let invoice = self.invoice.clone();
        let payment_keypair = self.payment_keypair;
        vec![StateTransition::new(
            Self::await_invoice_confirmation(global_context, operation_id, txid),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_confirmed_invoice(
                    result,
                    old_state,
                    invoice.clone(),
                    payment_keypair,
                ))
            },
        )]
    }

    async fn await_invoice_confirmation(
        global_context: DynGlobalClientContext,
        operation_id: OperationId,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(operation_id, txid).await
    }

    async fn transition_confirmed_invoice(
        result: Result<(), String>,
        old_state: LightningReceiveStateMachine,
        invoice: Bolt11Invoice,
        keypair: KeyPair,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(_) => LightningReceiveStateMachine {
                operation_id: old_state.operation_id,
                state: LightningReceiveStates::ConfirmedInvoice(LightningReceiveConfirmedInvoice {
                    invoice,
                    keypair,
                }),
            },
            Err(_) => LightningReceiveStateMachine {
                operation_id: old_state.operation_id,
                state: LightningReceiveStates::Canceled(LightningReceiveError::Rejected),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveConfirmedInvoice {
    invoice: Bolt11Invoice,
    keypair: KeyPair,
}

impl LightningReceiveConfirmedInvoice {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let invoice = self.invoice.clone();
        let timeout = invoice.expiry_time();
        let keypair = self.keypair;
        let global_context = global_context.clone();
        vec![
            StateTransition::new(
                Self::await_incoming_contract_account(invoice, global_context.clone()),
                move |dbtx, contract, old_state| {
                    Box::pin(Self::transition_funded(
                        old_state,
                        keypair,
                        contract,
                        dbtx,
                        global_context.clone(),
                    ))
                },
            ),
            StateTransition::new(
                Self::await_payment_timeout(timeout),
                |_dbtx, (), old_state| Box::pin(Self::transition_timeout(old_state)),
            ),
        ]
    }

    async fn await_incoming_contract_account(
        invoice: Bolt11Invoice,
        global_context: DynGlobalClientContext,
    ) -> Result<IncomingContractAccount, LightningReceiveError> {
        // TODO: Get rid of polling
        loop {
            let contract_id = (*invoice.payment_hash()).into();
            let contract = global_context
                .module_api()
                .get_incoming_contract(contract_id)
                .await;

            if let Ok(contract) = contract {
                match contract.contract.decrypted_preimage {
                    DecryptedPreimage::Pending => {}
                    DecryptedPreimage::Some(_) => {
                        return Ok(contract);
                    }
                    DecryptedPreimage::Invalid => {
                        return Err(LightningReceiveError::InvalidPreimage);
                    }
                }
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn transition_funded(
        old_state: LightningReceiveStateMachine,
        keypair: KeyPair,
        result: Result<IncomingContractAccount, LightningReceiveError>,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(contract) => {
                let outpoint =
                    Self::claim_incoming_contract(dbtx, contract, keypair, global_context).await;
                LightningReceiveStateMachine {
                    operation_id: old_state.operation_id,
                    state: LightningReceiveStates::Funded(LightningReceiveFunded { outpoint }),
                }
            }
            Err(e) => LightningReceiveStateMachine {
                operation_id: old_state.operation_id,
                state: LightningReceiveStates::Canceled(e),
            },
        }
    }

    async fn claim_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        contract: IncomingContractAccount,
        keypair: KeyPair,
        global_context: DynGlobalClientContext,
    ) -> OutPoint {
        let input = contract.claim();
        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input,
            keys: vec![keypair],
            // The input of the refund tx is managed by this state machine, so no new state machines
            // need to be created
            state_machines: Arc::new(|_, _| vec![]),
        };

        let (txid, _) = global_context.claim_input(dbtx, client_input).await;
        OutPoint { txid, out_idx: 0 }
    }

    async fn await_payment_timeout(timeout: Duration) {
        // Add 10% of the invoice expiry_time as a buffer before we stop awaiting the
        // payment
        let timeout_buffer = timeout.as_secs_f64() * 0.1;
        let payment_timeout = timeout.add(Duration::from_secs_f64(timeout_buffer));
        sleep(payment_timeout).await
    }

    async fn transition_timeout(
        old_state: LightningReceiveStateMachine,
    ) -> LightningReceiveStateMachine {
        LightningReceiveStateMachine {
            operation_id: old_state.operation_id,
            state: LightningReceiveStates::Canceled(LightningReceiveError::Timeout),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveFunded {
    outpoint: OutPoint,
}

impl LightningReceiveFunded {
    fn transitions(
        &self,
        operation_id: OperationId,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let txid = self.outpoint.txid;
        vec![StateTransition::new(
            Self::await_claim_success(operation_id, global_context.clone(), txid),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_claim_success(result, old_state, txid))
            },
        )]
    }

    async fn await_claim_success(
        operation_id: OperationId,
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(operation_id, txid).await
    }

    async fn transition_claim_success(
        result: Result<(), String>,
        old_state: LightningReceiveStateMachine,
        txid: TransactionId,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(_) => {
                // Claim successful
                LightningReceiveStateMachine {
                    operation_id: old_state.operation_id,
                    state: LightningReceiveStates::Success(txid),
                }
            }
            Err(_) => {
                // Claim rejection
                LightningReceiveStateMachine {
                    operation_id: old_state.operation_id,
                    state: LightningReceiveStates::Canceled(LightningReceiveError::ClaimRejected),
                }
            }
        }
    }
}
