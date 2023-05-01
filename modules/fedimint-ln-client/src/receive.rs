use std::sync::Arc;
use std::time::Duration;

use bitcoin::util::key::KeyPair;
use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::Decoder;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_common::contracts::incoming::IncomingContract;
use fedimint_ln_common::contracts::{ContractId, IdentifiableContract};
use fedimint_ln_common::{LightningInput, LightningOutputOutcome};
use lightning_invoice::Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
///     ConfirmedInvoice -- await claim transaction acceptance  --> Funded
///     ConfirmedInvoice -- await claim transaction timeout --> Canceled
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
pub struct LightningReceiveCommon {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveStateMachine {
    pub common: LightningReceiveCommon,
    pub state: LightningReceiveStates,
}

impl State for LightningReceiveStateMachine {
    type ModuleContext = LightningClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            LightningReceiveStates::SubmittedOffer(submitted_offer) => {
                submitted_offer.transitions(&self.common, global_context, context)
            }
            LightningReceiveStates::Canceled(_) => {
                vec![]
            }
            LightningReceiveStates::ConfirmedInvoice(confirmed_invoice) => {
                confirmed_invoice.transitions(global_context)
            }
            LightningReceiveStates::Funded(funded) => {
                funded.transitions(self.common.clone(), global_context)
            }
            LightningReceiveStates::Success(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveSubmittedOffer {
    pub offer_txid: TransactionId,
    pub invoice: Invoice,
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
}

impl LightningReceiveSubmittedOffer {
    fn transitions(
        &self,
        common: &LightningReceiveCommon,
        global_context: &DynGlobalClientContext,
        context: &LightningClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let global_context = global_context.clone();
        let rejected_context = global_context.clone();
        let txid = self.offer_txid;
        let invoice = self.invoice.clone();
        let payment_keypair = self.payment_keypair;
        let rejected_common = common.clone();
        vec![
            StateTransition::new(
                Self::await_invoice_confirmation(
                    global_context,
                    context.ln_decoder.clone(),
                    txid,
                    invoice,
                    payment_keypair,
                ),
                move |_dbtx, result, old_state| {
                    Box::pin(Self::transition_confirmed_invoice(result, old_state))
                },
            ),
            StateTransition::new(
                Self::await_invoice_rejection(rejected_context, rejected_common, txid),
                |_dbtx, (), old_state| Box::pin(Self::transition_invoice_rejected(old_state)),
            ),
        ]
    }

    async fn await_invoice_confirmation(
        global_context: DynGlobalClientContext,
        module_decoder: Decoder,
        txid: TransactionId,
        invoice: Invoice,
        payment_keypair: KeyPair,
    ) -> Result<ConfirmedInvoice, LightningReceiveError> {
        let outpoint = OutPoint { txid, out_idx: 0 };
        let timeout = Duration::from_secs(15);
        global_context
            .api()
            .await_output_outcome::<LightningOutputOutcome>(outpoint, timeout, &module_decoder)
            .await
            .map_err(|_| LightningReceiveError::Rejected)?;
        let confirmed_invoice = ConfirmedInvoice {
            invoice,
            keypair: payment_keypair,
        };

        Ok(confirmed_invoice)
    }

    async fn await_invoice_rejection(
        global_context: DynGlobalClientContext,
        common: LightningReceiveCommon,
        txid: TransactionId,
    ) {
        global_context
            .await_tx_rejected(common.operation_id, txid)
            .await;
    }

    async fn transition_confirmed_invoice(
        result: Result<ConfirmedInvoice, LightningReceiveError>,
        old_state: LightningReceiveStateMachine,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(confirmed_invoice) => LightningReceiveStateMachine {
                common: old_state.common,
                state: LightningReceiveStates::ConfirmedInvoice(LightningReceiveConfirmedInvoice {
                    confirmed_invoice,
                }),
            },
            Err(e) => LightningReceiveStateMachine {
                common: old_state.common,
                state: LightningReceiveStates::Canceled(e),
            },
        }
    }

    async fn transition_invoice_rejected(
        old_state: LightningReceiveStateMachine,
    ) -> LightningReceiveStateMachine {
        LightningReceiveStateMachine {
            common: old_state.common,
            state: LightningReceiveStates::Canceled(LightningReceiveError::Rejected),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveConfirmedInvoice {
    confirmed_invoice: ConfirmedInvoice,
}

impl LightningReceiveConfirmedInvoice {
    fn transitions(
        &self,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let invoice = self.confirmed_invoice.invoice.clone();
        let timeout = invoice.expiry_time();
        let keypair = self.confirmed_invoice.keypair;
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
        invoice: Invoice,
        global_context: DynGlobalClientContext,
    ) -> IncomingContractAccount {
        // TODO: Get rid of polling
        loop {
            let contract_id = (*invoice.payment_hash()).into();
            let contract =
                LightningClientContext::get_incoming_contract(contract_id, global_context.clone())
                    .await;

            if let Ok(contract) = contract {
                return contract;
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn transition_funded(
        old_state: LightningReceiveStateMachine,
        keypair: KeyPair,
        contract: IncomingContractAccount,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
    ) -> LightningReceiveStateMachine {
        let outpoint = Self::claim_incoming_contract(dbtx, contract, keypair, global_context).await;
        LightningReceiveStateMachine {
            common: old_state.common,
            state: LightningReceiveStates::Funded(LightningReceiveFunded { outpoint }),
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

        let txid = global_context.claim_input(dbtx, client_input).await;
        OutPoint { txid, out_idx: 0 }
    }

    async fn await_payment_timeout(timeout: Duration) {
        sleep(timeout).await
    }

    async fn transition_timeout(
        old_state: LightningReceiveStateMachine,
    ) -> LightningReceiveStateMachine {
        LightningReceiveStateMachine {
            common: old_state.common,
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
        common: LightningReceiveCommon,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let txid = self.outpoint.txid;
        vec![StateTransition::new(
            Self::await_claim_success(common, global_context.clone(), txid),
            move |_dbtx, result, old_state| {
                Box::pin(Self::transition_claim_success(result, old_state, txid))
            },
        )]
    }

    async fn await_claim_success(
        common: LightningReceiveCommon,
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), ()> {
        global_context
            .await_tx_accepted(common.operation_id, txid)
            .await
    }

    async fn transition_claim_success(
        result: Result<(), ()>,
        old_state: LightningReceiveStateMachine,
        txid: TransactionId,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(_) => {
                // Claim successful
                LightningReceiveStateMachine {
                    common: old_state.common,
                    state: LightningReceiveStates::Success(txid),
                }
            }
            Err(_) => {
                // Claim rejection
                LightningReceiveStateMachine {
                    common: old_state.common,
                    state: LightningReceiveStates::Canceled(LightningReceiveError::ClaimRejected),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct IncomingContractAccount {
    pub amount: Amount,
    pub contract: IncomingContract,
}

impl IncomingContractAccount {
    pub fn claim(&self) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}

// TODO: should this have some kind of "state" enum - e.g. pending, paid,
// expired
/// Invoice whose "offer" has been accepted by federation
#[derive(Debug, Encodable, Clone, Eq, PartialEq, Decodable, Serialize, Deserialize)]
pub struct ConfirmedInvoice {
    /// The invoice itself
    pub invoice: Invoice,
    /// Keypair that will be able to sweep contract once it has received payment
    pub keypair: KeyPair,
}

impl ConfirmedInvoice {
    pub fn contract_id(&self) -> ContractId {
        // FIXME: Should we be using the payment hash?
        (*self.invoice.payment_hash()).into()
    }
}
