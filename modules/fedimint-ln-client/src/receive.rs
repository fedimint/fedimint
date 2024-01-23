use std::sync::Arc;
use std::time::Duration;

use bitcoin::util::key::KeyPair;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::ClientInput;
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::incoming::IncomingContractAccount;
use fedimint_ln_common::contracts::{DecryptedPreimage, FundedContract};
use fedimint_ln_common::{LightningClientContext, LightningInput};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info};

use crate::LightningClientStateMachines;

const RETRY_DELAY: Duration = Duration::from_secs(1);

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
    Success(Vec<OutPoint>),
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

    fn operation_id(&self) -> fedimint_core::core::OperationId {
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
#[serde(rename_all = "snake_case")]
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
        // No network calls are done here, we just await other state machines, so no
        // retry logic is needed
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
        let keypair = self.keypair;
        let global_context = global_context.clone();
        vec![StateTransition::new(
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
        )]
    }

    async fn await_incoming_contract_account(
        invoice: Bolt11Invoice,
        global_context: DynGlobalClientContext,
    ) -> Result<IncomingContractAccount, LightningReceiveError> {
        let contract_id = (*invoice.payment_hash()).into();
        loop {
            // Consider time before the api call to account for network delays
            let now_epoch = fedimint_core::time::duration_since_epoch();
            match get_incoming_contract(&global_context, contract_id).await {
                Ok(Some(incoming_contract_account)) => {
                    match incoming_contract_account.contract.decrypted_preimage {
                        DecryptedPreimage::Pending => {
                            // Previously we would time out here but we may miss a payment if we do
                            // so
                            info!("Waiting for preimage decryption for contract {contract_id}");
                        }
                        DecryptedPreimage::Some(_) => return Ok(incoming_contract_account),
                        DecryptedPreimage::Invalid => {
                            return Err(LightningReceiveError::InvalidPreimage)
                        }
                    }
                }
                Ok(None) => {
                    // only when we are sure that the invoice is still pending that we can
                    // check for a timeout
                    const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(60);
                    if has_invoice_expired(&invoice, now_epoch, CLOCK_SKEW_TOLERANCE) {
                        return Err(LightningReceiveError::Timeout);
                    } else {
                        debug!("Still waiting preimage decryption for contract {contract_id}");
                    }
                }
                Err(error) => {
                    error.report_if_important();
                    info!("External LN payment retryable error waiting for preimage decryption: {error:?}");
                }
            }
            sleep(RETRY_DELAY).await;
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
                let (txid, out_points) =
                    Self::claim_incoming_contract(dbtx, contract, keypair, global_context).await;
                LightningReceiveStateMachine {
                    operation_id: old_state.operation_id,
                    state: LightningReceiveStates::Funded(LightningReceiveFunded {
                        txid,
                        out_points,
                    }),
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
    ) -> (TransactionId, Vec<OutPoint>) {
        let input = contract.claim();
        let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
            input,
            keys: vec![keypair],
            // The input of the refund tx is managed by this state machine, so no new state machines
            // need to be created
            state_machines: Arc::new(|_, _| vec![]),
        };

        global_context.claim_input(dbtx, client_input).await
    }
}

fn has_invoice_expired(
    invoice: &Bolt11Invoice,
    now_epoch: Duration,
    clock_skew_tolerance: Duration,
) -> bool {
    assert!(now_epoch >= clock_skew_tolerance);
    // tolerate some clock skew
    invoice.would_expire(now_epoch - clock_skew_tolerance)
}

async fn get_incoming_contract(
    global_context: &DynGlobalClientContext,
    contract_id: fedimint_ln_common::contracts::ContractId,
) -> Result<Option<IncomingContractAccount>, fedimint_core::api::FederationError> {
    match global_context
        .module_api()
        .fetch_contract(contract_id)
        .await
    {
        Ok(Some(contract)) => {
            if let FundedContract::Incoming(incoming) = contract.contract {
                Ok(Some(IncomingContractAccount {
                    amount: contract.amount,
                    contract: incoming.contract,
                }))
            } else {
                Err(fedimint_core::api::FederationError::general(
                    anyhow::anyhow!("Contract {contract_id} is not an incoming contract"),
                ))
            }
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct LightningReceiveFunded {
    txid: TransactionId,
    out_points: Vec<OutPoint>,
}

impl LightningReceiveFunded {
    fn transitions(
        &self,
        operation_id: OperationId,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<LightningReceiveStateMachine>> {
        let out_points = self.out_points.clone();
        vec![StateTransition::new(
            Self::await_claim_success(operation_id, global_context.clone(), self.txid),
            move |_dbtx, result, old_state| {
                let out_points = out_points.clone();
                Box::pin(Self::transition_claim_success(
                    result, old_state, out_points,
                ))
            },
        )]
    }

    async fn await_claim_success(
        operation_id: OperationId,
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        // No network calls are done here, we just await other state machines, so no
        // retry logic is needed
        global_context.await_tx_accepted(operation_id, txid).await
    }

    async fn transition_claim_success(
        result: Result<(), String>,
        old_state: LightningReceiveStateMachine,
        out_points: Vec<OutPoint>,
    ) -> LightningReceiveStateMachine {
        match result {
            Ok(_) => {
                // Claim successful
                LightningReceiveStateMachine {
                    operation_id: old_state.operation_id,
                    state: LightningReceiveStates::Success(out_points),
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bitcoin_hashes::{sha256, Hash};
    use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
    use secp256k1::SecretKey;

    use super::*;

    #[test]
    fn test_invoice_expiration() -> anyhow::Result<()> {
        let now = fedimint_core::time::duration_since_epoch();
        let one_second = Duration::from_secs(1);
        for expiration in [one_second, Duration::from_secs(3600)] {
            for tolerance in [one_second, Duration::from_secs(60)] {
                let invoice = invoice(now, expiration)?;
                assert!(!has_invoice_expired(&invoice, now - one_second, tolerance));
                assert!(!has_invoice_expired(&invoice, now, tolerance));
                assert!(!has_invoice_expired(&invoice, now + expiration, tolerance));
                assert!(!has_invoice_expired(
                    &invoice,
                    now + expiration + tolerance - one_second,
                    tolerance
                ));
                assert!(has_invoice_expired(
                    &invoice,
                    now + expiration + tolerance,
                    tolerance
                ));
                assert!(has_invoice_expired(
                    &invoice,
                    now + expiration + tolerance + one_second,
                    tolerance
                ));
            }
        }
        Ok(())
    }

    fn invoice(now_epoch: Duration, expiry_time: Duration) -> anyhow::Result<Bolt11Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&[0; 32]))
            .duration_since_epoch(now_epoch)
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(1000)
            .expiry_time(expiry_time)
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &secret_key))?)
    }
}
