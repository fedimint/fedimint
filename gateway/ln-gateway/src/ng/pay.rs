use std::sync::Arc;

use fedimint_client::sm::{ClientSMDatabaseTransaction, OperationId, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_client::contracts::IdentifiableContract;
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use futures::future;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use super::{GatewayClientContext, GatewayClientStateMachines};
use crate::gatewaylnrpc::{PayInvoiceRequest, PayInvoiceResponse};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that executes the Lightning payment on behalf of
/// the fedimint user that requested an invoice to be paid.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    PayInvoice -- fetch contract failed --> Canceled
///    PayInvoice -- validate contract failed --> CancelContract
///    PayInvoice -- pay invoice unsuccessful --> CancelContract
///    PayInvoice -- pay invoice successful --> ClaimOutgoingContract
///    ClaimOutgoingContract -- claim tx submission --> Preimage
///    CancelContract -- cancel tx submission successful --> Canceled
///    CancelContract -- cancel tx submission unsuccessful --> Failed
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayPayStates {
    PayInvoice(GatewayPayInvoice),
    CancelContract(GatewayPayCancelContract),
    Preimage(OutPoint),
    Canceled(Option<TransactionId>),
    ClaimOutgoingContract(GatewayPayClaimOutgoingContract),
    Failed,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayCommon {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayStateMachine {
    pub common: GatewayPayCommon,
    pub state: GatewayPayStates,
}

impl State for GatewayPayStateMachine {
    type ModuleContext = GatewayClientContext;

    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        match &self.state {
            GatewayPayStates::PayInvoice(gateway_pay_invoice) => gateway_pay_invoice.transitions(
                global_context.clone(),
                context.clone(),
                self.common.clone(),
            ),
            GatewayPayStates::ClaimOutgoingContract(gateway_pay_claim_outgoing_contract) => {
                gateway_pay_claim_outgoing_contract.transitions(
                    global_context.clone(),
                    context.clone(),
                    self.common.clone(),
                )
            }
            GatewayPayStates::CancelContract(gateway_pay_cancel) => gateway_pay_cancel.transitions(
                global_context.clone(),
                context.clone(),
                self.common.clone(),
            ),
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        self.common.operation_id
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum OutgoingContractError {
    #[error("Invalid OutgoingContract {contract_id}")]
    InvalidOutgoingContract { contract_id: ContractId },
    #[error("The contract is already cancelled and can't be processed by the gateway")]
    CancelledContract,
    #[error("The Account or offer is keyed to another gateway")]
    NotOurKey,
    #[error("Invoice is missing amount")]
    InvoiceMissingAmount,
    #[error("Outgoing contract is underfunded, wants us to pay {0}, but only contains {1}")]
    Underfunded(Amount, Amount),
    #[error("The contract's timeout is in the past or does not allow for a safety margin")]
    TimeoutTooClose,
    #[error("Gateway could not retrieve metadata about the contract.")]
    MissingContractData,
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum OutgoingPaymentError {
    #[error("OutgoingContract does not exist {contract_id}")]
    OutgoingContractDoesNotExist { contract_id: ContractId },
    #[error("An error occurred while paying the lightning invoice.")]
    LightningPayError { contract: OutgoingContractAccount },
    #[error("An invalid contract was specified.")]
    InvalidOutgoingContract {
        error: OutgoingContractError,
        contract: OutgoingContractAccount,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayInvoice {
    pub contract_id: ContractId,
}

impl GatewayPayInvoice {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        vec![StateTransition::new(
            Self::await_buy_preimage(global_context.clone(), self.contract_id, context.clone()),
            move |_dbtx, result, _old_state| {
                info!("await_buy_preimage done: {result:?}");
                Box::pin(Self::transition_bought_preimage(result, common.clone()))
            },
        )]
    }

    async fn await_buy_preimage(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
        context: GatewayClientContext,
    ) -> Result<(OutgoingContractAccount, Preimage), OutgoingPaymentError> {
        info!("await_buy_preimage id={contract_id:?}");
        let account = global_context
            .module_api()
            .fetch_contract(contract_id)
            .await
            .map_err(|_| OutgoingPaymentError::OutgoingContractDoesNotExist { contract_id })?;

        if let FundedContract::Outgoing(contract) = account.contract {
            let outgoing_contract_account = OutgoingContractAccount {
                amount: account.amount,
                contract,
            };

            let consensus_block_height = global_context
                .module_api()
                .fetch_consensus_block_height()
                .await
                .map_err(|_| OutgoingPaymentError::InvalidOutgoingContract {
                    error: OutgoingContractError::TimeoutTooClose,
                    contract: outgoing_contract_account.clone(),
                })?;

            if consensus_block_height.is_none() {
                return Err(OutgoingPaymentError::InvalidOutgoingContract {
                    error: OutgoingContractError::MissingContractData,
                    contract: outgoing_contract_account.clone(),
                });
            }

            let payment_parameters = Self::validate_outgoing_account(
                &outgoing_contract_account,
                context.redeem_key,
                context.timelock_delta,
                consensus_block_height.unwrap(),
            )
            .await
            .map_err(|e| OutgoingPaymentError::InvalidOutgoingContract {
                error: e,
                contract: outgoing_contract_account.clone(),
            })?;
            let preimage = Self::await_buy_preimage_over_lightning(
                context,
                payment_parameters,
                outgoing_contract_account.clone(),
            )
            .await?;
            return Ok((outgoing_contract_account, preimage));
        }

        Err(OutgoingPaymentError::OutgoingContractDoesNotExist { contract_id })
    }

    async fn await_buy_preimage_over_lightning(
        context: GatewayClientContext,
        buy_preimage: PaymentParameters,
        contract: OutgoingContractAccount,
    ) -> Result<Preimage, OutgoingPaymentError> {
        let invoice = buy_preimage.invoice.clone();
        let max_delay = buy_preimage.max_delay;
        let max_fee_percent = buy_preimage.max_fee_percent();
        match context
            .lnrpc
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay,
                max_fee_percent,
            })
            .await
        {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                Ok(Preimage(slice))
            }
            Err(e) => {
                info!("error paying lightning invoice {e:?}");
                Err(OutgoingPaymentError::LightningPayError { contract })
            }
        }
    }

    async fn transition_bought_preimage(
        result: Result<(OutgoingContractAccount, Preimage), OutgoingPaymentError>,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        match result {
            Ok((contract, preimage)) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::ClaimOutgoingContract(GatewayPayClaimOutgoingContract {
                    contract,
                    preimage,
                }),
            },
            Err(OutgoingPaymentError::InvalidOutgoingContract {
                error: _error,
                contract,
            }) => {
                // TODO: include the underlying error while canceling the contract
                return GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::CancelContract(GatewayPayCancelContract { contract }),
                };
            }
            Err(OutgoingPaymentError::LightningPayError { contract }) => {
                info!("transition to CancelContract");
                return GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::CancelContract(GatewayPayCancelContract { contract }),
                };
            }
            Err(_) => {
                return GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Canceled(None),
                };
            }
        }
    }

    async fn validate_outgoing_account(
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::KeyPair,
        timelock_delta: u64,
        consensus_block_height: u64,
    ) -> Result<PaymentParameters, OutgoingContractError> {
        let our_pub_key = secp256k1::XOnlyPublicKey::from_keypair(&redeem_key).0;

        if account.contract.cancelled {
            return Err(OutgoingContractError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(OutgoingContractError::NotOurKey);
        }

        let invoice = account.contract.invoice.clone();
        let invoice_amount = Amount::from_msats(
            invoice
                .amount_milli_satoshis()
                .ok_or(OutgoingContractError::InvoiceMissingAmount)?,
        );

        if account.amount < invoice_amount {
            return Err(OutgoingContractError::Underfunded(
                invoice_amount,
                account.amount,
            ));
        }

        let max_delay = (account.contract.timelock as u64)
            .checked_sub(consensus_block_height)
            .and_then(|delta| delta.checked_sub(timelock_delta));
        if max_delay.is_none() {
            return Err(OutgoingContractError::TimeoutTooClose);
        }

        Ok(PaymentParameters {
            max_delay: max_delay.unwrap(),
            invoice_amount,
            max_send_amount: account.amount,
            invoice,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PaymentParameters {
    max_delay: u64,
    invoice_amount: Amount,
    max_send_amount: Amount,
    invoice: lightning_invoice::Invoice,
}

impl PaymentParameters {
    fn max_fee_percent(&self) -> f64 {
        let max_absolute_fee = self.max_send_amount - self.invoice_amount;
        (max_absolute_fee.msats as f64) / (self.invoice_amount.msats as f64)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayClaimOutgoingContract {
    contract: OutgoingContractAccount,
    preimage: Preimage,
}

impl GatewayPayClaimOutgoingContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let contract = self.contract.clone();
        let preimage = self.preimage.clone();
        vec![StateTransition::new(
            future::ready(()),
            move |dbtx, _, _| {
                Box::pin(Self::transition_claim_outgoing_contract(
                    dbtx,
                    global_context.clone(),
                    context.clone(),
                    common.clone(),
                    contract.clone(),
                    preimage.clone(),
                ))
            },
        )]
    }

    async fn transition_claim_outgoing_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
        contract: OutgoingContractAccount,
        preimage: Preimage,
    ) -> GatewayPayStateMachine {
        let claim_input = contract.claim(preimage);
        let client_input = ClientInput::<LightningInput, GatewayClientStateMachines> {
            input: claim_input,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![context.redeem_key],
        };

        let (txid, _) = global_context.claim_input(dbtx, client_input).await;
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::Preimage(OutPoint { txid, out_idx: 0 }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayCancelContract {
    contract: OutgoingContractAccount,
}

impl GatewayPayCancelContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let contract = self.contract.clone();
        vec![StateTransition::new(
            future::ready(()),
            move |dbtx, _, _| {
                Box::pin(Self::transition_canceled(
                    dbtx,
                    contract.clone(),
                    global_context.clone(),
                    context.clone(),
                    common.clone(),
                ))
            },
        )]
    }

    async fn transition_canceled(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        contract: OutgoingContractAccount,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        let cancel_signature = context.secp.sign_schnorr(
            &contract.contract.cancellation_message().into(),
            &context.redeem_key,
        );
        let cancel_output = LightningOutput::CancelOutgoing {
            contract: contract.contract.contract_id(),
            gateway_signature: cancel_signature,
        };
        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachines> {
            output: cancel_output,
            state_machines: Arc::new(|_, _| vec![]),
        };

        match global_context.fund_output(dbtx, client_output).await {
            Ok((txid, _)) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::Canceled(Some(txid)),
            },
            Err(_) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::Failed,
            },
        }
    }
}
