use std::sync::Arc;
use std::time::Duration;

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, IdentifiableContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use futures::future;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_stream::StreamExt;

use super::{
    GatewayClientContext, GatewayClientExt, GatewayClientStateMachines, GatewayExtReceiveStates,
};
use crate::fetch_lightning_node_info;
use crate::gateway_lnrpc::{PayInvoiceRequest, PayInvoiceResponse};
use crate::lnrpc_client::LightningRpcError;

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
///    PayInvoice -- pay invoice over Lightning successful --> ClaimOutgoingContract
///    PayInvoice -- pay invoice via direct swap successful --> WaitForSwapPreimage
///    WaitForSwapPreimage -- received preimage --> ClaimOutgoingContract
///    WaitForSwapPreimage -- wait for preimge failed --> Canceled
///    ClaimOutgoingContract -- claim tx submission --> Preimage
///    CancelContract -- cancel tx submission successful --> Canceled
///    CancelContract -- cancel tx submission unsuccessful --> Failed
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum GatewayPayStates {
    PayInvoice(GatewayPayInvoice),
    CancelContract(Box<GatewayPayCancelContract>),
    Preimage(Vec<OutPoint>, Preimage),
    OfferDoesNotExist(ContractId),
    Canceled {
        txid: TransactionId,
        contract_id: ContractId,
        error: OutgoingPaymentError,
    },
    WaitForSwapPreimage(Box<GatewayPayWaitForSwapPreimage>),
    ClaimOutgoingContract(Box<GatewayPayClaimOutgoingContract>),
    Failed {
        error: OutgoingPaymentError,
        error_message: String,
    },
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
            GatewayPayStates::WaitForSwapPreimage(gateway_pay_wait_for_swap_preimage) => {
                gateway_pay_wait_for_swap_preimage.transitions(context.clone(), self.common.clone())
            }
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

    fn operation_id(&self) -> fedimint_core::core::OperationId {
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
    #[error("The invoice is expired. Expiry duration: {0:?}")]
    InvoiceExpired(Duration),
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum OutgoingPaymentError {
    #[error("OutgoingContract does not exist {contract_id}")]
    OutgoingContractDoesNotExist { contract_id: ContractId },
    #[error("An error occurred while paying the lightning invoice.")]
    LightningPayError {
        contract: OutgoingContractAccount,
        lightning_error: LightningRpcError,
    },
    #[error("An invalid contract was specified.")]
    InvalidOutgoingContract {
        error: OutgoingContractError,
        contract: OutgoingContractAccount,
    },
    #[error("An error occurred while attempting direct swap between federations.")]
    SwapFailed {
        contract: OutgoingContractAccount,
        swap_error: String,
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
            Self::await_get_payment_parameters(global_context, self.contract_id, context.clone()),
            move |_dbtx, result, _old_state| {
                Box::pin(Self::transition_buy_preimage(
                    context.clone(),
                    result,
                    common.clone(),
                ))
            },
        )]
    }

    async fn await_get_payment_parameters(
        global_context: DynGlobalClientContext,
        contract_id: ContractId,
        context: GatewayClientContext,
    ) -> Result<(OutgoingContractAccount, PaymentParameters), OutgoingPaymentError> {
        let account = global_context
            .module_api()
            .wait_contract(contract_id)
            .await
            .map_err(|_| OutgoingPaymentError::OutgoingContractDoesNotExist { contract_id })?;

        if let FundedContract::Outgoing(contract) = account.contract {
            let outgoing_contract_account = OutgoingContractAccount {
                amount: account.amount,
                contract,
            };

            let consensus_block_count = global_context
                .module_api()
                .fetch_consensus_block_count()
                .await
                .map_err(|_| OutgoingPaymentError::InvalidOutgoingContract {
                    error: OutgoingContractError::TimeoutTooClose,
                    contract: outgoing_contract_account.clone(),
                })?;

            if consensus_block_count.is_none() {
                return Err(OutgoingPaymentError::InvalidOutgoingContract {
                    error: OutgoingContractError::MissingContractData,
                    contract: outgoing_contract_account.clone(),
                });
            }

            let payment_parameters = Self::validate_outgoing_account(
                &outgoing_contract_account,
                context.redeem_key,
                context.timelock_delta,
                consensus_block_count.unwrap(),
            )
            .await
            .map_err(|e| OutgoingPaymentError::InvalidOutgoingContract {
                error: e,
                contract: outgoing_contract_account.clone(),
            })?;

            return Ok((outgoing_contract_account, payment_parameters));
        }

        Err(OutgoingPaymentError::OutgoingContractDoesNotExist { contract_id })
    }

    async fn buy_preimage_over_lightning(
        context: GatewayClientContext,
        buy_preimage: PaymentParameters,
        contract: OutgoingContractAccount,
    ) -> Result<Preimage, OutgoingPaymentError> {
        let invoice = buy_preimage.invoice.clone();
        let max_delay = buy_preimage.max_delay;
        let max_fee_msat = buy_preimage.max_send_amount.msats;
        match context
            .lnrpc
            .pay(PayInvoiceRequest {
                invoice: invoice.to_string(),
                max_delay,
                max_fee_msat,
                payment_hash: invoice.payment_hash().to_vec(),
            })
            .await
        {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                Ok(Preimage(slice))
            }
            Err(error) => Err(OutgoingPaymentError::LightningPayError {
                contract,
                lightning_error: error,
            }),
        }
    }

    async fn buy_preimage_via_direct_swap(
        client: Client,
        invoice: Bolt11Invoice,
        contract: OutgoingContractAccount,
    ) -> Result<(FederationId, OperationId), OutgoingPaymentError> {
        let swap_params = invoice
            .try_into()
            .map_err(|e| OutgoingPaymentError::SwapFailed {
                contract: contract.clone(),
                swap_error: format!("Failed to parse invoice into swap parameters: {}", e),
            })?;

        let operation_id = client
            .gateway_handle_direct_swap(swap_params)
            .await
            .map_err(|e| OutgoingPaymentError::SwapFailed {
                contract: contract.clone(),
                swap_error: format!("Failed to initiate direct swap: {}", e),
            })?;

        Ok((client.federation_id(), operation_id))
    }

    async fn transition_buy_preimage(
        context: GatewayClientContext,
        result: Result<(OutgoingContractAccount, PaymentParameters), OutgoingPaymentError>,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        match result {
            Ok((contract, payment_parameters)) => {
                if let Some(client) = Self::check_swap_to_federation(
                    context.clone(),
                    payment_parameters.invoice.clone(),
                )
                .await
                {
                    return match Self::buy_preimage_via_direct_swap(
                        client,
                        payment_parameters.invoice.clone(),
                        contract.clone(),
                    )
                    .await
                    {
                        Ok((federation_id, operation_id)) => GatewayPayStateMachine {
                            common,
                            state: GatewayPayStates::WaitForSwapPreimage(Box::new(
                                GatewayPayWaitForSwapPreimage {
                                    contract,
                                    federation_id,
                                    operation_id,
                                },
                            )),
                        },
                        Err(e) => GatewayPayStateMachine {
                            common,
                            state: GatewayPayStates::CancelContract(Box::new(
                                GatewayPayCancelContract { contract, error: e },
                            )),
                        },
                    };
                }

                match Self::buy_preimage_over_lightning(
                    context,
                    payment_parameters,
                    contract.clone(),
                )
                .await
                {
                    Ok(preimage) => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                            GatewayPayClaimOutgoingContract { contract, preimage },
                        )),
                    },
                    Err(e) => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract { contract, error: e },
                        )),
                    },
                }
            }
            Err(e) => {
                match e.clone() {
                    OutgoingPaymentError::InvalidOutgoingContract { error: _, contract } => {
                        GatewayPayStateMachine {
                            common,
                            state: GatewayPayStates::CancelContract(Box::new(
                                GatewayPayCancelContract { contract, error: e },
                            )),
                        }
                    }
                    OutgoingPaymentError::LightningPayError {
                        contract,
                        lightning_error: _,
                    } => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract { contract, error: e },
                        )),
                    },
                    OutgoingPaymentError::SwapFailed {
                        contract,
                        swap_error: _,
                    } => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract { contract, error: e },
                        )),
                    },
                    OutgoingPaymentError::OutgoingContractDoesNotExist { contract_id } => {
                        GatewayPayStateMachine {
                            common,
                            state: GatewayPayStates::OfferDoesNotExist(contract_id),
                        }
                    }
                }
            }
        }
    }

    async fn validate_outgoing_account(
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::KeyPair,
        timelock_delta: u64,
        consensus_block_count: u64,
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
            .checked_sub(consensus_block_count.saturating_sub(1))
            .and_then(|delta| delta.checked_sub(timelock_delta));
        if max_delay.is_none() {
            return Err(OutgoingContractError::TimeoutTooClose);
        }

        if invoice.is_expired() {
            return Err(OutgoingContractError::InvoiceExpired(invoice.expiry_time()));
        }

        Ok(PaymentParameters {
            max_delay: max_delay.unwrap(),
            max_send_amount: account.amount,
            invoice,
        })
    }

    // Checks if the invoice route hint last hop has source node id matching this
    // gateways node pubkey and if the short channel id matches one assigned by
    // this gateway to a connected federation. In this case, the gateway can
    // avoid paying the invoice over the lightning network and instead perform a
    // direct swap between the two federations.
    async fn check_swap_to_federation(
        context: GatewayClientContext,
        invoice: Bolt11Invoice,
    ) -> Option<Client> {
        let rhints = invoice.route_hints();
        match rhints.first().and_then(|rh| rh.0.last()) {
            None => None,
            Some(hop) => {
                let node_info = fetch_lightning_node_info(context.lnrpc.clone())
                    .await
                    .ok()?;

                if hop.src_node_id != node_info.0 {
                    return None;
                }

                let scid_to_feds = context.all_scids.read().await;
                match scid_to_feds.get(&hop.short_channel_id).cloned() {
                    None => None,
                    Some(federation_id) => {
                        let clients = context.all_clients.read().await;
                        clients.get(&federation_id).cloned()
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub struct PaymentParameters {
    max_delay: u64,
    max_send_amount: Amount,
    invoice: lightning_invoice::Bolt11Invoice,
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
        let claim_input = contract.claim(preimage.clone());
        let client_input = ClientInput::<LightningInput, GatewayClientStateMachines> {
            input: claim_input,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![context.redeem_key],
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;

        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::Preimage(out_points, preimage),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayWaitForSwapPreimage {
    contract: OutgoingContractAccount,
    federation_id: FederationId,
    operation_id: OperationId,
}

impl GatewayPayWaitForSwapPreimage {
    fn transitions(
        &self,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let federation_id = self.federation_id;
        let operation_id = self.operation_id;
        let contract = self.contract.clone();
        vec![StateTransition::new(
            Self::await_preimage(context, federation_id, operation_id, contract.clone()),
            move |_dbtx, result, _old_state| {
                let c2 = contract.clone();
                Box::pin(Self::transition_claim_outgoing_contract(
                    common.clone(),
                    result,
                    c2,
                ))
            },
        )]
    }

    async fn await_preimage(
        context: GatewayClientContext,
        federation_id: FederationId,
        operation_id: OperationId,
        contract: OutgoingContractAccount,
    ) -> Result<Preimage, OutgoingPaymentError> {
        let client = context
            .all_clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(OutgoingPaymentError::SwapFailed {
                contract: contract.clone(),
                swap_error: "Federation client not found".to_string(),
            })?;

        let mut stream = client
            .gateway_subscribe_ln_receive(operation_id)
            .await
            .map_err(|e| OutgoingPaymentError::SwapFailed {
                contract: contract.clone(),
                swap_error: format!("Failed to subscribe to ln receive of direct swap: {}", e),
            })?
            .into_stream();

        loop {
            if let Some(state) = stream.next().await {
                match state {
                    GatewayExtReceiveStates::Funding => {
                        continue;
                    }
                    GatewayExtReceiveStates::Preimage(preimage) => {
                        return Ok(preimage);
                    }
                    _ => {
                        return Err(OutgoingPaymentError::SwapFailed {
                            contract,
                            swap_error: "Failed to receive preimage".to_string(),
                        });
                    }
                }
            }
        }
    }

    async fn transition_claim_outgoing_contract(
        common: GatewayPayCommon,
        result: Result<Preimage, OutgoingPaymentError>,
        contract: OutgoingContractAccount,
    ) -> GatewayPayStateMachine {
        match result {
            Ok(preimage) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                    GatewayPayClaimOutgoingContract { contract, preimage },
                )),
            },
            Err(e) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                    contract,
                    error: e,
                })),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub struct GatewayPayCancelContract {
    contract: OutgoingContractAccount,
    error: OutgoingPaymentError,
}

impl GatewayPayCancelContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let contract = self.contract.clone();
        let error = self.error.clone();
        vec![StateTransition::new(
            future::ready(()),
            move |dbtx, _, _| {
                Box::pin(Self::transition_canceled(
                    dbtx,
                    contract.clone(),
                    global_context.clone(),
                    context.clone(),
                    common.clone(),
                    error.clone(),
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
        error: OutgoingPaymentError,
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
                state: GatewayPayStates::Canceled {
                    txid,
                    contract_id: contract.contract.contract_id(),
                    error,
                },
            },
            Err(e) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::Failed {
                    error,
                    error_message: format!(
                        "Failed to submit refund transaction to federation {e:?}"
                    ),
                },
            },
        }
    }
}
