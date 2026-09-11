use std::fmt::{self, Display};

use fedimint_client::ClientHandleArc;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{Amount, OutPoint, TransactionId, secp256k1};
use fedimint_lightning::{LightningRpcError, PayInvoiceResponse};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_common::config::FeeToAmount;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, IdentifiableContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use futures::future;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, warn};

use super::{GatewayClientContext, GatewayExtReceiveStates};
use crate::events::{OutgoingPaymentFailed, OutgoingPaymentSucceeded};
use crate::{GatewayClientModule, SwapParameters};

const TIMELOCK_DELTA: u64 = 10;

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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
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

impl fmt::Display for GatewayPayStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayPayStates::PayInvoice(_) => write!(f, "PayInvoice"),
            GatewayPayStates::CancelContract(_) => write!(f, "CancelContract"),
            GatewayPayStates::Preimage(..) => write!(f, "Preimage"),
            GatewayPayStates::OfferDoesNotExist(_) => write!(f, "OfferDoesNotExist"),
            GatewayPayStates::Canceled { .. } => write!(f, "Canceled"),
            GatewayPayStates::WaitForSwapPreimage(_) => write!(f, "WaitForSwapPreimage"),
            GatewayPayStates::ClaimOutgoingContract(_) => write!(f, "ClaimOutgoingContract"),
            GatewayPayStates::Failed { .. } => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayCommon {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayStateMachine {
    pub common: GatewayPayCommon,
    pub state: GatewayPayStates,
}

impl fmt::Display for GatewayPayStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gateway Pay State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

impl State for GatewayPayStateMachine {
    type ModuleContext = GatewayClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            GatewayPayStates::PayInvoice(gateway_pay_invoice) => {
                gateway_pay_invoice.transitions(global_context.clone(), context, &self.common)
            }
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

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
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
    #[error("The invoice is expired. Expiry happened at timestamp: {0}")]
    InvoiceExpired(u64),
    #[error("The invoice amount plus the gateway fee overflows")]
    InvoiceAmountTooLarge,
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub enum OutgoingPaymentErrorType {
    #[error("OutgoingContract does not exist {contract_id}")]
    OutgoingContractDoesNotExist { contract_id: ContractId },
    #[error("An error occurred while paying the lightning invoice.")]
    LightningPayError { lightning_error: LightningRpcError },
    #[error("An invalid contract was specified.")]
    InvalidOutgoingContract { error: OutgoingContractError },
    #[error("An error occurred while attempting direct swap between federations.")]
    SwapFailed { swap_error: String },
    #[error("Invoice has already been paid")]
    InvoiceAlreadyPaid,
    #[error("No federation configuration")]
    InvalidFederationConfiguration,
    #[error("Invalid invoice preimage")]
    InvalidInvoicePreimage,
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub struct OutgoingPaymentError {
    pub error_type: OutgoingPaymentErrorType,
    pub contract_id: ContractId,
    pub contract: Option<OutgoingContractAccount>,
}

impl Display for OutgoingPaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingContractError: {}", self.error_type)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayInvoice {
    pub pay_invoice_payload: PayInvoicePayload,
}

impl GatewayPayInvoice {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: &GatewayClientContext,
        common: &GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let payload = self.pay_invoice_payload.clone();
        vec![StateTransition::new(
            Self::fetch_parameters_and_pay(
                global_context,
                payload,
                context.clone(),
                common.clone(),
            ),
            |_dbtx, result, _old_state| Box::pin(futures::future::ready(result)),
        )]
    }

    async fn fetch_parameters_and_pay(
        global_context: DynGlobalClientContext,
        pay_invoice_payload: PayInvoicePayload,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        match Self::await_get_payment_parameters(
            global_context,
            context.clone(),
            pay_invoice_payload.contract_id,
            pay_invoice_payload.payment_data.clone(),
            pay_invoice_payload.federation_id,
        )
        .await
        {
            Ok((contract, payment_parameters)) => {
                Self::buy_preimage(
                    context.clone(),
                    contract.clone(),
                    payment_parameters.clone(),
                    common.clone(),
                    pay_invoice_payload.clone(),
                )
                .await
            }
            Err(e) => {
                warn!("Failed to get payment parameters: {e:?}");
                match e.contract.clone() {
                    Some(contract) => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract { contract, error: e },
                        )),
                    },
                    None => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::OfferDoesNotExist(e.contract_id),
                    },
                }
            }
        }
    }

    /// Checks the gateway's database to determine if the current gateway
    /// generated the invoice using the LNv2 protocol. If it did, the
    /// gateway can buy the preimage and use it to claim the LNv1
    /// `OutgoingContract`.
    async fn buy_lnv2_preimage(
        context: &GatewayClientContext,
        contract: OutgoingContractAccount,
        swap_parameters: SwapParameters,
        common: GatewayPayCommon,
        fresh_dispatch_refusal: Option<OutgoingContractError>,
    ) -> Option<GatewayPayStateMachine> {
        let amount = swap_parameters.amount_msat;
        if let Ok(Some((lnv2_incoming_contract, client))) = context
            .lightning_manager
            .is_lnv2_direct_swap(swap_parameters.payment_hash, amount)
            .await
        {
            let state = match client
                .get_first_module::<fedimint_gwv2_client::GatewayClientModuleV2>()
                .expect("Must have client module")
                .relay_direct_swap(
                    lnv2_incoming_contract,
                    amount.msats,
                    fresh_dispatch_refusal.is_none(),
                )
                .await
            {
                Ok(Some(final_receive_state)) => match final_receive_state {
                    fedimint_gwv2_client::FinalReceiveState::Success(preimage) => {
                        GatewayPayStateMachine {
                            common,
                            state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                                GatewayPayClaimOutgoingContract {
                                    contract,
                                    preimage: Preimage(preimage),
                                },
                            )),
                        }
                    }
                    state => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract {
                                contract: contract.clone(),
                                error: OutgoingPaymentError {
                                    contract_id: contract.contract.contract_id(),
                                    contract: Some(contract.clone()),
                                    error_type: OutgoingPaymentErrorType::SwapFailed {
                                        swap_error: format!(
                                            "Failed to initiate LNv1 -> LNv2 swap. LNv2 state: {state:?}"
                                        ),
                                    },
                                },
                            },
                        )),
                    },
                },
                Ok(None) => {
                    let error = fresh_dispatch_refusal
                        .expect("the relay only refuses a fresh dispatch when one was denied");
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract {
                                contract: contract.clone(),
                                error: OutgoingPaymentError {
                                    contract_id: contract.contract.contract_id(),
                                    contract: Some(contract.clone()),
                                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                                        error,
                                    },
                                },
                            },
                        )),
                    }
                }
                Err(err) => GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                        contract: contract.clone(),
                        error: OutgoingPaymentError {
                            contract_id: contract.contract.contract_id(),
                            contract: Some(contract.clone()),
                            error_type: OutgoingPaymentErrorType::SwapFailed {
                                swap_error: format!(
                                    "Failed to initiate LNv1 -> LNv2 swap. Err: {err}"
                                ),
                            },
                        },
                    })),
                },
            };

            return Some(state);
        }

        None
    }

    async fn buy_preimage(
        context: GatewayClientContext,
        contract: OutgoingContractAccount,
        payment_parameters: PaymentParameters,
        common: GatewayPayCommon,
        payload: PayInvoicePayload,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage contract {contract:?}");
        // Verify that this client is authorized to receive the preimage.
        if let Err(err) = context
            .lightning_manager
            .verify_preimage_authentication(
                payload.payment_data.payment_hash(),
                payload.preimage_auth,
                contract.clone(),
            )
            .await
        {
            warn!("Preimage authentication failed: {err} for contract {contract:?}");
            return GatewayPayStateMachine {
                common,
                state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                    contract,
                    error: err,
                })),
            };
        }

        // Not all clients support LNv2 yet, so here we check if we are trying to pay an
        // LNv2 invoice. If this gateway also supports LNv2, the gateway can do
        // a swap between LNv1 `OutgoingContract` and an
        // LNv2 `IncomingContract`.
        let swap_parameters: anyhow::Result<SwapParameters> =
            payment_parameters.payment_data.clone().try_into();
        if let Ok(swap_parameters) = swap_parameters
            && let Some(new_state) = Self::buy_lnv2_preimage(
                &context,
                contract.clone(),
                swap_parameters,
                common.clone(),
                payment_parameters.fresh_dispatch.clone().err(),
            )
            .await
        {
            return new_state;
        }

        match context
            .lightning_manager
            .get_client_for_invoice(payment_parameters.payment_data.clone())
            .await
        {
            Some(client) => {
                client
                    .with(|client| {
                        Self::buy_preimage_via_direct_swap(
                            client,
                            payment_parameters.payment_data.clone(),
                            contract.clone(),
                            common.clone(),
                            payment_parameters.fresh_dispatch.clone().err(),
                        )
                    })
                    .await
            }
            _ => {
                Self::buy_preimage_over_lightning(
                    context,
                    payment_parameters,
                    contract.clone(),
                    common.clone(),
                )
                .await
            }
        }
    }

    async fn await_get_payment_parameters(
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        contract_id: ContractId,
        payment_data: PaymentData,
        federation_id: FederationId,
    ) -> Result<(OutgoingContractAccount, PaymentParameters), OutgoingPaymentError> {
        debug!("Await payment parameters for outgoing contract {contract_id:?}");
        let account = global_context
            .module_api()
            .await_contract(contract_id)
            .await;

        if let FundedContract::Outgoing(contract) = account.contract {
            let outgoing_contract_account = OutgoingContractAccount {
                amount: account.amount,
                contract,
            };

            let consensus_block_count = global_context
                .module_api()
                .fetch_consensus_block_count()
                .await
                .map_err(|_| OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                        error: OutgoingContractError::TimeoutTooClose,
                    },
                })?;

            debug!(
                "Consensus block count: {consensus_block_count:?} for outgoing contract {contract_id:?}"
            );
            if consensus_block_count.is_none() {
                return Err(OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                        error: OutgoingContractError::MissingContractData,
                    },
                });
            }

            let routing_fees = context
                .lightning_manager
                .get_routing_fees(federation_id)
                .await
                .ok_or(OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvalidFederationConfiguration,
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                })?;

            let payment_parameters = Self::validate_outgoing_account(
                &outgoing_contract_account,
                context.redeem_key,
                consensus_block_count.unwrap(),
                &payment_data,
                routing_fees,
            )
            .map_err(|e| {
                warn!("Invalid outgoing contract: {e:?}");
                OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract { error: e },
                }
            })?;
            debug!("Got payment parameters: {payment_parameters:?} for contract {contract_id:?}");
            return Ok((outgoing_contract_account, payment_parameters));
        }

        error!("Contract {contract_id:?} is not an outgoing contract");
        Err(OutgoingPaymentError {
            contract_id,
            contract: None,
            error_type: OutgoingPaymentErrorType::OutgoingContractDoesNotExist { contract_id },
        })
    }

    async fn buy_preimage_over_lightning(
        context: GatewayClientContext,
        buy_preimage: PaymentParameters,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage over lightning for contract {contract:?}");

        // A payment the node already knows resolves through `pay`'s
        // idempotent resume path, which never re-dispatches, so a drifted
        // timelock or expiry gate only refuses a dispatch that never happened.
        if let Err(error) = &buy_preimage.fresh_dispatch
            && !context
                .lightning_manager
                .outbound_payment_exists(buy_preimage.payment_data.payment_hash())
                .await
        {
            warn!(
                ?contract,
                err = %error.fmt_compact(),
                "Refusing fresh lightning dispatch"
            );
            return GatewayPayStateMachine {
                common,
                state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                    contract: contract.clone(),
                    error: OutgoingPaymentError {
                        contract_id: contract.contract.contract_id(),
                        contract: Some(contract),
                        error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                            error: error.clone(),
                        },
                    },
                })),
            };
        }

        // On the resume path `pay` consults the node's own payment record
        // before the budget, so `0` is a fail-closed sentinel: should that
        // record have vanished in between, LND rejects a zero CLTV limit and
        // LDK finds no route, rather than dispatching under a stale budget.
        let max_delay = buy_preimage.fresh_dispatch.clone().unwrap_or(0);
        let max_fee = buy_preimage.max_send_amount.saturating_sub(
            buy_preimage
                .payment_data
                .amount()
                .expect("We already checked that an amount was supplied"),
        );

        let payment_result = context
            .lightning_manager
            .pay(buy_preimage.payment_data, max_delay, max_fee)
            .await;

        match payment_result {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                debug!("Preimage received for contract {contract:?}");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                        GatewayPayClaimOutgoingContract { contract, preimage },
                    )),
                }
            }
            Err(error) => Self::gateway_pay_cancel_contract(error, contract, common),
        }
    }

    fn gateway_pay_cancel_contract(
        error: LightningRpcError,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        warn!("Failed to buy preimage with {error} for contract {contract:?}");
        let outgoing_error = OutgoingPaymentError {
            contract_id: contract.contract.contract_id(),
            contract: Some(contract.clone()),
            error_type: OutgoingPaymentErrorType::LightningPayError {
                lightning_error: error,
            },
        };
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                contract,
                error: outgoing_error,
            })),
        }
    }

    async fn buy_preimage_via_direct_swap(
        client: ClientHandleArc,
        payment_data: PaymentData,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
        fresh_dispatch_refusal: Option<OutgoingContractError>,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage via direct swap for contract {contract:?}");
        match payment_data.try_into() {
            Ok(swap_params) => match client
                .get_first_module::<GatewayClientModule>()
                .expect("Must have client module")
                .gateway_handle_direct_swap(swap_params, fresh_dispatch_refusal.is_none())
                .await
            {
                Ok(Some(operation_id)) => {
                    debug!("Direct swap initiated for contract {contract:?}");
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::WaitForSwapPreimage(Box::new(
                            GatewayPayWaitForSwapPreimage {
                                contract,
                                federation_id: client.federation_id(),
                                operation_id,
                            },
                        )),
                    }
                }
                Ok(None) => {
                    let error = fresh_dispatch_refusal
                        .expect("the relay only refuses a fresh dispatch when one was denied");
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract {
                                contract: contract.clone(),
                                error: OutgoingPaymentError {
                                    contract_id: contract.contract.contract_id(),
                                    contract: Some(contract.clone()),
                                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                                        error,
                                    },
                                },
                            },
                        )),
                    }
                }
                Err(e) => {
                    info!("Failed to initiate direct swap: {e:?} for contract {contract:?}");
                    let outgoing_payment_error = OutgoingPaymentError {
                        contract_id: contract.contract.contract_id(),
                        contract: Some(contract.clone()),
                        error_type: OutgoingPaymentErrorType::SwapFailed {
                            swap_error: format!("Failed to initiate direct swap: {e}"),
                        },
                    };
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract {
                                contract: contract.clone(),
                                error: outgoing_payment_error,
                            },
                        )),
                    }
                }
            },
            Err(e) => {
                info!("Failed to initiate direct swap: {e:?} for contract {contract:?}");
                let outgoing_payment_error = OutgoingPaymentError {
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract.clone()),
                    error_type: OutgoingPaymentErrorType::SwapFailed {
                        swap_error: format!("Failed to initiate direct swap: {e}"),
                    },
                };
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                        contract: contract.clone(),
                        error: outgoing_payment_error,
                    })),
                }
            }
        }
    }

    fn validate_outgoing_account(
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::key::Keypair,
        consensus_block_count: u64,
        payment_data: &PaymentData,
        routing_fees: RoutingFees,
    ) -> Result<PaymentParameters, OutgoingContractError> {
        let our_pub_key = secp256k1::PublicKey::from_keypair(&redeem_key);

        if account.contract.cancelled {
            return Err(OutgoingContractError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(OutgoingContractError::NotOurKey);
        }

        // The contract id and the payment data reach us as independent fields of
        // `PayInvoicePayload`, and an outgoing contract carries no invoice, so nothing
        // ties the two together implicitly. Without this check we would pay an invoice
        // whose preimage cannot satisfy the contract we are being paid from.
        if account.contract.hash != payment_data.payment_hash() {
            return Err(OutgoingContractError::InvalidOutgoingContract {
                contract_id: account.contract.contract_id(),
            });
        }

        let payment_amount = payment_data
            .amount()
            .ok_or(OutgoingContractError::InvoiceMissingAmount)?;

        // A pruned invoice carries a raw, caller-controlled amount. Add the fee
        // with checked arithmetic so a huge amount cannot overflow `u64` and
        // wrap the underfunding check below into passing against a near-empty
        // contract.
        let gateway_fee = routing_fees.to_amount(&payment_amount);
        let necessary_contract_amount = payment_amount
            .checked_add(gateway_fee)
            .ok_or(OutgoingContractError::InvoiceAmountTooLarge)?;
        if account.amount < necessary_contract_amount {
            return Err(OutgoingContractError::Underfunded(
                necessary_contract_amount,
                account.amount,
            ));
        }

        // `max_delay` becomes the lightning node's CLTV limit, and LND treats
        // a limit of zero as "unset", enforcing its `--max-cltv-expiry`
        // default instead. That would let the HTLC outlive the contract
        // timelock, so zero must fail closed just like the underflow case.
        let max_delay = u64::from(account.contract.timelock)
            .checked_sub(consensus_block_count.saturating_sub(1))
            .and_then(|delta| delta.checked_sub(TIMELOCK_DELTA))
            .filter(|max_delay| *max_delay > 0);

        // The timelock budget and invoice expiry drift with the chain tip and
        // the wall clock, and this validation re-runs from scratch whenever
        // the state machine restarts. Failing validation outright would
        // cancel a payment that may have been dispatched before a crash and
        // still be in flight -- one that settles or fails regardless of
        // either gate -- returning the escrow while the payment can still
        // claim it. They are therefore recorded as a refusal that each rail
        // consults only before dispatching fresh; anything already started
        // resumes unconditionally.
        let fresh_dispatch = match max_delay {
            None => Err(OutgoingContractError::TimeoutTooClose),
            Some(_) if payment_data.is_expired() => Err(OutgoingContractError::InvoiceExpired(
                payment_data.expiry_timestamp(),
            )),
            Some(max_delay) => Ok(max_delay),
        };

        Ok(PaymentParameters {
            fresh_dispatch,
            max_send_amount: account.amount,
            payment_data: payment_data.clone(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
struct PaymentParameters {
    /// `Ok` carries the CLTV budget a fresh dispatch must respect. `Err` means
    /// a drifted pre-dispatch gate (timelock budget or invoice expiry) forbids
    /// starting one. Each rail consults this only before initiating; a
    /// dispatch that already exists resumes unconditionally.
    fresh_dispatch: Result<u64, OutgoingContractError>,
    max_send_amount: Amount,
    payment_data: PaymentData,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
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
            move |dbtx, (), _| {
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
        debug!("Claiming outgoing contract {contract:?}");

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                OutgoingPaymentSucceeded {
                    outgoing_contract: contract.clone(),
                    contract_id: contract.contract.contract_id(),
                    preimage: preimage.consensus_encode_to_hex(),
                },
            )
            .await;

        let claim_input = contract.claim(preimage.clone());
        let client_input = ClientInput::<LightningInput> {
            input: claim_input,
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![context.redeem_key],
        };

        let out_points = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed")
            .into_iter()
            .collect();
        debug!("Claimed outgoing contract {contract:?} with out points {out_points:?}");
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::Preimage(out_points, preimage),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
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
                let common = common.clone();
                let contract = contract.clone();
                Box::pin(async {
                    Self::transition_claim_outgoing_contract(common, result, contract)
                })
            },
        )]
    }

    async fn await_preimage(
        context: GatewayClientContext,
        federation_id: FederationId,
        operation_id: OperationId,
        contract: OutgoingContractAccount,
    ) -> Result<Preimage, OutgoingPaymentError> {
        debug!("Waiting preimage for contract {contract:?}");

        let client = context
            .lightning_manager
            .get_client(&federation_id)
            .await
            .ok_or(OutgoingPaymentError {
                contract_id: contract.contract.contract_id(),
                contract: Some(contract.clone()),
                error_type: OutgoingPaymentErrorType::SwapFailed {
                    swap_error: "Federation client not found".to_string(),
                },
            })?;

        async {
            let mut stream = client
                .value()
                .get_first_module::<GatewayClientModule>()
                .expect("Must have client module")
                .gateway_subscribe_ln_receive(operation_id)
                .await
                .map_err(|e| {
                    let contract_id = contract.contract.contract_id();
                    warn!(
                        ?contract_id,
                        "Failed to subscribe to ln receive of direct swap: {e:?}"
                    );
                    OutgoingPaymentError {
                        contract_id,
                        contract: Some(contract.clone()),
                        error_type: OutgoingPaymentErrorType::SwapFailed {
                            swap_error: format!(
                                "Failed to subscribe to ln receive of direct swap: {e}"
                            ),
                        },
                    }
                })?
                .into_stream();

            loop {
                debug!("Waiting next state of preimage buy for contract {contract:?}");
                if let Some(state) = stream.next().await {
                    match state {
                        GatewayExtReceiveStates::Funding => {
                            debug!(?contract, "Funding");
                            continue;
                        }
                        GatewayExtReceiveStates::Preimage(preimage) => {
                            debug!(?contract, "Received preimage");
                            return Ok(preimage);
                        }
                        other => {
                            warn!(?contract, "Got state {other:?}");
                            return Err(OutgoingPaymentError {
                                contract_id: contract.contract.contract_id(),
                                contract: Some(contract),
                                error_type: OutgoingPaymentErrorType::SwapFailed {
                                    swap_error: "Failed to receive preimage".to_string(),
                                },
                            });
                        }
                    }
                }
            }
        }
        .instrument(client.span())
        .await
    }

    fn transition_claim_outgoing_contract(
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
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
            move |dbtx, (), _| {
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
        info!("Canceling outgoing contract {contract:?}");

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                OutgoingPaymentFailed {
                    outgoing_contract: contract.clone(),
                    contract_id: contract.contract.contract_id(),
                    error: error.clone(),
                },
            )
            .await;

        let cancel_signature = context.secp.sign_schnorr(
            &bitcoin::secp256k1::Message::from_digest(
                *contract.contract.cancellation_message().as_ref(),
            ),
            &context.redeem_key,
        );
        let cancel_output = LightningOutput::new_v0_cancel_outgoing(
            contract.contract.contract_id(),
            cancel_signature,
        );
        let client_output = ClientOutput::<LightningOutput> {
            output: cancel_output,
            amounts: Amounts::ZERO,
        };

        match global_context
            .fund_output(dbtx, ClientOutputBundle::new_no_sm(vec![client_output]))
            .await
        {
            Ok(change_range) => {
                info!(
                    "Canceled outgoing contract {contract:?} with txid {:?}",
                    change_range.txid()
                );
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Canceled {
                        txid: change_range.txid(),
                        contract_id: contract.contract.contract_id(),
                        error,
                    },
                }
            }
            Err(e) => {
                warn!("Failed to cancel outgoing contract {contract:?}: {e:?}");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Failed {
                        error,
                        error_message: format!(
                            "Failed to submit refund transaction to federation {e:?}"
                        ),
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::key::Keypair;
    use fedimint_core::Amount;
    use fedimint_core::secp256k1::{self, SecretKey};
    use fedimint_ln_client::pay::PaymentData;
    use fedimint_ln_common::PrunedInvoice;
    use fedimint_ln_common::contracts::IdentifiableContract as _;
    use fedimint_ln_common::contracts::outgoing::{OutgoingContract, OutgoingContractAccount};
    use lightning_invoice::RoutingFees;

    use super::{GatewayPayInvoice, OutgoingContractError, TIMELOCK_DELTA};

    const CONSENSUS_BLOCK_COUNT: u64 = 1;
    const INVOICE_AMOUNT: Amount = Amount::from_msats(1000);

    fn gateway_keypair() -> Keypair {
        Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &SecretKey::from_slice(&[1; 32]).expect("Valid secret key"),
        )
    }

    /// An account that is valid in every respect other than the payment hash,
    /// which the caller chooses so a mismatch can be tested in isolation.
    fn contract_account(hash: sha256::Hash) -> OutgoingContractAccount {
        // Comfortably beyond `CONSENSUS_BLOCK_COUNT + TIMELOCK_DELTA`
        contract_account_with_timelock(hash, 100)
    }

    fn contract_account_with_timelock(
        hash: sha256::Hash,
        timelock: u32,
    ) -> OutgoingContractAccount {
        contract_account_with(hash, INVOICE_AMOUNT, timelock)
    }

    fn contract_account_with(
        hash: sha256::Hash,
        amount: Amount,
        timelock: u32,
    ) -> OutgoingContractAccount {
        let gateway_key = secp256k1::PublicKey::from_keypair(&gateway_keypair());

        OutgoingContractAccount {
            amount,
            contract: OutgoingContract {
                hash,
                gateway_key,
                timelock,
                user_key: gateway_key,
                cancelled: false,
            },
        }
    }

    fn payment_data(payment_hash: sha256::Hash) -> PaymentData {
        pruned_payment_data(payment_hash, INVOICE_AMOUNT)
    }

    fn pruned_payment_data(payment_hash: sha256::Hash, amount: Amount) -> PaymentData {
        PaymentData::PrunedInvoice(PrunedInvoice {
            amount,
            destination: secp256k1::PublicKey::from_keypair(&gateway_keypair()),
            destination_features: vec![],
            payment_hash,
            payment_secret: [0; 32],
            route_hints: vec![],
            min_final_cltv_delta: 0,
            expiry_timestamp: u64::MAX,
        })
    }

    fn validate(
        contract_hash: sha256::Hash,
        invoice_hash: sha256::Hash,
    ) -> Result<(), OutgoingContractError> {
        validate_account(&contract_account(contract_hash), invoice_hash)
    }

    /// Surfaces a recorded fresh-dispatch refusal as an error so tests can
    /// assert on the drifting gates alongside the hard validation errors.
    fn validate_account(
        account: &OutgoingContractAccount,
        invoice_hash: sha256::Hash,
    ) -> Result<(), OutgoingContractError> {
        validate_payment_data(account, &payment_data(invoice_hash))
    }

    fn validate_payment_data(
        account: &OutgoingContractAccount,
        payment_data: &PaymentData,
    ) -> Result<(), OutgoingContractError> {
        GatewayPayInvoice::validate_outgoing_account(
            account,
            gateway_keypair(),
            CONSENSUS_BLOCK_COUNT,
            payment_data,
            RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
        )
        .and_then(|parameters| parameters.fresh_dispatch.map(|_| ()))
    }

    /// Payment data whose invoice expired at the unix epoch.
    fn expired_payment_data(payment_hash: sha256::Hash) -> PaymentData {
        match payment_data(payment_hash) {
            PaymentData::PrunedInvoice(mut invoice) => {
                invoice.expiry_timestamp = 0;
                PaymentData::PrunedInvoice(invoice)
            }
            PaymentData::Invoice(..) => unreachable!("the fixture builds a pruned invoice"),
        }
    }

    /// Guards against the fixture being invalid for some unrelated reason,
    /// which would make the rejection test below pass vacuously.
    #[test]
    fn accepts_contract_matching_the_invoice() {
        let hash = sha256::Hash::hash(b"preimage");

        assert_eq!(validate(hash, hash), Ok(()));
    }

    /// A timelock close enough to the consensus height that `max_delay`
    /// computes to zero must refuse a fresh dispatch: LND treats a CLTV limit
    /// of zero as "unset" and substitutes its `--max-cltv-expiry` default,
    /// which would let the HTLC outlive the contract timelock and the user
    /// refund the contract while the payment is still in flight. The refusal
    /// is recorded rather than failing validation so a payment dispatched
    /// before a restart can still resume.
    #[test]
    fn rejects_timelock_yielding_a_max_delay_of_zero() {
        let hash = sha256::Hash::hash(b"preimage");
        let zero_delay_timelock =
            u32::try_from(CONSENSUS_BLOCK_COUNT - 1 + TIMELOCK_DELTA).expect("small constant");

        let validate_with_timelock =
            |timelock| validate_account(&contract_account_with_timelock(hash, timelock), hash);

        // The smallest acceptable timelock, asserted so this test pins the
        // boundary rather than passing against a check that rejects
        // everything.
        assert_eq!(validate_with_timelock(zero_delay_timelock + 1), Ok(()));

        assert_eq!(
            validate_with_timelock(zero_delay_timelock),
            Err(OutgoingContractError::TimeoutTooClose)
        );
        assert_eq!(
            validate_with_timelock(zero_delay_timelock - 1),
            Err(OutgoingContractError::TimeoutTooClose)
        );
    }

    /// An expired invoice must refuse a fresh dispatch. Like the timelock
    /// gate, the refusal is recorded rather than failing validation, so a
    /// payment dispatched before a restart can still resume past it.
    #[test]
    fn records_refusal_for_an_expired_invoice() {
        let hash = sha256::Hash::hash(b"preimage");

        assert_eq!(
            validate_payment_data(&contract_account(hash), &expired_payment_data(hash)),
            Err(OutgoingContractError::InvoiceExpired(0))
        );
    }

    /// When both drifting gates fail, the timelock refusal is reported: with
    /// no timelock budget left the payment cannot be dispatched at all, so
    /// expiry never gets a say. Pinned so error reporting stays stable.
    #[test]
    fn timelock_refusal_takes_precedence_over_expiry() {
        let hash = sha256::Hash::hash(b"preimage");
        let zero_delay_timelock =
            u32::try_from(CONSENSUS_BLOCK_COUNT - 1 + TIMELOCK_DELTA).expect("small constant");

        assert_eq!(
            validate_payment_data(
                &contract_account_with_timelock(hash, zero_delay_timelock),
                &expired_payment_data(hash),
            ),
            Err(OutgoingContractError::TimeoutTooClose)
        );
    }

    #[test]
    fn rejects_contract_not_committing_to_the_invoice() {
        // A client picks the contract id and the invoice independently, so a
        // contract funded against an unrelated hash must not authorize paying
        // this invoice: the preimage we would obtain cannot claim the contract,
        // leaving the gateway out of pocket with no way to recover.
        let contract_hash = sha256::Hash::hash(b"contract preimage");
        let invoice_hash = sha256::Hash::hash(b"unrelated invoice preimage");

        assert_eq!(
            validate(contract_hash, invoice_hash),
            Err(OutgoingContractError::InvalidOutgoingContract {
                contract_id: contract_account(contract_hash).contract.contract_id(),
            })
        );
    }

    /// A pruned invoice's amount is a raw, caller-supplied `u64`. An amount so
    /// large that `payment_amount + fee` overflows must be rejected: otherwise
    /// the sum wraps to a small value, the underfunding check passes against a
    /// near-empty contract, and the gateway pays out real funds it can never
    /// reclaim.
    #[test]
    fn rejects_invoice_amount_that_would_overflow_the_underfunding_check() {
        let hash = sha256::Hash::hash(b"preimage");

        // A one-millisatoshi base fee makes `u64::MAX + fee` wrap to zero, so
        // before the fix the underfunding check passed against any contract.
        let fees = RoutingFees {
            base_msat: 1,
            proportional_millionths: 0,
        };

        let validate_amount = |contract_amount: Amount, invoice_amount: Amount| {
            GatewayPayInvoice::validate_outgoing_account(
                &contract_account_with(hash, contract_amount, 100),
                gateway_keypair(),
                CONSENSUS_BLOCK_COUNT,
                &pruned_payment_data(hash, invoice_amount),
                fees,
            )
            .map(|_| ())
        };

        // The attack: a wrapping invoice amount against a near-empty contract.
        assert_eq!(
            validate_amount(Amount::from_msats(1), Amount::from_msats(u64::MAX)),
            Err(OutgoingContractError::InvoiceAmountTooLarge)
        );

        // The largest amount whose sum with the fee still fits is accepted when
        // the contract funds it, so the guard rejects exactly the overflow and
        // nothing else.
        let largest_representable = Amount::from_msats(u64::MAX - u64::from(fees.base_msat));
        assert_eq!(
            validate_amount(Amount::from_msats(u64::MAX), largest_representable),
            Ok(())
        );
    }
}
