use std::fmt::Display;
use std::sync::Arc;

use bitcoin_hashes::sha256;
use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientOutput};
use fedimint_client::{ClientArc, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, IdentifiableContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use futures::future;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use super::{GatewayClientContext, GatewayClientStateMachines, GatewayExtReceiveStates};
use crate::db::PreimageAuthentication;
use crate::gateway_lnrpc::{PayInvoiceRequest, PayInvoiceResponse};
use crate::lightning::LightningRpcError;
use crate::state_machine::GatewayClientModule;
use crate::GatewayState;

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
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayCommon {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
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
    #[error("The invoice is expired. Expiry happened at timestamp: {0}")]
    InvoiceExpired(u64),
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
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
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub struct OutgoingPaymentError {
    error_type: OutgoingPaymentErrorType,
    contract_id: ContractId,
    contract: Option<OutgoingContractAccount>,
}

impl Display for OutgoingPaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingContractError: {}", self.error_type)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayInvoice {
    pub pay_invoice_payload: PayInvoicePayload,
}

impl GatewayPayInvoice {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let payload = self.pay_invoice_payload.clone();
        vec![StateTransition::new(
            Self::fetch_parameters_and_pay(
                global_context,
                payload.clone(),
                context.clone(),
                common.clone(),
            ),
            move |_dbtx, result, _old_state| Box::pin(futures::future::ready(result)),
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

    async fn buy_preimage(
        context: GatewayClientContext,
        contract: OutgoingContractAccount,
        payment_parameters: PaymentParameters,
        common: GatewayPayCommon,
        payload: PayInvoicePayload,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage contract {contract:?}");
        // Verify that this client is authorized to receive the preimage.
        if let Err(err) = Self::verify_preimage_authentication(
            &context,
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

        if let Some(client) =
            Self::check_swap_to_federation(context.clone(), payment_parameters.payment_data.clone())
                .await
        {
            Self::buy_preimage_via_direct_swap(
                client,
                payment_parameters.payment_data.clone(),
                contract.clone(),
                common.clone(),
            )
            .await
        } else {
            Self::buy_preimage_over_lightning(
                context,
                payment_parameters,
                contract.clone(),
                common.clone(),
            )
            .await
        }
    }

    async fn await_get_payment_parameters(
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        contract_id: ContractId,
        payment_data: PaymentData,
    ) -> Result<(OutgoingContractAccount, PaymentParameters), OutgoingPaymentError> {
        debug!("Await payment parameters for outgoing contract {contract_id:?}");
        let account = global_context
            .module_api()
            .wait_contract(contract_id)
            .await
            .map_err(|_| OutgoingPaymentError {
                contract_id,
                contract: None,
                error_type: OutgoingPaymentErrorType::OutgoingContractDoesNotExist { contract_id },
            })?;

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

            debug!("Consensus block count: {consensus_block_count:?} for outgoing contract {contract_id:?}");
            if consensus_block_count.is_none() {
                return Err(OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                        error: OutgoingContractError::MissingContractData,
                    },
                });
            }

            let payment_parameters = Self::validate_outgoing_account(
                &outgoing_contract_account,
                context.redeem_key,
                context.timelock_delta,
                consensus_block_count.unwrap(),
                &payment_data,
            )
            .await
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
        let payment_data = buy_preimage.payment_data.clone();

        let max_delay = buy_preimage.max_delay;
        let max_fee = buy_preimage.max_send_amount
            - buy_preimage
                .payment_data
                .amount()
                .expect("We already checked that an amount was supplied");

        let lightning_context = match context.gateway.get_lightning_context().await {
            Ok(lightning_context) => lightning_context,
            Err(error) => {
                return Self::gateway_pay_cancel_contract(error, contract, common);
            }
        };

        let payment_result = match buy_preimage.payment_data {
            PaymentData::Invoice(invoice) => {
                lightning_context
                    .lnrpc
                    .pay(PayInvoiceRequest {
                        invoice: invoice.to_string(),
                        max_delay,
                        max_fee_msat: max_fee.msats,
                        payment_hash: payment_data.payment_hash().to_vec(),
                    })
                    .await
            }
            PaymentData::PrunedInvoice(invoice) => {
                lightning_context
                    .lnrpc
                    .pay_private(invoice, buy_preimage.max_delay, max_fee)
                    .await
            }
        };

        match payment_result {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                debug!("Preimage received for contract {contract:?}");
                let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                        GatewayPayClaimOutgoingContract {
                            contract,
                            preimage: Preimage(slice),
                        },
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
        client: ClientArc,
        payment_data: PaymentData,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage via direct swap for contract {contract:?}");
        match payment_data.try_into() {
            Ok(swap_params) => match client
                .get_first_module::<GatewayClientModule>()
                .gateway_handle_direct_swap(swap_params)
                .await
            {
                Ok(operation_id) => {
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

    /// Verifies that the supplied `preimage_auth` is the same as the
    /// `preimage_auth` that initiated the payment. If it is not, then this
    /// will return an error because this client is not authorized to receive
    /// the preimage.
    async fn verify_preimage_authentication(
        context: &GatewayClientContext,
        payment_hash: sha256::Hash,
        preimage_auth: sha256::Hash,
        contract: OutgoingContractAccount,
    ) -> Result<(), OutgoingPaymentError> {
        let mut dbtx = context.gateway.gateway_db.begin_transaction().await;
        if let Some(secret_hash) = dbtx
            .get_value(&PreimageAuthentication { payment_hash })
            .await
        {
            if secret_hash != preimage_auth {
                return Err(OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvoiceAlreadyPaid,
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract),
                });
            }
        } else {
            // Committing the `preimage_auth` to the database can fail if two users try to
            // pay the same invoice at the same time.
            dbtx.insert_new_entry(&PreimageAuthentication { payment_hash }, &preimage_auth)
                .await;
            return dbtx
                .commit_tx_result()
                .await
                .map_err(|_| OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvoiceAlreadyPaid,
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract),
                });
        }

        Ok(())
    }

    async fn validate_outgoing_account(
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::KeyPair,
        timelock_delta: u64,
        consensus_block_count: u64,
        payment_data: &PaymentData,
    ) -> Result<PaymentParameters, OutgoingContractError> {
        let our_pub_key = secp256k1::PublicKey::from_keypair(&redeem_key);

        if account.contract.cancelled {
            return Err(OutgoingContractError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(OutgoingContractError::NotOurKey);
        }

        let payment_amount = payment_data
            .amount()
            .ok_or(OutgoingContractError::InvoiceMissingAmount)?;

        if account.amount < payment_amount {
            return Err(OutgoingContractError::Underfunded(
                payment_amount,
                account.amount,
            ));
        }

        let max_delay = (account.contract.timelock as u64)
            .checked_sub(consensus_block_count.saturating_sub(1))
            .and_then(|delta| delta.checked_sub(timelock_delta));
        if max_delay.is_none() {
            return Err(OutgoingContractError::TimeoutTooClose);
        }

        if payment_data.is_expired() {
            return Err(OutgoingContractError::InvoiceExpired(
                payment_data.expiry_timestamp(),
            ));
        }

        Ok(PaymentParameters {
            max_delay: max_delay.unwrap(),
            max_send_amount: account.amount,
            payment_data: payment_data.clone(),
        })
    }

    // Checks if the invoice route hint last hop has source node id matching this
    // gateways node pubkey and if the short channel id matches one assigned by
    // this gateway to a connected federation. In this case, the gateway can
    // avoid paying the invoice over the lightning network and instead perform a
    // direct swap between the two federations.
    async fn check_swap_to_federation(
        context: GatewayClientContext,
        payment_data: PaymentData,
    ) -> Option<ClientArc> {
        let rhints = payment_data.route_hints();
        match rhints.first().and_then(|rh| rh.0.last()) {
            None => None,
            Some(hop) => match context.gateway.state.read().await.clone() {
                GatewayState::Running { lightning_context } => {
                    if hop.src_node_id != lightning_context.lightning_public_key {
                        return None;
                    }

                    let scid_to_feds = context.gateway.scid_to_federation.read().await;
                    match scid_to_feds.get(&hop.short_channel_id).cloned() {
                        None => None,
                        Some(federation_id) => {
                            let clients = context.gateway.clients.read().await;
                            clients.get(&federation_id).cloned()
                        }
                    }
                }
                _ => None,
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
pub struct PaymentParameters {
    max_delay: u64,
    max_send_amount: Amount,
    payment_data: PaymentData,
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
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
        debug!("Claiming outgoing contract {contract:?}");
        let claim_input = contract.claim(preimage.clone());
        let client_input = ClientInput::<LightningInput, GatewayClientStateMachines> {
            input: claim_input,
            state_machines: Arc::new(|_, _| vec![]),
            keys: vec![context.redeem_key],
        };

        let out_points = global_context.claim_input(dbtx, client_input).await.1;
        debug!("Claimed outgoing contract {contract:?} with out points {out_points:?}");
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::Preimage(out_points, preimage),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
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
        debug!("Waiting preimage for contract {contract:?}");
        let client = context
            .gateway
            .clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(OutgoingPaymentError {
                contract_id: contract.contract.contract_id(),
                contract: Some(contract.clone()),
                error_type: OutgoingPaymentErrorType::SwapFailed {
                    swap_error: "Federation client not found".to_string(),
                },
            })?;

        let mut stream = client
            .get_first_module::<GatewayClientModule>()
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

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
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
        info!("Canceling outgoing contract {contract:?}");
        let cancel_signature = context.secp.sign_schnorr(
            &contract.contract.cancellation_message().into(),
            &context.redeem_key,
        );
        let cancel_output = LightningOutput::new_v0_cancel_outgoing(
            contract.contract.contract_id(),
            cancel_signature,
        );
        let client_output = ClientOutput::<LightningOutput, GatewayClientStateMachines> {
            output: cancel_output,
            state_machines: Arc::new(|_, _| vec![]),
        };

        match global_context.fund_output(dbtx, client_output).await {
            Ok((txid, _)) => {
                info!("Canceled outgoing contract {contract:?} with txid {txid:?}");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Canceled {
                        txid,
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
