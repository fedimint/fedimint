//! Error types of the lightning client.
//!
//! Every failure this module reports to its callers is named here, so there is
//! one place for an integrator to look.

use fedimint_api_client::api::{FederationError, ServerError};
use fedimint_client_module::error::{
    OperationAlreadyExistsError, OperationLookupError, TransactionSubmitError,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::DatabaseError;
use fedimint_core::secp256k1;
use fedimint_core::secp256k1::PublicKey;
#[cfg(feature = "uniffi")]
use fedimint_core::util::FmtCompact as _;
use fedimint_ln_common::contracts::ContractId;
use lightning_invoice::{CreationError, Currency};
use thiserror::Error;

use crate::incoming::IncomingSmError;

/// A failure to pick a Lightning gateway for an operation.
///
/// Choosing a gateway is one question with two entry points: pick the best
/// available one, or look a specific one up. Both can end without a usable
/// answer, either because the federation has no registrations at all or
/// because the ones it has do not respond.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewaySelectionError {
    /// The caller named a gateway and that gateway did not answer.
    #[error("Gateway {gateway_id} is offline")]
    Offline {
        /// The gateway the caller asked for.
        gateway_id: PublicKey,
    },

    /// No gateway is registered with the federation, so there is nothing to
    /// choose from.
    #[error("No gateway is registered with the federation")]
    NoGatewaysRegistered,

    /// Gateways are registered, but none of them answered.
    #[error("No registered gateway was reachable")]
    NoneReachable,

    /// The gateway cache could not be refreshed from the federation, so there
    /// is no up-to-date list to choose from.
    #[error("The gateway cache could not be refreshed")]
    Federation(#[source] Box<FederationError>),
}

impl From<FederationError> for GatewaySelectionError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

#[cfg(feature = "uniffi")]
impl From<GatewaySelectionError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: GatewaySelectionError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to work out the largest invoice amount the client could pay in
/// full.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpendableAmountError {
    /// No gateway could be chosen, so there is no fee schedule to compute
    /// against.
    #[error("No gateway could be selected for the payment")]
    Gateway(#[from] GatewaySelectionError),

    /// Gateway selection succeeded but returned nothing.
    ///
    /// This is defensive: the selection this method performs always either
    /// yields a gateway or fails, so no caller is expected to see it.
    #[error("No gateway is available to send the payment")]
    NoGatewayAvailable,

    /// The balance cannot cover the smallest payable amount plus the gateway
    /// and federation fees, so there is no amount to send.
    #[error("The balance {balance} is too low to send any amount after fees")]
    BalanceTooLow {
        /// The balance the answer was computed against.
        balance: fedimint_core::Amount,
    },

    /// The fee probe failed for a reason unrelated to the balance.
    #[error("The fee quote for the payment failed")]
    Quote(#[source] TransactionSubmitError),
}

/// A failure to follow a lightning operation.
///
/// Every entry point that takes an operation id and reports on it, the pay,
/// receive, claim and recurring-receive subscriptions, the payment-detail
/// lookup and the outgoing-payment await, first has to find the operation and
/// then check that it is the kind of lightning operation being asked about.
/// Both halves are named here, so a caller can tell "I have never seen that
/// operation" from "that operation is a receive, not a payment".
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LnSubscribeError {
    /// The operation could not be looked up, or belongs to another module.
    #[error("The lightning operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation belongs to the lightning module, but it is not an
    /// outgoing payment.
    #[error("The operation is not a lightning payment")]
    NotAPayment,

    /// The operation belongs to the lightning module, but it is not a receive.
    #[error("The operation is not a lightning receive")]
    NotAReceive,

    /// The operation belongs to the lightning module, but it is not a claim of
    /// an already-funded incoming contract.
    #[error("The operation is not a lightning claim")]
    NotAClaim,

    /// The operation belongs to the lightning module, but it is not a receive
    /// against a recurring payment code.
    #[error("The operation is not a recurring lightning receive")]
    NotARecurringReceive,

    /// The operation is a payment, but it is settled inside the federation
    /// rather than over Lightning, so it has no external payment states.
    #[error("The operation is an external lightning payment, not an internal one")]
    NotInternalPayment,

    /// The operation is a payment, but it is settled inside the federation, so
    /// it has no Lightning payment states.
    #[error("The operation is an internal lightning payment, not an external one")]
    NotExternalPayment,

    /// The payment's update stream ended without reaching a final state.
    #[error("The outgoing lightning payment did not reach a final state")]
    NoFinalState,
}

#[cfg(feature = "uniffi")]
impl From<LnSubscribeError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: LnSubscribeError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to pay a BOLT11 invoice.
///
/// The first three variants predate this type's move into this module and are
/// the conditions a caller most often has to react to: an attempt that is
/// still running, no gateway to route through, and a contract that someone has
/// already funded for this payment hash. The rest name what used to be folded
/// into one opaque message: the invoice itself being unusable, the gateway or
/// the federation refusing, and the transaction failing to submit.
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
#[non_exhaustive]
pub enum PayBolt11InvoiceError {
    /// An earlier attempt to pay this same invoice has not finished.
    #[error("Previous payment attempt({}) still in progress", .operation_id.fmt_full())]
    PreviousPaymentAttemptStillInProgress {
        /// The operation the earlier attempt runs under.
        operation_id: OperationId,
    },

    /// The payment has to go out over Lightning and no gateway was supplied.
    #[error("No LN gateway available")]
    NoLnGatewayAvailable,

    /// A contract for this payment hash is already funded, so funding another
    /// would pay twice.
    #[error("Funded contract already exists: {}", .contract_id)]
    FundedContractAlreadyExists {
        /// The contract that already holds funds.
        contract_id: ContractId,
    },

    /// The invoice's expiry has passed, so the recipient will not accept the
    /// payment.
    #[error("The invoice has expired")]
    InvoiceExpired,

    /// The invoice is for a different chain than this federation runs on.
    #[error("The invoice is for {found:?}, but this federation is on {expected:?}")]
    WrongCurrency {
        /// The currency this federation's network implies.
        expected: Currency,
        /// The currency the invoice names.
        found: Currency,
    },

    /// The invoice carries no amount, so there is nothing to lock into a
    /// contract.
    #[error("The invoice does not specify an amount")]
    MissingInvoiceAmount,

    /// The chosen gateway did not answer, so funding a contract for it would
    /// lock money up with nobody to claim it.
    #[error("The gateway is not available")]
    GatewayUnavailable(#[source] ServerError),

    /// The federation did not report a consensus block count, so the
    /// contract's timelock cannot be computed.
    #[error("The federation did not report a consensus block count")]
    NoConsensusBlockCount,

    /// A request to the federation failed.
    #[error("The federation request failed")]
    Federation(#[source] Box<FederationError>),

    /// The internal (federation-settled) contract for this payment could not
    /// be built.
    #[error("The internal payment contract could not be created")]
    InternalContract(#[source] IncomingSmError),

    /// This client's internal-payment markers could not be derived, so an
    /// internal payment cannot be recognised.
    #[error("The internal payment markers could not be derived")]
    PaymentMarkers(#[source] secp256k1::Error),

    /// The caller's extra metadata could not be serialized into the operation
    /// log.
    #[error("The extra metadata could not be serialized")]
    ExtraMeta(#[source] serde_json::Error),

    /// The payment attempt could not be written to the database.
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// The transaction funding the payment could not be built or submitted.
    #[error("The payment transaction could not be submitted")]
    Transaction(#[from] TransactionSubmitError),
}

impl From<FederationError> for PayBolt11InvoiceError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

#[cfg(feature = "uniffi")]
impl From<PayBolt11InvoiceError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: PayBolt11InvoiceError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to create a BOLT11 invoice to be paid into this federation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CreateBolt11InvoiceError {
    /// This client's internal-payment markers could not be derived, so the
    /// invoice cannot be built for an internal payment.
    #[error("The internal payment markers could not be derived")]
    PaymentMarkers(#[source] secp256k1::Error),

    /// The invoice could not be assembled from the parameters given.
    #[error("The invoice could not be built")]
    InvoiceCreation(#[source] CreationError),

    /// The transaction publishing the offer could not be built or submitted.
    #[error("The offer transaction could not be submitted")]
    Transaction(#[from] TransactionSubmitError),

    /// The federation rejected the transaction publishing the offer, so
    /// nothing would be able to pay the invoice.
    ///
    /// The payload is the message the submission recorded rather than an error
    /// value, so it is part of this error's own message.
    #[error("The offer transaction was rejected: {reason}")]
    OfferRejected {
        /// What the submission reported.
        reason: String,
    },
}

#[cfg(feature = "uniffi")]
impl From<CreateBolt11InvoiceError> for fedimint_core::util::ffi::UniffiError {
    fn from(e: CreateBolt11InvoiceError) -> Self {
        Self::General(e.fmt_compact().to_string())
    }
}

/// A failure to claim an incoming contract the federation already holds.
///
/// This is the deprecated pre-recurring-payments receive path: a client that
/// knows the key an invoice was issued against goes looking for the contract
/// funded under it and spends it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaimIncomingContractError {
    /// The federation holds no funded contract under this id, so there is
    /// nothing to claim.
    #[error("No funded contract exists for {contract_id}")]
    ContractNotFound {
        /// The contract that was looked for.
        contract_id: ContractId,
    },

    /// The contract could not be fetched from the federation.
    #[error("The contract could not be fetched")]
    Federation(#[source] Box<FederationError>),

    /// The transaction claiming the contract could not be built or submitted.
    #[error("The claim transaction could not be submitted")]
    Transaction(#[from] TransactionSubmitError),
}

impl From<FederationError> for ClaimIncomingContractError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

/// A failure to restart the claim of an already-paid lightning invoice.
///
/// This is a break-glass recovery tool, so most of its refusals are about the
/// original operation not being in a state that can be reclaimed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReclaimLnReceiveError {
    /// The original operation could not be looked up, or belongs to another
    /// module.
    #[error("The original operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The original operation's metadata could not be read, which normally
    /// means an earlier database migration left it in a shape this version
    /// does not understand.
    #[error("The lightning operation metadata could not be read")]
    Meta(#[source] serde_json::Error),

    /// The original operation is a lightning operation, but not one of the
    /// receives a reclaim can restart.
    #[error("The operation is not a reclaimable lightning receive")]
    NotReclaimable,

    /// The original receive still has running state machines, so it is
    /// already trying to claim and a second attempt would race it.
    #[error("The lightning receive is still active")]
    StillActive,

    /// The key the invoice was issued against is not in this client's state
    /// history, so the contract cannot be spent.
    #[error("The original receive key is not available in the local state history")]
    ReceiveKeyUnavailable,

    /// An operation for the reclaim attempt already exists.
    #[error("The reclaim operation already exists")]
    OperationAlreadyExists(#[from] OperationAlreadyExistsError),
}
