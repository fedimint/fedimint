//! Structured diagnostics for outgoing Lightning payments that failed.
//!
//! These are recorded in the gateway's event log so operators can tell where
//! in the network a payment failed, and why, without asking the payer for the
//! invoice. They are diagnostics only: nothing in the gateway branches on them.

use fedimint_core::Amount;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// The most HTLC attempts kept per failed payment.
///
/// LND may try a payment along many routes before giving up, and every
/// recorded attempt carries its whole route, so the record is capped to keep
/// event log entries small. The most recent attempts are kept: they reflect
/// the network as it was when the payment finally failed.
pub const MAX_RECORDED_FAILED_ATTEMPTS: usize = 10;

/// Why, and where in the network, an outgoing Lightning payment failed, as
/// far as the Lightning backend reports it.
#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable, Default,
)]
pub struct PaymentFailureDiagnostics {
    /// The backend's reason for failing the payment as a whole, such as LND's
    /// `FAILURE_REASON_NO_ROUTE` or LDK's `RouteNotFound`.
    pub payment_failure_reason: Option<String>,

    /// The failed HTLC attempts, oldest first. At most
    /// [`MAX_RECORDED_FAILED_ATTEMPTS`] are kept.
    ///
    /// Empty when the backend does not report individual attempts, which is
    /// always the case for LDK, or when the payment failed before any HTLC
    /// was sent, e.g. because no route was found.
    pub failed_attempts: Vec<FailedHtlcAttempt>,

    /// How many earlier failed attempts were left out of `failed_attempts`
    /// to respect [`MAX_RECORDED_FAILED_ATTEMPTS`].
    pub omitted_failed_attempts: u64,
}

impl PaymentFailureDiagnostics {
    /// Builds diagnostics from failed attempts in the order they were made,
    /// keeping only the most recent [`MAX_RECORDED_FAILED_ATTEMPTS`].
    pub fn new(
        payment_failure_reason: Option<String>,
        mut failed_attempts: Vec<FailedHtlcAttempt>,
    ) -> Self {
        let omitted = failed_attempts
            .len()
            .saturating_sub(MAX_RECORDED_FAILED_ATTEMPTS);
        failed_attempts.drain(..omitted);

        Self {
            payment_failure_reason,
            failed_attempts,
            omitted_failed_attempts: omitted as u64,
        }
    }
}

/// A single HTLC attempt of a payment that the network failed.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FailedHtlcAttempt {
    /// The route the HTLC was sent along, from the gateway's first hop to the
    /// destination.
    pub route: Vec<AttemptedHop>,

    /// The BOLT 4 failure code reported for the attempt in lower snake case,
    /// such as `temporary_channel_failure` or `unknown_next_peer`.
    ///
    /// `None` if the backend reported no failure details for the attempt.
    /// Besides BOLT 4 codes, LND reports failures it could not attribute to a
    /// hop as `internal_failure`, `unknown_failure` or `unreadable_failure`.
    pub failure_code: Option<String>,

    /// The position along `route` of the node that reported the failure: `0`
    /// is the gateway's own node and `i` is the node of `route[i - 1]`.
    pub failure_source_index: Option<u32>,

    /// The node that reported the failure. `None` if the gateway's own node
    /// reported it, or if the failure could not be attributed to a hop.
    pub failing_node: Option<PublicKey>,

    /// The short channel id of the channel the failing node could not forward
    /// the HTLC over. `None` when the destination itself failed the HTLC,
    /// since there is no next channel then.
    pub failing_short_channel_id: Option<u64>,
}

/// One hop along the route of an HTLC attempt.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct AttemptedHop {
    /// The node receiving the HTLC at this hop. `None` only if the backend
    /// reported a key that does not parse.
    pub node_id: Option<PublicKey>,

    /// The channel the HTLC reaches `node_id` over.
    pub short_channel_id: u64,

    /// The amount `node_id` forwards to the next hop, or receives if it is
    /// the destination.
    pub amount_to_forward: Amount,

    /// The fee `node_id` charges for forwarding to the next hop.
    pub fee: Amount,
}

#[cfg(test)]
mod tests;
