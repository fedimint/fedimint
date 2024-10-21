//! Map `gateway_lnrpc` protobuf types to rust types

use std::fmt::Display;

use hex::ToHex;

use crate::lightning::InterceptPaymentRequest;

/// Utility struct for formatting an intercepted HTLC. Useful for debugging.
pub struct PrettyInterceptPaymentRequest<'a>(pub &'a InterceptPaymentRequest);

impl Display for PrettyInterceptPaymentRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PrettyInterceptPaymentRequest(payment_request) = self;
        write!(
            f,
            "InterceptPaymentRequest {{ payment_hash: {}, amount_msat: {:?}, expiry: {:?}, short_channel_id: {:?}, incoming_chan_id: {:?}, htlc_id: {:?} }}",
            payment_request.payment_hash.encode_hex::<String>(),
            payment_request.amount_msat,
            payment_request.expiry,
            payment_request.short_channel_id,
            payment_request.incoming_chan_id,
            payment_request.htlc_id,
        )
    }
}
