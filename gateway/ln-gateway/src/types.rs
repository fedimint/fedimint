//! Map `gateway_lnrpc` protobuf types to rust types

use std::fmt::Display;

use anyhow::anyhow;
use fedimint_core::secp256k1::PublicKey;
use hex::ToHex;

use crate::gateway_lnrpc::InterceptHtlcRequest;

impl TryFrom<crate::gateway_lnrpc::get_route_hints_response::RouteHintHop>
    for fedimint_ln_common::route_hints::RouteHintHop
{
    type Error = anyhow::Error;

    fn try_from(
        hop: crate::gateway_lnrpc::get_route_hints_response::RouteHintHop,
    ) -> Result<Self, Self::Error> {
        let binding = hop.src_node_id.try_into();
        let slice: &[u8; 33] = match &binding {
            Ok(slice) => slice,
            Err(_) => return Err(anyhow!("malformed source node id")),
        };

        Ok(Self {
            src_node_id: PublicKey::from_slice(slice).expect("invalid source node id"),
            short_channel_id: hop.short_channel_id,
            base_msat: hop.base_msat,
            proportional_millionths: hop.proportional_millionths,
            cltv_expiry_delta: hop.cltv_expiry_delta as u16,
            htlc_minimum_msat: hop.htlc_minimum_msat,
            htlc_maximum_msat: hop.htlc_maximum_msat,
        })
    }
}

impl TryFrom<crate::gateway_lnrpc::GetRouteHintsResponse>
    for Vec<fedimint_ln_common::route_hints::RouteHint>
{
    type Error = anyhow::Error;

    fn try_from(res: crate::gateway_lnrpc::GetRouteHintsResponse) -> Result<Self, Self::Error> {
        let mut route_hints = Vec::<fedimint_ln_common::route_hints::RouteHint>::new();

        for route_hint in res.route_hints {
            let mut hops = Vec::new();

            for hop in route_hint.hops {
                hops.push(hop.try_into()?);
            }

            route_hints.push(fedimint_ln_common::route_hints::RouteHint(hops));
        }

        Ok(route_hints)
    }
}

/// Utility struct for formatting an intercepted HTLC. Useful for debugging.
pub struct PrettyInterceptHtlcRequest<'a>(pub &'a InterceptHtlcRequest);

impl Display for PrettyInterceptHtlcRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PrettyInterceptHtlcRequest(htlc_request) = self;
        write!(
            f,
            "InterceptHtlcRequest {{ payment_hash: {}, incoming_amount_msat: {:?}, outgoing_amount_msat: {:?}, incoming_expiry: {:?}, short_channel_id: {:?}, incoming_chan_id: {:?}, htlc_id: {:?} }}",
            htlc_request.payment_hash.encode_hex::<String>(),
            htlc_request.incoming_amount_msat,
            htlc_request.outgoing_amount_msat,
            htlc_request.incoming_expiry,
            htlc_request.short_channel_id,
            htlc_request.incoming_chan_id,
            htlc_request.htlc_id,
        )
    }
}
