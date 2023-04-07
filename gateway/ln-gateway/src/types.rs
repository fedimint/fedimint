//! Map `gatewaylnrpc` protobuf types to rust types

use anyhow::anyhow;
use secp256k1::PublicKey;

impl TryFrom<crate::gatewaylnrpc::get_route_hints_response::RouteHintHop>
    for fedimint_client_legacy::modules::ln::route_hints::RouteHintHop
{
    type Error = anyhow::Error;

    fn try_from(
        hop: crate::gatewaylnrpc::get_route_hints_response::RouteHintHop,
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

impl TryFrom<crate::gatewaylnrpc::GetRouteHintsResponse>
    for Vec<fedimint_client_legacy::modules::ln::route_hints::RouteHint>
{
    type Error = anyhow::Error;

    fn try_from(res: crate::gatewaylnrpc::GetRouteHintsResponse) -> Result<Self, Self::Error> {
        let mut route_hints =
            Vec::<fedimint_client_legacy::modules::ln::route_hints::RouteHint>::new();

        for route_hint in res.route_hints {
            let mut hops = Vec::new();

            for hop in route_hint.hops {
                hops.push(hop.try_into()?);
            }

            route_hints.push(fedimint_client_legacy::modules::ln::route_hints::RouteHint(
                hops,
            ));
        }

        Ok(route_hints)
    }
}
