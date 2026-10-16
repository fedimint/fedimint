// TODO: upstream serde support to LDK
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct RouteHintHop {
    /// The `node_id` of the non-target end of the route
    pub src_node_id: PublicKey,
    /// The `short_channel_id` of this channel
    pub short_channel_id: u64,
    /// Flat routing fee in millisatoshis
    pub base_msat: u32,
    /// Liquidity-based routing fee in millionths of a routed amount.
    /// In other words, 10000 is 1%.
    pub proportional_millionths: u32,
    /// The difference in CLTV values between this node and the next node.
    pub cltv_expiry_delta: u16,
    /// The minimum value, in msat, which must be relayed to the next hop.
    pub htlc_minimum_msat: Option<u64>,
    /// The maximum value in msat available for routing with a single HTLC.
    pub htlc_maximum_msat: Option<u64>,
}

/// A list of hops along a payment path terminating with a channel to the
/// recipient.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct RouteHint(pub Vec<RouteHintHop>);

impl RouteHint {
    pub fn to_ldk_route_hint(&self) -> lightning_invoice::RouteHint {
        lightning_invoice::RouteHint(
            self.0
                .iter()
                .map(|hop| lightning_invoice::RouteHintHop {
                    src_node_id: hop.src_node_id,
                    short_channel_id: hop.short_channel_id,
                    fees: RoutingFees {
                        base_msat: hop.base_msat,
                        proportional_millionths: hop.proportional_millionths,
                    },
                    cltv_expiry_delta: hop.cltv_expiry_delta,
                    htlc_minimum_msat: hop.htlc_minimum_msat,
                    htlc_maximum_msat: hop.htlc_maximum_msat,
                })
                .collect(),
        )
    }
}

impl From<lightning_invoice::RouteHint> for RouteHint {
    fn from(rh: lightning_invoice::RouteHint) -> Self {
        RouteHint(rh.0.into_iter().map(Into::into).collect())
    }
}

impl From<lightning_invoice::RouteHintHop> for RouteHintHop {
    fn from(rhh: lightning_invoice::RouteHintHop) -> Self {
        RouteHintHop {
            src_node_id: rhh.src_node_id,
            short_channel_id: rhh.short_channel_id,
            base_msat: rhh.fees.base_msat,
            proportional_millionths: rhh.fees.proportional_millionths,
            cltv_expiry_delta: rhh.cltv_expiry_delta,
            htlc_minimum_msat: rhh.htlc_minimum_msat,
            htlc_maximum_msat: rhh.htlc_maximum_msat,
        }
    }
}
