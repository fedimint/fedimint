use anyhow::Context;
use bitcoin::hashes::sha256;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{encode_bolt11_invoice_features_without_length, Amount};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Preimage(pub [u8; 32]);

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

/// Data needed to pay an invoice
///
/// This is a subset of the data from a [`lightning_invoice::Bolt11Invoice`]
/// that does not contain the description, which increases privacy for the user.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub struct PrunedInvoice {
    pub amount: Amount,
    pub destination: PublicKey,
    /// Wire-format encoding of feature bit vector
    #[serde(with = "fedimint_core::hex::serde", default)]
    pub destination_features: Vec<u8>,
    pub payment_hash: sha256::Hash,
    pub payment_secret: [u8; 32],
    pub route_hints: Vec<RouteHint>,
    pub min_final_cltv_delta: u64,
    /// Time at which the invoice expires in seconds since unix epoch
    pub expiry_timestamp: u64,
}

impl PrunedInvoice {
    pub fn new(invoice: &Bolt11Invoice, amount: Amount) -> Self {
        // We use expires_at since it doesn't rely on the std feature in
        // lightning-invoice. See #3838.
        let expiry_timestamp = invoice.expires_at().map_or(u64::MAX, |t| t.as_secs());

        let destination_features = if let Some(features) = invoice.features() {
            encode_bolt11_invoice_features_without_length(features)
        } else {
            vec![]
        };

        PrunedInvoice {
            amount,
            destination: invoice
                .payee_pub_key()
                .copied()
                .unwrap_or_else(|| invoice.recover_payee_pub_key()),
            destination_features,
            payment_hash: *invoice.payment_hash(),
            payment_secret: invoice.payment_secret().0,
            route_hints: invoice.route_hints().into_iter().map(Into::into).collect(),
            min_final_cltv_delta: invoice.min_final_cltv_expiry_delta(),
            expiry_timestamp,
        }
    }
}

impl TryFrom<Bolt11Invoice> for PrunedInvoice {
    type Error = anyhow::Error;

    fn try_from(invoice: Bolt11Invoice) -> Result<Self, Self::Error> {
        Ok(PrunedInvoice::new(
            &invoice,
            Amount::from_msats(
                invoice
                    .amount_milli_satoshis()
                    .context("Invoice amount is missing")?,
            ),
        ))
    }
}
