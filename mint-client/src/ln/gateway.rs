use bitcoin::secp256k1;
use lightning::routing::network_graph::RoutingFees;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGateway {
    pub mint_pub_key: secp256k1::schnorrsig::PublicKey,
    pub node_pub_key: secp256k1::PublicKey,
    pub api: String,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

mod serde_routing_fees {
    use lightning::routing::network_graph::RoutingFees;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(rf: &RoutingFees, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (rf.base_msat, rf.proportional_millionths).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RoutingFees, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (base_msat, proportional_millionths) = <(u32, u32)>::deserialize(deserializer)?;

        Ok(RoutingFees {
            base_msat,
            proportional_millionths,
        })
    }
}
