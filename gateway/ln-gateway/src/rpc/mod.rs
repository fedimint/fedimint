pub mod rpc_client;
pub mod rpc_server;

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin29::{Address, Network};
use fedimint_core::config::{ClientConfig, FederationId, JsonClientConfig};
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_ln_common::config::parse_routing_fees;
use fedimint_ln_common::{route_hints, serde_option_routing_fees};
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};

pub const V1_API_ENDPOINT: &str = "v1";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectFedPayload {
    pub invite_code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaveFedPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoPayload;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestorePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigPayload {
    pub federation_id: Option<FederationId>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BalancePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepositAddressPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawPayload {
    pub federation_id: FederationId,
    pub amount: BitcoinAmountOrAll,
    pub address: Address,
}

/// Information about one of the feds we are connected to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationInfo {
    pub federation_id: FederationId,
    pub balance_msat: Amount,
    pub config: ClientConfig,
    pub channel_id: Option<u64>,
    pub routing_fees: Option<FederationRoutingFees>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationInfo>,
    pub channels: Option<BTreeMap<u64, FederationId>>,
    pub lightning_pub_key: Option<String>,
    pub lightning_alias: Option<String>,
    #[serde(with = "serde_option_routing_fees")]
    pub fees: Option<RoutingFees>,
    pub route_hints: Vec<route_hints::RouteHint>,
    pub gateway_id: secp256k1::PublicKey,
    pub gateway_state: String,
    pub network: Option<Network>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayFedConfig {
    pub federations: BTreeMap<FederationId, JsonClientConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FederationRoutingFees {
    pub base_msat: u32,
    pub proportional_millionths: u32,
}

impl From<FederationRoutingFees> for RoutingFees {
    fn from(value: FederationRoutingFees) -> Self {
        RoutingFees {
            base_msat: value.base_msat,
            proportional_millionths: value.proportional_millionths,
        }
    }
}

impl From<RoutingFees> for FederationRoutingFees {
    fn from(value: RoutingFees) -> Self {
        FederationRoutingFees {
            base_msat: value.base_msat,
            proportional_millionths: value.proportional_millionths,
        }
    }
}

impl FromStr for FederationRoutingFees {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let routing_fees = parse_routing_fees(s)?;
        Ok(FederationRoutingFees {
            base_msat: routing_fees.base_msat,
            proportional_millionths: routing_fees.proportional_millionths,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetConfigurationPayload {
    pub password: Option<String>,
    pub num_route_hints: Option<u32>,
    pub routing_fees: Option<String>,
    pub network: Option<Network>,
    pub per_federation_routing_fees: Option<Vec<(FederationId, FederationRoutingFees)>>,
}
