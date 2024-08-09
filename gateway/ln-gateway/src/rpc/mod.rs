pub mod rpc_client;
pub mod rpc_server;

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use fedimint_core::config::{ClientConfig, FederationId, JsonClientConfig};
use fedimint_core::core::OperationId;
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::config::parse_routing_fees;
use fedimint_ln_common::{route_hints, serde_option_routing_fees};
use fedimint_mint_client::OOBNotes;
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
    pub address: Address<NetworkUnchecked>,
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
    /// Mapping from short channel id to the federation id that it belongs to.
    // TODO: Remove this alias once it no longer breaks backwards compatibility.
    #[serde(alias = "channels")]
    pub federation_fake_scids: Option<BTreeMap<u64, FederationId>>,
    pub lightning_pub_key: Option<String>,
    pub lightning_alias: Option<String>,
    #[serde(with = "serde_option_routing_fees")]
    pub fees: Option<RoutingFees>,
    pub route_hints: Vec<route_hints::RouteHint>,
    pub gateway_id: secp256k1::PublicKey,
    pub gateway_state: String,
    pub network: Option<Network>,
    // TODO: This is here to allow for backwards compatibility with old versions of this struct. We
    // should be able to remove it once 0.4.0 is released.
    #[serde(default)]
    pub block_height: Option<u32>,
    // TODO: This is here to allow for backwards compatibility with old versions of this struct. We
    // should be able to remove it once 0.4.0 is released.
    #[serde(default)]
    pub synced_to_chain: bool,
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
    pub routing_fees: Option<FederationRoutingFees>,
    pub network: Option<Network>,
    pub per_federation_routing_fees: Option<Vec<(FederationId, FederationRoutingFees)>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetFundingAddressPayload;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenChannelPayload {
    pub pubkey: secp256k1::PublicKey,
    pub host: String,
    pub channel_size_sats: u64,
    pub push_amount_sats: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseChannelsWithPeerPayload {
    pub pubkey: secp256k1::PublicKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendEcashPayload {
    /// Federation id of the e-cash to spend
    pub federation_id: FederationId,
    /// The amount of e-cash to spend
    pub amount: Amount,
    /// If the exact amount cannot be represented, return e-cash of a higher
    /// value instead of failing
    pub allow_overpay: bool,
    /// After how many seconds we will try to reclaim the e-cash if it
    /// hasn't been redeemed by the recipient. Defaults to one week.
    pub timeout: u64,
    /// If the necessary information to join the federation the e-cash
    /// belongs to should be included in the serialized notes
    pub include_invite: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendEcashResponse {
    pub operation_id: OperationId,
    pub notes: OOBNotes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiveEcashPayload {
    pub notes: OOBNotes,
    pub wait: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiveEcashResponse {
    pub amount: Amount,
}
