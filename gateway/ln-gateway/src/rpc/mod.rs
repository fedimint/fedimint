pub mod rpc_client;
pub mod rpc_server;

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use fedimint_core::config::{FederationId, JsonClientConfig};
use fedimint_core::core::OperationId;
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::config::parse_routing_fees;
use fedimint_mint_client::OOBNotes;
use fedimint_wallet_client::PegOutFees;
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use serde::{Deserialize, Serialize};

use crate::lightning::LightningMode;
use crate::SafeUrl;

pub const V1_API_ENDPOINT: &str = "v1";

pub const ADDRESS_ENDPOINT: &str = "/address";
pub const BACKUP_ENDPOINT: &str = "/backup";
pub const CONFIGURATION_ENDPOINT: &str = "/config";
pub const CONNECT_FED_ENDPOINT: &str = "/connect_fed";
pub const CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/create_bolt11_invoice_for_operator";
pub const GATEWAY_INFO_ENDPOINT: &str = "/info";
pub const GET_BALANCES_ENDPOINT: &str = "/balances";
pub const GATEWAY_INFO_POST_ENDPOINT: &str = "/info";
pub const GET_LN_ONCHAIN_ADDRESS_ENDPOINT: &str = "/get_ln_onchain_address";
pub const LEAVE_FED_ENDPOINT: &str = "/leave_fed";
pub const LIST_ACTIVE_CHANNELS_ENDPOINT: &str = "/list_active_channels";
pub const MNEMONIC_ENDPOINT: &str = "/mnemonic";
pub const OPEN_CHANNEL_ENDPOINT: &str = "/open_channel";
pub const CLOSE_CHANNELS_WITH_PEER_ENDPOINT: &str = "/close_channels_with_peer";
pub const PAY_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/pay_invoice_for_operator";
pub const RECEIVE_ECASH_ENDPOINT: &str = "/receive_ecash";
pub const SET_CONFIGURATION_ENDPOINT: &str = "/set_configuration";
pub const STOP_ENDPOINT: &str = "/stop";
pub const SEND_ONCHAIN_ENDPOINT: &str = "/send_onchain";
pub const SPEND_ECASH_ENDPOINT: &str = "/spend_ecash";
pub const WITHDRAW_ENDPOINT: &str = "/withdraw";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectFedPayload {
    pub invite_code: String,
    #[serde(default)]
    #[cfg(feature = "tor")]
    pub use_tor: Option<bool>,
    pub recover: Option<bool>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigPayload {
    pub federation_id: Option<FederationId>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawResponse {
    pub txid: bitcoin::Txid,
    pub fees: PegOutFees,
}

/// Information about one of the feds we are connected to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationInfo {
    pub federation_id: FederationId,
    pub balance_msat: Amount,
    pub federation_index: u64,
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
    pub api: SafeUrl,
    pub lightning_mode: Option<LightningMode>,
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
pub struct CreateInvoiceForOperatorPayload {
    pub amount_msats: u64,
    pub expiry_secs: Option<u32>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PayInvoiceForOperatorPayload {
    pub invoice: Bolt11Invoice,
}

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
pub struct SendOnchainPayload {
    pub address: Address<NetworkUnchecked>,
    pub amount: BitcoinAmountOrAll,
    pub fee_rate_sats_per_vbyte: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendEcashPayload {
    /// Federation id of the e-cash to spend
    pub federation_id: FederationId,
    /// The amount of e-cash to spend
    pub amount: Amount,
    /// If the exact amount cannot be represented, return e-cash of a higher
    /// value instead of failing
    #[serde(default)]
    pub allow_overpay: bool,
    /// After how many seconds we will try to reclaim the e-cash if it
    /// hasn't been redeemed by the recipient. Defaults to one week.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// If the necessary information to join the federation the e-cash
    /// belongs to should be included in the serialized notes
    #[serde(default)]
    pub include_invite: bool,
}

/// Default timeout for e-cash redemption of one week in seconds
fn default_timeout() -> u64 {
    604_800
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendEcashResponse {
    pub operation_id: OperationId,
    pub notes: OOBNotes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiveEcashPayload {
    pub notes: OOBNotes,
    #[serde(default)]
    pub wait: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiveEcashResponse {
    pub amount: Amount,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct GatewayBalances {
    pub onchain_balance_sats: u64,
    pub lightning_balance_msats: u64,
    pub ecash_balances: Vec<FederationBalanceInfo>,
    pub inbound_lightning_liquidity_msats: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FederationBalanceInfo {
    pub federation_id: FederationId,
    pub ecash_balance_msats: Amount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MnemonicResponse {
    pub mnemonic: Vec<String>,

    // Legacy federations are federations that the gateway joined prior to v0.5.0
    // and do not derive their secrets from the gateway's mnemonic. They also use
    // a separate database from the gateway's db.
    pub legacy_federations: Vec<FederationId>,
}
