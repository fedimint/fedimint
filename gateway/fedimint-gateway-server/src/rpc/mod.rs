pub mod rpc_client;
pub mod rpc_server;

use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use fedimint_core::config::{FederationId, JsonClientConfig};
use fedimint_core::core::OperationId;
use fedimint_core::util::{get_average, get_median};
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_eventlog::{EventKind, EventLogId, PersistedLogEntry, StructuredPaymentEvents};
use fedimint_mint_client::OOBNotes;
use fedimint_wallet_client::PegOutFees;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use crate::config::LightningMode;
use crate::db::FederationConfig;
use crate::SafeUrl;

pub const V1_API_ENDPOINT: &str = "v1";

pub const ADDRESS_ENDPOINT: &str = "/address";
pub const ADDRESS_RECHECK_ENDPOINT: &str = "/address_recheck";
pub const BACKUP_ENDPOINT: &str = "/backup";
pub const CONFIGURATION_ENDPOINT: &str = "/config";
pub const CONNECT_FED_ENDPOINT: &str = "/connect_fed";
pub const CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/create_bolt11_invoice_for_operator";
pub const GATEWAY_INFO_ENDPOINT: &str = "/info";
pub const GET_BALANCES_ENDPOINT: &str = "/balances";
pub const GATEWAY_INFO_POST_ENDPOINT: &str = "/info";
pub const GET_INVOICE_ENDPOINT: &str = "/get_invoice";
pub const GET_LN_ONCHAIN_ADDRESS_ENDPOINT: &str = "/get_ln_onchain_address";
pub const LEAVE_FED_ENDPOINT: &str = "/leave_fed";
pub const LIST_ACTIVE_CHANNELS_ENDPOINT: &str = "/list_active_channels";
pub const MNEMONIC_ENDPOINT: &str = "/mnemonic";
pub const OPEN_CHANNEL_ENDPOINT: &str = "/open_channel";
pub const CLOSE_CHANNELS_WITH_PEER_ENDPOINT: &str = "/close_channels_with_peer";
pub const PAY_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/pay_invoice_for_operator";
pub const PAYMENT_LOG_ENDPOINT: &str = "/payment_log";
pub const PAYMENT_SUMMARY_ENDPOINT: &str = "/payment_summary";
pub const RECEIVE_ECASH_ENDPOINT: &str = "/receive_ecash";
pub const SET_FEES_ENDPOINT: &str = "/set_fees";
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
pub struct DepositAddressRecheckPayload {
    pub address: Address<NetworkUnchecked>,
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
    pub federation_name: Option<String>,
    pub balance_msat: Amount,
    pub config: FederationConfig,
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
    pub network: Network,
    // TODO: This is here to allow for backwards compatibility with old versions of this struct. We
    // should be able to remove it once 0.4.0 is released.
    #[serde(default)]
    pub block_height: Option<u32>,
    // TODO: This is here to allow for backwards compatibility with old versions of this struct. We
    // should be able to remove it once 0.4.0 is released.
    #[serde(default)]
    pub synced_to_chain: bool,
    pub api: SafeUrl,
    pub lightning_mode: LightningMode,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayFedConfig {
    pub federations: BTreeMap<FederationId, JsonClientConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetFeesPayload {
    pub federation_id: Option<FederationId>,
    pub lightning_base: Option<Amount>,
    pub lightning_parts_per_million: Option<u64>,
    pub transaction_base: Option<Amount>,
    pub transaction_parts_per_million: Option<u64>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentLogPayload {
    // The position in the log to stop querying. No events will be returned from after
    // this `EventLogId`. If it is `None`, the last `EventLogId` is used.
    pub end_position: Option<EventLogId>,

    // The number of events to return
    pub pagination_size: usize,

    pub federation_id: FederationId,
    pub event_kinds: Vec<EventKind>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentLogResponse(pub Vec<PersistedLogEntry>);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentSummaryResponse {
    pub outgoing: PaymentStats,
    pub incoming: PaymentStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentStats {
    pub average_latency: Option<Duration>,
    pub median_latency: Option<Duration>,
    pub total_fees: Amount,
    pub total_success: usize,
    pub total_failure: usize,
}

impl PaymentStats {
    /// Computes the payment statistics for the given structured payment events.
    pub fn compute(events: &StructuredPaymentEvents) -> Self {
        PaymentStats {
            average_latency: get_average(&events.latencies).map(Duration::from_micros),
            median_latency: get_median(&events.latencies).map(Duration::from_micros),
            total_fees: Amount::from_msats(events.fees.iter().map(|a| a.msats).sum()),
            total_success: events.latencies.len(),
            total_failure: events.latencies_failure.len(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentSummaryPayload {
    pub start_millis: u64,
    pub end_millis: u64,
}
