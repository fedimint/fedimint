use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint};
use clap::Subcommand;
use envs::{
    FM_LDK_ALIAS_ENV, FM_LND_MACAROON_ENV, FM_LND_RPC_ADDR_ENV, FM_LND_TLS_CERT_ENV, FM_PORT_LDK,
};
use fedimint_api_client::api::net::ConnectorType;
use fedimint_core::config::{FederationId, JsonClientConfig};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::{SafeUrl, get_average, get_median};
use fedimint_core::{Amount, BitcoinAmountOrAll, secp256k1};
use fedimint_eventlog::{EventKind, EventLogId, PersistedLogEntry, StructuredPaymentEvents};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_mint_client::OOBNotes;
use fedimint_wallet_client::PegOutFees;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

pub mod envs;

pub const V1_API_ENDPOINT: &str = "v1";

pub const ADDRESS_ENDPOINT: &str = "/address";
pub const ADDRESS_RECHECK_ENDPOINT: &str = "/address_recheck";
pub const BACKUP_ENDPOINT: &str = "/backup";
pub const CONFIGURATION_ENDPOINT: &str = "/config";
pub const CONNECT_FED_ENDPOINT: &str = "/connect_fed";
pub const CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/create_bolt11_invoice_for_operator";
pub const CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT: &str = "/create_bolt12_offer_for_operator";
pub const GATEWAY_INFO_ENDPOINT: &str = "/info";
pub const GET_BALANCES_ENDPOINT: &str = "/balances";
pub const GET_INVOICE_ENDPOINT: &str = "/get_invoice";
pub const GET_LN_ONCHAIN_ADDRESS_ENDPOINT: &str = "/get_ln_onchain_address";
pub const LEAVE_FED_ENDPOINT: &str = "/leave_fed";
pub const LIST_CHANNELS_ENDPOINT: &str = "/list_channels";
pub const LIST_TRANSACTIONS_ENDPOINT: &str = "/list_transactions";
pub const MNEMONIC_ENDPOINT: &str = "/mnemonic";
pub const OPEN_CHANNEL_ENDPOINT: &str = "/open_channel";
pub const CLOSE_CHANNELS_WITH_PEER_ENDPOINT: &str = "/close_channels_with_peer";
pub const PAY_INVOICE_FOR_OPERATOR_ENDPOINT: &str = "/pay_invoice_for_operator";
pub const PAY_OFFER_FOR_OPERATOR_ENDPOINT: &str = "/pay_offer_for_operator";
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
    /// When provided (from UI preview flow), uses these quoted fees.
    /// When None, fetches current fees from the wallet.
    #[serde(default)]
    pub quoted_fees: Option<PegOutFees>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawResponse {
    pub txid: bitcoin::Txid,
    pub fees: PegOutFees,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawPreviewPayload {
    pub federation_id: FederationId,
    pub amount: BitcoinAmountOrAll,
    pub address: Address<NetworkUnchecked>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawPreviewResponse {
    pub withdraw_amount: Amount,
    pub address: String,
    pub peg_out_fees: PegOutFees,
    pub total_cost: Amount,
    /// Estimated mint fees when withdrawing all. None for partial withdrawals.
    #[serde(default)]
    pub mint_fees: Option<Amount>,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfig {
    pub invite_code: InviteCode,
    // Unique integer identifier per-federation that is assigned when the gateways joins a
    // federation.
    #[serde(alias = "mint_channel_id")]
    pub federation_index: u64,
    pub lightning_fee: PaymentFee,
    pub transaction_fee: PaymentFee,
    pub connector: ConnectorType,
}

/// Information about one of the feds we are connected to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationInfo {
    pub federation_id: FederationId,
    pub federation_name: Option<String>,
    pub balance_msat: Amount,
    pub config: FederationConfig,
    pub last_backup_time: Option<SystemTime>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationInfo>,
    /// Mapping from short channel id to the federation id that it belongs to.
    // TODO: Remove this alias once it no longer breaks backwards compatibility.
    #[serde(alias = "channels")]
    pub federation_fake_scids: Option<BTreeMap<u64, FederationId>>,
    pub gateway_state: String,
    pub lightning_info: LightningInfo,
    pub lightning_mode: LightningMode,
    pub registrations: BTreeMap<RegisteredProtocol, (SafeUrl, secp256k1::PublicKey)>,
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

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GatewayBalances {
    pub onchain_balance_sats: u64,
    pub lightning_balance_msats: u64,
    pub ecash_balances: Vec<FederationBalanceInfo>,
    pub inbound_lightning_liquidity_msats: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
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
            average_latency: get_average(&events.latencies_usecs).map(Duration::from_micros),
            median_latency: get_median(&events.latencies_usecs).map(Duration::from_micros),
            total_fees: Amount::from_msats(events.fees.iter().map(|a| a.msats).sum()),
            total_success: events.latencies_usecs.len(),
            total_failure: events.latencies_failure.len(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentSummaryPayload {
    pub start_millis: u64,
    pub end_millis: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelInfo {
    pub remote_pubkey: secp256k1::PublicKey,
    pub channel_size_sats: u64,
    pub outbound_liquidity_sats: u64,
    pub inbound_liquidity_sats: u64,
    pub is_active: bool,
    pub funding_outpoint: Option<OutPoint>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenChannelRequest {
    pub pubkey: secp256k1::PublicKey,
    pub host: String,
    pub channel_size_sats: u64,
    pub push_amount_sats: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendOnchainRequest {
    pub address: Address<NetworkUnchecked>,
    pub amount: BitcoinAmountOrAll,
    pub fee_rate_sats_per_vbyte: u64,
}

impl fmt::Display for SendOnchainRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SendOnchainRequest {{ address: {}, amount: {}, fee_rate_sats_per_vbyte: {} }}",
            self.address.assume_checked_ref(),
            self.amount,
            self.fee_rate_sats_per_vbyte
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseChannelsWithPeerRequest {
    pub pubkey: secp256k1::PublicKey,
    #[serde(default)]
    pub force: bool,
    pub sats_per_vbyte: Option<u64>,
}

impl fmt::Display for CloseChannelsWithPeerRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CloseChannelsWithPeerRequest {{ pubkey: {}, force: {}, sats_per_vbyte: {} }}",
            self.pubkey,
            self.force,
            match self.sats_per_vbyte {
                Some(sats) => sats.to_string(),
                None => "None".to_string(),
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseChannelsWithPeerResponse {
    pub num_channels_closed: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetInvoiceRequest {
    pub payment_hash: sha256::Hash,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetInvoiceResponse {
    pub preimage: Option<String>,
    pub payment_hash: Option<sha256::Hash>,
    pub amount: Amount,
    pub created_at: SystemTime,
    pub status: PaymentStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListTransactionsPayload {
    pub start_secs: u64,
    pub end_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListTransactionsResponse {
    pub transactions: Vec<PaymentDetails>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentDetails {
    pub payment_hash: Option<sha256::Hash>,
    pub preimage: Option<String>,
    pub payment_kind: PaymentKind,
    pub amount: Amount,
    pub direction: PaymentDirection,
    pub status: PaymentStatus,
    pub timestamp_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum PaymentKind {
    Bolt11,
    Bolt12Offer,
    Bolt12Refund,
    Onchain,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum PaymentDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateOfferPayload {
    pub amount: Option<Amount>,
    pub description: Option<String>,
    pub expiry_secs: Option<u32>,
    pub quantity: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateOfferResponse {
    pub offer: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PayOfferPayload {
    pub offer: String,
    pub amount: Option<Amount>,
    pub quantity: Option<u64>,
    pub payer_note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PayOfferResponse {
    pub preimage: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum PaymentStatus {
    Pending,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize, Eq, PartialEq)]
pub enum LightningMode {
    #[clap(name = "lnd")]
    Lnd {
        /// LND RPC address
        #[arg(long = "lnd-rpc-host", env = FM_LND_RPC_ADDR_ENV)]
        lnd_rpc_addr: String,

        /// LND TLS cert file path
        #[arg(long = "lnd-tls-cert", env = FM_LND_TLS_CERT_ENV)]
        lnd_tls_cert: String,

        /// LND macaroon file path
        #[arg(long = "lnd-macaroon", env = FM_LND_MACAROON_ENV)]
        lnd_macaroon: String,
    },
    #[clap(name = "ldk")]
    Ldk {
        /// LDK lightning server port
        #[arg(long = "ldk-lightning-port", env = FM_PORT_LDK)]
        lightning_port: u16,

        /// LDK's Alias
        #[arg(long = "ldk-alias", env = FM_LDK_ALIAS_ENV)]
        alias: String,
    },
}

#[derive(Clone)]
pub enum ChainSource {
    Bitcoind {
        username: String,
        password: String,
        server_url: SafeUrl,
    },
    Esplora {
        server_url: SafeUrl,
    },
}

impl fmt::Display for ChainSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainSource::Bitcoind {
                username: _,
                password: _,
                server_url,
            } => {
                write!(f, "Bitcoind source with URL: {server_url}")
            }
            ChainSource::Esplora { server_url } => {
                write!(f, "Esplora source with URL: {server_url}")
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LightningInfo {
    Connected {
        public_key: PublicKey,
        alias: String,
        network: Network,
        block_height: u64,
        synced_to_chain: bool,
    },
    NotConnected,
}

#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Encodable, Decodable, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RegisteredProtocol {
    Http,
    Iroh,
}
