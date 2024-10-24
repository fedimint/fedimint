pub mod cln;
pub mod ldk;
pub mod lnd;

use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin30::{Address, Network};
use clap::Subcommand;
use fedimint_bip39::Mnemonic;
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_env_var_set;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{backoff_util, retry, SafeUrl};
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::PrunedInvoice;
use futures::stream::BoxStream;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use self::cln::NetworkLnRpcClient;
use self::lnd::GatewayLndClient;
use crate::envs::{
    FM_GATEWAY_LIGHTNING_ADDR_ENV, FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV, FM_LDK_ESPLORA_SERVER_URL,
    FM_LDK_NETWORK, FM_LND_MACAROON_ENV, FM_LND_RPC_ADDR_ENV, FM_LND_TLS_CERT_ENV, FM_PORT_LDK,
};
use crate::gateway_lnrpc::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse, EmptyResponse,
    GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse,
    InterceptHtlcRequest, InterceptHtlcResponse, OpenChannelResponse, PayInvoiceResponse,
    WithdrawOnchainResponse,
};

pub const MAX_LIGHTNING_RETRIES: u32 = 10;

pub type HtlcResult = std::result::Result<InterceptHtlcRequest, tonic::Status>;
pub type RouteHtlcStream<'a> = BoxStream<'a, HtlcResult>;

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub enum LightningRpcError {
    #[error("Failed to connect to Lightning node")]
    FailedToConnect,
    #[error("Failed to retrieve node info: {failure_reason}")]
    FailedToGetNodeInfo { failure_reason: String },
    #[error("Failed to retrieve route hints: {failure_reason}")]
    FailedToGetRouteHints { failure_reason: String },
    #[error("Payment failed: {failure_reason}")]
    FailedPayment { failure_reason: String },
    #[error("Failed to route HTLCs: {failure_reason}")]
    FailedToRouteHtlcs { failure_reason: String },
    #[error("Failed to complete HTLC: {failure_reason}")]
    FailedToCompleteHtlc { failure_reason: String },
    #[error("Failed to open channel: {failure_reason}")]
    FailedToOpenChannel { failure_reason: String },
    #[error("Failed to close channel: {failure_reason}")]
    FailedToCloseChannelsWithPeer { failure_reason: String },
    #[error("Failed to get Invoice: {failure_reason}")]
    FailedToGetInvoice { failure_reason: String },
    #[error("Failed to get funding address: {failure_reason}")]
    FailedToGetLnOnchainAddress { failure_reason: String },
    #[error("Failed to withdraw funds on-chain: {failure_reason}")]
    FailedToWithdrawOnchain { failure_reason: String },
    #[error("Failed to connect to peer: {failure_reason}")]
    FailedToConnectToPeer { failure_reason: String },
    #[error("Failed to list active channels: {failure_reason}")]
    FailedToListActiveChannels { failure_reason: String },
    #[error("Failed to get balances: {failure_reason}")]
    FailedToGetBalances { failure_reason: String },
    #[error("Failed to subscribe to invoice updates: {failure_reason}")]
    FailedToSubscribeToInvoiceUpdates { failure_reason: String },
    #[error("Failed to sync to chain: {failure_reason}")]
    FailedToSyncToChain { failure_reason: String },
    #[error("Invalid metadata: {failure_reason}")]
    InvalidMetadata { failure_reason: String },
}

/// Represents an active connection to the lightning node.
#[derive(Clone, Debug)]
pub struct LightningContext {
    pub lnrpc: Arc<dyn ILnRpcClient>,
    pub lightning_public_key: PublicKey,
    pub lightning_alias: String,
    pub lightning_network: Network,
}

/// A trait that the gateway uses to interact with a lightning node. This allows
/// the gateway to be agnostic to the specific lightning node implementation
/// being used.
#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key and alias of the lightning node
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError>;

    /// Get route hints to the lightning node
    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.pay_private(
            PrunedInvoice::try_from(invoice).map_err(|_| LightningRpcError::FailedPayment {
                failure_reason: "Invoice has no amount".to_string(),
            })?,
            max_delay,
            max_fee,
        )
        .await
    }

    /// Attempt to pay an invoice using the lightning node using a
    /// [`PrunedInvoice`], increasing the user's privacy by not sending the
    /// invoice description to the gateway.
    async fn pay_private(
        &self,
        _invoice: PrunedInvoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        Err(LightningRpcError::FailedPayment {
            failure_reason: "Private payments not supported".to_string(),
        })
    }

    /// Returns true if the lightning backend supports payments without full
    /// invoices. If this returns true, then [`ILnRpcClient::pay_private`] has
    /// to be implemented.
    fn supports_private_payments(&self) -> bool {
        false
    }

    /// Consumes the current client and returns a stream of intercepted HTLCs
    /// and a new client. `complete_htlc` must be called for all successfully
    /// intercepted HTLCs sent to the returned stream.
    ///
    /// `route_htlcs` can only be called once for a given client, since the
    /// returned stream grants exclusive routing decisions to the caller.
    /// For this reason, `route_htlc` consumes the client and returns one
    /// wrapped in an `Arc`. This lets the compiler enforce that `route_htlcs`
    /// can only be called once for a given client, since the value inside
    /// the `Arc` cannot be consumed.
    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError>;

    /// Complete an HTLC that was intercepted by the gateway. Must be called for
    /// all successfully intercepted HTLCs sent to the stream returned by
    /// `route_htlcs`.
    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError>;

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError>;

    /// Get a funding address belonging to the gateway's lightning node
    /// wallet.
    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError>;

    async fn withdraw_onchain(
        &self,
        address: Address,
        amount: BitcoinAmountOrAll,
        fee_rate_sats_per_vbyte: u64,
    ) -> Result<WithdrawOnchainResponse, LightningRpcError>;

    /// Open a channel with a peer lightning node from the gateway's lightning
    /// node.
    async fn open_channel(
        &self,
        pubkey: secp256k1::PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<OpenChannelResponse, LightningRpcError>;

    /// Close all channels with a peer lightning node from the gateway's
    /// lightning node.
    async fn close_channels_with_peer(
        &self,
        pubkey: secp256k1::PublicKey,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError>;

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError>;

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError>;
}

impl dyn ILnRpcClient {
    /// Retrieve route hints from the Lightning node, capped at
    /// `num_route_hints`. The route hints should be ordered based on liquidity
    /// of incoming channels.
    pub async fn parsed_route_hints(&self, num_route_hints: u32) -> Vec<RouteHint> {
        if num_route_hints == 0 {
            return vec![];
        }

        let route_hints =
            self.routehints(num_route_hints as usize)
                .await
                .unwrap_or(GetRouteHintsResponse {
                    route_hints: Vec::new(),
                });
        route_hints.try_into().expect("Could not parse route hints")
    }

    /// Retrieves the basic information about the Gateway's connected Lightning
    /// node.
    pub async fn parsed_node_info(
        &self,
    ) -> std::result::Result<(PublicKey, String, Network, u32, bool), LightningRpcError> {
        let GetNodeInfoResponse {
            pub_key,
            alias,
            network,
            block_height,
            synced_to_chain,
        } = self.info().await?;
        let node_pub_key =
            PublicKey::from_slice(&pub_key).map_err(|e| LightningRpcError::InvalidMetadata {
                failure_reason: format!("Invalid node pubkey {e}"),
            })?;
        let network =
            Network::from_str(&network).map_err(|e| LightningRpcError::InvalidMetadata {
                failure_reason: format!("Invalid network {network}: {e}"),
            })?;
        Ok((node_pub_key, alias, network, block_height, synced_to_chain))
    }

    /// Waits for the Lightning node to be synced to the Bitcoin blockchain.
    pub async fn wait_for_chain_sync(&self) -> std::result::Result<(), LightningRpcError> {
        if is_env_var_set(FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV) {
            debug!("Skip waiting for gateway to sync to chain");
            return Ok(());
        }

        retry(
            "Wait for chain sync",
            backoff_util::background_backoff(),
            || async {
                let info = self.info().await?;
                let block_height = info.block_height;
                if info.synced_to_chain {
                    Ok(())
                } else {
                    warn!(?block_height, "Lightning node is not synced yet");
                    Err(anyhow::anyhow!("Not synced yet"))
                }
            },
        )
        .await
        .map_err(|e| LightningRpcError::FailedToSyncToChain {
            failure_reason: format!("Failed to sync to chain: {e:?}"),
        })?;

        info!("Gateway successfully synced with the chain");
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelInfo {
    pub remote_pubkey: secp256k1::PublicKey,
    pub channel_size_sats: u64,
    pub outbound_liquidity_sats: u64,
    pub inbound_liquidity_sats: u64,
    pub short_channel_id: u64,
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
    #[clap(name = "cln")]
    Cln {
        #[arg(long = "cln-extension-addr", env = FM_GATEWAY_LIGHTNING_ADDR_ENV)]
        cln_extension_addr: SafeUrl,
    },
    #[clap(name = "ldk")]
    Ldk {
        /// LDK esplora server URL
        #[arg(long = "ldk-esplora-server-url", env = FM_LDK_ESPLORA_SERVER_URL)]
        esplora_server_url: String,

        /// LDK network (defaults to regtest if not provided)
        #[arg(long = "ldk-network", env = FM_LDK_NETWORK, default_value = "regtest")]
        network: Network,

        /// LDK lightning server port
        #[arg(long = "ldk-lightning-port", env = FM_PORT_LDK)]
        lightning_port: u16,
    },
}

#[async_trait]
pub trait LightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient>;
    fn lightning_mode(&self) -> Option<LightningMode> {
        None
    }
}

#[derive(Clone)]
pub struct GatewayLightningBuilder {
    pub lightning_mode: LightningMode,
    pub gateway_db: Database,
    pub ldk_data_dir: PathBuf,
    pub mnemonic: Mnemonic,
}

#[async_trait]
impl LightningBuilder for GatewayLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        match self.lightning_mode.clone() {
            LightningMode::Cln { cln_extension_addr } => {
                Box::new(NetworkLnRpcClient::new(cln_extension_addr))
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Box::new(GatewayLndClient::new(
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
                None,
                self.gateway_db.clone(),
            )),
            LightningMode::Ldk {
                esplora_server_url,
                network,
                lightning_port,
            } => Box::new(
                ldk::GatewayLdkClient::new(
                    &self.ldk_data_dir,
                    &esplora_server_url,
                    network,
                    lightning_port,
                    self.mnemonic.clone(),
                )
                .unwrap(),
            ),
        }
    }

    fn lightning_mode(&self) -> Option<LightningMode> {
        Some(self.lightning_mode.clone())
    }
}
