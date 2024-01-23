pub mod cln;
pub mod coinos;
pub mod lnd;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Subcommand;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::Amount;
use fedimint_ln_common::PrunedInvoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::oneshot::Sender;
use tokio::sync::Mutex;

use self::cln::{NetworkLnRpcClient, RouteHtlcStream};
use self::coinos::GatewayCoinosClient;
use self::lnd::GatewayLndClient;
use crate::gateway_lnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};

pub const MAX_LIGHTNING_RETRIES: u32 = 10;

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
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
    #[error("Failed to get Invoice: {failure_reason}")]
    FailedToGetInvoice { failure_reason: String },
}

pub trait GatewayApiClient: Debug + Send + Sync + Clone + Sized {
    fn bind_addr(&self) -> &SocketAddr;
    fn api_key(&self) -> &String;
    fn outcomes(&self) -> &Arc<Mutex<BTreeMap<u64, Sender<InterceptHtlcResponse>>>>;
}

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
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError>;

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

    // Consumes the current lightning client because `route_htlcs` should only be
    // called once per client. A stream of intercepted HTLCs and a `Arc<dyn
    // ILnRpcClient> are returned to the caller. The caller can use this new
    // client to interact with the lightning node, but since it is an `Arc` is
    // cannot call `route_htlcs` again.
    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError>;

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError>;
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum LightningMode {
    #[clap(name = "lnd")]
    Lnd {
        /// LND RPC address
        #[arg(long = "lnd-rpc-host", env = "FM_LND_RPC_ADDR")]
        lnd_rpc_addr: String,

        /// LND TLS cert file path
        #[arg(long = "lnd-tls-cert", env = "FM_LND_TLS_CERT")]
        lnd_tls_cert: String,

        /// LND macaroon file path
        #[arg(long = "lnd-macaroon", env = "FM_LND_MACAROON")]
        lnd_macaroon: String,
    },
    #[clap(name = "cln")]
    Cln {
        #[arg(long = "cln-extension-addr", env = "FM_GATEWAY_LIGHTNING_ADDR")]
        cln_extension_addr: SafeUrl,
    },
    #[clap(name = "coinos")]
    Coinos {
        #[arg(long = "bind-addr", env = "FM_GATEWAY_WEBSERVER_BIND_ADDR")]
        bind_addr: SocketAddr,
        #[arg(long = "api-key", env = "FM_GATEWAY_LIGHTNING_API_KEY")]
        api_key: String,
    },
}

#[async_trait]
pub trait LightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient>;
}

#[derive(Clone)]
pub struct GatewayLightningBuilder {
    pub lightning_mode: LightningMode,
}

#[async_trait]
impl LightningBuilder for GatewayLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        match self.lightning_mode.clone() {
            LightningMode::Cln { cln_extension_addr } => {
                Box::new(NetworkLnRpcClient::new(cln_extension_addr).await)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Box::new(
                GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon, None).await,
            ),
            LightningMode::Coinos { bind_addr, api_key } => {
                let outcomes = Arc::new(Mutex::new(BTreeMap::new()));
                Box::new(GatewayCoinosClient::new(bind_addr, api_key, outcomes).await)
            }
        }
    }
}

pub async fn send_htlc_to_webhook(
    outcomes: &Arc<Mutex<BTreeMap<u64, Sender<InterceptHtlcResponse>>>>,
    htlc: InterceptHtlcResponse,
) -> Result<(), LightningRpcError> {
    let htlc_id = htlc.htlc_id;
    if let Some(sender) = outcomes.lock().await.remove(&htlc_id) {
        sender
            .send(htlc)
            .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "Failed to send back to webhook".to_string(),
            })?;
        Ok(())
    } else {
        Err(LightningRpcError::FailedToCompleteHtlc {
            failure_reason: format!("Could not find sender for HTLC {}", htlc_id),
        })
    }
}
