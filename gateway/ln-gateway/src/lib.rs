pub mod client;
pub mod db;
pub mod lnd;
pub mod lnrpc_client;
pub mod ng;
pub mod rpc;
pub mod types;
pub mod utils;

pub mod gatewaylnrpc {
    tonic::include_proto!("gatewaylnrpc");
}

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Txid};
use bitcoin_hashes::hex::ToHex;
use clap::Subcommand;
use client::StandardGatewayClientBuilder;
use fedimint_core::api::{FederationError, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::time::now;
use fedimint_core::util::NextOrPending;
use fedimint_core::Amount;
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::KIND;
use fedimint_wallet_client::{WalletClientExt, WithdrawState};
use futures::stream::StreamExt;
use gatewaylnrpc::intercept_htlc_response::{Action, Cancel};
use gatewaylnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use lightning::routing::gossip::RoutingFees;
use lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use ng::{GatewayClientExt, GatewayClientModule, GatewayExtRegisterStates};
use rand::Rng;
use rpc::FederationInfo;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};
use url::Url;

use crate::gatewaylnrpc::intercept_htlc_response::{Forward, Settle};
use crate::lnd::GatewayLndClient;
use crate::lnrpc_client::NetworkLnRpcClient;
use crate::ng::{GatewayExtPayStates, GatewayExtReceiveStates, Htlc};
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, GatewayInfo,
    InfoPayload, RestorePayload, WithdrawPayload,
};

/// LND HTLC interceptor can't handle SCID of 0, so start from 1
const INITIAL_SCID: u64 = 1;

/// How long a gateway announcement stays valid
pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

const ROUTE_HINT_RETRIES: usize = 10;
const ROUTE_HINT_RETRY_SLEEP: Duration = Duration::from_secs(2);

pub const DEFAULT_FEES: RoutingFees = RoutingFees {
    /// Base routing fee. Default is 0 msat
    base_msat: 0,
    /// Liquidity-based routing fee in millionths of a routed amount.
    /// In other words, 10000 is 1%. The default is 10000 (1%).
    proportional_millionths: 10000,
};

pub type Result<T> = std::result::Result<T, GatewayError>;

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
        cln_extension_addr: Url,
    },
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Lightning rpc operation error: {0:?}")]
    LnRpcError(#[from] tonic::Status),
    #[error("Federation error: {0:?}")]
    FederationError(#[from] FederationError),
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
    #[error("Failed to fetch route hints")]
    FailedToFetchRouteHints,
    #[error("Failed to open the database")]
    DatabaseError,
    #[error("Federation client error")]
    ClientNgError,
}

impl GatewayError {
    pub fn other(msg: String) -> Self {
        error!(msg);
        GatewayError::Other(anyhow!(msg))
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{self:?}")).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}

#[derive(Clone)]
pub struct Gateway {
    lnrpc: Arc<dyn ILnRpcClient>,
    lightning_mode: Option<LightningMode>,
    clients: Arc<RwLock<BTreeMap<FederationId, Arc<fedimint_client::Client>>>>,
    scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
    client_builder: StandardGatewayClientBuilder,
    channel_id_generator: Arc<Mutex<AtomicU64>>,
    fees: RoutingFees,
    gatewayd_db: Database,
    api: Url,
    task_group: TaskGroup,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lightning_mode: LightningMode,
        client_builder: StandardGatewayClientBuilder,
        fees: RoutingFees,
        gatewayd_db: Database,
        api: Url,
    ) -> Result<Self> {
        let lnrpc = Self::create_lightning_client(lightning_mode.clone()).await;

        let mut gw = Self {
            lnrpc,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            client_builder,
            channel_id_generator: Arc::new(Mutex::new(AtomicU64::new(INITIAL_SCID))),
            lightning_mode: Some(lightning_mode),
            fees,
            gatewayd_db,
            api,
            task_group: TaskGroup::new(),
        };

        gw.load_clients().await?;
        gw.route_htlcs().await?;

        Ok(gw)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_lightning_connection(
        lnrpc: Arc<dyn ILnRpcClient>,
        client_builder: StandardGatewayClientBuilder,
        fees: RoutingFees,
        gatewayd_db: Database,
        api: Url,
    ) -> Result<Self> {
        let mut gw = Self {
            lnrpc,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            client_builder,
            channel_id_generator: Arc::new(Mutex::new(AtomicU64::new(INITIAL_SCID))),
            lightning_mode: None,
            fees,
            gatewayd_db,
            api,
            task_group: TaskGroup::new(),
        };

        gw.load_clients().await?;
        gw.route_htlcs().await?;

        Ok(gw)
    }

    async fn create_lightning_client(mode: LightningMode) -> Arc<dyn ILnRpcClient> {
        match mode {
            LightningMode::Cln { cln_extension_addr } => {
                Arc::new(NetworkLnRpcClient::new(cln_extension_addr).await)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Arc::new(GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon).await),
        }
    }

    async fn create_boxxed_lightning_client(mode: LightningMode) -> Box<dyn ILnRpcClient> {
        match mode {
            LightningMode::Cln { cln_extension_addr } => {
                Box::new(NetworkLnRpcClient::new(cln_extension_addr).await)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Box::new(GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon).await),
        }
    }

    pub async fn route_htlcs(&mut self) -> Result<()> {
        let scid_to_federation = self.scid_to_federation.clone();
        let clients = self.clients.clone();
        let ln_mode = self.lightning_mode.clone();
        self.task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    loop {
                        if handle.is_shutting_down() {
                            break;
                        }

                        // Create a stream used to communicate with the Lightning implementation
                        let (sender, ln_receiver) = mpsc::channel::<InterceptHtlcResponse>(100);

                        if let Some(ln_mode) = ln_mode.clone() {
                            let mut lnrpc = Self::create_boxxed_lightning_client(ln_mode).await;

                            // Re-create the HTLC stream if the connection breaks
                            match lnrpc
                                .route_htlcs(ln_receiver.into(), &mut TaskGroup::new())
                                .await
                            {
                                Ok(stream) => {
                                    // Blocks until the connection to the lightning node breaks
                                    info!("Established HTLC stream");
                                    Self::handle_htlc_stream(stream, sender, handle.clone(), scid_to_federation.clone(), clients.clone()).await;
                                    tracing::warn!("HTLC Stream Lightning connection broken");
                                }
                                Err(_) => {
                                    error!("route_htlcs failed to open HTLC stream. Waiting 5 seconds and trying again");
                                    sleep(Duration::from_secs(5)).await;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                },
            )
            .await;
        Ok(())
    }

    async fn handle_htlc_stream(
        mut stream: RouteHtlcStream<'_>,
        sender: Sender<InterceptHtlcResponse>,
        handle: TaskHandle,
        scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
        clients: Arc<RwLock<BTreeMap<FederationId, Arc<fedimint_client::Client>>>>,
    ) {
        while let Some(Ok(htlc_request)) = stream.next().await {
            if handle.is_shutting_down() {
                break;
            }

            let scid_to_feds = scid_to_federation.read().await;
            let federation_id = scid_to_feds.get(&htlc_request.short_channel_id);
            // Just forward the HTLC if we do not have a federation that
            // corresponds to the short channel id
            if let Some(federation_id) = federation_id {
                let clients = clients.read().await;
                let client = clients.get(federation_id);
                // Just forward the HTLC if we do not have a client that
                // corresponds to the federation id
                if let Some(client) = client {
                    let htlc: Result<Htlc> = htlc_request
                        .clone()
                        .try_into()
                        .map_err(|_| GatewayError::ClientNgError);
                    if let Ok(htlc) = htlc {
                        let intercept_op = client.gateway_handle_intercepted_htlc(htlc).await;
                        // TODO: Refactor this into the state machine so we don't need to wait here
                        if let Ok(intercept_op) = intercept_op {
                            let intercept_sub =
                                client.gateway_subscribe_ln_receive(intercept_op).await;
                            if let Ok(intercept_sub) = intercept_sub {
                                let mut intercept_sub = intercept_sub.into_stream();

                                let outcome = loop {
                                    if let Ok(state) = intercept_sub.ok().await {
                                        match state {
                                            GatewayExtReceiveStates::Preimage(preimage) => {
                                                break InterceptHtlcResponse {
                                                    action: Some(Action::Settle(Settle {
                                                        preimage: preimage.0.to_vec(),
                                                    })),
                                                    incoming_chan_id: htlc_request.incoming_chan_id,
                                                    htlc_id: htlc_request.htlc_id,
                                                };
                                            }
                                            GatewayExtReceiveStates::FundingFailed(failed) => {
                                                break InterceptHtlcResponse {
                                                    action: Some(Action::Cancel(Cancel {
                                                        reason: failed,
                                                    })),
                                                    incoming_chan_id: htlc_request.incoming_chan_id,
                                                    htlc_id: htlc_request.htlc_id,
                                                }
                                            }
                                            GatewayExtReceiveStates::RefundSuccess(_) => {
                                                break InterceptHtlcResponse {
                                                    action: Some(Action::Cancel(Cancel {
                                                        reason: "Gateway is being refunded"
                                                            .to_string(),
                                                    })),
                                                    incoming_chan_id: htlc_request.incoming_chan_id,
                                                    htlc_id: htlc_request.htlc_id,
                                                }
                                            }
                                            GatewayExtReceiveStates::RefundError(failed) => {
                                                break InterceptHtlcResponse {
                                                    action: Some(Action::Cancel(Cancel {
                                                        reason: failed,
                                                    })),
                                                    incoming_chan_id: htlc_request.incoming_chan_id,
                                                    htlc_id: htlc_request.htlc_id,
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                };

                                if let Err(error) = sender.send(outcome).await {
                                    error!(
                                        "Error sending HTLC response to lightning node: {error:?}"
                                    );
                                }
                                continue;
                            }
                        }
                    }
                }
            }

            let outcome = InterceptHtlcResponse {
                action: Some(Action::Forward(Forward {})),
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(error) = sender.send(outcome).await {
                error!("Error sending HTLC response to lightning node: {error:?}");
            }
        }
    }

    async fn fetch_lightning_route_info(&self) -> Result<(Vec<RouteHint>, PublicKey, String)> {
        let mut num_retries = 0;
        let (route_hints, node_pub_key, alias) = loop {
            let route_hints: Vec<RouteHint> = self
                .lnrpc
                .routehints()
                .await?
                .try_into()
                .expect("Could not parse route hints");

            let GetNodeInfoResponse { pub_key, alias } = self.lnrpc.info().await?;
            let node_pub_key = PublicKey::from_slice(&pub_key)
                .map_err(|e| GatewayError::Other(anyhow!("Invalid node pubkey {}", e)))?;

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                break (route_hints, node_pub_key, alias);
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            num_retries += 1;
            sleep(ROUTE_HINT_RETRY_SLEEP).await;
        };

        Ok((route_hints, node_pub_key, alias))
    }

    async fn load_clients(&mut self) -> Result<()> {
        let dbtx = self.gatewayd_db.begin_transaction().await;
        if let Ok(configs) = self.client_builder.load_configs(dbtx).await {
            let channel_id_generator = self.channel_id_generator.lock().await;
            let mut next_channel_id = channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = Arc::new(
                    self.client_builder
                        .build(config.clone(), self.lnrpc.clone(), &mut self.task_group)
                        .await?,
                );

                // Registering each client happens in the background, since we're loading the
                // clients for the first time, just add them to the in-memory
                // maps
                let federation_id = config.config.federation_id;
                let scid = config.mint_channel_id;
                self.clients.write().await.insert(federation_id, client);
                self.scid_to_federation
                    .write()
                    .await
                    .insert(scid, federation_id);

                if config.mint_channel_id > next_channel_id {
                    next_channel_id = config.mint_channel_id + 1;
                }
            }
            channel_id_generator.store(next_channel_id, Ordering::SeqCst);
        }
        Ok(())
    }

    pub async fn register_client(
        &mut self,
        client: fedimint_client::Client,
        federation_id: FederationId,
        scid: u64,
        route_hints: Vec<RouteHint>,
    ) -> Result<()> {
        let register_op = client
            .register_with_federation(self.api.clone(), route_hints, GW_ANNOUNCEMENT_TTL)
            .await?;
        // TODO: Move this inside of the state machine
        {
            let mut register_sub = client
                .gateway_subscribe_register(register_op)
                .await?
                .into_stream();
            loop {
                let state = register_sub.ok().await?;
                match state {
                    GatewayExtRegisterStates::Success => break,
                    GatewayExtRegisterStates::Done => break,
                    _ => {}
                }
            }
        }

        self.clients
            .write()
            .await
            .insert(federation_id, Arc::new(client));
        self.scid_to_federation
            .write()
            .await
            .insert(scid, federation_id);
        Ok(())
    }

    pub async fn remove_client(
        &self,
        federation_id: FederationId,
    ) -> Result<Arc<fedimint_client::Client>> {
        self.clients
            .write()
            .await
            .remove(&federation_id)
            .ok_or(GatewayError::Other(anyhow::anyhow!(
                "No federation with id {}",
                federation_id.to_string()
            )))
    }

    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<Arc<fedimint_client::Client>> {
        self.clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(GatewayError::Other(anyhow::anyhow!(
                "No federation with id {}",
                federation_id.to_string()
            )))
    }

    async fn handle_connect_federation(
        &mut self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo> {
        let connect = WsClientConnectInfo::from_str(&payload.connect).map_err(|e| {
            GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        // The gateway deterministically assigns a channel id (u64) to each federation
        // connected. TODO: explicitly handle the case where the channel id
        // overflows
        let channel_id = self
            .channel_id_generator
            .lock()
            .await
            .fetch_add(1, Ordering::SeqCst);

        // Downloading the config can fail if another user tries to download at the same
        // time. Just retry after a small delay
        let gw_client_cfg = loop {
            match self
                .client_builder
                .create_config(connect.clone(), channel_id, self.fees)
                .await
            {
                Ok(gw_client_cfg) => break gw_client_cfg,
                Err(_) => {
                    let random_delay: f64 = rand::thread_rng().gen();
                    tracing::warn!(
                        "Error downloading client config, trying again in {random_delay}"
                    );
                    sleep(Duration::from_secs_f64(random_delay)).await;
                }
            }
        };

        let federation_id = gw_client_cfg.config.federation_id;
        let (route_hints, _, _) = self.fetch_lightning_route_info().await?;

        let client = self
            .client_builder
            .build(
                gw_client_cfg.clone(),
                self.lnrpc.clone(),
                &mut self.task_group,
            )
            .await?;

        let (gateway, _) = client.get_first_module::<GatewayClientModule>(&KIND);

        let registration = gateway.to_gateway_registration_info(
            route_hints.clone(),
            GW_ANNOUNCEMENT_TTL,
            self.api.clone(),
        );

        let balance = client.get_balance().await;

        self.register_client(client, federation_id, channel_id, route_hints)
            .await?;

        let dbtx = self.gatewayd_db.begin_transaction().await;
        self.client_builder
            .save_config(gw_client_cfg.clone(), dbtx)
            .await?;

        Ok(FederationInfo {
            federation_id,
            registration,
            balance,
        })
    }

    pub async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        let mut federations = Vec::new();
        let federation_clients = self.clients.read().await.clone().into_iter();
        let (route_hints, node_pub_key, alias) = self.fetch_lightning_route_info().await?;
        for (federation_id, client) in federation_clients {
            // TODO: We're reconstructing these registrations, which could have changed in
            // the meantime, which might break some tests if they're expecting
            // the same values as the previous registration
            let (gateway, _) = client.get_first_module::<GatewayClientModule>(&KIND);
            let registration = gateway.to_gateway_registration_info(
                route_hints.clone(),
                GW_ANNOUNCEMENT_TTL,
                self.api.clone(),
            );
            let balance = client.get_balance().await;

            federations.push(FederationInfo {
                federation_id,
                registration,
                balance,
            });
        }

        Ok(GatewayInfo {
            federations,
            version_hash: env!("CODE_VERSION").to_string(),
            lightning_pub_key: node_pub_key.to_hex(),
            lightning_alias: alias,
            fees: self.fees,
        })
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let client = self.select_client(federation_id).await?;
        let operation_id = client.gateway_pay_bolt11_invoice(contract_id).await?;
        let mut updates = client
            .gateway_subscribe_ln_pay(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                GatewayExtPayStates::Success {
                    preimage,
                    outpoint: _,
                } => return Ok(preimage),
                GatewayExtPayStates::Fail => {
                    return Err(GatewayError::Other(anyhow!("Payment failed")))
                }
                GatewayExtPayStates::Canceled => {
                    return Err(GatewayError::Other(anyhow!("Outgoing contract canceled")))
                }
                _ => {}
            };
        }

        return Err(GatewayError::Other(anyhow!(
            "Unexpected error occurred while paying the invoice"
        )));
    }

    pub async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        Ok(self
            .select_client(payload.federation_id)
            .await?
            .get_balance()
            .await)
    }

    pub async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        let (_, address) = self
            .select_client(payload.federation_id)
            .await?
            .get_deposit_address(now() + Duration::from_secs(86400 * 365))
            .await?;
        Ok(address)
    }

    pub async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<Txid> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        let client = self.select_client(federation_id).await?;
        // TODO: This should probably be passed in as a parameter
        let fees = client.get_withdraw_fee(address.clone(), amount).await?;

        let operation_id = self
            .select_client(federation_id)
            .await?
            .withdraw(address, amount, fees)
            .await?;
        let mut updates = client
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            info!("Update: {update:?}");

            match update {
                WithdrawState::Succeeded(txid) => {
                    return Ok(txid);
                }
                WithdrawState::Failed(e) => {
                    return Err(GatewayError::Other(anyhow!(e)));
                }
                _ => {}
            }
        }

        return Err(GatewayError::Other(anyhow!(
            "Unexpected error occurred while withdrawing"
        )));
    }

    pub async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id: _ }: BackupPayload,
    ) -> Result<()> {
        unimplemented!("Backup is not currently supported");
    }

    pub async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id: _ }: RestorePayload,
    ) -> Result<()> {
        unimplemented!("Restore is not currently supported");
    }

    pub async fn spawn_blocking_webserver(self, listen: SocketAddr, password: String) {
        let rx = run_webserver(password, listen, self)
            .await
            .expect("Failed to start webserver");

        let res = rx.await;
        if res.is_err() {
            error!("Error shutting down gatewayd: {res:?}");
        }
    }
}
