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
use fedimint_core::api::{FederationError, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::task::{sleep, RwLock, TaskGroup};
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
use tokio::sync::mpsc;
use tracing::{error, info};
use url::Url;

use crate::client::DynGatewayClientBuilder;
use crate::gatewaylnrpc::intercept_htlc_response::{Forward, Settle};
use crate::lnd::GatewayLndClient;
use crate::lnrpc_client::NetworkLnRpcClient;
use crate::ng::{GatewayExtPayStates, GatewayExtReceiveStates, Htlc};
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, GatewayInfo,
    GatewayRequest, GatewayRpcSender, InfoPayload, RestorePayload, WithdrawPayload,
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
pub struct Gateway {
    lnrpc: Arc<dyn ILnRpcClient>,
    lightning_mode: Option<LightningMode>,
    clients: Arc<RwLock<BTreeMap<FederationId, Arc<fedimint_client::Client>>>>,
    scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
    client_builder: DynGatewayClientBuilder,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    channel_id_generator: AtomicU64,
    fees: RoutingFees,
    gatewayd_db: Database,
    api: Url,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lightning_mode: LightningMode,
        client_builder: DynGatewayClientBuilder,
        task_group: &mut TaskGroup,
        fees: RoutingFees,
        gatewayd_db: Database,
        api: Url,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let lnrpc = Self::create_lightning_client(lightning_mode.clone()).await?;

        let mut gw = Self {
            lnrpc,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            sender,
            receiver,
            client_builder,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            lightning_mode: Some(lightning_mode),
            fees,
            gatewayd_db,
            api,
        };

        gw.load_clients(task_group).await?;
        gw.route_htlcs(task_group).await?;

        Ok(gw)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_lightning_connection(
        lnrpc: Arc<dyn ILnRpcClient>,
        client_builder: DynGatewayClientBuilder,
        fees: RoutingFees,
        gatewayd_db: Database,
        task_group: &mut TaskGroup,
        api: Url,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let mut gw = Self {
            lnrpc,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            sender,
            receiver,
            client_builder,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            lightning_mode: None,
            fees,
            gatewayd_db,
            api,
        };

        gw.load_clients(task_group).await?;
        gw.route_htlcs(task_group).await?;

        Ok(gw)
    }

    async fn create_lightning_client(mode: LightningMode) -> Result<Arc<dyn ILnRpcClient>> {
        let lnrpc: Arc<dyn ILnRpcClient> = match mode {
            LightningMode::Cln { cln_extension_addr } => {
                info!(
                    "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                    cln_extension_addr
                );
                Arc::new(NetworkLnRpcClient::new(cln_extension_addr).await?)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => {
                info!(
                    "Gateway configured to connect to LND LnRpcClient at \n address: {:?},\n tls cert path: {:?},\n macaroon path: {} ",
                    lnd_rpc_addr, lnd_tls_cert, lnd_macaroon
                );
                Arc::new(GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon).await?)
            }
        };

        Ok(lnrpc)
    }

    pub async fn route_htlcs(&self, task_group: &mut TaskGroup) -> Result<()> {
        // Create a stream used to communicate with the Lightning implementation
        let (sender, ln_receiver) = mpsc::channel::<InterceptHtlcResponse>(100);

        let mut lnrpc: Box<dyn ILnRpcClient> = match &self.lightning_mode {
            Some(LightningMode::Cln { cln_extension_addr }) => {
                info!(
                    "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                    cln_extension_addr
                );
                Box::new(NetworkLnRpcClient::new(cln_extension_addr.clone()).await?)
            }
            Some(LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            }) => Box::new(
                GatewayLndClient::new(
                    lnd_rpc_addr.clone(),
                    lnd_tls_cert.clone(),
                    lnd_macaroon.clone(),
                )
                .await?,
            ),
            _ => return Ok(()),
        };

        let mut stream: RouteHtlcStream = lnrpc.route_htlcs(ln_receiver.into(), task_group).await?;

        let scid_to_federation = self.scid_to_federation.clone();
        let clients = self.clients.clone();
        task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    // TODO: Need to recreate the lightning connection if it breaks while processing
                    // HTLCs
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
                                let htlc: Result<Htlc> = htlc_request.clone().try_into().map_err(|_| GatewayError::ClientNgError);
                                if let Ok(htlc) = htlc {
                                    let intercept_op = client.gateway_handle_intercepted_htlc(htlc).await;
                                    // TODO: Refactor this into the state machine so we don't need to wait here
                                    if let Ok(intercept_op) = intercept_op {

                                        let intercept_sub = client
                                            .gateway_subscribe_ln_receive(intercept_op)
                                            .await;
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
                                                                    reason: "Gateway is being refunded".to_string(),
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
                                                error!("Error sending HTLC response to lightning node: {error:?}");
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
                },
            )
            .await;
        Ok(())
    }

    async fn fetch_lightning_route_info(&self) -> Result<(Vec<RouteHint>, PublicKey, String)> {
        let mut num_retries = 0;
        let (route_hints, node_pub_key, alias) = loop {
            let route_hints: Vec<RouteHint> = self
                .lnrpc
                .routehints()
                .await
                .expect("Could not fetch route hints")
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

    async fn load_clients(&mut self, task_group: &mut TaskGroup) -> Result<()> {
        let dbtx = self.gatewayd_db.begin_transaction().await;
        if let Ok(configs) = self.client_builder.load_configs(dbtx).await {
            let mut next_channel_id = self.channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = Arc::new(
                    self.client_builder
                        .build(config.clone(), self.lnrpc.clone(), task_group)
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
            self.channel_id_generator
                .store(next_channel_id, Ordering::SeqCst);
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

    async fn select_client(
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
        fees: RoutingFees,
        task_group: &mut TaskGroup,
    ) -> Result<FederationInfo> {
        let connect = WsClientConnectInfo::from_str(&payload.connect).map_err(|e| {
            GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        // The gateway deterministically assigns a channel id (u64) to each federation
        // connected. TODO: explicitly handle the case where the channel id
        // overflows
        let channel_id = self.channel_id_generator.fetch_add(1, Ordering::SeqCst);

        // Downloading the config can fail if another user tries to download at the same
        // time. Just retry after a small delay
        let gw_client_cfg = loop {
            match self
                .client_builder
                .create_config(connect.clone(), channel_id, fees)
                .await
            {
                Ok(gw_client_cfg) => break gw_client_cfg,
                Err(_) => {
                    let random_delay = rand::thread_rng().gen_range(1..=3);
                    tracing::warn!(
                        "Error downloading client config, trying again in {random_delay}"
                    );
                    sleep(Duration::from_secs(random_delay)).await;
                }
            }
        };

        let federation_id = gw_client_cfg.config.federation_id;
        let (route_hints, _, _) = self.fetch_lightning_route_info().await?;

        let client = self
            .client_builder
            .build(gw_client_cfg.clone(), self.lnrpc.clone(), task_group)
            .await?;

        let (gateway, _) = client.get_first_module::<GatewayClientModule>(&KIND);

        let registration = gateway.to_gateway_registration_info(
            route_hints.clone(),
            GW_ANNOUNCEMENT_TTL,
            self.api.clone(),
        );

        self.register_client(client, federation_id, channel_id, route_hints)
            .await?;

        let dbtx = self.gatewayd_db.begin_transaction().await;
        self.client_builder
            .save_config(gw_client_cfg.clone(), dbtx)
            .await?;

        Ok(FederationInfo {
            federation_id,
            registration,
        })
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
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

            federations.push(FederationInfo {
                federation_id,
                registration,
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

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        Ok(self
            .select_client(payload.federation_id)
            .await?
            .get_balance()
            .await)
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        let (_, address) = self
            .select_client(payload.federation_id)
            .await?
            .get_deposit_address(now() + Duration::from_secs(86400 * 365))
            .await?;
        Ok(address)
    }

    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<Txid> {
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

    async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id: _ }: BackupPayload,
    ) -> Result<()> {
        unimplemented!("Backup is not currently supported");
    }

    async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id: _ }: RestorePayload,
    ) -> Result<()> {
        unimplemented!("Restore is not currently supported");
    }

    pub async fn spawn_webserver(
        &self,
        listen: SocketAddr,
        password: String,
        task_group: &mut TaskGroup,
    ) {
        let sender = GatewayRpcSender::new(self.sender.clone());
        let tx = run_webserver(password, listen, sender, task_group)
            .await
            .expect("Failed to start webserver");

        // TODO: try to drive forward outgoing and incoming payments that were
        // interrupted
        let loop_ctrl = task_group.make_handle();
        let shutdown_sender = self.sender.clone();
        loop_ctrl
            .on_shutdown(Box::new(|| {
                Box::pin(async move {
                    // Send shutdown signal to the webserver
                    let _ = tx.send(());

                    // Send shutdown signal to the handler loop
                    let _ = shutdown_sender.send(GatewayRequest::Shutdown).await;
                })
            }))
            .await;
    }

    pub async fn run(mut self, task_group: &mut TaskGroup) -> Result<()> {
        let loop_ctrl = task_group.make_handle();
        // Handle messages from webserver and plugin
        while let Some(msg) = self.receiver.recv().await {
            tracing::trace!("Gateway received message {:?}", msg);

            // Shut down main loop if requested
            if loop_ctrl.is_shutting_down() {
                break;
            }

            match msg {
                GatewayRequest::Info(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_get_info(payload)
                        })
                        .await;
                }
                GatewayRequest::ConnectFederation(inner) => {
                    let fees = self.fees;

                    inner
                        .handle(&mut self, task_group, |gateway, tg, payload| {
                            gateway.handle_connect_federation(payload, fees, tg)
                        })
                        .await;
                }
                GatewayRequest::PayInvoice(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_pay_invoice_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::Balance(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_balance_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::DepositAddress(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_address_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::Withdraw(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_withdraw_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::Backup(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_backup_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::Restore(inner) => {
                    inner
                        .handle(&mut self, task_group, |gateway, _, payload| {
                            gateway.handle_restore_msg(payload)
                        })
                        .await;
                }
                GatewayRequest::Shutdown => {
                    info!("Gatewayd received shutdown request");
                    break;
                }
            }
        }

        Ok(())
    }
}
