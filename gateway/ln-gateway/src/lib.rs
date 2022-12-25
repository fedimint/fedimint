pub mod actor;
pub mod client;
pub mod config;
pub mod ln;
pub mod rpc;
pub mod utils;

pub mod gwlightningrpc {
    tonic::include_proto!("gwlightningrpc");
}

use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_api::{task::TaskGroup, Amount, TransactionId};
// use fedimint_server::modules::ln::contracts::Preimage;
use mint_client::{
    api::WsFederationConnect, ln::PayInvoicePayload, mint::MintClientError, ClientError,
    FederationId, GatewayClient,
};
use rpc::{ln_rpc_client::LnRpcClient, FederationInfo};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, warn};

use crate::{
    actor::GatewayActor,
    client::GatewayClientBuilder,
    config::GatewayConfig,
    ln::LightningError,
    rpc::{
        rpc_server::run_webserver, BalancePayload, ConnectFedPayload, DepositAddressPayload,
        DepositPayload, GatewayInfo, GatewayRequest, GatewayRpcSender, InfoPayload,
        WithdrawPayload,
    },
};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

pub struct LnGateway {
    config: GatewayConfig,
    actors: Mutex<HashMap<Sha256Hash, Arc<GatewayActor>>>,
    ln_rpc: Mutex<Option<Arc<LnRpcClient>>>,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    client_builder: GatewayClientBuilder,
    task_group: TaskGroup,
}

impl LnGateway {
    pub async fn new(
        config: GatewayConfig,
        client_builder: GatewayClientBuilder,
        task_group: TaskGroup,
    ) -> Self {
        // Create message channels
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let ln_gw = Self {
            config: config.clone(),
            actors: Mutex::new(HashMap::new()),
            ln_rpc: Mutex::new(None),
            sender,
            receiver,
            client_builder,
            task_group,
        };

        ln_gw
            .create_lightning_rpc_client(config.lnrpc_bind_address)
            .await;

        ln_gw.load_federation_actors().await;

        ln_gw
    }

    async fn create_lightning_rpc_client(&self, address: SocketAddr) {
        let ln_rpc = Arc::new(
            LnRpcClient::new(address)
                .await
                .expect("Failed to create Lightning RPC client"),
        );

        self.ln_rpc.lock().await.replace(ln_rpc);
    }

    async fn get_ln_rpc_client(&self) -> Arc<LnRpcClient> {
        self.ln_rpc
            .lock()
            .await
            .clone()
            .expect("Missing lightning RPC client")
    }

    async fn load_federation_actors(&self) {
        if let Ok(configs) = self.client_builder.load_configs() {
            for config in configs {
                let client = self
                    .client_builder
                    .build(config.clone())
                    .await
                    .expect("Could not build federation client");

                if let Err(e) = self.connect_federation(Arc::new(client)).await {
                    error!("Failed to connect federation: {}", e);
                }
            }
        } else {
            warn!("Could not load any previous federation configs");
        }
    }

    async fn select_actor(&self, federation_id: FederationId) -> Result<Arc<GatewayActor>> {
        self.actors
            .lock()
            .await
            .get(&federation_id.hash())
            .cloned()
            .ok_or(LnGatewayError::UnknownFederation)
    }

    /// Register a federation to the gateway.
    ///
    /// # Returns
    ///
    /// A `GatewayActor` that can be used to execute gateway functions for the federation
    pub async fn connect_federation(
        &self,
        client: Arc<GatewayClient>,
    ) -> Result<Arc<GatewayActor>> {
        let actor = Arc::new(
            GatewayActor::new(client.clone())
                .await
                .expect("Failed to create actor"),
        );

        let FederationInfo {
            federation_id,
            mint_pubkey,
        } = actor
            .get_info()
            .expect("Failed to get federation info from new actor");

        self.get_ln_rpc_client()
            .await
            .subscribe_intercept_htlcs(mint_pubkey)
            .await
            .expect("Failed to subscribe to intercept HTLCs");

        self.actors
            .lock()
            .await
            .insert(federation_id.hash(), actor.clone());
        Ok(actor)
    }

    // Webserver handler for requests to register a federation
    async fn handle_connect_federation(&self, payload: ConnectFedPayload) -> Result<()> {
        let connect: WsFederationConnect = serde_json::from_str(&payload.connect).map_err(|e| {
            LnGatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        let node_pub_key = self
            .get_ln_rpc_client()
            .await
            .get_pub_key()
            .await
            .expect("Failed to get node pubkey from Lightning node");

        let gw_client_cfg = self
            .client_builder
            .create_config(
                connect,
                node_pub_key,
                self.config.api_announce_address.clone(),
            )
            .await
            .expect("Failed to create gateway client config");

        let client = Arc::new(
            self.client_builder
                .build(gw_client_cfg.clone())
                .await
                .expect("Failed to build gateway client"),
        );

        if let Err(e) = self.connect_federation(client.clone()).await {
            error!("Failed to connect federation: {}", e);
        }

        if let Err(e) = self.client_builder.save_config(client.config()) {
            warn!(
                "Failed to save default federation client configuration: {}",
                e
            );
        }

        Ok(())
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        let federations = self
            .actors
            .lock()
            .await
            .iter()
            .map(|(_, actor)| actor.get_info().expect("Failed to get actor info"))
            .collect();

        Ok(GatewayInfo {
            federations,
            version_hash: env!("GIT_HASH").to_string(),
        })
    }

    // async fn handle_receive_invoice_msg(&self, payload: ReceivePaymentPayload) -> Result<Preimage> {
    //     let ReceivePaymentPayload { htlc_accepted } = payload;

    //     let invoice_amount = htlc_accepted.htlc.amount;
    //     let payment_hash = htlc_accepted.htlc.payment_hash;
    //     debug!("Incoming htlc for payment hash {}", payment_hash);

    //     // FIXME: Issue 664: We should avoid having a special reference to a federation
    //     // all requests, including `ReceivePaymentPayload`, should contain the federation id
    //     // TODO: Parse federation id from routing hint in htlc_accepted message
    //     self.select_actor(self.config.default_federation.clone())
    //         .await?
    //         .buy_preimage_internal(&payment_hash, &invoice_amount)
    //         .await
    // }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id).await?;
        let outpoint = actor
            .pay_invoice(self.get_ln_rpc_client().await.clone(), contract_id)
            .await?;
        actor
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        self.select_actor(payload.federation_id)
            .await?
            .get_balance()
            .await
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        self.select_actor(payload.federation_id)
            .await?
            .get_deposit_address()
            .await
    }

    async fn handle_deposit_msg(&self, payload: DepositPayload) -> Result<TransactionId> {
        let DepositPayload {
            txout_proof,
            transaction,
            federation_id,
        } = payload;

        self.select_actor(federation_id)
            .await?
            .deposit(txout_proof, transaction)
            .await
    }

    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<TransactionId> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        self.select_actor(federation_id)
            .await?
            .withdraw(amount, address)
            .await
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tg = self.task_group.clone();

        let cfg = self.config.clone();
        let sender = GatewayRpcSender::new(self.sender.clone());
        tg.spawn("Gateway Webserver", move |server_ctrl| async move {
            let mut webserver = tokio::spawn(run_webserver(
                cfg.webserver_password.clone(),
                cfg.webserver_bind_address,
                sender,
            ));

            // Shut down webserver if requested
            if server_ctrl.is_shutting_down() {
                webserver.abort();
                let _ = futures::executor::block_on(&mut webserver);
            }
        })
        .await;

        // TODO: try to drive forward outgoing and incoming payments that were interrupted
        let loop_ctrl = tg.make_handle();
        loop {
            // Shut down main loop if requested
            if loop_ctrl.is_shutting_down() {
                break;
            }

            let least_wait_until = Instant::now() + Duration::from_millis(100);

            // Handle messages from webserver and plugin
            while let Ok(msg) = self.receiver.try_recv() {
                tracing::trace!("Gateway received message {:?}", msg);
                match msg {
                    GatewayRequest::Info(inner) => {
                        inner.handle(|payload| self.handle_get_info(payload)).await;
                    }
                    GatewayRequest::ConnectFederation(inner) => {
                        inner
                            .handle(|payload| self.handle_connect_federation(payload))
                            .await;
                    }
                    // GatewayRequest::ReceivePayment(inner) => {
                    //     inner
                    //         .handle(|payload| self.handle_receive_invoice_msg(payload))
                    //         .await;
                    // }
                    GatewayRequest::PayInvoice(inner) => {
                        inner
                            .handle(|payload| self.handle_pay_invoice_msg(payload))
                            .await;
                    }
                    GatewayRequest::Balance(inner) => {
                        inner
                            .handle(|payload| self.handle_balance_msg(payload))
                            .await;
                    }
                    GatewayRequest::DepositAddress(inner) => {
                        inner
                            .handle(|payload| self.handle_address_msg(payload))
                            .await;
                    }
                    GatewayRequest::Deposit(inner) => {
                        inner
                            .handle(|payload| self.handle_deposit_msg(payload))
                            .await;
                    }
                    GatewayRequest::Withdraw(inner) => {
                        inner
                            .handle(|payload| self.handle_withdraw_msg(payload))
                            .await;
                    }
                }
            }

            fedimint_api::task::sleep_until(least_wait_until).await;
        }
        Ok(())
    }
}

impl Drop for LnGateway {
    fn drop(&mut self) {
        futures::executor::block_on(self.task_group.shutdown());
    }
}

#[derive(Debug, Error)]
pub enum LnGatewayError {
    #[error("Federation client operation error: {0:?}")]
    ClientError(#[from] ClientError),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
    #[error("Mint client error: {0:?}")]
    MintClientE(#[from] MintClientError),
    #[error("Actor not found")]
    UnknownFederation,
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for LnGatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{:?}", self)).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}
