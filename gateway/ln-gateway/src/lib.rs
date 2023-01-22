pub mod actor;
pub mod client;
pub mod cln;
pub mod config;
pub mod ln;
pub mod rpc;
pub mod utils;

pub mod gatewaylnrpc {
    tonic::include_proto!("gatewaylnrpc");
}

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::Address;
use fedimint_api::config::ModuleGenRegistry;
use fedimint_api::{config::FederationId, module::registry::ModuleDecoderRegistry};
use fedimint_api::{task::TaskGroup, Amount, TransactionId};
use fedimint_server::modules::ln::contracts::Preimage;
use mint_client::{
    api::WsFederationConnect, ln::PayInvoicePayload, mint::MintClientError, ClientError,
    GatewayClient,
};
use rpc::{BackupPayload, RestorePayload};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, warn};

use crate::{
    actor::GatewayActor,
    client::DynGatewayClientBuilder,
    config::GatewayConfig,
    ln::{LightningError, LnRpc},
    rpc::{
        rpc_server::run_webserver, BalancePayload, ConnectFedPayload, DepositAddressPayload,
        DepositPayload, GatewayInfo, GatewayRequest, GatewayRpcSender, InfoPayload,
        ReceivePaymentPayload, WithdrawPayload,
    },
};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

pub struct LnGateway {
    config: GatewayConfig,
    decoders: ModuleDecoderRegistry,
    module_gens: ModuleGenRegistry,
    actors: Mutex<HashMap<String, Arc<GatewayActor>>>,
    ln_rpc: Arc<dyn LnRpc>,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    client_builder: DynGatewayClientBuilder,
    task_group: TaskGroup,
    channel_id_generator: AtomicU64,
}

impl LnGateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: GatewayConfig,
        decoders: ModuleDecoderRegistry,
        module_gens: ModuleGenRegistry,
        ln_rpc: Arc<dyn LnRpc>,
        client_builder: DynGatewayClientBuilder,
        // TODO: consider encapsulating message channel within LnGateway
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
        task_group: TaskGroup,
    ) -> Self {
        let ln_gw = Self {
            config,
            actors: Mutex::new(HashMap::new()),
            ln_rpc,
            sender,
            receiver,
            client_builder,
            task_group,
            channel_id_generator: AtomicU64::new(0),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
        };

        ln_gw.load_federation_actors(decoders, module_gens).await;

        ln_gw
    }

    async fn load_federation_actors(
        &self,
        decoders: ModuleDecoderRegistry,
        module_gens: ModuleGenRegistry,
    ) {
        if let Ok(configs) = self.client_builder.load_configs() {
            let mut next_channel_id = self.channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = self
                    .client_builder
                    .build(config.clone(), decoders.clone(), module_gens.clone())
                    .await
                    .expect("Could not build federation client");

                if let Err(e) = self.connect_federation(Arc::new(client)).await {
                    error!("Failed to connect federation: {}", e);
                }

                if config.mint_channel_id > next_channel_id {
                    next_channel_id = config.mint_channel_id + 1;
                }
            }
            self.channel_id_generator
                .store(next_channel_id, Ordering::SeqCst);
        } else {
            warn!("Could not load any previous federation configs");
        }
    }

    async fn select_actor(&self, federation_id: FederationId) -> Result<Arc<GatewayActor>> {
        self.actors
            .lock()
            .await
            .get(&federation_id.to_string())
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

        self.actors.lock().await.insert(
            client.config().client_config.federation_id.to_string(),
            actor.clone(),
        );
        Ok(actor)
    }

    // Webserver handler for requests to register a federation
    async fn handle_connect_federation(&self, payload: ConnectFedPayload) -> Result<()> {
        let connect: WsFederationConnect = serde_json::from_str(&payload.connect).map_err(|e| {
            LnGatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        let node_pub_key = self
            .ln_rpc
            .pubkey()
            .await
            .expect("Failed to get node pubkey from Lightning node");

        // The gateway deterministically assigns a channel id (u64) to each federation connected.
        // TODO: explicitly handle the case where the channel id overflows
        let channel_id = self.channel_id_generator.fetch_add(1, Ordering::SeqCst);

        let gw_client_cfg = self
            .client_builder
            .create_config(
                connect,
                channel_id,
                node_pub_key,
                self.config.announce_address.clone(),
            )
            .await
            .expect("Failed to create gateway client config");

        let client = Arc::new(
            self.client_builder
                .build(
                    gw_client_cfg.clone(),
                    self.decoders.clone(),
                    self.module_gens.clone(),
                )
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

    /// Handles an intercepted HTLC that might be an incoming payment we are receiving on behalf of
    /// a federation user.
    async fn handle_receive_payment(&self, payload: ReceivePaymentPayload) -> Result<Preimage> {
        let ReceivePaymentPayload { htlc_accepted } = payload;

        let invoice_amount = htlc_accepted.htlc.amount;
        let payment_hash = htlc_accepted.htlc.payment_hash;
        debug!("Incoming htlc for payment hash {}", payment_hash);

        // FIXME: Issue 664: We should avoid having a special reference to a federation
        // all requests, including `ReceivePaymentPayload`, should contain the federation id
        //
        // We use a random federation as the default (works because we only have one federation registered)
        //
        // TODO: Use subscribe intercept htlc streams to avoid actor selection with every intercepted htlc!
        self.actors.lock().await.values().collect::<Vec<_>>()[0]
            .buy_preimage_internal(&payment_hash, &invoice_amount)
            .await
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id).await?;
        let outpoint = actor.pay_invoice(self.ln_rpc.clone(), contract_id).await?;
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

    async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id }: BackupPayload,
    ) -> Result<()> {
        self.select_actor(federation_id).await?.backup().await
    }

    async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id }: RestorePayload,
    ) -> Result<()> {
        self.select_actor(federation_id).await?.restore().await
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tg = self.task_group.clone();

        let cfg = self.config.clone();
        let sender = GatewayRpcSender::new(self.sender.clone());
        tg.spawn("Gateway Webserver", move |server_ctrl| async move {
            let mut webserver = tokio::spawn(run_webserver(
                cfg.password.clone(),
                cfg.bind_address,
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
                    GatewayRequest::ReceivePayment(inner) => {
                        inner
                            .handle(|payload| self.handle_receive_payment(payload))
                            .await;
                    }
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
                    GatewayRequest::Backup(inner) => {
                        inner
                            .handle(|payload| self.handle_backup_msg(payload))
                            .await;
                    }
                    GatewayRequest::Restore(inner) => {
                        inner
                            .handle(|payload| self.handle_restore_msg(payload))
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
