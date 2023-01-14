use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bitcoin::Address;
use fedimint_api::{
    config::{FederationId, ModuleGenRegistry},
    module::registry::ModuleDecoderRegistry,
    task::TaskGroup,
    Amount, TransactionId,
};
use fedimint_server::api::WsFederationConnect;
use mint_client::modules::ln::{contracts::Preimage, route_hints::RouteHint};
use mint_client::{ln::PayInvoicePayload, GatewayClient};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use super::actor::GatewayActor;
use crate::{
    client::DynGatewayClientBuilder,
    gatewayd::lnrpc_client::{DynLnRpcClient, GetRouteHintsResponse},
    rpc::{
        rpc_server::run_webserver, BackupPayload, BalancePayload, ConnectFedPayload,
        DepositAddressPayload, DepositPayload, GatewayInfo, GatewayRequest, GatewayRpcSender,
        InfoPayload, ReceivePaymentPayload, RestorePayload, WithdrawPayload,
    },
    LnGatewayError, Result,
};

const ROUTE_HINT_RETRIES: usize = 10;
const ROUTE_HINT_RETRY_SLEEP: Duration = Duration::from_secs(2);

pub struct Gateway {
    decoders: ModuleDecoderRegistry,
    module_gens: ModuleGenRegistry,
    lnrpc: DynLnRpcClient,
    actors: Mutex<HashMap<String, Arc<GatewayActor>>>,
    client_builder: DynGatewayClientBuilder,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    task_group: TaskGroup,
    channel_id_generator: AtomicU64,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lnrpc: DynLnRpcClient,
        client_builder: DynGatewayClientBuilder,
        decoders: ModuleDecoderRegistry,
        module_gens: ModuleGenRegistry,
        task_group: TaskGroup,
    ) -> Self {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        // Source route hints form the LN node
        let mut num_retries = 0;
        let route_hints = loop {
            let GetRouteHintsResponse { route_hints } = lnrpc
                .route_hints()
                .await
                .expect("Could not feth route hints");

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                break route_hints;
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            num_retries += 1;
            tokio::time::sleep(ROUTE_HINT_RETRY_SLEEP).await;
        };

        let gw = Self {
            lnrpc,
            actors: Mutex::new(HashMap::new()),
            sender,
            receiver,
            client_builder,
            task_group,
            channel_id_generator: AtomicU64::new(0),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
        };

        gw.load_federation_actors(decoders, module_gens, route_hints)
            .await;

        gw
    }

    async fn load_federation_actors(
        &self,
        decoders: ModuleDecoderRegistry,
        module_gens: ModuleGenRegistry,
        route_hints: Vec<RouteHint>,
    ) {
        if let Ok(configs) = self.client_builder.load_configs() {
            let mut next_channel_id = self.channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = self
                    .client_builder
                    .build(config.clone(), decoders.clone(), module_gens.clone())
                    .await
                    .expect("Could not build federation client");

                if let Err(e) = self
                    .connect_federation(Arc::new(client), route_hints.clone())
                    .await
                {
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

    pub async fn connect_federation(
        &self,
        client: Arc<GatewayClient>,
        route_hints: Vec<RouteHint>,
    ) -> Result<Arc<GatewayActor>> {
        let actor = Arc::new(
            GatewayActor::new(client.clone(), route_hints)
                .await
                .expect("Failed to create actor"),
        );

        // TODO: Subscribe for HTLC intercept on behalf of this federation

        self.actors.lock().await.insert(
            client.config().client_config.federation_id.to_string(),
            actor.clone(),
        );
        Ok(actor)
    }

    async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
        route_hints: Vec<RouteHint>,
    ) -> Result<()> {
        let connect: WsFederationConnect = serde_json::from_str(&payload.connect).map_err(|e| {
            LnGatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        let node_pub_key = self
            .lnrpc
            .pubkey()
            .await
            .expect("Failed to get node pubkey from Lightning node");

        // The gateway deterministically assigns a channel id (u64) to each federation connected.
        // TODO: explicitly handle the case where the channel id overflows
        let channel_id = self.channel_id_generator.fetch_add(1, Ordering::SeqCst);

        let gw_client_cfg = self
            .client_builder
            .create_config(connect, channel_id, node_pub_key, self.module_gens.clone())
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

        if let Err(e) = self.connect_federation(client.clone(), route_hints).await {
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
    async fn handle_receive_payment(&self, _payload: ReceivePaymentPayload) -> Result<Preimage> {
        Err(LnGatewayError::Other(anyhow::anyhow!(
            "Not implemented: handle_receive_payment"
        )))
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id).await?;
        let outpoint = actor.pay_invoice(self.lnrpc.clone(), contract_id).await?;
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

    pub async fn run(mut self, listen: SocketAddr, password: String) -> Result<()> {
        let mut tg = self.task_group.clone();

        let sender = GatewayRpcSender::new(self.sender.clone());
        tg.spawn("Gateway Webserver", move |server_ctrl| async move {
            let mut webserver = tokio::spawn(run_webserver(password, listen, sender));

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
                        let GetRouteHintsResponse { route_hints } =
                            self.lnrpc.route_hints().await?;
                        inner
                            .handle(|payload| {
                                self.handle_connect_federation(payload, route_hints.clone())
                            })
                            .await;
                    }
                    // TODO: Remove this handler because Gateway uses lnrpc to intercept HTLCs
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

impl Drop for Gateway {
    fn drop(&mut self) {
        futures::executor::block_on(self.task_group.shutdown());
    }
}
