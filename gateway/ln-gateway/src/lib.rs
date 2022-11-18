pub mod actor;
pub mod client;
pub mod cln;
pub mod config;
pub mod ln;
pub mod rpc;
pub mod utils;

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_api::{config::ClientConfig, task::TaskGroup, Amount, NumPeers, TransactionId};
use fedimint_server::modules::ln::contracts::Preimage;
use mint_client::{
    api::{WsFederationApi, WsFederationConnect},
    ln::PayInvoicePayload,
    mint::MintClientError,
    query::CurrentConsensus,
    ClientError, FederationId, GatewayClient, GatewayClientConfig,
};
use secp256k1::KeyPair;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use url::Url;

use crate::{
    actor::GatewayActor,
    client::GatewayClientBuilder,
    config::GatewayConfig,
    ln::{LightningError, LnRpc},
    rpc::{
        rpc_server::run_webserver, BalancePayload, DepositAddressPayload, DepositPayload,
        GatewayInfo, GatewayRequest, GatewayRpcSender, InfoPayload, ReceivePaymentPayload,
        RegisterFedPayload, WithdrawPayload,
    },
};

pub type Result<T> = std::result::Result<T, LnGatewayError>;

pub struct LnGateway {
    config: GatewayConfig,
    actors: Mutex<HashMap<Sha256Hash, Arc<GatewayActor>>>,
    ln_rpc: Arc<dyn LnRpc>,
    webserver: tokio::task::JoinHandle<axum::response::Result<()>>,
    receiver: mpsc::Receiver<GatewayRequest>,
    client_builder: GatewayClientBuilder,
    task_group: TaskGroup,
}

impl LnGateway {
    pub fn new(
        config: GatewayConfig,
        ln_rpc: Arc<dyn LnRpc>,
        client_builder: GatewayClientBuilder,
        // TODO: consider encapsulating message channel within LnGateway
        sender: mpsc::Sender<GatewayRequest>,
        receiver: mpsc::Receiver<GatewayRequest>,
        task_group: TaskGroup,
    ) -> Self {
        // Run webserver asynchronously in tokio
        let webserver = tokio::spawn(run_webserver(
            config.password.clone(),
            config.address,
            GatewayRpcSender::new(sender),
        ));

        Self {
            config,
            actors: Mutex::new(HashMap::new()),
            ln_rpc,
            webserver,
            receiver,
            client_builder,
            task_group,
        }
    }

    fn select_actor(&self, federation_id: FederationId) -> Result<Arc<GatewayActor>> {
        self.actors
            .lock()
            .map_err(|_| LnGatewayError::Other(anyhow::anyhow!("Failed to select an actor")))?
            .get(&federation_id.hash())
            .cloned()
            .ok_or(LnGatewayError::UnknownFederation)
    }

    /// Register a federation to the gateway.
    ///
    /// # Returns
    ///
    /// A `GatewayActor` that can be used to execute gateway functions for the federation
    pub async fn register_federation(
        &self,
        client: Arc<GatewayClient>,
    ) -> Result<Arc<GatewayActor>> {
        let federation_id = FederationId(client.config().client_config.federation_name);

        let actor = Arc::new(
            GatewayActor::new(client.clone(), federation_id.clone())
                .await
                .expect("Failed to create actor"),
        );

        if let Ok(mut actors) = self.actors.lock() {
            actors.insert(federation_id.hash(), actor.clone());
        }
        Ok(actor)
    }

    // Webserver handler for requests to register a federation
    async fn handle_register_federation(&self, payload: RegisterFedPayload) -> Result<()> {
        let connect: WsFederationConnect =
            serde_json::from_str(&payload.connect).expect("Invalid federation connect info");
        let api = WsFederationApi::new(connect.members);

        let client_cfg: ClientConfig = api
            .request(
                "/config",
                (),
                CurrentConsensus::new(api.peers().one_honest()),
            )
            .await
            .expect("Failed to get client config");

        let mut rng = rand::rngs::OsRng;
        let ctx = secp256k1::Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        let node_pub_key = self
            .ln_rpc
            .pubkey()
            .await
            .expect("Failed to get node pubkey from Lightning node");

        let gw_client_cfg = GatewayClientConfig {
            client_config: client_cfg,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key,
            api: Url::parse(format!("http://{}", self.config.address).as_str())
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
        };

        let client = self.client_builder.build(gw_client_cfg.clone())?;

        if let Err(e) = self.register_federation(Arc::new(client)).await {
            error!("Failed to register federation: {}", e);
        }

        if let Err(e) = self.client_builder.save_config(gw_client_cfg) {
            warn!(
                "Failed to save default federation client configuration: {}",
                e
            );
        }

        Ok(())
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        if let Ok(actors) = self.actors.lock() {
            return Ok(GatewayInfo {
                version_hash: env!("GIT_HASH").to_string(),
                federations: actors.iter().map(|(_, actor)| actor.id.clone()).collect(),
            });
        }
        Err(LnGatewayError::Other(anyhow::anyhow!(
            "Failed to fetch gateway get info"
        )))
    }

    async fn handle_receive_invoice_msg(&self, payload: ReceivePaymentPayload) -> Result<Preimage> {
        let ReceivePaymentPayload { htlc_accepted } = payload;

        let invoice_amount = htlc_accepted.htlc.amount;
        let payment_hash = htlc_accepted.htlc.payment_hash;
        debug!("Incoming htlc for payment hash {}", payment_hash);

        // FIXME: Issue 664: We should avoid having a special reference to a federation
        // all requests, including `ReceivePaymentPayload`, should contain the federation id
        // TODO: Parse federation id from routing hint in htlc_accepted message
        self.select_actor(self.config.default_federation.clone())?
            .buy_preimage_internal(&payment_hash, &invoice_amount)
            .await
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id)?;
        let outpoint = actor.pay_invoice(self.ln_rpc.clone(), contract_id).await?;
        actor
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        self.select_actor(payload.federation_id)?
            .get_balance()
            .await
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        self.select_actor(payload.federation_id)?
            .get_deposit_address()
            .await
    }

    async fn handle_deposit_msg(&self, payload: DepositPayload) -> Result<TransactionId> {
        let DepositPayload {
            txout_proof,
            transaction,
            federation_id,
        } = payload;

        self.select_actor(federation_id)?
            .deposit(txout_proof, transaction)
            .await
    }

    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<TransactionId> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        self.select_actor(federation_id)?
            .withdraw(amount, address)
            .await
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tg = self.task_group.clone();
        let loop_ctrl = tg.make_handle();

        // TODO: try to drive forward outgoing and incoming payments that were interrupted
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
                    GatewayRequest::RegisterFederation(inner) => {
                        inner
                            .handle(|payload| self.handle_register_federation(payload))
                            .await;
                    }
                    GatewayRequest::ReceivePayment(inner) => {
                        inner
                            .handle(|payload| self.handle_receive_invoice_msg(payload))
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
                }
            }

            fedimint_api::task::sleep_until(least_wait_until).await;
        }
        Ok(())
    }
}

impl Drop for LnGateway {
    fn drop(&mut self) {
        self.webserver.abort();
        let _ = futures::executor::block_on(&mut self.webserver);
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
