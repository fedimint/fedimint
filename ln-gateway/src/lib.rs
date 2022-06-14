pub mod ln;

use crate::ln::{LightningError, LnRpc};
use minimint::modules::ln::contracts::ContractId;
use minimint_api::{db::Database, OutPoint};
use mint_client::clients::gateway::{GatewayClient, GatewayClientConfig, GatewayClientError};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, instrument};
use tracing::{error, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct LnGatewayConfig {
    pub federation_client: GatewayClientConfig,
    pub ln_socket: PathBuf,
}

pub struct LnGateway {
    federation_client: Arc<GatewayClient>,
    ln_client: Arc<dyn LnRpc>,
    fetcher: tokio::task::JoinHandle<()>,
}

impl LnGateway {
    pub async fn from_config(db: Box<dyn Database>, cfg: LnGatewayConfig) -> LnGateway {
        let LnGatewayConfig {
            federation_client,
            ln_socket,
        } = cfg;
        let federation_client = GatewayClient::new(federation_client, db);
        let ln_client = cln_rpc::ClnRpc::new(ln_socket)
            .await
            .expect("connect to ln_socket");
        let ln_client = Mutex::new(ln_client);

        Self::new(Arc::new(federation_client), Box::new(ln_client)).await
    }

    pub async fn new(
        federation_client: Arc<GatewayClient>,
        ln_client: Box<dyn LnRpc>,
    ) -> LnGateway {
        let ln_client: Arc<dyn LnRpc> = ln_client.into();
        let fetcher = tokio::spawn(background_fetch(
            federation_client.clone(),
            ln_client.clone(),
        ));

        LnGateway {
            federation_client,
            ln_client,
            fetcher,
        }
    }

    #[instrument(skip_all, fields(%contract_id))]
    pub async fn pay_invoice(
        &self,
        contract_id: ContractId,
        rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint, LnGatewayError> {
        debug!("Fetching contract");
        let contract_account = self
            .federation_client
            .fetch_outgoing_contract(contract_id)
            .await?;

        let payment_params = self
            .federation_client
            .validate_outgoing_account(&contract_account)
            .await?;

        debug!(
            account = ?contract_account,
            "Fetched and validated contract account"
        );

        self.federation_client
            .save_outgoing_payment(contract_account.clone());

        let preimage = match self
            .ln_client
            .pay(
                &contract_account.contract.invoice,
                payment_params.max_delay,
                payment_params.max_fee_percent,
            )
            .await
        {
            Ok(preimage) => {
                debug!(?preimage, "Successfully paid LN invoice");
                preimage
            }
            Err(e) => {
                warn!("LN payment failed, aborting");
                self.federation_client.abort_outgoing_payment(contract_id);
                return Err(LnGatewayError::CouldNotRoute(e));
            }
        };

        // FIXME: figure out how to treat RNGs (maybe include in context?)
        debug!("Claiming outgoing contract");
        let outpoint = self
            .federation_client
            .claim_outgoing_contract(contract_id, preimage, rng)
            .await?;

        Ok(outpoint)
    }

    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<(), LnGatewayError> {
        Ok(self
            .federation_client
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?)
    }
}

/// This function runs as a background process fetching issued token signatures and driving forward
/// payments which were interrupted during execution.
#[instrument(skip_all)]
async fn background_fetch(federation_client: Arc<GatewayClient>, _ln_client: Arc<dyn LnRpc>) {
    // TODO: also try to drive forward payments that were interrupted
    loop {
        let least_wait_until = Instant::now() + Duration::from_millis(100);
        let pending_fetches = federation_client
            .list_fetchable_coins()
            .into_iter()
            .map(|out_point| {
                // TODO: get rid of cloning
                let federation_client = federation_client.clone();
                async move {
                    if let Err(e) = federation_client.fetch_coins(out_point).await {
                        error!(error = %e, "Fetching coins failed");
                    }
                }
            })
            .collect::<Vec<_>>();
        futures::future::join_all(pending_fetches).await;
        tokio::time::sleep_until(least_wait_until).await;
    }
}

impl Drop for LnGateway {
    fn drop(&mut self) {
        self.fetcher.abort();
        assert!(futures::executor::block_on(&mut self.fetcher).is_err());
    }
}

#[derive(Debug, Error)]
pub enum LnGatewayError {
    #[error("Federation operation error: {0:?}")]
    FederationError(GatewayClientError),
    #[error("Our LN node could not route the payment: {0:?}")]
    CouldNotRoute(LightningError),
}

impl From<GatewayClientError> for LnGatewayError {
    fn from(e: GatewayClientError) -> Self {
        LnGatewayError::FederationError(e)
    }
}
