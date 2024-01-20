use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use fedimint_ln_common::PrunedInvoice;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::oneshot::Sender;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;

use super::{send_htlc_to_webhook, ILnRpcClient, LightningRpcError, RouteHtlcStream};
use crate::gateway_lnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};
use crate::rpc::rpc_webhook_server::run_webhook_server;

#[derive(Debug, Serialize, Deserialize)]
pub struct CoinosInvoiceResponse {
    pub amount: u64,
    pub created: u64,
    pub currency: String,
    pub hash: Bolt11Invoice,
    pub id: String,
    pub rate: f64,
    pub pending: u64,
    pub received: u64,
    pub text: String,
    pub tip: Option<String>,
    pub r#type: String,
    pub uid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoinosPayResponse {
    pub id: String,
    pub amount: i64,
    pub fee: u64,
    pub hash: String,
    pub ourfee: u64,
    pub iid: Option<String>,
    pub uid: String,
    pub confirmed: bool,
    pub rate: f64,
    pub currency: String,
    pub r#type: String,
    pub r#ref: String,
    pub tip: Option<String>,
    pub created: u64,
}

#[derive(Clone)]
pub struct GatewayCoinosClient {
    bind_addr: SocketAddr,
    api_key: String,
    pub outcomes: Arc<Mutex<BTreeMap<u64, Sender<InterceptHtlcResponse>>>>,
}

impl GatewayCoinosClient {
    pub async fn new(
        bind_addr: SocketAddr,
        api_key: String,
        outcomes: Arc<Mutex<BTreeMap<u64, Sender<InterceptHtlcResponse>>>>,
    ) -> Self {
        info!("Gateway configured to connect to Coinos at \n address: {bind_addr:?}");
        Self {
            api_key,
            bind_addr,
            outcomes,
        }
    }
}

impl fmt::Debug for GatewayCoinosClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoinosClient")
    }
}

#[async_trait]
impl ILnRpcClient for GatewayCoinosClient {
    /// Returns the public key of the lightning node to use in route hint
    /// Coinos always uses the same pubkey, so we can get it by querying
    /// for an invoice and then parsing the pubkey and network
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let endpoint = "https://coinos.io/api/invoice";
        let alias = "Coinos";

        let client = reqwest::Client::new();
        let req = json!({
            "invoice": {
                "amount": 1000,
                "type": "lightning"
            }
        });
        let response = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&req)
            .send()
            .await
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: format!("Failed to get invoice: {:?}", e),
            })?;

        let invoice_response = response.json::<CoinosInvoiceResponse>().await.unwrap();
        let pub_key = invoice_response.hash.payee_pub_key().ok_or_else(|| {
            LightningRpcError::FailedToGetInvoice {
                failure_reason: "Failed to get pubkey from invoice".to_string(),
            }
        })?;

        return Ok(GetNodeInfoResponse {
            pub_key: pub_key.serialize().to_vec(),
            alias: alias.to_string(),
            network: invoice_response.hash.network().to_string(),
        });
    }

    /// We can probably just use the Coinos node pubkey here?
    /// SCID is the short channel ID mapping to the federation
    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        todo!()
    }

    /// Pay an invoice using the Coinos Api
    async fn pay(
        &self,
        request: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let endpoint = "https://coinos.io/api/payments";
        let client = reqwest::Client::new();
        let req = json!({
            "payreq": request.invoice,
        });
        let response = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&req)
            .send()
            .await
            .map_err(|e| LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to pay invoice: {:?}", e),
            })?;

        let _pay_response = response.json::<CoinosPayResponse>().await.map_err(|e| {
            LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to parse invoice: {:?}", e),
            }
        })?;
        // TODO: We need the preimage back from a successful payment
        // let preimage = pay_response.preimage;

        Ok(PayInvoiceResponse { preimage: vec![] })
    }

    // FIXME: deduplicate implementation with pay
    async fn pay_private(
        &self,
        _invoice: PrunedInvoice,
        _max_delay: u64,
        _max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        todo!()

        // Ok(PayInvoiceResponse { preimage })
    }

    /// Returns true if the lightning backend supports payments without full
    /// invoices
    fn supports_private_payments(&self) -> bool {
        false
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        const CHANNEL_SIZE: usize = 100;
        let (gateway_sender, gateway_receiver) =
            mpsc::channel::<Result<InterceptHtlcRequest, tonic::Status>>(CHANNEL_SIZE);

        let new_client =
            Arc::new(Self::new(self.bind_addr, self.api_key.clone(), self.outcomes.clone()).await);

        run_webhook_server(self.bind_addr, task_group, gateway_sender.clone(), *self)
            .await
            .map_err(|_| LightningRpcError::FailedToRouteHtlcs {
                failure_reason: "Failed to start webhook server".to_string(),
            })?;

        Ok((Box::pin(ReceiverStream::new(gateway_receiver)), new_client))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        send_htlc_to_webhook(&self.outcomes, htlc).await?;
        Ok(EmptyResponse {})
    }
}
