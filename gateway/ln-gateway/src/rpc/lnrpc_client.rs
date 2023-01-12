use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use fedimint_api::{dyn_newtype_define, task::TaskGroup};
use fedimint_server::modules::ln::contracts::Preimage;
use futures::{stream, StreamExt};
use lightning_invoice::Invoice;
use secp256k1::PublicKey;
use tokio::sync::{mpsc, Mutex};
use tonic::{transport::Channel, Request};
use tracing::error;

use super::HtlcInterceptPayload;
use crate::{
    gatewaylnrpc::{
        gateway_lightning_client::GatewayLightningClient, GetPubKeyRequest, GetPubKeyResponse,
        PayInvoiceRequest, PayInvoiceResponse,
    },
    LightningError, LnGatewayError, Result,
};

#[derive(Debug, Clone)]

pub struct InvoiceInfo {
    pub invoice: Invoice,
    pub max_delay: u64,
    pub max_fee_percent: f64,
}

/**
 * Convenience wrapper around `GatewayLightningClient` protocol spec
 * This provides ease in constructing rpc requests and parsing responses.
 */
#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    // Get the public key of the lightning node
    async fn get_pubkey(&self) -> Result<PublicKey>;

    // Attempt to pay an invoice using the lightning node
    async fn pay_invoice(&self, invoices: Vec<InvoiceInfo>) -> Result<Vec<Result<Preimage>>>;

    // Subscribe to intercept htlcs that belong to a specific mint identified by `short_channel_id`
    async fn subscribe_intercept_htlcs(
        &self,
        short_channel_id: u64,
    ) -> Result<mpsc::Receiver<HtlcInterceptPayload>>;
}

dyn_newtype_define!(
    /// Arc reference to a gateway lightning rpc client
    #[derive(Clone)]
    pub LnRpcClient(Arc<ILnRpcClient>)
);

impl LnRpcClient {
    pub fn new(client: Arc<dyn ILnRpcClient + Send + Sync>) -> Self {
        LnRpcClient(client)
    }
}

/**
 * An `ILnRpcClient` that wraps around `GatewayLightningClient` for convenience,
 * and makes real RPC requests over the wire to a remote lightning node.
 * The lightnign node is exposed via a corresponding `GatewayLightningServer`.
 */
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: Mutex<GatewayLightningClient<Channel>>,
    task_group: TaskGroup,
}

impl NetworkLnRpcClient {
    pub async fn new(address: SocketAddr, task_group: TaskGroup) -> Result<Self> {
        // TODO: Use secure connections to `GatewayLightningServer`
        let url = format!("http://{}", address);

        let client = GatewayLightningClient::connect(url)
            .await
            .expect("Failed to construct gateway lightning rpc client");

        Ok(Self {
            client: Mutex::new(client),
            task_group,
        })
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn get_pubkey(&self) -> Result<PublicKey> {
        let request = Request::new(GetPubKeyRequest {});
        let GetPubKeyResponse { pub_key } = self
            .client
            .lock()
            .await
            .get_pub_key(request)
            .await
            .expect("Failed to get pubkey")
            .into_inner();

        println!("NODE PUBKEY={:?}", pub_key);
        Ok(PublicKey::from_slice(&pub_key).expect("Failed to parse pubkey"))
    }

    async fn pay_invoice(&self, invoices: Vec<InvoiceInfo>) -> Result<Vec<Result<Preimage>>> {
        let requests = stream::iter(invoices.into_iter().map(|ii| PayInvoiceRequest {
            invoice: ii.invoice.to_string(),
            max_delay: ii.max_delay,
            max_fee_percent: ii.max_fee_percent,
        }));

        let mut stream = self
            .client
            .lock()
            .await
            .pay_invoice(Request::new(requests))
            .await
            .expect("Failed to pay invoice")
            .into_inner();

        let mut output: Vec<Result<Preimage>> = Vec::new();

        while let Some(response) = stream.next().await {
            let res = match response {
                Ok(PayInvoiceResponse { preimage, .. }) => {
                    let slice: [u8; 32] = preimage.try_into().expect("Failed to parse preimage");
                    Ok(Preimage(slice))
                }
                Err(status) => {
                    error!("Failed to pay invoice: {}", status.message());
                    Err(LnGatewayError::CouldNotRoute(LightningError(Some(
                        status.code().into(),
                    ))))
                }
            };
            output.push(res);
        }

        Ok(output)
    }

    async fn subscribe_intercept_htlcs(
        &self,
        _short_channel_id: u64,
    ) -> Result<mpsc::Receiver<HtlcInterceptPayload>> {
        unimplemented!()
    }
}

/**
 * A generic factory trait for creating `LnRpcClient` instances.
 */
#[async_trait]
pub trait ILnRpcClientFactory: Debug {
    async fn create(&self, address: SocketAddr, task_group: TaskGroup) -> Result<LnRpcClient>;
}

dyn_newtype_define!(
    /// Arc reference to a gateway lightning rpc client factory
    #[derive(Clone)]
    pub LnRpcClientFactory(Arc<ILnRpcClientFactory>)
);

/**
 * An `ILnRpcClientFactory` that creates `NetworkLnRpcClient` instances.
 */
#[derive(Debug, Default)]
pub struct NetworkLnRpcClientFactory;

#[async_trait]
impl ILnRpcClientFactory for NetworkLnRpcClientFactory {
    async fn create(&self, address: SocketAddr, task_group: TaskGroup) -> Result<LnRpcClient> {
        let client = NetworkLnRpcClient::new(address, task_group)
            .await
            .expect("Failed to build network ln rpc client");
        Ok(LnRpcClient(Arc::new(client)))
    }
}
