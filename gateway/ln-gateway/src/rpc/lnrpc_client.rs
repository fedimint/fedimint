use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use bitcoin_hashes::Hash;
use fedimint_api::{dyn_newtype_define, task::TaskGroup, Amount};
use fedimint_server::modules::ln::contracts::Preimage;
use lightning_invoice::Invoice;
use secp256k1::PublicKey;
use tokio::sync::{mpsc, Mutex};
use tonic::{transport::Channel, Request};

use crate::{
    gwlightningrpc::{
        gateway_lightning_client::GatewayLightningClient, GetPubKeyRequest, GetPubKeyResponse,
        PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
        SubscribeInterceptHtlcsResponse,
    },
    rpc::HtlcInterceptPayload,
    Result,
};

/**
 * Convenience wrapper around `GatewayLightningClient` protocol spec
 * This provides ease in constructing rpc requests and parsing responses.
 */
#[async_trait]
pub trait ILnRpcClient: Debug {
    // Get the public key of the lightning node
    async fn get_pubkey(&self) -> Result<PublicKey>;

    // Attempt to pay an invoice using the lightning node
    async fn pay_invoice(
        &self,
        invoice: Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage>;

    // Subscribe to intercept htlcs that belong to a specific mint
    // TODO: Build a filtering abstraction over the default tonic streaming api
    async fn subscribe_intercept_htlcs(
        &self,
        mint_pub_key: XOnlyPublicKey,
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

    async fn pay_invoice(
        &self,
        invoice: Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage> {
        let request = Request::new(PayInvoiceRequest {
            invoice: invoice.to_string(),
            max_delay,
            max_fee_percent,
        });
        let PayInvoiceResponse {
            payment_hash,
            preimage,
        } = self
            .client
            .lock()
            .await
            .pay_invoice(request)
            .await
            .expect("Failed to pay invoice")
            .into_inner();

        println!("PAYMENT HASH={:?}", payment_hash);
        let slice: [u8; 32] = preimage
            .to_vec()
            .try_into()
            .expect("Failed to parse preimage");
        Ok(Preimage(slice))
    }

    async fn subscribe_intercept_htlcs(
        &self,
        mint_pub_key: XOnlyPublicKey,
    ) -> Result<mpsc::Receiver<HtlcInterceptPayload>> {
        let request = Request::new(SubscribeInterceptHtlcsRequest {
            mint_pub_key: mint_pub_key.serialize().to_vec(),
        });

        let mut stream = self
            .client
            .lock()
            .await
            .subscribe_intercept_htlcs(request)
            .await
            .expect("Failed to subscribe intercept htlcs")
            .into_inner();

        // Create message channels
        let (sender, receiver) = mpsc::channel::<HtlcInterceptPayload>(100);

        // Spawn a task to listen for messages from the stream.
        // Adapt the data from protobuf types to gateway types.
        let mut tg = self.task_group.clone();
        tg.spawn(
            "Watch HTLC intercept stream",
            move |stream_ctrl| async move {
                while let Some(SubscribeInterceptHtlcsResponse {
                    payment_hash,
                    amount,
                    ..
                }) = stream
                    .message()
                    .await
                    .expect("Failed to get HTLC intercept message")
                {
                    let invoice_amount = Amount::from_sats(amount);
                    let payment_hash =
                        Hash::from_slice(&payment_hash).expect("Failed to parse payment hash");

                    sender
                        .send(HtlcInterceptPayload {
                            invoice_amount,
                            payment_hash,
                        })
                        .await
                        .expect("Failed to send HTLC intercepted message");

                    // Shutdown the task group when the stream is closed
                    if stream_ctrl.is_shutting_down() {
                        break;
                    }
                }
            },
        )
        .await;

        Ok(receiver)
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
