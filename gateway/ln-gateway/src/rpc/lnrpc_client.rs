use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use fedimint_api::{dyn_newtype_define, task::TaskGroup, Amount};
use fedimint_server::modules::ln::contracts::Preimage;
use futures::{stream, StreamExt};
use lightning_invoice::Invoice;
use secp256k1::PublicKey;
use tokio::sync::{mpsc, Mutex};
use tonic::{transport::Channel, Request};
use tracing::{error, info};

use super::{GatewayChannelMessage, GatewayMessageSender, ProcessHtlcMessage, ProcessHtlcResponse};
use crate::{
    gatewaylnrpc::{
        complete_htlcs_request::{Action, Cancel, Settle},
        gateway_lightning_client::GatewayLightningClient,
        CompleteHtlcsRequest, GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest,
        PayInvoiceResponse, SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
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
    ) -> Result<mpsc::Receiver<GatewayChannelMessage>>;
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
        short_channel_id: u64,
    ) -> Result<mpsc::Receiver<GatewayChannelMessage>> {
        let mut client = self.client.lock().await.clone();
        let mut stream = client
            .subscribe_intercept_htlcs(Request::new(SubscribeInterceptHtlcsRequest {
                short_channel_id,
            }))
            .await
            .expect("Failed to subscribe intercept htlcs")
            .into_inner();

        // Spawn a task to listen for messages from the htlc stream.
        // Adapt HTLC data from protobuf types to gateway types and send for processing.
        let mut tg = self.task_group.clone();
        let (tx, rx) = mpsc::channel::<GatewayChannelMessage>(100);

        tg.spawn(
            "Subscribe to HTLC intercept stream",
            move |subscription| async move {
                loop {
                    // Shutdown the task group when the stream is closed
                    if subscription.is_shutting_down() {
                        break;
                    }

                    let mut htlc_outcomes = Vec::<CompleteHtlcsRequest>::new();

                    while let Some(SubscribeInterceptHtlcsResponse {
                        outgoing_amount_msat,
                        intercepted_htlc_id,
                        ..
                    }) = stream
                        .message()
                        .await
                        .expect("Failed to get HTLC intercept message")
                    {
                        // TODO: Assert short channel id matches the one we subscribed to, or cancel processing of intercepted HTLC
                        // TODO: Assert the offered fee derived from invoice amount and outgoing amount is acceptable or cancel processing of intercepted HTLC
                        // TODO: Assert the HTLC expiry or cancel processing of intercepted HTLC

                        let sender = GatewayMessageSender::new(tx.clone());

                        let outcome = match sender
                            .send(ProcessHtlcMessage {
                                amount_msat: Amount::from_msats(outgoing_amount_msat),
                            })
                            .await
                        {
                            Ok(ProcessHtlcResponse { preimage }) => {
                                info!("Successfully processed intercepted HTLC");
                                CompleteHtlcsRequest {
                                    action: Some(Action::Settle(Settle {
                                        preimage: preimage.0.to_vec(),
                                        intercepted_htlc_id,
                                    })),
                                }
                            }
                            Err(e) => {
                                error!("Failed to process intercepted HTLC: {:?}", e);
                                CompleteHtlcsRequest {
                                    action: Some(Action::Cancel(Cancel {
                                        reason: e.to_string(),
                                        intercepted_htlc_id,
                                    })),
                                }
                            }
                        };

                        htlc_outcomes.push(outcome);
                    }

                    // TODO: Send HTLC outcomes to gateway lightning rpc server
                }
            },
        )
        .await;

        Ok(rx)
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
