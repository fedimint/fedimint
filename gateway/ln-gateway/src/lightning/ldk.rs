use core::panic;
use std::collections::HashMap;
use std::future::IntoFuture;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::task::TaskGroup;
use fedimint_core::BitcoinHash;
use ldk_node::bitcoin::hashes::Hash;
use ldk_node::io::sqlite_store::SqliteStore;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::{BuildError, Network, PaymentStatus, UnknownPreimageFetcher};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tracing::error;

use super::cln::{HtlcResult, RouteHtlcStream};
use super::{ILnRpcClient, LightningRpcError};
use crate::gateway_lnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};

pub struct GatewayLdkClient {
    node: ldk_node::Node<SqliteStore>,
    network: Network,
    preimage_fetcher: Arc<LdkPreimageFetcher>,
    route_htlc_stream_or: Option<Mutex<RouteHtlcStream<'static>>>,
}

impl std::fmt::Debug for GatewayLdkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GatewayLdkClient {{ node: {{ TODO: Display node details. }} }}"
        )
    }
}

#[derive(Debug)]
struct LdkPreimageFetcher {
    in_flight_htlc_txs: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<InterceptHtlcResponse>>>,
    htlc_id: Mutex<u64>,
    intercept_htlc_request_stream_tx: Mutex<tokio::sync::mpsc::Sender<HtlcResult>>,
}

impl LdkPreimageFetcher {
    pub fn new() -> (Self, RouteHtlcStream<'static>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1000);
        (
            Self {
                in_flight_htlc_txs: Mutex::new(HashMap::new()),
                htlc_id: Mutex::new(0),
                intercept_htlc_request_stream_tx: Mutex::new(tx),
            },
            Box::pin(ReceiverStream::new(rx)),
        )
    }

    pub async fn get_next_htlc_id(&self) -> u64 {
        let mut htlc_id = self.htlc_id.lock().await;
        *htlc_id += 1;
        *htlc_id
    }
}

#[async_trait::async_trait]
impl UnknownPreimageFetcher for LdkPreimageFetcher {
    async fn get_preimage(
        &self,
        payment_hash: PaymentHash,
    ) -> Result<ldk_node::lightning::ln::PaymentPreimage, ldk_node::NodeError> {
        let htlc_id = self.get_next_htlc_id().await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.in_flight_htlc_txs.lock().await.insert(htlc_id, tx);
        self.intercept_htlc_request_stream_tx
            .lock()
            .await
            .send(Ok(InterceptHtlcRequest {
                payment_hash: payment_hash.0.to_vec(),
                // TODO: Fill out the rest of the fields in the InterceptHtlcRequest.
                incoming_amount_msat: 0,
                outgoing_amount_msat: 0,
                incoming_expiry: 0,
                short_channel_id: 0,
                incoming_chan_id: 0,
                htlc_id,
            }))
            .await
            .unwrap();
        match rx.into_future().await {
            Ok(response) => {
                if let Some(action) = response.action {
                    if let crate::Action::Settle(settle) = action {
                        Ok(ldk_node::lightning::ln::PaymentPreimage(
                            settle.preimage.try_into().unwrap(),
                        ))
                    } else {
                        Err(ldk_node::NodeError::InvalidPaymentPreimage)
                    }
                } else {
                    Err(ldk_node::NodeError::InvalidPaymentPreimage)
                }
            }
            Err(_) => Err(ldk_node::NodeError::InvalidPaymentPreimage),
        }
    }
}

impl GatewayLdkClient {
    pub async fn new(storage_dir_path: String, network: Network) -> Result<Self, BuildError> {
        let (preimage_fetcher, route_htlc_stream) = LdkPreimageFetcher::new();
        let preimage_fetcher_arc = Arc::from(preimage_fetcher);

        let node = ldk_node::Builder::new()
            .set_unknown_preimage_fetcher(preimage_fetcher_arc.clone())
            .set_storage_dir_path(storage_dir_path)
            .set_network(network)
            .build()
            .unwrap();

        Ok(GatewayLdkClient {
            node,
            network,
            preimage_fetcher: preimage_fetcher_arc,
            route_htlc_stream_or: Some(Mutex::from(route_htlc_stream)),
        })
    }

    pub fn start(&self) -> Result<(), LightningRpcError> {
        self.node.start().map_err(|e| {
            error!("Failed to start LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })
    }

    pub fn stop(&self) -> Result<(), LightningRpcError> {
        self.node.stop().map_err(|e| {
            error!("Failed to stop LDK Node: {e:?}");
            LightningRpcError::FailedToConnect
        })
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        Ok(GetNodeInfoResponse {
            pub_key: self.node.node_id().serialize().to_vec(),
            // TODO: This is a placeholder. We need to get the actual alias from the LDK node.
            alias: "LDK Fedimint Gateway Node".to_string(),
            network: match self.network {
                Network::Bitcoin => "main",
                Network::Testnet => "test",
                Network::Signet => "signet",
                Network::Regtest => "regtest",
            }
            .to_string(),
        })
    }

    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        panic!("GatewayLdkClient::routehints() not implemented")
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let parsed_invoice: Bolt11Invoice = Bolt11Invoice::from_str(&invoice.invoice).unwrap();
        match self.node.send_payment(&parsed_invoice) {
            Ok(_) => {}
            Err(e) => {
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!("LDK payment failed to initialize: {e:?}"),
                });
            }
        }
        loop {
            if let Some(payment_details) = self
                .node
                .payment(&PaymentHash(parsed_invoice.payment_hash().to_byte_array()))
            {
                if payment_details.status == PaymentStatus::Failed {
                    return Err(LightningRpcError::FailedPayment {
                        failure_reason: "LDK payment failed".to_string(),
                    });
                }
                if let Some(preimage) = payment_details.preimage {
                    return Ok(PayInvoiceResponse {
                        preimage: preimage.0.to_vec(),
                    });
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn route_htlcs<'a>(
        mut self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let route_htlc_stream = match self.route_htlc_stream_or.take() {
            Some(stream) => Ok(Box::pin(stream.into_inner())),
            None => Err(LightningRpcError::FailedToRouteHtlcs {
                failure_reason:
                    "Stream does not exist. Likely was already taken by calling `route_htlcs()`."
                        .to_string(),
            }),
        }?;

        Ok((route_htlc_stream, Arc::new(*self)))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let rx = match self
            .preimage_fetcher
            .in_flight_htlc_txs
            .lock()
            .await
            .remove(&htlc.htlc_id)
        {
            Some(rx) => rx,
            None => {
                return Err(LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: String::from("Invalid HTLC"),
                });
            }
        };

        rx.send(htlc).unwrap();

        Ok(EmptyResponse {})
    }

    async fn create_invoice_for_hash(
        &self,
        amount_msat: u64,
        description: String,
        expiry_secs: u64,
        payment_hash: sha256::Hash,
    ) -> Result<Bolt11Invoice, LightningRpcError> {
        Ok(self
            .node
            .receive_payment_with_hash(
                amount_msat,
                &description,
                expiry_secs as u32,
                PaymentHash(payment_hash.into_inner()),
            )
            .unwrap())
    }

    fn supports_htlc_interception(&self) -> bool {
        false
    }
}
