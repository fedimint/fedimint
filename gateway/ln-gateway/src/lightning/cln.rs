use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use futures::stream::BoxStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::info;

use super::{ILnRpcClient, LightningRpcError};
use crate::gateway_lnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gateway_lnrpc::{
    EmptyRequest, EmptyResponse, GetNodeInfoResponse, GetRouteHintsRequest, GetRouteHintsResponse,
    InterceptHtlcRequest, InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};
use crate::lightning::MAX_LIGHTNING_RETRIES;
pub type HtlcResult = std::result::Result<InterceptHtlcRequest, tonic::Status>;
pub type RouteHtlcStream<'a> = BoxStream<'a, HtlcResult>;

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    connection_url: SafeUrl,
}

impl NetworkLnRpcClient {
    pub async fn new(url: SafeUrl) -> Self {
        info!(
            "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {} ",
            url.to_string()
        );
        NetworkLnRpcClient {
            connection_url: url,
        }
    }

    async fn connect(
        connection_url: SafeUrl,
    ) -> Result<GatewayLightningClient<Channel>, LightningRpcError> {
        let mut retries = 0;
        let client = loop {
            if retries >= MAX_LIGHTNING_RETRIES {
                return Err(LightningRpcError::FailedToConnect);
            }

            retries += 1;

            if let Ok(endpoint) = Endpoint::from_shared(connection_url.to_string()) {
                if let Ok(client) = GatewayLightningClient::connect(endpoint.clone()).await {
                    break client;
                }
            }

            tracing::debug!("Couldn't connect to CLN extension, retrying in 1 second...");
            sleep(Duration::from_secs(1)).await;
        };

        Ok(client)
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let req = Request::new(EmptyRequest {});
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.get_node_info(req).await.map_err(|status| {
            LightningRpcError::FailedToGetNodeInfo {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        let req = Request::new(GetRouteHintsRequest {
            num_route_hints: num_route_hints as u64,
        });
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.get_route_hints(req).await.map_err(|status| {
            LightningRpcError::FailedToGetRouteHints {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let req = Request::new(invoice);
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res =
            client
                .pay_invoice(req)
                .await
                .map_err(|status| LightningRpcError::FailedPayment {
                    failure_reason: status.message().to_string(),
                })?;
        Ok(res.into_inner())
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client
            .route_htlcs(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToRouteHtlcs {
                failure_reason: status.message().to_string(),
            })?;
        Ok((
            Box::pin(res.into_inner()),
            Arc::new(Self::new(self.connection_url.clone()).await),
        ))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.complete_htlc(htlc).await.map_err(|status| {
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }
}
