use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::Amount;
use fedimint_ln_common::PrunedInvoice;
use futures::stream::StreamExt;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::info;

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, RouteHtlcStream};
use crate::lightning::extension::{
    CLN_CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CLN_COMPLETE_PAYMENT_ENDPOINT,
    CLN_CREATE_INVOICE_ENDPOINT, CLN_GET_BALANCES_ENDPOINT, CLN_INFO_ENDPOINT,
    CLN_LIST_ACTIVE_CHANNELS_ENDPOINT, CLN_LN_ONCHAIN_ADDRESS_ENDPOINT, CLN_OPEN_CHANNEL_ENDPOINT,
    CLN_PAY_PRUNED_INVOICE_ENDPOINT, CLN_ROUTE_HINTS_ENDPOINT, CLN_ROUTE_HTLCS_ENDPOINT,
    CLN_SEND_ONCHAIN_ENDPOINT,
};
use crate::lightning::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse,
    GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsRequest,
    GetRouteHintsResponse, InterceptPaymentRequest, InterceptPaymentResponse,
    ListActiveChannelsResponse, OpenChannelResponse, PayInvoiceResponse, PayPrunedInvoiceRequest,
    SendOnchainResponse,
};
use crate::rpc::{CloseChannelsWithPeerPayload, OpenChannelPayload, SendOnchainPayload};

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    connection_url: SafeUrl,
    client: reqwest::Client,
}

impl NetworkLnRpcClient {
    pub fn new(url: SafeUrl) -> Self {
        info!(
            "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {} ",
            url.to_string()
        );
        NetworkLnRpcClient {
            connection_url: url,
            client: reqwest::Client::new(),
        }
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        url: SafeUrl,
        payload: Option<P>,
    ) -> Result<T, reqwest::Error> {
        let mut builder = self.client.request(method, url.clone().to_unsafe());
        if let Some(payload) = payload {
            builder = builder
                .json(&payload)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
        }

        let response = builder.send().await?;
        response.json::<T>().await
    }

    async fn call_get<T: DeserializeOwned>(&self, url: SafeUrl) -> Result<T, reqwest::Error> {
        self.call(Method::GET, url, None::<()>).await
    }

    async fn call_post<P: Serialize, T: DeserializeOwned>(
        &self,
        url: SafeUrl,
        payload: P,
    ) -> Result<T, reqwest::Error> {
        self.call(Method::POST, url, Some(payload)).await
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_INFO_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url)
            .await
            .map_err(|e| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: e.to_string(),
            })
    }

    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_ROUTE_HINTS_ENDPOINT)
            .expect("invalid base url");
        self.call_post(
            url,
            GetRouteHintsRequest {
                num_route_hints: num_route_hints as u64,
            },
        )
        .await
        .map_err(|e| LightningRpcError::FailedToGetRouteHints {
            failure_reason: e.to_string(),
        })
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_PAY_PRUNED_INVOICE_ENDPOINT)
            .expect("invalid base url");
        self.call_post(
            url,
            PayPrunedInvoiceRequest {
                pruned_invoice: Some(invoice),
                max_delay,
                max_fee_msat: max_fee,
            },
        )
        .await
        .map_err(|e| LightningRpcError::FailedPayment {
            failure_reason: e.to_string(),
        })
    }

    fn supports_private_payments(&self) -> bool {
        true
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_ROUTE_HTLCS_ENDPOINT)
            .expect("invalid base url");
        let response = reqwest::get(url.to_unsafe()).await.map_err(|e| {
            LightningRpcError::FailedToRouteHtlcs {
                failure_reason: e.to_string(),
            }
        })?;

        let stream = response.bytes_stream().filter_map(|item| async {
            match item {
                Ok(bytes) => {
                    let request = serde_json::from_slice::<InterceptPaymentRequest>(&bytes)
                        .expect("Failed to deserialize InterceptPaymentRequest");
                    Some(request)
                }
                Err(e) => {
                    tracing::error!(?e, "Error receiving JSON over stream");
                    None
                }
            }
        });

        Ok((
            Box::pin(stream),
            Arc::new(Self::new(self.connection_url.clone())),
        ))
    }

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_COMPLETE_PAYMENT_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, htlc)
            .await
            .map_err(|e| LightningRpcError::FailedToCompleteHtlc {
                failure_reason: e.to_string(),
            })
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_CREATE_INVOICE_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, create_invoice_request)
            .await
            .map_err(|e| LightningRpcError::FailedToGetInvoice {
                failure_reason: e.to_string(),
            })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_LN_ONCHAIN_ADDRESS_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url)
            .await
            .map_err(|e| LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: e.to_string(),
            })
    }

    async fn send_onchain(
        &self,
        payload: SendOnchainPayload,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_SEND_ONCHAIN_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload)
            .await
            .map_err(|e| LightningRpcError::FailedToWithdrawOnchain {
                failure_reason: e.to_string(),
            })
    }

    async fn open_channel(
        &self,
        payload: OpenChannelPayload,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_OPEN_CHANNEL_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload)
            .await
            .map_err(|e| LightningRpcError::FailedToOpenChannel {
                failure_reason: e.to_string(),
            })
    }

    async fn close_channels_with_peer(
        &self,
        payload: CloseChannelsWithPeerPayload,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_CLOSE_CHANNELS_WITH_PEER_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await.map_err(|e| {
            LightningRpcError::FailedToCloseChannelsWithPeer {
                failure_reason: e.to_string(),
            }
        })
    }

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_LIST_ACTIVE_CHANNELS_ENDPOINT)
            .expect("invalid base url");
        let response: ListActiveChannelsResponse = self.call_get(url).await.map_err(|e| {
            LightningRpcError::FailedToListActiveChannels {
                failure_reason: e.to_string(),
            }
        })?;
        Ok(response.channels)
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let url = self
            .connection_url
            .join(CLN_GET_BALANCES_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url)
            .await
            .map_err(|e| LightningRpcError::FailedToGetBalances {
                failure_reason: e.to_string(),
            })
    }
}
