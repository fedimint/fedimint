use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Address;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::PrunedInvoice;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::info;

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, RouteHtlcStream};
use crate::gateway_lnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gateway_lnrpc::{
    self, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, CreateInvoiceRequest,
    CreateInvoiceResponse, EmptyRequest, EmptyResponse, GetBalancesResponse,
    GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsRequest, GetRouteHintsResponse,
    InterceptHtlcResponse, OpenChannelRequest, OpenChannelResponse, PayInvoiceResponse,
    PayPrunedInvoiceRequest, WithdrawOnchainRequest, WithdrawOnchainResponse,
};
use crate::lightning::MAX_LIGHTNING_RETRIES;

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    connection_url: SafeUrl,
}

impl NetworkLnRpcClient {
    pub fn new(url: SafeUrl) -> Self {
        info!(
            "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {} ",
            url.to_string()
        );
        NetworkLnRpcClient {
            connection_url: url,
        }
    }

    async fn connect(&self) -> Result<GatewayLightningClient<Channel>, LightningRpcError> {
        let mut retries = 0;
        let client = loop {
            if retries >= MAX_LIGHTNING_RETRIES {
                return Err(LightningRpcError::FailedToConnect);
            }

            retries += 1;

            if let Ok(endpoint) = Endpoint::from_shared(self.connection_url.to_string()) {
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
        let mut client = self.connect().await?;
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
        let mut client = self.connect().await?;
        let res = client.get_route_hints(req).await.map_err(|status| {
            LightningRpcError::FailedToGetRouteHints {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let req = Request::new(PayPrunedInvoiceRequest {
            pruned_invoice: Some(gateway_lnrpc::PrunedInvoice {
                amount_msat: invoice.amount.msats,
                destination: invoice.destination.consensus_encode_to_vec(),
                destination_features: invoice.destination_features,
                payment_hash: invoice.payment_hash.consensus_encode_to_vec(),
                payment_secret: invoice.payment_secret.to_vec(),
                min_final_cltv_delta: invoice.min_final_cltv_delta,
            }),
            max_delay,
            max_fee_msat: max_fee.msats,
        });
        let mut client = self.connect().await?;
        let res = client.pay_pruned_invoice(req).await.map_err(|status| {
            LightningRpcError::FailedPayment {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    fn supports_private_payments(&self) -> bool {
        true
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .route_htlcs(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToRouteHtlcs {
                failure_reason: status.message().to_string(),
            })?;
        Ok((
            Box::pin(res.into_inner()),
            Arc::new(Self::new(self.connection_url.clone())),
        ))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client.complete_htlc(htlc).await.map_err(|status| {
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .create_invoice(create_invoice_request)
            .await
            .map_err(|status| LightningRpcError::FailedToGetInvoice {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res.into_inner())
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .get_ln_onchain_address(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res.into_inner())
    }

    async fn withdraw_onchain(
        &self,
        address: Address,
        amount: BitcoinAmountOrAll,
        fee_rate_sats_per_vbyte: u64,
    ) -> Result<WithdrawOnchainResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .withdraw_onchain(WithdrawOnchainRequest {
                address: address.to_string(),
                amount_sats: match amount {
                    // This leaves the field empty, which is interpreted as "all funds".
                    BitcoinAmountOrAll::All => None,
                    BitcoinAmountOrAll::Amount(amount) => Some(amount.to_sat()),
                },
                fee_rate_sats_per_vbyte,
            })
            .await
            .map_err(|status| LightningRpcError::FailedToWithdrawOnchain {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res.into_inner())
    }

    async fn open_channel(
        &self,
        pubkey: secp256k1::PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        let res = client
            .open_channel(OpenChannelRequest {
                pubkey: pubkey.serialize().to_vec(),
                host,
                channel_size_sats,
                push_amount_sats,
            })
            .await
            .map_err(|status| LightningRpcError::FailedToOpenChannel {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res.into_inner())
    }

    async fn close_channels_with_peer(
        &self,
        pubkey: secp256k1::PublicKey,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .close_channels_with_peer(CloseChannelsWithPeerRequest {
                pubkey: pubkey.serialize().to_vec(),
            })
            .await
            .map_err(|status| LightningRpcError::FailedToCloseChannelsWithPeer {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res.into_inner())
    }

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError> {
        let mut client = self.connect().await?;
        let res = client
            .list_active_channels(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToListActiveChannels {
                failure_reason: status.message().to_string(),
            })?;
        Ok(res
            .into_inner()
            .channels
            .into_iter()
            .map(|channel| ChannelInfo {
                remote_pubkey: secp256k1::PublicKey::from_slice(&channel.remote_pubkey)
                    .expect("Lightning node returned invalid remote channel pubkey"),
                channel_size_sats: channel.channel_size_sats,
                outbound_liquidity_sats: channel.outbound_liquidity_sats,
                inbound_liquidity_sats: channel.inbound_liquidity_sats,
                short_channel_id: channel.short_channel_id,
            })
            .collect())
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        Ok(client
            .get_balances(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToGetBalances {
                failure_reason: status.message().to_string(),
            })?
            .into_inner())
    }
}
