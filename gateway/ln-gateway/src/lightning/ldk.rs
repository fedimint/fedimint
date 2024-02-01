use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::task::TaskGroup;
use fedimint_core::BitcoinHash;
use ldk_node::io::sqlite_store::SqliteStore;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::BuildError;
use tracing::error;

use super::cln::RouteHtlcStream;
use super::{ILnRpcClient, LightningRpcError};
use crate::gateway_lnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};

pub struct GatewayLdkClient {
    node: ldk_node::Node<SqliteStore>,
}

impl std::fmt::Debug for GatewayLdkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GatewayLdkClient {{ node: {{ TODO: Display node details. }} }}"
        )
    }
}

impl GatewayLdkClient {
    pub async fn new() -> Result<Self, BuildError> {
        let node = ldk_node::Builder::new()
            // TODO: Set unknown preimage fetcher
            // .set_unknown_preimage_fetcher(fetcher)
            .build()
            .unwrap();

        Ok(GatewayLdkClient { node })
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

    // pub fn create_invoice_for_hash(&self) {
    //     self.node
    //         .receive_payment_with_hash(amount_msat, description, expiry_secs,
    // payment_hash)
    // }

    // pub fn foo(&self) {
    //     self.node.
    // }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        panic!("GatewayLdkClient::info() not implemented")
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
        panic!("GatewayLdkClient::pay() not implemented")
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        panic!("GatewayLdkClient::route_htlcs() not implemented")
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        panic!("GatewayLdkClient::complete_htlc() not implemented")
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
}
