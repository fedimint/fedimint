use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::task::TaskGroup;
use tokio::sync::{mpsc, Mutex};
use tonic_lnd::routerrpc::ForwardHtlcInterceptResponse;
use tonic_lnd::{connect, LndClient};
use tracing::error;

use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyResponse, GetRouteHintsResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
};
use crate::lnrpc_client::{HtlcStream, ILnRpcClient};
use crate::GatewayError;

pub struct GatewayLndClient {
    client: LndClient,
    outcomes: Arc<Mutex<HashMap<sha256::Hash, LndSenderRef>>>,
    task_group: TaskGroup,
}

// Reference to a sender that forwards ForwardHtlcInterceptResponse messages to
// LND
type LndSenderRef = Arc<mpsc::Sender<ForwardHtlcInterceptResponse>>;

impl GatewayLndClient {
    pub async fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        task_group: TaskGroup,
    ) -> crate::Result<Self> {
        let client = connect(address, tls_cert, macaroon).await.map_err(|e| {
            error!("Failed to connect to lnrpc server: {:?}", e);
            GatewayError::Other(anyhow!("Failed to connect to lnrpc server"))
        })?;

        Ok(Self {
            client,
            outcomes: Arc::new(Mutex::new(HashMap::new())),
            task_group,
        })
    }
}

impl fmt::Debug for GatewayLndClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LndClient")
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLndClient {
    async fn pubkey(&self) -> crate::Result<GetPubKeyResponse> {
        todo!("implement lnd get pubkey")
    }

    async fn routehints(&self) -> crate::Result<GetRouteHintsResponse> {
        todo!("implement lnd get routehints")
    }

    async fn pay(&self, _invoice: PayInvoiceRequest) -> crate::Result<PayInvoiceResponse> {
        todo!("implement lnd pay")
    }

    async fn subscribe_htlcs<'a>(
        &self,
        _subscription: SubscribeInterceptHtlcsRequest,
    ) -> crate::Result<HtlcStream<'a>> {
        todo!("implement lnd subscribe htlcs")
    }

    async fn complete_htlc(
        &self,
        _outcome: CompleteHtlcsRequest,
    ) -> crate::Result<CompleteHtlcsResponse> {
        todo!("implement lnd complete htlc")
    }
}
