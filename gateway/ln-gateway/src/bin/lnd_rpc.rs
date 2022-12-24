use std::sync::Arc;

use fedimint_api::task::TaskGroup;
use ln_gateway::{
    config::{GatewayConfig, LndRpcConfig},
    gwlightningrpc::{
        gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
        GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    utils::read_gateway_config,
};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::error;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let GatewayConfig {
        lnrpc_bind_address,
        lnd_rpc_connect,
        ..
    } = read_gateway_config(None)?;

    match lnd_rpc_connect {
        Some(connect) => {
            let service = LndRpcService::new(connect)
                .await
                .expect("Failed to create lnd rpc service");
            let srv = GatewayLightningServer::new(service);

            Server::builder()
                .add_service(srv)
                .serve(lnrpc_bind_address)
                .await
                .map_err(|_| LndRpcError::RpcServerError)?;

            println!(
                "Gateway lightning rpc server listening on {}",
                lnrpc_bind_address
            );
        }
        None => {
            error!("Missing LND rpc connection config");
            Err(LndRpcError::ConfigurationError)?
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub struct LndRpcService {
    // LND rpc client.
    // We only depend on the router rpc of this client.
    client: Arc<Mutex<tonic_lnd::LndClient>>,
    task_group: TaskGroup,
}

impl LndRpcService {
    pub async fn new(cfg: LndRpcConfig) -> Result<Self, LndRpcError> {
        // Connecting to LND requires only host, port, cert file, and macaroon file
        let client = tonic_lnd::connect(
            cfg.node_host,
            cfg.node_port,
            cfg.tls_cert_path,
            cfg.macaroon_path,
        )
        .await
        .map_err(|_| LndRpcError::RpcServerError)
        .expect("Failed to connect to lnd");

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            task_group: TaskGroup::new(),
        })
    }
}

#[tonic::async_trait]
impl GatewayLightning for LndRpcService {
    async fn get_pub_key(
        &self,
        _request: Request<GetPubKeyRequest>,
    ) -> Result<Response<GetPubKeyResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn pay_invoice(
        &self,
        _request: Request<PayInvoiceRequest>,
    ) -> Result<Response<PayInvoiceResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    type SubscribeInterceptHtlcsStream =
        ReceiverStream<Result<SubscribeInterceptHtlcsResponse, Status>>;

    async fn subscribe_intercept_htlcs(
        &self,
        _request: Request<SubscribeInterceptHtlcsRequest>,
    ) -> Result<Response<Self::SubscribeInterceptHtlcsStream>, Status> {
        Err(Status::unimplemented("not implemented"))
    }
}

#[derive(Debug, Error)]
pub enum LndRpcError {
    #[error("ConfigurationError")]
    ConfigurationError,
    #[error("RpcServerError")]
    RpcServerError,
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
}
