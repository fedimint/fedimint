use std::sync::Arc;

use fedimint_api::task::TaskGroup;
use fedimint_server::config::load_from_file;
use ln_gateway::{
    config::LndRpcConfig,
    gwlightningrpc::{
        gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
        GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    utils::try_read_gateway_dir,
};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::error;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Read configurations
    let dir = try_read_gateway_dir()?;
    let gw_cfg_path = dir.join("lnrpc.config");
    let config: LndRpcConfig = load_from_file(&gw_cfg_path)
        .map_err(|_| LndRpcError::ConfigurationError)
        .expect("Failed to parse config");

    let address = config.lnrpc_bind_address;

    let service = LndRpcService::new(config)
        .await
        .expect("Failed to create lnd rpc service");
    let srv = GatewayLightningServer::new(service);

    Server::builder()
        .add_service(srv)
        .serve(address)
        .await
        .map_err(|_| LndRpcError::RpcServerError)?;

    println!(
        "LND gateway lightning rpc server listening at : {}",
        address
    );

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
