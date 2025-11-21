use std::sync::Arc;

#[allow(unused)]
use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::module::{ApiMethod, ApiRequestErased};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_WS;
use jsonrpsee_core::client::ClientT;
pub use jsonrpsee_core::client::Error as JsonRpcClientError;
use jsonrpsee_types::ErrorCode;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[allow(unused)]
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde_json::Value;
use tracing::trace;
pub type JsonRpcResult<T> = Result<T, JsonRpcClientError>;

use super::Connector;
use crate::api::{
    DynGatewayConnection, DynGuaridianConnection, IConnection, IGuardianConnection, PeerError,
    PeerResult,
};

#[derive(Debug, Clone)]
pub struct WebsocketConnector {}

impl WebsocketConnector {
    pub fn new() -> Self {
        Self {}
    }

    async fn make_new_connection(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<Arc<WsClient>> {
        trace!(target: LOG_NET_WS, %url, "Creating new websocket connection");

        #[cfg(not(target_family = "wasm"))]
        let mut client = {
            use jsonrpsee_ws_client::{CustomCertStore, WsClientBuilder};
            use tokio_rustls::rustls::RootCertStore;

            install_crypto_provider().await;
            let webpki_roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
            let mut root_certs = RootCertStore::empty();
            root_certs.extend(webpki_roots);

            let tls_cfg = CustomCertStore::builder()
                .with_root_certificates(root_certs)
                .with_no_client_auth();

            WsClientBuilder::default()
                .max_concurrent_requests(u16::MAX as usize)
                .with_custom_cert_store(tls_cfg)
        };

        #[cfg(target_family = "wasm")]
        let client = WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        if let Some(api_secret) = api_secret {
            #[cfg(not(target_family = "wasm"))]
            {
                // on native platforms, jsonrpsee-client ignores `user:pass@...` in the Url,
                // but we can set up the headers manually

                use base64::Engine as _;
                use jsonrpsee_ws_client::{HeaderMap, HeaderValue};
                let mut headers = HeaderMap::new();

                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("fedimint:{api_secret}"));

                headers.insert(
                    "Authorization",
                    HeaderValue::from_str(&format!("Basic {auth}")).expect("Can't fail"),
                );

                client = client.set_headers(headers);
            }
            #[cfg(target_family = "wasm")]
            {
                // on wasm, url will be handled by the browser, which should take care of
                // `user:pass@...`
                let mut url = url.clone();
                url.set_username("fedimint")
                    .map_err(|_| PeerError::InvalidEndpoint(anyhow!("invalid username")))?;
                url.set_password(Some(&api_secret))
                    .map_err(|_| PeerError::InvalidEndpoint(anyhow!("invalid secret")))?;

                let client = client
                    .build(url.as_str())
                    .await
                    .map_err(|err| PeerError::InternalClientError(err.into()))?;

                return Ok(Arc::new(client));
            }
        }

        let client = client
            .build(url.as_str())
            .await
            .map_err(|err| PeerError::InternalClientError(err.into()))?;

        Ok(Arc::new(client))
    }
}

impl Default for WebsocketConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Connector for WebsocketConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<DynGuaridianConnection> {
        let client = self.make_new_connection(url, api_secret).await?;
        Ok(client.into_dyn())
    }

    async fn connect_gateway(&self, _url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        Err(anyhow!("Unsupported transport method"))
    }
}

#[async_trait]
impl IConnection for WsClient {
    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }

    fn is_connected(&self) -> bool {
        WsClient::is_connected(self)
    }
}

#[async_trait]
impl IGuardianConnection for WsClient {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(ClientT::request(self, &method, [request.to_json()])
            .await
            .map_err(jsonrpc_error_to_peer_error)?)
    }
}

#[async_trait]
impl IConnection for Arc<WsClient> {
    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }

    fn is_connected(&self) -> bool {
        WsClient::is_connected(self)
    }
}

#[async_trait]
impl IGuardianConnection for Arc<WsClient> {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(
            ClientT::request(self.as_ref(), &method, [request.to_json()])
                .await
                .map_err(jsonrpc_error_to_peer_error)?,
        )
    }
}

fn jsonrpc_error_to_peer_error(jsonrpc_error: JsonRpcClientError) -> PeerError {
    match jsonrpc_error {
        JsonRpcClientError::Call(error_object) => {
            let error = anyhow!(error_object.message().to_owned());
            match ErrorCode::from(error_object.code()) {
                ErrorCode::ParseError | ErrorCode::OversizedRequest | ErrorCode::InvalidRequest => {
                    PeerError::InvalidRequest(error)
                }
                ErrorCode::MethodNotFound => PeerError::InvalidRpcId(error),
                ErrorCode::InvalidParams => PeerError::InvalidRequest(error),
                ErrorCode::InternalError | ErrorCode::ServerIsBusy | ErrorCode::ServerError(_) => {
                    PeerError::ServerError(error)
                }
            }
        }
        JsonRpcClientError::Transport(error) => PeerError::Transport(anyhow!(error)),
        JsonRpcClientError::RestartNeeded(arc) => PeerError::Transport(anyhow!(arc)),
        JsonRpcClientError::ParseError(error) => PeerError::InvalidResponse(anyhow!(error)),
        JsonRpcClientError::InvalidSubscriptionId => {
            PeerError::Transport(anyhow!("Invalid subscription id"))
        }
        JsonRpcClientError::InvalidRequestId(invalid_request_id) => {
            PeerError::InvalidRequest(anyhow!(invalid_request_id))
        }
        JsonRpcClientError::RequestTimeout => PeerError::Transport(anyhow!("Request timeout")),
        JsonRpcClientError::Custom(e) => PeerError::Transport(anyhow!(e)),
        JsonRpcClientError::HttpNotImplemented => {
            PeerError::ServerError(anyhow!("Http not implemented"))
        }
        JsonRpcClientError::EmptyBatchRequest(empty_batch_request) => {
            PeerError::InvalidRequest(anyhow!(empty_batch_request))
        }
        JsonRpcClientError::RegisterMethod(register_method_error) => {
            PeerError::InvalidResponse(anyhow!(register_method_error))
        }
    }
}
