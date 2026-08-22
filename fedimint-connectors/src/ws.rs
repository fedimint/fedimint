use std::sync::Arc;

#[allow(unused)]
use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::module::{ApiMethod, ApiRequestErased};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
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
use crate::{
    Connectivity, DynGatewayConnection, DynGuaridianConnection, IConnection, IGuardianConnection,
    ServerError, ServerResult,
};

/// Connector for WebSocket federation APIs.
#[derive(Debug, Clone)]
pub struct WebsocketConnector {}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct ConfiguredWebsocketConnector {
    inner: WebsocketConnector,
    follow_redirects: bool,
}

impl WebsocketConnector {
    /// Create a WebSocket connector with redirects enabled.
    pub fn new() -> Self {
        Self {}
    }

    /// Configure whether the native WebSocket client follows redirects.
    ///
    /// For an IP-literal URL, disabling redirects dials the supplied endpoint
    /// once and does not connect to a redirect target. jsonrpsee still parses
    /// an absolute `Location` and may resolve its hostname before returning.
    ///
    /// A hostname may resolve to multiple original addresses, and jsonrpsee
    /// can apply redirected request metadata to a remaining original address.
    /// Redirect rejection therefore does not provide a hostname destination
    /// guarantee. It also does not pin routing, TLS, or SNI; callers must
    /// separately validate and pass the exact IP-literal URL.
    #[cfg(not(target_family = "wasm"))]
    pub fn follow_redirects(self, follow_redirects: bool) -> impl Connector {
        ConfiguredWebsocketConnector {
            inner: self,
            follow_redirects,
        }
    }

    async fn make_new_connection(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
        _follow_redirects: bool,
    ) -> ServerResult<Arc<WsClient>> {
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

            let client = WsClientBuilder::default()
                .max_concurrent_requests(u16::MAX as usize)
                .with_custom_cert_store(tls_cfg);

            if _follow_redirects {
                client
            } else {
                // jsonrpsee counts the initial connection attempt against this
                // budget. For an IP-literal URL, one attempt dials the supplied
                // endpoint and stops before dialing a redirect target.
                client.max_redirections(1)
            }
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
                    .map_err(|_| ServerError::InvalidEndpoint(anyhow!("invalid username")))?;
                url.set_password(Some(&api_secret))
                    .map_err(|_| ServerError::InvalidEndpoint(anyhow!("invalid secret")))?;

                let client = client
                    .build(url.as_str())
                    .await
                    .map_err(|err| ServerError::InternalClientError(err.into()))?;

                return Ok(Arc::new(client));
            }
        }

        let client = client
            .build(url.as_str())
            .await
            .map_err(|err| ServerError::InternalClientError(err.into()))?;

        Ok(Arc::new(client))
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::future::Future;
    use std::io::ErrorKind;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::{ConnectorRegistry, DynGuaridianConnection};

    async fn assert_redirect_rejected<F, Fut>(connect: F)
    where
        F: FnOnce(SafeUrl) -> Fut,
        Fut: Future<Output = ServerResult<DynGuaridianConnection>>,
    {
        timeout(
            Duration::from_secs(10),
            assert_redirect_rejected_inner(connect),
        )
        .await
        .expect("redirect rejection test timed out");
    }

    async fn assert_redirect_rejected_inner<F, Fut>(connect: F)
    where
        F: FnOnce(SafeUrl) -> Fut,
        Fut: Future<Output = ServerResult<DynGuaridianConnection>>,
    {
        let redirect_target =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        redirect_target
            .set_nonblocking(true)
            .expect("make redirect target nonblocking");
        let redirect_target_addr = redirect_target
            .local_addr()
            .expect("read redirect target address");
        let original_endpoint = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind original endpoint");
        let original_endpoint_addr = original_endpoint
            .local_addr()
            .expect("read original endpoint address");

        let original_endpoint_task =
            fedimint_core::runtime::spawn("WebSocket redirect original endpoint", async move {
                let (mut stream, _) = original_endpoint
                    .accept()
                    .await
                    .expect("accept initial connection");
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let bytes_read = stream.read(&mut buffer).await.expect("read handshake");
                    assert_ne!(bytes_read, 0, "client closed before sending handshake");
                    request.extend_from_slice(&buffer[..bytes_read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: ws://{redirect_target_addr}/\r\n\
                         Content-Length: 0\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("send redirect");
                request
            });

        let url = SafeUrl::parse(&format!("ws://{original_endpoint_addr}/"))
            .expect("parse original endpoint URL");
        connect(url).await.expect_err("redirect must be rejected");

        let request = original_endpoint_task
            .await
            .expect("original endpoint task completed");
        assert!(
            request.starts_with(b"GET / HTTP/1.1\r\n"),
            "original endpoint did not receive a WebSocket handshake"
        );
        assert!(
            matches!(redirect_target.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "redirect target received a connection"
        );
    }

    #[tokio::test]
    async fn websocket_connector_can_disable_redirects() {
        assert_redirect_rejected(|url| async move {
            WebsocketConnector::new()
                .follow_redirects(false)
                .connect_guardian(&url, None)
                .await
        })
        .await;
    }

    #[tokio::test]
    async fn registry_propagates_disabled_websocket_redirects() {
        let registry = ConnectorRegistry::build_from_testing_defaults()
            .ws_follow_redirects(false)
            .bind()
            .await
            .expect("build connector registry");

        assert_redirect_rejected(|url| async move { registry.connect_guardian(&url, None).await })
            .await;
    }

    #[tokio::test]
    async fn websocket_redirects_are_enabled_by_default() {
        let redirect_target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect target");
        let redirect_target_addr = redirect_target
            .local_addr()
            .expect("read redirect target address");
        let original_endpoint = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind original endpoint");
        let original_endpoint_addr = original_endpoint
            .local_addr()
            .expect("read original endpoint address");

        let original_endpoint_task =
            fedimint_core::runtime::spawn("WebSocket redirect original endpoint", async move {
                let (mut stream, _) = original_endpoint
                    .accept()
                    .await
                    .expect("accept initial connection");
                let mut request = [0; 4096];
                let bytes_read = stream.read(&mut request).await.expect("read handshake");
                assert_ne!(bytes_read, 0, "client closed before sending handshake");
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: ws://{redirect_target_addr}/\r\n\
                         Content-Length: 0\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("send redirect");
            });
        let redirect_target_task =
            fedimint_core::runtime::spawn("WebSocket redirect target", async move {
                redirect_target
                    .accept()
                    .await
                    .expect("default connector should dial redirect target");
            });
        let url = SafeUrl::parse(&format!("ws://{original_endpoint_addr}/"))
            .expect("parse original endpoint URL");

        timeout(Duration::from_secs(10), async {
            let registry = ConnectorRegistry::build_from_testing_defaults()
                .bind()
                .await
                .expect("build connector registry");
            let connection = registry.connect_guardian(&url, None).await;
            assert!(connection.is_err(), "closed redirect target must fail");
            original_endpoint_task
                .await
                .expect("original endpoint task completed");
            redirect_target_task
                .await
                .expect("redirect target task completed");
        })
        .await
        .expect("redirect test timed out");
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
    ) -> ServerResult<DynGuaridianConnection> {
        let client = self.make_new_connection(url, api_secret, true).await?;
        Ok(client.into_dyn())
    }

    async fn connect_gateway(&self, _url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        Err(anyhow!("Unsupported transport method"))
    }

    fn connectivity(&self, _url: &SafeUrl) -> Connectivity {
        Connectivity::Direct
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait::async_trait]
impl Connector for ConfiguredWebsocketConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        let client = self
            .inner
            .make_new_connection(url, api_secret, self.follow_redirects)
            .await?;
        Ok(client.into_dyn())
    }

    async fn connect_gateway(&self, _url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        Err(anyhow!("Unsupported transport method"))
    }

    fn connectivity(&self, _url: &SafeUrl) -> Connectivity {
        Connectivity::Direct
    }
}

#[apply(async_trait_maybe_send!)]
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
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(ClientT::request(self, &method, [request.to_json()])
            .await
            .map_err(jsonrpc_error_to_peer_error)?)
    }
}

#[apply(async_trait_maybe_send!)]
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
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
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

fn jsonrpc_error_to_peer_error(jsonrpc_error: JsonRpcClientError) -> ServerError {
    match jsonrpc_error {
        JsonRpcClientError::Call(error_object) => {
            let error = anyhow!(error_object.message().to_owned());
            match ErrorCode::from(error_object.code()) {
                ErrorCode::ParseError | ErrorCode::OversizedRequest | ErrorCode::InvalidRequest => {
                    ServerError::InvalidRequest(error)
                }
                ErrorCode::MethodNotFound => ServerError::InvalidRpcId(error),
                ErrorCode::InvalidParams => ServerError::InvalidRequest(error),
                ErrorCode::InternalError | ErrorCode::ServerIsBusy | ErrorCode::ServerError(_) => {
                    ServerError::ServerError(error)
                }
            }
        }
        JsonRpcClientError::Transport(error) => ServerError::Transport(anyhow!(error)),
        JsonRpcClientError::RestartNeeded(arc) => ServerError::Transport(anyhow!(arc)),
        JsonRpcClientError::ParseError(error) => ServerError::InvalidResponse(anyhow!(error)),
        JsonRpcClientError::InvalidSubscriptionId => {
            ServerError::Transport(anyhow!("Invalid subscription id"))
        }
        JsonRpcClientError::InvalidRequestId(invalid_request_id) => {
            ServerError::InvalidRequest(anyhow!(invalid_request_id))
        }
        JsonRpcClientError::RequestTimeout => ServerError::Transport(anyhow!("Request timeout")),
        JsonRpcClientError::Custom(e) => ServerError::Transport(anyhow!(e)),
        JsonRpcClientError::HttpNotImplemented => {
            ServerError::ServerError(anyhow!("Http not implemented"))
        }
        JsonRpcClientError::EmptyBatchRequest(empty_batch_request) => {
            ServerError::InvalidRequest(anyhow!(empty_batch_request))
        }
        JsonRpcClientError::RegisterMethod(register_method_error) => {
            ServerError::InvalidResponse(anyhow!(register_method_error))
        }
    }
}
