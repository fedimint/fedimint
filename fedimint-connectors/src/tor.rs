#[cfg(all(feature = "tor", not(target_family = "wasm")))]
use std::fmt;
use std::sync::Arc;

use anyhow::anyhow;
use arti_client::{TorAddr, TorClient, TorClientConfig};
use async_trait::async_trait;
use base64::Engine as _;
use fedimint_core::util::SafeUrl;
use jsonrpsee_ws_client::{HeaderMap, HeaderValue, WsClientBuilder};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig as TlsClientConfig, RootCertStore};
use tracing::debug;

use super::{Connector, DynGuaridianConnection};
use crate::{DynGatewayConnection, IGuardianConnection as _, ServerError};

#[derive(Clone)]
pub struct TorConnector {
    tor_client: TorClient<tor_rtcompat::PreferredRuntime>,
}

impl fmt::Debug for TorConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorEndpoint").finish_non_exhaustive()
    }
}

impl TorConnector {
    pub async fn bootstrap() -> anyhow::Result<Self> {
        use tracing::debug;

        use crate::ServerError;

        let tor_config = TorClientConfig::default();
        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|err| ServerError::InternalClientError(err.into()))?
            .isolated_client();

        debug!("Successfully created and bootstrapped the `TorClient`, for given `TorConfig`.");

        Ok(Self { tor_client })
    }
}

#[async_trait]
impl Connector for TorConnector {
    #[allow(clippy::too_many_lines)]
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> super::ServerResult<DynGuaridianConnection> {
        let addr = (
            url.host_str()
                .ok_or_else(|| ServerError::InvalidEndpoint(anyhow!("Expected host str")))?,
            url.port_or_known_default()
                .ok_or_else(|| ServerError::InvalidEndpoint(anyhow!("Expected port number")))?,
        );
        let tor_addr = TorAddr::from(addr).map_err(|e| {
            ServerError::InvalidEndpoint(anyhow!("Invalid endpoint addr: {addr:?}: {e:#}"))
        })?;

        let tor_addr_clone = tor_addr.clone();

        debug!(
            ?tor_addr,
            ?addr,
            "Successfully created `TorAddr` for given address (i.e. host and port)"
        );

        // TODO: It can be updated to use `is_onion_address()` implementation,
        // once https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2214 lands.
        let anonymized_stream = if url.is_onion_address() {
            let mut stream_prefs = arti_client::StreamPrefs::default();
            stream_prefs.connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true));

            let anonymized_stream = self
                .tor_client
                .connect_with_prefs(tor_addr, &stream_prefs)
                .await
                .map_err(|e| ServerError::Connection(e.into()))?;

            debug!(
                ?tor_addr_clone,
                "Successfully connected to onion address `TorAddr`, and established an anonymized `DataStream`"
            );
            anonymized_stream
        } else {
            let anonymized_stream = self
                .tor_client
                .connect(tor_addr)
                .await
                .map_err(|e| ServerError::Connection(e.into()))?;

            debug!(
                ?tor_addr_clone,
                "Successfully connected to `Hostname`or `Ip` `TorAddr`, and established an anonymized `DataStream`"
            );
            anonymized_stream
        };

        let is_tls = match url.scheme() {
            "wss" => true,
            "ws" => false,
            unexpected_scheme => {
                return Err(ServerError::InvalidEndpoint(anyhow!(
                    "Unsupported scheme: {unexpected_scheme}"
                )));
            }
        };

        let tls_connector = if is_tls {
            let webpki_roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
            let mut root_certs = RootCertStore::empty();
            root_certs.extend(webpki_roots);

            let tls_config = TlsClientConfig::builder()
                .with_root_certificates(root_certs)
                .with_no_client_auth();
            let tls_connector = TlsConnector::from(Arc::new(tls_config));
            Some(tls_connector)
        } else {
            None
        };

        let mut ws_client_builder =
            WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        if let Some(api_secret) = api_secret {
            // on native platforms, jsonrpsee-client ignores `user:pass@...` in the Url,
            // but we can set up the headers manually

            let mut headers = HeaderMap::new();

            let auth =
                base64::engine::general_purpose::STANDARD.encode(format!("fedimint:{api_secret}"));

            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Basic {auth}")).expect("Can't fail"),
            );

            ws_client_builder = ws_client_builder.set_headers(headers);
        }

        match tls_connector {
            None => {
                let client = ws_client_builder
                    .build_with_stream(url.as_str(), anonymized_stream)
                    .await
                    .map_err(|e| ServerError::Connection(e.into()))?;

                Ok(client.into_dyn())
            }
            Some(tls_connector) => {
                let host = url
                    .host_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| ServerError::InvalidEndpoint(anyhow!("Invalid host str")))?;

                // FIXME: (@leonardo) Is this leaking any data ? Should investigate it further
                // if it's really needed.
                let server_name = rustls_pki_types::ServerName::try_from(host)
                    .map_err(|e| ServerError::InvalidEndpoint(e.into()))?;

                let anonymized_tls_stream = tls_connector
                    .connect(server_name, anonymized_stream)
                    .await
                    .map_err(|e| ServerError::Connection(e.into()))?;

                let client = ws_client_builder
                    .build_with_stream(url.as_str(), anonymized_tls_stream)
                    .await
                    .map_err(|e| ServerError::Connection(e.into()))?;

                Ok(client.into_dyn())
            }
        }
    }

    async fn connect_gateway(&self, _url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        Err(anyhow!("Unsupported transport method"))
    }
}
