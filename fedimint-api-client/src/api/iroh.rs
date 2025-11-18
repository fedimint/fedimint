use std::collections::BTreeMap;
use std::fmt;
use std::pin::Pin;
use std::str::FromStr;

use anyhow::{Context, bail};
use async_trait::async_trait;
use fedimint_core::envs::{
    FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_RESOLVER_ENABLE_ENV, is_env_var_set_opt,
    parse_kv_list_from_env,
};
use fedimint_core::iroh_prod::FM_IROH_DNS_FEDIMINT_PROD;
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, FEDIMINT_GATEWAY_ALPN,
    IrohApiRequest, IrohGatewayRequest, IrohGatewayResponse,
};
use fedimint_core::task::spawn;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_logging::LOG_NET_IROH;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use iroh_base::ticket::NodeTicket;
use iroh_next::Watcher as _;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use tracing::{debug, trace, warn};
use url::Url;

use super::{DynGuaridianConnection, IGuardianConnection, PeerError, PeerResult};
use crate::api::{DynGatewayConnection, IGatewayConnection};

#[derive(Clone)]
pub(crate) struct IrohConnector {
    stable: iroh::endpoint::Endpoint,
    next: Option<iroh_next::endpoint::Endpoint>,

    /// List of overrides to use when attempting to connect to given
    /// `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

impl fmt::Debug for IrohConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpoint")
            .field("stable-id", &self.stable.node_id())
            .field(
                "next-id",
                &self.next.as_ref().map(iroh_next::Endpoint::node_id),
            )
            .finish_non_exhaustive()
    }
}

impl IrohConnector {
    pub async fn new(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        iroh_enable_next: bool,
    ) -> anyhow::Result<Self> {
        const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";
        let mut s = Self::new_no_overrides(iroh_dns, iroh_enable_dht, iroh_enable_next).await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
        }

        Ok(s)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn new_no_overrides(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        iroh_enable_next: bool,
    ) -> anyhow::Result<Self> {
        let iroh_dns_servers: Vec<_> = iroh_dns.map_or_else(
            || {
                FM_IROH_DNS_FEDIMINT_PROD
                    .into_iter()
                    .map(|url| Url::parse(url).expect("Hardcoded, can't fail"))
                    .collect()
            },
            |url| vec![url.to_unsafe()],
        );

        let endpoint_stable = Box::pin({
            let iroh_dns_servers = iroh_dns_servers.clone();
            async {
                let mut builder = Endpoint::builder();

                for iroh_dns in iroh_dns_servers {
                    builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
                }

                // As a client, we don't need to register on any relays
                let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

                #[cfg(not(target_family = "wasm"))]
                if iroh_enable_dht {
                    builder = builder.discovery_dht();
                }

                // instead of `.discovery_n0`, which brings publisher we don't want
                {
                    if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
                        #[cfg(target_family = "wasm")]
                        {
                            builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
                        }
                    } else {
                        warn!(
                            target: LOG_NET_IROH,
                            "Iroh pkarr resolver is disabled"
                        );
                    }

                    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
                        #[cfg(not(target_family = "wasm"))]
                        {
                            builder = builder.add_discovery(move |_| {
                                Some(iroh::discovery::dns::DnsDiscovery::n0_dns())
                            });
                        }
                    } else {
                        warn!(
                            target: LOG_NET_IROH,
                            "Iroh n0 discovery is disabled"
                        );
                    }
                }

                let endpoint = builder.bind().await?;
                debug!(
                    target: LOG_NET_IROH,
                    node_id = %endpoint.node_id(),
                    node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                    "Iroh api client endpoint (stable)"
                );
                Ok::<_, anyhow::Error>(endpoint)
            }
        });
        let endpoint_next = Box::pin(async {
            let mut builder = iroh_next::Endpoint::builder();

            for iroh_dns in iroh_dns_servers {
                builder = builder.add_discovery(
                    iroh_next::discovery::pkarr::PkarrResolver::builder(iroh_dns).build(),
                );
            }

            // As a client, we don't need to register on any relays
            let mut builder = builder.relay_mode(iroh_next::RelayMode::Disabled);

            #[cfg(not(target_family = "wasm"))]
            if iroh_enable_dht {
                builder = builder.discovery_dht();
            }

            // instead of `.discovery_n0`, which brings publisher we don't want
            {
                // Resolve using HTTPS requests to our DNS server's /pkarr path in browsers
                #[cfg(target_family = "wasm")]
                {
                    builder =
                        builder.add_discovery(iroh_next::discovery::pkarr::PkarrResolver::n0_dns());
                }
                // Resolve using DNS queries outside browsers.
                #[cfg(not(target_family = "wasm"))]
                {
                    builder =
                        builder.add_discovery(iroh_next::discovery::dns::DnsDiscovery::n0_dns());
                }
            }

            let endpoint = builder.bind().await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.node_id(),
                node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                "Iroh api client endpoint (next)"
            );
            Ok(endpoint)
        });

        let (endpoint_stable, endpoint_next) = if iroh_enable_next {
            let (s, n) = tokio::try_join!(endpoint_stable, endpoint_next)?;
            (s, Some(n))
        } else {
            (endpoint_stable.await?, None)
        };

        Ok(Self {
            stable: endpoint_stable,
            next: endpoint_next,
            connection_overrides: BTreeMap::new(),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    pub fn node_id_from_url(url: &SafeUrl) -> anyhow::Result<NodeId> {
        if url.scheme() != "iroh" {
            bail!(
                "Unsupported scheme: {}, passed to iroh endpoint handler",
                url.scheme()
            );
        }
        let host = url.host_str().context("Missing host string in Iroh URL")?;

        let node_id = PublicKey::from_str(host).context("Failed to parse node id")?;

        Ok(node_id)
    }
}

#[async_trait::async_trait]
impl crate::api::Connector for IrohConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> PeerResult<DynGuaridianConnection> {
        if api_secret.is_some() {
            // There seem to be no way to pass secret over current Iroh calling
            // convention
            PeerError::Connection(anyhow::format_err!(
                "Iroh api secrets currently not supported"
            ));
        }
        let node_id = Self::node_id_from_url(url).map_err(|source| PeerError::InvalidPeerUrl {
            source,
            url: url.to_owned(),
        })?;
        let mut futures = FuturesUnordered::<
            Pin<
                Box<dyn Future<Output = (PeerResult<DynGuaridianConnection>, &'static str)> + Send>,
            >,
        >::new();
        let connection_override = self.connection_overrides.get(&node_id).cloned();

        let self_clone = self.clone();
        futures.push(Box::pin({
            let connection_override = connection_override.clone();
            async move {
                (
                    self_clone
                        .make_new_connection_stable(node_id, connection_override)
                        .await
                        .map(super::IGuardianConnection::into_dyn),
                    "stable",
                )
            }
        }));

        if let Some(endpoint_next) = &self.next {
            let self_clone = self.clone();
            let endpoint_next = endpoint_next.clone();
            futures.push(Box::pin(async move {
                (
                    self_clone
                        .make_new_connection_next(&endpoint_next, node_id, connection_override)
                        .await
                        .map(super::IGuardianConnection::into_dyn),
                    "next",
                )
            }));
        }

        // Remember last error, so we have something to return if
        // neither connection works.
        let mut prev_err = None;

        // Loop until first success, or running out of connections.
        while let Some((result, iroh_stack)) = futures.next().await {
            match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    warn!(
                        target: LOG_NET_IROH,
                        err = %err.fmt_compact(),
                        %iroh_stack,
                        "Join error in iroh connection task"
                    );
                    prev_err = Some(err);
                }
            }
        }

        Err(prev_err.unwrap_or_else(|| {
            PeerError::ServerError(anyhow::anyhow!("Both iroh connection attempts failed"))
        }))
    }

    async fn connect_gateway(&self, url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        let node_id = Self::node_id_from_url(url)?;
        if let Some(node_addr) = self.connection_overrides.get(&node_id).cloned() {
            let conn = self
                .stable
                .connect(node_addr.clone(), FEDIMINT_GATEWAY_ALPN)
                .await?;

            #[cfg(not(target_family = "wasm"))]
            Self::spawn_connection_monitoring_stable(&self.stable, node_id);

            Ok(IGatewayConnection::into_dyn(conn))
        } else {
            let conn = self.stable.connect(node_id, FEDIMINT_GATEWAY_ALPN).await?;
            Ok(IGatewayConnection::into_dyn(conn))
        }
    }
}

impl IrohConnector {
    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_stable(endpoint: &Endpoint, node_id: NodeId) {
        if let Ok(mut conn_type_watcher) = endpoint.conn_type(node_id) {
            #[allow(clippy::let_underscore_future)]
            let _ = spawn("iroh connection (stable)", async move {
                if let Ok(conn_type) = conn_type_watcher.get() {
                    debug!(target: LOG_NET_IROH, %node_id, type = %conn_type, "Connection type (initial)");
                }
                while let Ok(event) = conn_type_watcher.updated().await {
                    debug!(target: LOG_NET_IROH, %node_id, type = %event, "Connection type (changed)");
                }
            });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_next(
        endpoint: &iroh_next::Endpoint,
        node_addr: &iroh_next::NodeAddr,
    ) {
        if let Some(mut conn_type_watcher) = endpoint.conn_type(node_addr.node_id) {
            let node_id = node_addr.node_id;
            #[allow(clippy::let_underscore_future)]
            let _ = spawn("iroh connection (next)", async move {
                if let Ok(conn_type) = conn_type_watcher.get() {
                    debug!(target: LOG_NET_IROH, %node_id, type = %conn_type, "Connection type (initial)");
                }
                while let Ok(event) = conn_type_watcher.updated().await {
                    debug!(target: LOG_NET_IROH, node_id = %node_id, %event, "Connection type changed");
                }
            });
        }
    }

    async fn make_new_connection_stable(
        &self,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> PeerResult<Connection> {
        trace!(target: LOG_NET_IROH, %node_id, "Creating new stable connection");
        let conn = match node_addr.clone() {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                let conn = self.stable
                    .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                    .await;

                #[cfg(not(target_family = "wasm"))]
                if conn.is_ok() {
                    Self::spawn_connection_monitoring_stable(&self.stable, node_id);
                }
                conn
            }
            None => self.stable.connect(node_id, FEDIMINT_API_ALPN).await,
        }.map_err(PeerError::Connection)?;

        Ok(conn)
    }

    async fn make_new_connection_next(
        &self,
        endpoint_next: &iroh_next::Endpoint,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> PeerResult<iroh_next::endpoint::Connection> {
        let next_node_id = iroh_next::NodeId::from_bytes(node_id.as_bytes()).expect("Can't fail");

        let endpoint_next = endpoint_next.clone();

        trace!(target: LOG_NET_IROH, %node_id, "Creating new next connection");
        let conn = match node_addr.clone() {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                let node_addr = node_addr_stable_to_next(&node_addr);
                let conn = endpoint_next
                    .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                    .await;

                #[cfg(not(target_family = "wasm"))]
                if conn.is_ok() {
                    Self::spawn_connection_monitoring_next(&endpoint_next, &node_addr);
                }

                conn
            }
            None => endpoint_next.connect(
                next_node_id,
                FEDIMINT_API_ALPN
            ).await,
        }
        .map_err(Into::into)
        .map_err(PeerError::Connection)?;

        Ok(conn)
    }
}

fn node_addr_stable_to_next(stable: &iroh::NodeAddr) -> iroh_next::NodeAddr {
    iroh_next::NodeAddr {
        node_id: iroh_next::NodeId::from_bytes(stable.node_id.as_bytes()).expect("Can't fail"),
        relay_url: stable
            .relay_url
            .as_ref()
            .map(|u| iroh_next::RelayUrl::from_str(&u.to_string()).expect("Can't fail")),
        direct_addresses: stable.direct_addresses.clone(),
    }
}
#[async_trait]
impl IGuardianConnection for Connection {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.finish().map_err(|e| PeerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(1_000_000)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| PeerError::InvalidResponse(e.into()))?;

        response.map_err(|e| PeerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }

    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IGuardianConnection for iroh_next::endpoint::Connection {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> PeerResult<Value> {
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.finish().map_err(|e| PeerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(1_000_000)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| PeerError::InvalidResponse(e.into()))?;

        response.map_err(|e| PeerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }

    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IGatewayConnection for Connection {
    async fn request(
        &self,
        password: Option<String>,
        _method: Method,
        route: &str,
        payload: Option<Value>,
    ) -> PeerResult<Value> {
        let iroh_request = IrohGatewayRequest {
            route: route.to_string(),
            params: payload,
            password,
        };
        let json = serde_json::to_vec(&iroh_request).expect("serialization cant fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        sink.finish().map_err(|e| PeerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(1_000_000)
            .await
            .map_err(|e| PeerError::Transport(e.into()))?;

        let response = serde_json::from_slice::<IrohGatewayResponse>(&response)
            .map_err(|e| PeerError::InvalidResponse(e.into()))?;
        match StatusCode::from_u16(response.status).map_err(|e| {
            PeerError::InvalidResponse(anyhow::anyhow!("Invalid status code: {}", e))
        })? {
            StatusCode::OK => Ok(response.body),
            status => Err(PeerError::ServerError(anyhow::anyhow!(
                "Server returned status code: {}",
                status
            ))),
        }
    }

    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}
