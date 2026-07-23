use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use fedimint_core::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use fedimint_core::envs::{
    FM_GW_IROH_CONNECT_OVERRIDES_PLAIN_ENV, FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
    FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_RESOLVER_ENABLE_ENV, is_env_var_set_opt,
    parse_kv_list_from_env,
};
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, FEDIMINT_GATEWAY_ALPN,
    IrohApiRequest, IrohGatewayRequest, IrohGatewayResponse,
};
use fedimint_core::net::iroh::{IROH_IDLE_TIMEOUT, IROH_KEEP_ALIVE_INTERVAL};

/// The maximum number of bytes we are willing to buffer when reading an API
/// response from an iroh QUIC stream. This must be large enough to accommodate
/// the largest possible signed session outcome. A session can contain up to
/// `broadcast_rounds_per_session` (default 3600) rounds, each peer produces one
/// unit per round, and each unit can be up to `ALEPH_BFT_UNIT_BYTE_LIMIT`
/// bytes. The response is JSON-serialized which hex-encodes the consensus
/// bytes, roughly doubling the size. We use 2x the raw max as a conservative
/// upper bound. For a 4-peer federation this is ~1.44 GB.
const IROH_MAX_RESPONSE_BYTES: usize = ALEPH_BFT_UNIT_BYTE_LIMIT * 3600 * 4 * 2;

/// Wall-clock budget for a single iroh API request to make it through the QUIC
/// bi-stream (open + write + finish + read response). If exceeded we close the
/// underlying [`Connection`], which causes [`IConnection::is_connected`] to
/// return false on the next pool lookup so a fresh connection is established
/// for the retry. Used for endpoints that respond promptly (`block_count`,
/// `status`, etc).
const IROH_REQUEST_TIMEOUT_DEFAULT: Duration = Duration::from_secs(60);

/// Wall-clock budget for an iroh API request to a server-side long-poll
/// endpoint (`await_*` / `wait_*`). These wait on the server until an event
/// fires (block height reached, contract cancelled, etc.) before responding,
/// so they need a generous bound. Set well above realistic mainnet block
/// intervals; if a long-poll legitimately needs longer than this the upstream
/// `request_current_consensus_retry` loop will reconnect and retry.
const IROH_REQUEST_TIMEOUT_LONG_POLL: Duration = Duration::from_secs(60 * 60);

/// Application-level QUIC error code we use when closing a [`Connection`]
/// after a request timeout. Recorded by the peer as the close reason; chosen
/// arbitrarily but stable across stable and `iroh_next` impls so the two
/// emit identical telemetry. The value 1 distinguishes us from a graceful
/// close (0).
const IROH_REQUEST_TIMEOUT_ERROR_CODE: u32 = 1;
const IROH_REQUEST_TIMEOUT_ERROR_REASON: &[u8] = b"request timeout";

/// Request timeout strategy: long-poll endpoints (`await_*` / `wait_*`)
/// get the long bound, everything else gets the default. The string match
/// is a heuristic; it covers all currently-defined fedimint long-poll
/// endpoints and stays correct if new ones follow the existing naming
/// convention. False positives (a non-long-poll endpoint that happens to
/// match the prefix) just give that one method a longer leash; the worse
/// case is a false negative — a long-poll method that doesn't match
/// either prefix would get the 60s default and fail fast on legitimate
/// waits, but the upstream retry loop would reconnect and try again.
fn request_timeout_for_method(method: &ApiMethod) -> Duration {
    let name = match method {
        ApiMethod::Core(name) => name.as_str(),
        ApiMethod::Module(_, name) => name.as_str(),
    };
    if name.starts_with("await_") || name.starts_with("wait_") {
        IROH_REQUEST_TIMEOUT_LONG_POLL
    } else {
        IROH_REQUEST_TIMEOUT_DEFAULT
    }
}
use fedimint_core::task::spawn;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_NET_IROH;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

use super::{DynGuaridianConnection, IGuardianConnection, ServerError, ServerResult};
use crate::{Connectivity, DynGatewayConnection, IConnection, IGatewayConnection, IrohPeerInfo};

#[derive(Clone)]
pub(crate) struct IrohConnector {
    stable: iroh::endpoint::Endpoint,
    next: iroh_next::endpoint::Endpoint,

    /// List of overrides to use when attempting to connect to given
    /// `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    connection_overrides: BTreeMap<NodeId, NodeAddr>,

    /// Registry-owned signal bumped whenever any per-connection monitoring
    /// task observes a transport-level path change (e.g. iroh relay →
    /// direct). Consumers of [`crate::ConnectorRegistry`] subscribe via
    /// [`crate::ConnectorRegistry::connectivity_change_notifier`].
    path_change: Arc<watch::Sender<u64>>,
}

impl fmt::Debug for IrohConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpoint")
            .field("stable-id", &self.stable.node_id())
            .field("next-id", &self.next.id())
            .finish_non_exhaustive()
    }
}

impl IrohConnector {
    pub async fn new(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        path_change: Arc<watch::Sender<u64>>,
    ) -> anyhow::Result<Self> {
        let mut s = Self::new_no_overrides(iroh_dns, iroh_enable_dht, path_change).await?;

        // Overrides are `<node-id>=<socket-addr>` pairs: the node id is the key
        // and the value is a single direct address. iroh 1.0 no longer ships
        // the `NodeTicket` format, so we keep the override wire format version
        // agnostic and build the (legacy) `NodeAddr` from its parts. Pre-0.12
        // binaries read the `NodeTicket`-format `FM_IROH_CONNECT_OVERRIDES`
        // instead; devimint emits both side by side.
        for env_var in [
            FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
            FM_GW_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
        ] {
            for (k, v) in parse_kv_list_from_env::<NodeId, SocketAddr>(env_var)? {
                s = s.with_connection_override(k, NodeAddr::new(k).with_direct_addresses([v]));
            }
        }

        Ok(s)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn new_no_overrides(
        iroh_dns: Option<SafeUrl>,
        iroh_enable_dht: bool,
        path_change: Arc<watch::Sender<u64>>,
    ) -> anyhow::Result<Self> {
        let endpoint_stable = Box::pin({
            let iroh_dns = iroh_dns.clone();
            async {
                let mut builder = Endpoint::builder();

                if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
                    builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
                }

                // As a client, we don't need to register on any relays
                let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

                #[cfg(not(target_family = "wasm"))]
                if iroh_enable_dht {
                    builder = builder.discovery_dht();
                }

                // Add only resolver services here; the stable n0 convenience also
                // installs a publisher.
                {
                    if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
                        builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
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

                let endpoint = builder
                    .transport_config(quic_transport_config())
                    .bind()
                    .await?;
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
            let mut builder = iroh_next::Endpoint::builder(iroh_next::endpoint::presets::Minimal);

            if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
                builder = builder
                    .address_lookup(iroh_next::address_lookup::PkarrResolver::builder(iroh_dns));
            }

            // Server iroh-next endpoints publish relay-only address records by
            // default (the iroh 1.0 publishers filter out direct addresses), so
            // the client must be able to dial via relays; `RelayMode::Disabled`
            // would disable dialing them, not just registration.
            let mut builder = builder.relay_mode(iroh_next::RelayMode::Default);

            #[cfg(not(target_family = "wasm"))]
            if iroh_enable_dht {
                builder = builder
                    .address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
            }

            // Add only resolver services here; the iroh preset convenience also
            // installs a publisher.
            {
                // Resolve using HTTPS requests to our DNS server's /pkarr path.
                builder =
                    builder.address_lookup(iroh_next::address_lookup::PkarrResolver::n0_dns());
                // Resolve using DNS queries outside browsers.
                #[cfg(not(target_family = "wasm"))]
                {
                    builder = builder
                        .address_lookup(iroh_next::address_lookup::DnsAddressLookup::n0_dns());
                }
            }

            let endpoint = builder
                .transport_config(quic_transport_config_next())
                .bind()
                .await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.id(),
                node_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
                "Iroh api client endpoint (next)"
            );
            Ok(endpoint)
        });

        let (endpoint_stable, endpoint_next) = tokio::try_join!(endpoint_stable, endpoint_next)?;

        Ok(Self {
            stable: endpoint_stable,
            next: endpoint_next,
            connection_overrides: BTreeMap::new(),
            path_change,
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
impl crate::Connector for IrohConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        if api_secret.is_some() {
            // There seem to be no way to pass secret over current Iroh calling
            // convention
            ServerError::Connection(anyhow::format_err!(
                "Iroh api secrets currently not supported"
            ));
        }
        let node_id =
            Self::node_id_from_url(url).map_err(|source| ServerError::InvalidPeerUrl {
                source,
                url: url.to_owned(),
            })?;
        let next_only = crate::is_iroh_next_endpoint_url(url).map_err(|source| {
            ServerError::InvalidPeerUrl {
                source,
                url: url.to_owned(),
            }
        })?;
        let mut futures = FuturesUnordered::<
            Pin<
                Box<
                    dyn Future<Output = (ServerResult<DynGuaridianConnection>, &'static str)>
                        + Send,
                >,
            >,
        >::new();
        let connection_override = self.connection_overrides.get(&node_id).cloned();

        // Advertised Iroh 1.0 identities carry an internal `/v1` marker so we
        // avoid attempting the incompatible 0.35 stack for safety and efficiency.
        if next_only {
            return self
                .make_new_connection_next(&self.next, node_id, connection_override)
                .await
                .map(super::IGuardianConnection::into_dyn);
        }

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

        let self_clone = self.clone();
        let endpoint_next = self.next.clone();
        futures.push(Box::pin(async move {
            (
                self_clone
                    .make_new_connection_next(&endpoint_next, node_id, connection_override)
                    .await
                    .map(super::IGuardianConnection::into_dyn),
                "next",
            )
        }));

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
            ServerError::ServerError(anyhow::anyhow!("Both iroh connection attempts failed"))
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
            Self::spawn_connection_monitoring_stable(
                &self.stable,
                node_id,
                self.path_change.clone(),
            );

            Ok(IGatewayConnection::into_dyn(conn))
        } else {
            let conn = self.stable.connect(node_id, FEDIMINT_GATEWAY_ALPN).await?;
            Ok(IGatewayConnection::into_dyn(conn))
        }
    }

    fn connectivity(&self, url: &SafeUrl) -> Connectivity {
        let Ok(node_id) = Self::node_id_from_url(url) else {
            return Connectivity::Unknown;
        };
        let Ok(watcher) = self.stable.conn_type(node_id) else {
            return Connectivity::Unknown;
        };
        match watcher.get() {
            Ok(iroh::endpoint::ConnectionType::Direct(_)) => Connectivity::Direct,
            Ok(iroh::endpoint::ConnectionType::Relay(_)) => Connectivity::Relay,
            Ok(iroh::endpoint::ConnectionType::Mixed(..)) => Connectivity::Mixed,
            Ok(iroh::endpoint::ConnectionType::None) | Err(_) => Connectivity::Unknown,
        }
    }

    async fn iroh_peer_info(
        &self,
        url: &SafeUrl,
        path_timeout: Duration,
    ) -> ServerResult<Option<IrohPeerInfo>> {
        let node_id =
            Self::node_id_from_url(url).map_err(|source| ServerError::InvalidPeerUrl {
                source,
                url: url.to_owned(),
            })?;
        let connection_override = self.connection_overrides.get(&node_id).cloned();
        let _connection = self
            .make_new_connection_stable(node_id, connection_override)
            .await?;

        let mut conn_type_watcher = self
            .stable
            .conn_type(node_id)
            .map_err(ServerError::Connection)?;
        let mut conn_type = conn_type_watcher
            .get()
            .unwrap_or(iroh::endpoint::ConnectionType::None);

        if path_timeout > Duration::ZERO {
            let timeout = fedimint_core::runtime::sleep(path_timeout);
            tokio::pin!(timeout);

            while !matches!(
                conn_type,
                iroh::endpoint::ConnectionType::Direct(_)
                    | iroh::endpoint::ConnectionType::Mixed(..)
            ) {
                tokio::select! {
                    () = &mut timeout => break,
                    updated = conn_type_watcher.updated() => {
                        match updated {
                            Ok(updated) => conn_type = updated,
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        Ok(Some(self.iroh_peer_info_from_conn_type(node_id, conn_type)))
    }
}

impl IrohConnector {
    fn iroh_peer_info_from_conn_type(
        &self,
        node_id: NodeId,
        conn_type: iroh::endpoint::ConnectionType,
    ) -> IrohPeerInfo {
        let remote_info = self.stable.remote_info(node_id);

        let direct_addr = match &conn_type {
            iroh::endpoint::ConnectionType::Direct(addr)
            | iroh::endpoint::ConnectionType::Mixed(addr, _) => Some(*addr),
            iroh::endpoint::ConnectionType::Relay(_) | iroh::endpoint::ConnectionType::None => None,
        };

        let mut known_direct_addrs = remote_info
            .as_ref()
            .map(|info| {
                info.addrs
                    .iter()
                    .map(|addr_info| addr_info.addr)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if let Some(direct_addr) = direct_addr {
            known_direct_addrs.insert(direct_addr);
        }

        let relay_url = match &conn_type {
            iroh::endpoint::ConnectionType::Relay(relay_url)
            | iroh::endpoint::ConnectionType::Mixed(_, relay_url) => Some(relay_url.to_string()),
            iroh::endpoint::ConnectionType::Direct(_) | iroh::endpoint::ConnectionType::None => {
                remote_info.and_then(|info| info.relay_url.map(|relay| relay.relay_url.to_string()))
            }
        };

        IrohPeerInfo {
            node_id: node_id.to_string(),
            connectivity: connectivity_from_iroh_conn_type(&conn_type),
            direct_addr,
            known_direct_addrs: known_direct_addrs.into_iter().collect(),
            relay_url,
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_stable(
        endpoint: &Endpoint,
        node_id: NodeId,
        path_change: Arc<watch::Sender<u64>>,
    ) {
        if let Ok(mut conn_type_watcher) = endpoint.conn_type(node_id) {
            #[allow(clippy::let_underscore_future)]
            let _ = spawn("iroh connection (stable)", async move {
                if let Ok(conn_type) = conn_type_watcher.get() {
                    debug!(target: LOG_NET_IROH, %node_id, type = %conn_type, "Connection type (initial)");
                }
                while let Ok(event) = conn_type_watcher.updated().await {
                    debug!(target: LOG_NET_IROH, %node_id, type = %event, "Connection type (changed)");
                    path_change.send_modify(|c| *c = c.wrapping_add(1));
                }
            });
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn spawn_connection_monitoring_next(
        conn: &iroh_next::endpoint::Connection,
        node_id: iroh_next::EndpointId,
        path_change: Arc<watch::Sender<u64>>,
    ) {
        let conn = conn.clone();
        #[allow(clippy::let_underscore_future)]
        let _ = spawn("iroh connection (next)", async move {
            let mut paths = conn.paths_stream();
            if let Some(paths) = paths.next().await {
                debug!(target: LOG_NET_IROH, %node_id, ?paths, "Connection paths (initial)");
            }
            while let Some(paths) = paths.next().await {
                debug!(target: LOG_NET_IROH, %node_id, ?paths, "Connection paths changed");
                path_change.send_modify(|c| *c = c.wrapping_add(1));
            }
        });
    }

    async fn make_new_connection_stable(
        &self,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> ServerResult<Connection> {
        trace!(target: LOG_NET_IROH, %node_id, "Creating new stable connection");
        let conn = match node_addr.clone() {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                let conn = self.stable
                    .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                    .await;

                #[cfg(not(target_family = "wasm"))]
                if conn.is_ok() {
                    Self::spawn_connection_monitoring_stable(
                        &self.stable,
                        node_id,
                        self.path_change.clone(),
                    );
                }
                conn
            }
            None => self.stable.connect(node_id, FEDIMINT_API_ALPN).await,
        }.map_err(ServerError::Connection)?;

        Ok(conn)
    }

    async fn make_new_connection_next(
        &self,
        endpoint_next: &iroh_next::Endpoint,
        node_id: NodeId,
        node_addr: Option<NodeAddr>,
    ) -> ServerResult<iroh_next::endpoint::Connection> {
        let next_node_id =
            iroh_next::EndpointId::from_bytes(node_id.as_bytes()).expect("Can't fail");

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
                if let Ok(conn) = &conn {
                    Self::spawn_connection_monitoring_next(
                        conn,
                        node_addr.id,
                        self.path_change.clone(),
                    );
                }

                conn
            }
            None => endpoint_next.connect(
                next_node_id,
                FEDIMINT_API_ALPN
            ).await,
        }
        .map_err(Into::into)
        .map_err(ServerError::Connection)?;

        Ok(conn)
    }
}

/// QUIC transport config with explicit idle timeout and keep-alive
/// for the stable iroh endpoint.
fn quic_transport_config() -> iroh::endpoint::TransportConfig {
    let mut config = iroh::endpoint::TransportConfig::default();
    config.max_idle_timeout(Some(
        IROH_IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits in IdleTimeout"),
    ));
    config.keep_alive_interval(Some(IROH_KEEP_ALIVE_INTERVAL));
    config
}

/// QUIC transport config with explicit idle timeout and keep-alive
/// for the next iroh endpoint.
fn quic_transport_config_next() -> iroh_next::endpoint::QuicTransportConfig {
    iroh_next::endpoint::QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IROH_IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits in IdleTimeout"),
        ))
        .keep_alive_interval(IROH_KEEP_ALIVE_INTERVAL)
        .build()
}

fn connectivity_from_iroh_conn_type(conn_type: &iroh::endpoint::ConnectionType) -> Connectivity {
    match conn_type {
        iroh::endpoint::ConnectionType::Direct(_) => Connectivity::Direct,
        iroh::endpoint::ConnectionType::Relay(_) => Connectivity::Relay,
        iroh::endpoint::ConnectionType::Mixed(..) => Connectivity::Mixed,
        iroh::endpoint::ConnectionType::None => Connectivity::Unknown,
    }
}

fn node_addr_stable_to_next(stable: &iroh::NodeAddr) -> iroh_next::EndpointAddr {
    let next_node_id =
        iroh_next::EndpointId::from_bytes(stable.node_id.as_bytes()).expect("Can't fail");
    let relay_addrs = stable.relay_url.iter().map(|u| {
        iroh_next::TransportAddr::Relay(
            iroh_next::RelayUrl::from_str(&u.to_string()).expect("Can't fail"),
        )
    });
    let direct_addrs = stable
        .direct_addresses
        .iter()
        .copied()
        .map(iroh_next::TransportAddr::Ip);

    iroh_next::EndpointAddr::from_parts(next_node_id, relay_addrs.chain(direct_addrs))
}

#[apply(async_trait_maybe_send!)]
impl IConnection for Connection {
    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IGuardianConnection for Connection {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let timeout = request_timeout_for_method(&method);
        let method_str = method.to_string();
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let result = fedimint_core::runtime::timeout(timeout, async {
            let (mut sink, mut stream) = self
                .open_bi()
                .await
                .map_err(|e| ServerError::Transport(e.into()))?;

            sink.write_all(&json)
                .await
                .map_err(|e| ServerError::Transport(e.into()))?;

            sink.finish()
                .map_err(|e| ServerError::Transport(e.into()))?;

            stream
                .read_to_end(IROH_MAX_RESPONSE_BYTES)
                .await
                .map_err(|e| ServerError::Transport(e.into()))
        })
        .await;

        let response = match result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                // The bi-stream stalled past our budget. Close the QUIC
                // connection so [`Self::is_connected`] (which reads
                // `close_reason`) starts returning false; the connection
                // pool's `get_or_init_pool_entry` will then evict this
                // entry on the next access and the upstream retry loop
                // will get a fresh connection.
                warn!(
                    target: LOG_NET_IROH,
                    method = %method_str,
                    timeout_secs = timeout.as_secs(),
                    "iroh request timed out, closing connection",
                );
                self.close(
                    iroh::endpoint::VarInt::from_u32(IROH_REQUEST_TIMEOUT_ERROR_CODE),
                    IROH_REQUEST_TIMEOUT_ERROR_REASON,
                );
                return Err(ServerError::Transport(anyhow::anyhow!(
                    "iroh request {method_str} timed out after {timeout:?}"
                )));
            }
        };

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| ServerError::InvalidResponse(e.into()))?;

        response.map_err(|e| ServerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }
}

#[apply(async_trait_maybe_send!)]
impl IConnection for iroh_next::endpoint::Connection {
    async fn await_disconnection(&self) {
        self.closed().await;
    }

    fn is_connected(&self) -> bool {
        self.close_reason().is_none()
    }
}

#[async_trait]
impl IGuardianConnection for iroh_next::endpoint::Connection {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let timeout = request_timeout_for_method(&method);
        let method_str = method.to_string();
        let json = serde_json::to_vec(&IrohApiRequest { method, request })
            .expect("Serialization to vec can't fail");

        let result = fedimint_core::runtime::timeout(timeout, async {
            let (mut sink, mut stream) = self
                .open_bi()
                .await
                .map_err(|e| ServerError::Transport(e.into()))?;

            sink.write_all(&json)
                .await
                .map_err(|e| ServerError::Transport(e.into()))?;

            sink.finish()
                .map_err(|e| ServerError::Transport(e.into()))?;

            stream
                .read_to_end(IROH_MAX_RESPONSE_BYTES)
                .await
                .map_err(|e| ServerError::Transport(e.into()))
        })
        .await;

        let response = match result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                warn!(
                    target: LOG_NET_IROH,
                    method = %method_str,
                    timeout_secs = timeout.as_secs(),
                    "iroh request timed out, closing connection",
                );
                self.close(
                    iroh_next::endpoint::VarInt::from_u32(IROH_REQUEST_TIMEOUT_ERROR_CODE),
                    IROH_REQUEST_TIMEOUT_ERROR_REASON,
                );
                return Err(ServerError::Transport(anyhow::anyhow!(
                    "iroh request {method_str} timed out after {timeout:?}"
                )));
            }
        };

        // TODO: We should not be serializing Results on the wire
        let response = serde_json::from_slice::<Result<Value, ApiError>>(&response)
            .map_err(|e| ServerError::InvalidResponse(e.into()))?;

        response.map_err(|e| ServerError::InvalidResponse(anyhow::anyhow!("Api Error: {:?}", e)))
    }
}

#[apply(async_trait_maybe_send!)]
impl IGatewayConnection for Connection {
    async fn request(
        &self,
        password: Option<String>,
        _method: Method,
        route: &str,
        payload: Option<Value>,
    ) -> ServerResult<Value> {
        let iroh_request = IrohGatewayRequest {
            route: route.to_string(),
            params: payload,
            password,
        };
        let json = serde_json::to_vec(&iroh_request).expect("serialization cant fail");

        let (mut sink, mut stream) = self
            .open_bi()
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.write_all(&json)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        sink.finish()
            .map_err(|e| ServerError::Transport(e.into()))?;

        let response = stream
            .read_to_end(IROH_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        let response = serde_json::from_slice::<IrohGatewayResponse>(&response)
            .map_err(|e| ServerError::InvalidResponse(e.into()))?;
        match StatusCode::from_u16(response.status).map_err(|e| {
            ServerError::InvalidResponse(anyhow::anyhow!("Invalid status code: {}", e))
        })? {
            StatusCode::OK => Ok(response.body),
            status => Err(ServerError::ServerError(anyhow::anyhow!(
                "Server returned status code: {}",
                status
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use fedimint_core::PeerId;
    use fedimint_core::config::FederationId;
    use fedimint_core::invite_code::InviteCode;
    use fedimint_core::module::ApiMethod;
    use fedimint_core::util::SafeUrl;

    use super::{
        IROH_REQUEST_TIMEOUT_DEFAULT, IROH_REQUEST_TIMEOUT_LONG_POLL, request_timeout_for_method,
    };
    use crate::{iroh_next_endpoint_url, is_iroh_next_endpoint_url, preserve_iroh_next_marker};

    const TEST_ENDPOINT_ID: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    #[test]
    fn advertised_iroh_next_url_selects_only_the_next_stack() {
        let next_url = iroh_next_endpoint_url(TEST_ENDPOINT_ID).expect("valid endpoint ID");
        assert!(is_iroh_next_endpoint_url(&next_url).expect("valid Iroh API URL path"));

        let invite = InviteCode::new(next_url, PeerId::from(0), FederationId::dummy(), None);
        let round_tripped =
            InviteCode::from_str(&invite.to_string()).expect("invite code round-trips");
        assert!(is_iroh_next_endpoint_url(&round_tripped.url()).expect("valid Iroh API URL path"));

        let stable_url =
            SafeUrl::parse(&format!("iroh://{TEST_ENDPOINT_ID}")).expect("valid Iroh URL");
        assert!(!is_iroh_next_endpoint_url(&stable_url).expect("valid Iroh API URL path"));

        let replacement = SafeUrl::parse(
            "iroh://d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .expect("valid replacement URL");
        let replacement = preserve_iroh_next_marker(&round_tripped.url(), &replacement);
        assert!(is_iroh_next_endpoint_url(&replacement).expect("valid Iroh API URL path"));
    }

    #[test]
    fn unknown_iroh_api_version_path_is_rejected() {
        let url = SafeUrl::parse(&format!("iroh://{TEST_ENDPOINT_ID}/v2")).expect("valid Iroh URL");
        assert!(is_iroh_next_endpoint_url(&url).is_err());
    }

    /// Every `await_*` endpoint currently exposed by fedimint modules
    /// should be classified as long-poll. If a new endpoint is added
    /// without the prefix it will silently fall through to the default
    /// 60s budget — this list documents the contract and will surface
    /// renames as test churn.
    const AWAIT_ENDPOINTS: &[&str] = &[
        // fedimint-core
        "await_output_outcome",
        "await_outputs_outcomes",
        "await_session_outcome",
        "await_signed_session_outcome",
        "await_transaction",
        // fedimint-ln-common
        "await_account",
        "await_block_height",
        "await_offer",
        "await_outgoing_contract_cancelled",
        "await_preimage_decryption",
        // fedimint-lnv2-common
        "await_incoming_contract",
        "await_incoming_contracts",
        "await_preimage",
    ];

    /// A representative sample of prompt endpoints — anything that is
    /// expected to respond without server-side blocking.
    const PROMPT_ENDPOINTS: &[&str] = &[
        "block_count",
        "session_count",
        "session_status",
        "status",
        "version",
        "client_config",
        "audit",
        "account",
        "offer",
        "list_gateways",
        "submit_transaction",
        "consensus_block_count",
    ];

    #[test]
    fn await_prefix_gets_long_poll_timeout() {
        for name in AWAIT_ENDPOINTS {
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LONG_POLL,
                "core endpoint {name} should map to the long-poll timeout"
            );
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Module(0, (*name).to_owned())),
                IROH_REQUEST_TIMEOUT_LONG_POLL,
                "module endpoint {name} should map to the long-poll timeout"
            );
        }
    }

    #[test]
    fn wait_prefix_also_gets_long_poll_timeout() {
        // No fedimint endpoint currently uses this prefix, but the
        // selector accepts it so future additions following the
        // alternate naming convention don't silently get the default.
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core("wait_for_event".to_owned())),
            IROH_REQUEST_TIMEOUT_LONG_POLL,
        );
    }

    #[test]
    fn prompt_endpoints_get_default_timeout() {
        for name in PROMPT_ENDPOINTS {
            assert_eq!(
                request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
                IROH_REQUEST_TIMEOUT_DEFAULT,
                "endpoint {name} should map to the default timeout"
            );
        }
    }

    #[test]
    fn endpoints_that_merely_contain_await_are_not_misclassified() {
        // The selector is prefix-based, so an endpoint name with
        // "await" elsewhere in the string must not get the long
        // budget by accident.
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core("submit_await_thing".to_owned())),
            IROH_REQUEST_TIMEOUT_DEFAULT,
        );
    }
}
