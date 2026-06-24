use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{
    FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV, FM_IROH_NEXT_CONNECT_OVERRIDES_PLAIN_ENV,
    parse_kv_list_from_env,
};
use fedimint_core::net::STANDARD_FEDIMINT_P2P_PORT;
use fedimint_core::net::iroh::{build_iroh_endpoint, build_iroh_next_endpoint};
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::LOG_NET_IROH;
use fedimint_server_core::dashboard_ui::ConnectionType;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::{Endpoint, NodeAddr, NodeId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{trace, warn};

use super::IP2PConnector;
use crate::IrohNextSettings;
use crate::net::p2p_connection::{DynP2PConnection, IP2PConnection};

/// Parses the host and port from a url
pub fn parse_p2p(url: &SafeUrl) -> anyhow::Result<String> {
    ensure!(url.scheme() == "fedimint", "p2p url has invalid scheme");

    let host = url.host_str().context("p2p url is missing host")?;

    let port = url.port().unwrap_or(STANDARD_FEDIMINT_P2P_PORT);

    Ok(format!("{host}:{port}"))
}

#[derive(Debug, Clone)]
pub struct IrohConnector {
    /// Map of all peers' connection information we want to be connected to
    pub(crate) node_ids: BTreeMap<PeerId, NodeId>,
    /// The Iroh (stable) endpoint
    pub(crate) endpoint: Endpoint,
    /// Optional iroh-next endpoint
    pub(crate) endpoint_next: Option<iroh_next::Endpoint>,
    /// List of overrides to use when attempting to connect to given `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network connectivity.
    pub(crate) connection_overrides: BTreeMap<NodeId, NodeAddr>,
    /// List of overrides to use for iroh-next connection attempts.
    pub(crate) next_connection_overrides: BTreeMap<iroh_next::EndpointId, iroh_next::EndpointAddr>,
    /// Peers with last-known connectivity through the iroh-next stack.
    pub(crate) next_connected_peers: Arc<Mutex<BTreeSet<PeerId>>>,
}

pub(crate) const FEDIMINT_P2P_ALPN: &[u8] = b"FEDIMINT_P2P_ALPN";

impl IrohConnector {
    pub async fn new(
        secret_key: iroh::SecretKey,
        p2p_bind_addr: SocketAddr,
        iroh_dns: Option<SafeUrl>,
        iroh_relays: Vec<SafeUrl>,
        node_ids: BTreeMap<PeerId, NodeId>,
        iroh_next_settings: Option<&IrohNextSettings>,
    ) -> anyhow::Result<Self> {
        let mut s = Self::new_no_overrides(
            secret_key,
            p2p_bind_addr,
            iroh_dns,
            iroh_relays,
            node_ids,
            iroh_next_settings,
        )
        .await?;

        // Overrides are `<node-id>=<socket-addr>` pairs (the node id is the
        // key); iroh 1.0 no longer ships the `NodeTicket` format, so build the
        // `NodeAddr` from its parts to keep the wire format version agnostic.
        // Pre-0.12 guardians read the `NodeTicket`-format
        // `FM_IROH_CONNECT_OVERRIDES` instead; devimint emits both side by side.
        for (k, v) in
            parse_kv_list_from_env::<NodeId, SocketAddr>(FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV)?
        {
            s = s.with_connection_override(k, NodeAddr::new(k).with_direct_addresses([v]));
        }

        for (k, v) in parse_kv_list_from_env::<iroh_next::EndpointId, SocketAddr>(
            FM_IROH_NEXT_CONNECT_OVERRIDES_PLAIN_ENV,
        )? {
            s = s.with_next_connection_override(
                k,
                iroh_next::EndpointAddr::from_parts(k, [iroh_next::TransportAddr::Ip(v)]),
            );
        }

        Ok(s)
    }

    pub async fn new_no_overrides(
        secret_key: iroh::SecretKey,
        bind_addr: SocketAddr,
        iroh_dns: Option<SafeUrl>,
        iroh_relays: Vec<SafeUrl>,
        node_ids: BTreeMap<PeerId, NodeId>,
        iroh_next_settings: Option<&IrohNextSettings>,
    ) -> anyhow::Result<Self> {
        let identity = *node_ids
            .iter()
            .find(|entry| entry.1 == &secret_key.public())
            .expect("Our public key is not part of the keyset")
            .0;

        let next_p2p_sk = iroh_next::SecretKey::from_bytes(&secret_key.to_bytes());

        let endpoint = build_iroh_endpoint(
            secret_key,
            bind_addr,
            iroh_dns.clone(),
            iroh_relays.clone(),
            FEDIMINT_P2P_ALPN,
        )
        .await?;

        let endpoint_next = if let Some(next_settings) = iroh_next_settings {
            Some(
                build_iroh_next_endpoint(
                    next_p2p_sk,
                    next_settings.p2p_bind,
                    iroh_dns,
                    iroh_relays,
                    FEDIMINT_P2P_ALPN,
                )
                .await?,
            )
        } else {
            None
        };

        Ok(Self {
            node_ids: node_ids
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
            endpoint,
            endpoint_next,
            connection_overrides: BTreeMap::default(),
            next_connection_overrides: BTreeMap::default(),
            next_connected_peers: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    /// Add a direct-address override for an iroh-next endpoint connection
    /// attempt.
    pub fn with_next_connection_override(
        mut self,
        node: iroh_next::EndpointId,
        addr: iroh_next::EndpointAddr,
    ) -> Self {
        self.next_connection_overrides.insert(node, addr);
        self
    }
}

#[derive(Debug, Clone, Copy)]
enum IrohStack {
    Stable,
    Next,
}

impl IrohStack {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Next => "next",
        }
    }
}

#[async_trait]
impl<M> IP2PConnector<M> for IrohConnector
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    fn peers(&self) -> Vec<PeerId> {
        self.node_ids.keys().copied().collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        let node_id = *self.node_ids.get(&peer).expect("No node id found for peer");

        let mut futures = FuturesUnordered::<
            Pin<Box<dyn Future<Output = (anyhow::Result<DynP2PConnection<M>>, IrohStack)> + Send>>,
        >::new();

        // Stable endpoint connection attempt
        {
            let endpoint = self.endpoint.clone();
            let override_addr = self.connection_overrides.get(&node_id).cloned();
            futures.push(Box::pin(async move {
                let conn = match override_addr {
                    Some(node_addr) => {
                        trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for stable connection");
                        endpoint.connect(node_addr, FEDIMINT_P2P_ALPN).await
                    }
                    None => endpoint.connect(node_id, FEDIMINT_P2P_ALPN).await,
                };
                (conn.map(IP2PConnection::into_dyn), IrohStack::Stable)
            }));
        }

        // Iroh-next endpoint connection attempt
        if let Some(endpoint_next) = &self.endpoint_next {
            let endpoint_next = endpoint_next.clone();
            let next_node_id =
                iroh_next::EndpointId::from_bytes(node_id.as_bytes()).expect("Can't fail");
            let override_addr = self.next_connection_overrides.get(&next_node_id).cloned();
            futures.push(Box::pin(async move {
                let conn: Result<iroh_next::endpoint::Connection, _> = match override_addr {
                    Some(endpoint_addr) => {
                        trace!(target: LOG_NET_IROH, %next_node_id, "Using a connectivity override for next connection");
                        endpoint_next.connect(endpoint_addr, FEDIMINT_P2P_ALPN).await
                    }
                    None => endpoint_next.connect(next_node_id, FEDIMINT_P2P_ALPN).await,
                };
                (
                    conn.map(IP2PConnection::into_dyn).map_err(Into::into),
                    IrohStack::Next,
                )
            }));
        }

        let mut prev_err = None;
        while let Some((result, iroh_stack)) = futures.next().await {
            match result {
                Ok(connection) => {
                    if matches!(iroh_stack, IrohStack::Next) {
                        self.next_connected_peers
                            .lock()
                            .expect("next connected peers mutex should not be poisoned")
                            .insert(peer);
                    }
                    return Ok(connection);
                }
                Err(err) => {
                    let iroh_stack = iroh_stack.as_str();
                    warn!(
                        target: LOG_NET_IROH,
                        err = %err.fmt_compact_anyhow(),
                        %iroh_stack,
                        "P2P connection attempt failed"
                    );
                    prev_err = Some(err);
                }
            }
        }

        Err(prev_err.unwrap_or_else(|| anyhow::anyhow!("No connection attempts available")))
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)> {
        if let Some(endpoint_next) = &self.endpoint_next {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let connection = incoming
                        .context("Stable listener closed unexpectedly")?
                        .accept()?
                        .await?;

                    let node_id = connection.remote_node_id()?;
                    let auth_peer = self
                        .node_ids
                        .iter()
                        .find(|entry| entry.1 == &node_id)
                        .with_context(|| format!("Node id {node_id} is unknown"))?
                        .0;

                    Ok((*auth_peer, connection.into_dyn()))
                }
                incoming = endpoint_next.accept() => {
                    let connection = incoming
                        .context("Next listener closed unexpectedly")?
                        .accept()?
                        .await?;

                    let next_node_id = connection.remote_id();
                    // Convert iroh-next EndpointId back to stable NodeId for peer lookup
                    let node_id = NodeId::from_bytes(next_node_id.as_bytes())
                        .expect("Can't fail");
                    let auth_peer = *self
                        .node_ids
                        .iter()
                        .find(|entry| entry.1 == &node_id)
                        .with_context(|| format!("Node id {node_id} (next) is unknown"))?
                        .0;
                    self.next_connected_peers
                        .lock()
                        .expect("next connected peers mutex should not be poisoned")
                        .insert(auth_peer);

                    Ok((auth_peer, connection.into_dyn()))
                }
            }
        } else {
            let connection = self
                .endpoint
                .accept()
                .await
                .context("Listener closed unexpectedly")?
                .accept()?
                .await?;

            let node_id = connection.remote_node_id()?;
            let auth_peer = self
                .node_ids
                .iter()
                .find(|entry| entry.1 == &node_id)
                .with_context(|| format!("Node id {node_id} is unknown"))?
                .0;

            Ok((*auth_peer, connection.into_dyn()))
        }
    }

    fn connection_type(&self, peer: PeerId) -> Option<ConnectionType> {
        let node_id = *self.node_ids.get(&peer).expect("No node id found for peer");

        // Check stable endpoint first
        if let Ok(watcher) = self.endpoint.conn_type(node_id)
            && let Ok(conn_type) = watcher.get()
        {
            match conn_type {
                iroh::endpoint::ConnectionType::None => {}
                iroh::endpoint::ConnectionType::Direct(..) => return Some(ConnectionType::Direct),
                iroh::endpoint::ConnectionType::Relay(..) => return Some(ConnectionType::Relay),
                iroh::endpoint::ConnectionType::Mixed(..) => return Some(ConnectionType::Mixed),
            }
        }

        self.next_connected_peers
            .lock()
            .expect("next connected peers mutex should not be poisoned")
            .contains(&peer)
            .then_some(ConnectionType::IrohNext)
    }
}
