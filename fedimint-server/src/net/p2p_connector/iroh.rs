use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::{Context as _, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_IROH_CONNECT_OVERRIDES_ENV, parse_kv_list_from_env};
use fedimint_core::net::STANDARD_FEDIMINT_P2P_PORT;
use fedimint_core::net::iroh::{build_iroh_endpoint, build_iroh_next_endpoint};
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::LOG_NET_IROH;
use fedimint_server_core::dashboard_ui::ConnectionType;
use futures::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::{Endpoint, NodeAddr, NodeId};
use iroh_base::ticket::NodeTicket;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{trace, warn};

use super::IP2PConnector;
use crate::IrohNextSettings;
use crate::net::broadcast_keys::derive_iroh_next_p2p_sk;
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
    /// Optional iroh-next (v0.90) endpoint
    pub(crate) endpoint_next: Option<iroh_next::Endpoint>,
    /// List of overrides to use when attempting to connect to given `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network connectivity.
    pub(crate) connection_overrides: BTreeMap<NodeId, NodeAddr>,
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
        broadcast_sk: Option<&fedimint_core::secp256k1::SecretKey>,
    ) -> anyhow::Result<Self> {
        let mut s = Self::new_no_overrides(
            secret_key,
            p2p_bind_addr,
            iroh_dns,
            iroh_relays,
            node_ids,
            iroh_next_settings,
            broadcast_sk,
        )
        .await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
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
        broadcast_sk: Option<&fedimint_core::secp256k1::SecretKey>,
    ) -> anyhow::Result<Self> {
        let identity = *node_ids
            .iter()
            .find(|entry| entry.1 == &secret_key.public())
            .expect("Our public key is not part of the keyset")
            .0;

        let endpoint = build_iroh_endpoint(
            secret_key,
            bind_addr,
            iroh_dns.clone(),
            iroh_relays.clone(),
            FEDIMINT_P2P_ALPN,
        )
        .await?;

        let endpoint_next = if let Some(next_settings) = iroh_next_settings
            && let Some(broadcast_sk) = broadcast_sk
        {
            let next_sk = derive_iroh_next_p2p_sk(broadcast_sk);
            Some(
                build_iroh_next_endpoint(
                    next_sk,
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
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
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
            Pin<
                Box<
                    dyn Future<Output = (anyhow::Result<DynP2PConnection<M>>, &'static str)> + Send,
                >,
            >,
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
                (conn.map(IP2PConnection::into_dyn), "stable")
            }));
        }

        // Iroh-next endpoint connection attempt
        if let Some(endpoint_next) = &self.endpoint_next {
            let endpoint_next = endpoint_next.clone();
            let next_node_id =
                iroh_next::NodeId::from_bytes(node_id.as_bytes()).expect("Can't fail");
            futures.push(Box::pin(async move {
                let conn = endpoint_next.connect(next_node_id, FEDIMINT_P2P_ALPN).await;
                (
                    conn.map(IP2PConnection::into_dyn).map_err(Into::into),
                    "next",
                )
            }));
        }

        let mut prev_err = None;
        while let Some((result, iroh_stack)) = futures.next().await {
            match result {
                Ok(connection) => return Ok(connection),
                Err(err) => {
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

                    let next_node_id = connection.remote_node_id()?;
                    // Convert iroh-next NodeId back to stable NodeId for peer lookup
                    let node_id = NodeId::from_bytes(next_node_id.as_bytes())
                        .expect("Can't fail");
                    let auth_peer = self
                        .node_ids
                        .iter()
                        .find(|entry| entry.1 == &node_id)
                        .with_context(|| format!("Node id {node_id} (next) is unknown"))?
                        .0;

                    Ok((*auth_peer, connection.into_dyn()))
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
        if let Ok(conn_type) = self.endpoint.conn_type(node_id).ok()?.get() {
            return match conn_type {
                iroh::endpoint::ConnectionType::None => None,
                iroh::endpoint::ConnectionType::Direct(..) => Some(ConnectionType::Direct),
                iroh::endpoint::ConnectionType::Relay(..) => Some(ConnectionType::Relay),
                iroh::endpoint::ConnectionType::Mixed(..) => Some(ConnectionType::Mixed),
            };
        }

        // Check iroh-next endpoint
        if let Some(endpoint_next) = &self.endpoint_next {
            let next_node_id =
                iroh_next::NodeId::from_bytes(node_id.as_bytes()).expect("Can't fail");
            if let Some(conn_type) = endpoint_next.conn_type(next_node_id) {
                use iroh_next::Watcher as _;
                return match conn_type.get().ok()? {
                    iroh_next::endpoint::ConnectionType::None => None,
                    iroh_next::endpoint::ConnectionType::Direct(..) => Some(ConnectionType::Direct),
                    iroh_next::endpoint::ConnectionType::Relay(..) => Some(ConnectionType::Relay),
                    iroh_next::endpoint::ConnectionType::Mixed(..) => Some(ConnectionType::Mixed),
                };
            }
        }

        None
    }
}
