use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::{Context as _, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_IROH_CONNECT_OVERRIDES_ENV, parse_kv_list_from_env};
use fedimint_core::net::STANDARD_FEDIMINT_P2P_PORT;
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use fedimint_server_core::dashboard_ui::ConnectionType;
use iroh::{Endpoint, NodeAddr, NodeId, SecretKey};
use iroh_base::ticket::NodeTicket;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::trace;

use super::IP2PConnector;
use crate::net::p2p_connection::{DynP2PConnection, IP2PConnection as _};

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
    /// The Iroh endpoint
    pub(crate) endpoint: Endpoint,
    /// List of overrides to use when attempting to connect to given `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network connectivity.
    pub(crate) connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

pub(crate) const FEDIMINT_P2P_ALPN: &[u8] = b"FEDIMINT_P2P_ALPN";

impl IrohConnector {
    pub async fn new(
        secret_key: SecretKey,
        p2p_bind_addr: SocketAddr,
        iroh_dns: Option<SafeUrl>,
        iroh_relays: Vec<SafeUrl>,
        node_ids: BTreeMap<PeerId, NodeId>,
    ) -> anyhow::Result<Self> {
        let mut s =
            Self::new_no_overrides(secret_key, p2p_bind_addr, iroh_dns, iroh_relays, node_ids)
                .await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
        }

        Ok(s)
    }

    pub async fn new_no_overrides(
        secret_key: SecretKey,
        bind_addr: SocketAddr,
        iroh_dns: Option<SafeUrl>,
        iroh_relays: Vec<SafeUrl>,
        node_ids: BTreeMap<PeerId, NodeId>,
    ) -> anyhow::Result<Self> {
        let identity = *node_ids
            .iter()
            .find(|entry| entry.1 == &secret_key.public())
            .expect("Our public key is not part of the keyset")
            .0;

        let endpoint = build_iroh_endpoint(
            secret_key,
            bind_addr,
            iroh_dns,
            iroh_relays,
            FEDIMINT_P2P_ALPN,
        )
        .await?;

        Ok(Self {
            node_ids: node_ids
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
            endpoint,
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

        let connection = match self.connection_overrides.get(&node_id) {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                self.endpoint
                    .connect(node_addr.clone(), FEDIMINT_P2P_ALPN)
                    .await?
            }
            None => self.endpoint.connect(node_id, FEDIMINT_P2P_ALPN).await?,
        };

        Ok(connection.into_dyn())
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)> {
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

    fn connection_type(&self, peer: PeerId) -> Option<ConnectionType> {
        let node_id = *self.node_ids.get(&peer).expect("No node id found for peer");

        match self.endpoint.conn_type(node_id).ok()?.get().ok()? {
            iroh::endpoint::ConnectionType::None => None,
            iroh::endpoint::ConnectionType::Direct(..) => Some(ConnectionType::Direct),
            iroh::endpoint::ConnectionType::Relay(..) => Some(ConnectionType::Relay),
            iroh::endpoint::ConnectionType::Mixed(..) => Some(ConnectionType::Mixed),
        }
    }
}
