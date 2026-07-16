mod endpoint;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::{Context as _, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV, parse_kv_list_from_env};
use fedimint_core::net::STANDARD_FEDIMINT_P2P_PORT;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use fedimint_server_core::dashboard_ui::ConnectionType;
use iroh::{NodeAddr, NodeId, SecretKey};
use iroh_next::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::trace;

use self::endpoint::build_iroh_endpoint;
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
/// Iroh 1.0 guardian P2P connector with a stable Iroh 0.35 public boundary.
///
/// Persisted configuration and callers retain the 0.35 key and address types;
/// this connector converts their unchanged Ed25519 identity bytes into the Iroh
/// 1.0 runtime representation.
pub struct IrohConnector {
    /// Map of all peers' connection information we want to be connected to
    pub(crate) endpoint_ids: BTreeMap<PeerId, EndpointId>,
    /// The Iroh endpoint
    pub(crate) endpoint: Endpoint,
    /// List of overrides to use when attempting to connect to an endpoint
    ///
    /// This is useful for testing, or forcing non-default network connectivity.
    pub(crate) connection_overrides: BTreeMap<EndpointId, EndpointAddr>,
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

        // Overrides are `<endpoint-id>=<socket-addr>` pairs. Iroh 1.0 no longer
        // ships the `NodeTicket` format, so build the `EndpointAddr` from its
        // parts to keep the wire format version agnostic. Pre-0.12 guardians
        // read the `NodeTicket`-format
        // `FM_IROH_CONNECT_OVERRIDES` instead; devimint emits both side by side.
        for (k, v) in
            parse_kv_list_from_env::<EndpointId, SocketAddr>(FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV)?
        {
            s.connection_overrides
                .insert(k, EndpointAddr::from_parts(k, [TransportAddr::Ip(v)]));
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
        let secret_key = secret_key_stable_to_next(&secret_key);
        let endpoint_ids = node_ids
            .into_iter()
            .map(|(peer, node_id)| {
                endpoint_id_stable_to_next(node_id)
                    .with_context(|| format!("Converting Iroh endpoint ID for peer {peer}"))
                    .map(|endpoint_id| (peer, endpoint_id))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

        let identity = *endpoint_ids
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
            endpoint_ids: endpoint_ids
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
            endpoint,
            connection_overrides: BTreeMap::default(),
        })
    }

    /// Add a stable-Iroh connection override.
    ///
    /// This compatibility wrapper keeps the connector's existing public
    /// boundary while converting the address to its Iroh 1.0 runtime
    /// representation.
    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        let endpoint_id = endpoint_id_stable_to_next(node)
            .expect("an Iroh 0.35 node ID must be a valid Iroh 1.0 endpoint ID");
        let relay = addr
            .relay_url
            .map(|relay| TransportAddr::Relay(iroh_next::RelayUrl::from(url::Url::from(relay))));
        let direct = addr.direct_addresses.into_iter().map(TransportAddr::Ip);
        self.connection_overrides.insert(
            endpoint_id,
            EndpointAddr::from_parts(endpoint_id, relay.into_iter().chain(direct)),
        );
        self
    }
}

fn secret_key_stable_to_next(secret_key: &SecretKey) -> iroh_next::SecretKey {
    iroh_next::SecretKey::from_bytes(&secret_key.to_bytes())
}

fn endpoint_id_stable_to_next(node_id: NodeId) -> anyhow::Result<EndpointId> {
    Ok(EndpointId::from_bytes(node_id.as_bytes())?)
}

#[async_trait]
impl<M> IP2PConnector<M> for IrohConnector
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    fn peers(&self) -> Vec<PeerId> {
        self.endpoint_ids.keys().copied().collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        let endpoint_id = *self
            .endpoint_ids
            .get(&peer)
            .expect("No endpoint id found for peer");

        let connection = match self.connection_overrides.get(&endpoint_id) {
            Some(endpoint_addr) => {
                trace!(target: LOG_NET_IROH, %endpoint_id, "Using a connectivity override for connection");
                self.endpoint
                    .connect(endpoint_addr.clone(), FEDIMINT_P2P_ALPN)
                    .await?
            }
            None => {
                self.endpoint
                    .connect(endpoint_id, FEDIMINT_P2P_ALPN)
                    .await?
            }
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

        let endpoint_id = connection.remote_id();

        let auth_peer = self
            .endpoint_ids
            .iter()
            .find(|entry| entry.1 == &endpoint_id)
            .with_context(|| format!("Endpoint id {endpoint_id} is unknown"))?
            .0;

        Ok((*auth_peer, connection.into_dyn()))
    }

    fn connection_type(&self, _peer: PeerId) -> Option<ConnectionType> {
        // Iroh 1.0 reports paths on live connections rather than the endpoint.
        None
    }
}
