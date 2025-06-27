use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::envs::parse_kv_list_from_env;
use fedimint_core::module::{
    ApiError, ApiMethod, ApiRequestErased, FEDIMINT_API_ALPN, IrohApiRequest,
};
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_logging::LOG_NET_IROH;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey};
use iroh_base::ticket::NodeTicket;
use n0_future::task::JoinSet;
use serde_json::Value;
use tracing::{debug, trace, warn};

use super::{DynClientConnection, IClientConnection, IClientConnector, PeerError, PeerResult};

#[derive(Debug, Clone)]
pub struct IrohConnector {
    node_ids: BTreeMap<PeerId, NodeId>,
    endpoint_stable: Endpoint,
    endpoint_next: iroh_next::Endpoint,

    /// List of overrides to use when attempting to connect to given
    /// `NodeId`
    ///
    /// This is useful for testing, or forcing non-default network
    /// connectivity.
    pub connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

impl IrohConnector {
    pub async fn new(peers: BTreeMap<PeerId, SafeUrl>) -> anyhow::Result<Self> {
        const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";
        warn!(target: LOG_NET_IROH, "Iroh support is experimental");
        let mut s = Self::new_no_overrides(peers).await?;

        for (k, v) in parse_kv_list_from_env::<_, NodeTicket>(FM_IROH_CONNECT_OVERRIDES_ENV)? {
            s = s.with_connection_override(k, v.into());
        }

        Ok(s)
    }

    pub async fn new_no_overrides(peers: BTreeMap<PeerId, SafeUrl>) -> anyhow::Result<Self> {
        let node_ids = peers
            .into_iter()
            .map(|(peer, url)| {
                let host = url.host_str().context("Url is missing host")?;

                let node_id = PublicKey::from_str(host).context("Failed to parse node id")?;

                Ok((peer, node_id))
            })
            .collect::<anyhow::Result<BTreeMap<PeerId, NodeId>>>()?;

        let endpoint_stable = {
            let builder = Endpoint::builder().discovery_n0();
            #[cfg(not(target_family = "wasm"))]
            let builder = builder.discovery_dht();
            let endpoint = builder.bind().await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.node_id(),
                node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                "Iroh api client endpoint (stable)"
            );
            endpoint
        };
        let endpoint_next = {
            let builder = iroh_next::Endpoint::builder().discovery_n0();
            #[cfg(not(target_family = "wasm"))]
            let builder = builder.discovery_dht();
            let endpoint = builder.bind().await?;
            debug!(
                target: LOG_NET_IROH,
                node_id = %endpoint.node_id(),
                node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
                "Iroh api client endpoint (next)"
            );
            endpoint
        };

        Ok(Self {
            node_ids,
            endpoint_stable,
            endpoint_next,
            connection_overrides: BTreeMap::new(),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }
}

#[async_trait]
impl IClientConnector for IrohConnector {
    fn peers(&self) -> BTreeSet<PeerId> {
        self.node_ids.keys().copied().collect()
    }

    async fn connect(&self, peer_id: PeerId) -> PeerResult<DynClientConnection> {
        let node_id = *self
            .node_ids
            .get(&peer_id)
            .ok_or(PeerError::InvalidPeerId { peer_id })?;

        let mut join_set = JoinSet::new();
        let connection_override = self.connection_overrides.get(&node_id).cloned();
        let endpoint_stable = self.endpoint_stable.clone();
        let endpoint_next = self.endpoint_next.clone();

        join_set.spawn({
            let connection_override = connection_override.clone();
            async move {
                Ok(match connection_override {
                    Some(node_addr) => {
                        trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                        endpoint_stable
                            .connect(node_addr.clone(), FEDIMINT_API_ALPN)
                            .await
                    }
                    None => endpoint_stable.connect(node_id, FEDIMINT_API_ALPN).await,
                }.map_err(PeerError::Connection)?.into_dyn())
        }});

        join_set.spawn(async move {
            Ok(match connection_override {
                Some(node_addr) => {
                    trace!(target: LOG_NET_IROH, %node_id, "Using a connectivity override for connection");
                    endpoint_next
                        .connect(node_addr_stable_to_next(&node_addr), FEDIMINT_API_ALPN)
                        .await
                }
                None => endpoint_next.connect(
                        iroh_next::NodeId::from_bytes(node_id.as_bytes()).expect("Can't fail"),
                        FEDIMINT_API_ALPN
                    ).await,
                }.map_err(PeerError::Connection)?.into_dyn() )
        });

        // Remember last error, so we have something to return if
        // neither connection works.
        let mut prev_err = None;

        // Loop until first success, or running out of connections.
        while let Some(join) = join_set.join_next().await {
            match join {
                Ok(Ok(o)) => return Ok(o),
                Ok(Err(err)) => {
                    prev_err = Some(err);
                }
                Err(err) => {
                    warn!(
                        target: LOG_NET_IROH,
                        err = %err.fmt_compact(),
                        "Join error in iroh connection task"
                    );
                }
            }
        }

        Err(prev_err.unwrap_or_else(|| {
            PeerError::ServerError(anyhow::anyhow!("Both iroh connection task panicked?!"))
        }))
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
impl IClientConnection for Connection {
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
}

#[async_trait]
impl IClientConnection for iroh_next::endpoint::Connection {
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
}
