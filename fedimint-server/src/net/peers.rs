//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::peers::IPeerConnections`] and
//! its main implementation is [`ReconnectPeerConnections`], see these for
//! details.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_api_client::api::PeerConnectionStatus;
use fedimint_core::net::peers::{IPeerConnections, Recipient};
use fedimint_core::task::{Cancellable, Cancelled, TaskGroup};
use fedimint_core::util::backoff_util::{api_networking_backoff, FibonacciBackoff};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, instrument, warn};

use crate::metrics::{PEER_CONNECT_COUNT, PEER_DISCONNECT_COUNT, PEER_MESSAGES_COUNT};
use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;

/// Owned [`Connector`](crate::net::connect::Connector) trait object used by
/// [`ReconnectPeerConnections`]
pub type PeerConnector<M> = AnyConnector<PeerMessage<M>>;

/// Connection manager that automatically reconnects to peers
///
/// `ReconnectPeerConnections` is based on a
/// [`Connector`](crate::net::connect::Connector) object which is used to open
/// [`FramedTransport`](crate::net::framed::FramedTransport) connections. For
/// production deployments the `Connector` has to ensure that connections are
/// authenticated and encrypted.
#[derive(Clone)]
pub struct ReconnectPeerConnections<T> {
    connections: HashMap<PeerId, PeerConnection<T>>,
}

#[derive(Clone)]
struct PeerConnection<T> {
    outgoing: async_channel::Sender<T>,
    incoming: async_channel::Receiver<T>,
}

/// Specifies the network configuration for federation-internal communication
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Our federation member's identity
    pub identity: PeerId,
    /// Our listen address for incoming connections from other federation
    /// members
    pub p2p_bind_addr: SocketAddr,
    /// Map of all peers' connection information we want to be connected to
    pub peers: HashMap<PeerId, SafeUrl>,
}

/// Internal message type for [`ReconnectPeerConnections`], just public because
/// it appears in the public interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerMessage<M> {
    Message(M),
    Ping,
}

struct PeerConnectionStateMachine<M> {
    common: CommonPeerConnectionState<M>,
    state: PeerConnectionState<M>,
}

struct CommonPeerConnectionState<M> {
    incoming: async_channel::Sender<M>,
    outgoing: async_channel::Receiver<M>,
    our_id: PeerId,
    our_id_str: String,
    peer_id: PeerId,
    peer_id_str: String,
    peer_address: SafeUrl,
    connect: SharedAnyConnector<PeerMessage<M>>,
    incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
}
enum PeerConnectionState<M> {
    Disconnected(FibonacciBackoff),
    Connected(AnyFramedTransport<PeerMessage<M>>),
}

impl<T: 'static> ReconnectPeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync,
{
    /// Creates a new `ReconnectPeerConnections` connection manager from a
    /// network config and a [`Connector`](crate::net::connect::Connector).
    /// See [`ReconnectPeerConnections`] for requirements on the
    /// `Connector`.
    #[instrument(skip_all)]
    pub(crate) async fn new(
        cfg: NetworkConfig,
        connector: PeerConnector<T>,
        task_group: &TaskGroup,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    ) -> Self {
        let connector: SharedAnyConnector<PeerMessage<T>> = connector.into();
        let mut connection_senders = HashMap::new();
        let mut connections = HashMap::new();

        for (peer, peer_address) in cfg.peers.iter().filter(|(&peer, _)| peer != cfg.identity) {
            let (connection_sender, connection_receiver) =
                tokio::sync::mpsc::channel::<AnyFramedTransport<PeerMessage<T>>>(4);

            let connection = PeerConnection::new(
                cfg.identity,
                *peer,
                peer_address.clone(),
                connector.clone(),
                connection_receiver,
                status_channels.clone(),
                task_group,
            );

            connection_senders.insert(*peer, connection_sender);
            connections.insert(*peer, connection);

            status_channels
                .write()
                .await
                .insert(*peer, PeerConnectionStatus::Disconnected);
        }

        let mut listener = connector
            .listen(cfg.p2p_bind_addr)
            .await
            .expect("Could not bind to port");

        task_group.spawn_cancellable("handle-incoming-p2p-connections", async move {
            loop {
                match listener.next().await.expect("Listener closed") {
                    Ok((peer, connection)) => {
                        if connection_senders
                            .get_mut(&peer)
                            .expect("Authenticating connectors dont return unknown peers")
                            .send(connection)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    },
                    Err(err) => {
                        warn!(target: LOG_NET_PEER, our_id = %cfg.identity, %err, "Error while opening incoming connection");
                    }
                }
            }

            info!(target: LOG_NET_PEER, "Shutting down task listening for p2p connections");
        });

        ReconnectPeerConnections { connections }
    }
}

#[async_trait]
impl<M> IPeerConnections<M> for ReconnectPeerConnections<M>
where
    M: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Unpin + Send + Sync + 'static,
{
    async fn send(&mut self, recipient: Recipient, msg: M) {
        match recipient {
            Recipient::Everyone => {
                for connection in self.connections.values() {
                    connection.send(msg.clone()).await;
                }
            }
            Recipient::Peer(peer) => {
                if let Some(connection) = self.connections.get(&peer) {
                    connection.send(msg).await;
                } else {
                    warn!(target: LOG_NET_PEER, "No connection for peer {peer}");
                }
            }
        }
    }

    fn try_send(&self, recipient: Recipient, msg: M) {
        match recipient {
            Recipient::Everyone => {
                for connection in self.connections.values() {
                    connection.try_send(msg.clone());
                }
            }
            Recipient::Peer(peer) => {
                if let Some(connection) = self.connections.get(&peer) {
                    connection.try_send(msg);
                } else {
                    warn!(target: LOG_NET_PEER, "No connection for peer {peer}");
                }
            }
        }
    }

    async fn receive(&mut self) -> Option<(PeerId, M)> {
        select_all(self.connections.iter_mut().map(|(&peer, connection)| {
            Box::pin(async move {
                connection
                    .receive()
                    .await
                    .ok()
                    .map(|message| (peer, message))
            })
        }))
        .await
        .0
    }
}

impl<M> PeerConnectionStateMachine<M>
where
    M: Debug + Clone,
{
    async fn state_transition(mut self) -> Option<Self> {
        match self.state {
            PeerConnectionState::Disconnected(disconnected) => {
                let state = self
                    .common
                    .state_transition_disconnected(disconnected)
                    .await?;

                if let PeerConnectionState::Connected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer_id, PeerConnectionStatus::Connected);
                }

                Some(PeerConnectionStateMachine {
                    common: self.common,
                    state,
                })
            }
            PeerConnectionState::Connected(connected) => {
                let state = self.common.state_transition_connected(connected).await?;

                if let PeerConnectionState::Disconnected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer_id, PeerConnectionStatus::Disconnected);
                };

                Some(PeerConnectionStateMachine {
                    common: self.common,
                    state,
                })
            }
        }
    }
}

impl<M> CommonPeerConnectionState<M>
where
    M: Debug + Clone,
{
    async fn state_transition_connected(
        &mut self,
        mut connection: AnyFramedTransport<PeerMessage<M>>,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            maybe_msg = self.outgoing.recv() => {
                self.send_message_connected(connection, PeerMessage::Message(maybe_msg.ok()?)).await
            },
            maybe_connection = self.incoming_connections.recv() => {
                self.connect(maybe_connection?).await
            },
            Some(message_res) = connection.next() => {
                match message_res {
                    Ok(peer_message) => {
                        if let PeerMessage::Message(msg) = peer_message {
                            PEER_MESSAGES_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();

                            if self.incoming.send(msg).await.is_err(){
                                return None;
                            }
                        }

                        PeerConnectionState::Connected(connection)
                    },
                    Err(e) => self.disconnect(e),
                }
            },
            () = sleep(Duration::from_secs(10)) => {
                self.send_message_connected(connection, PeerMessage::Ping)
                    .await
            },
        })
    }

    async fn connect(
        &mut self,
        mut connection: AnyFramedTransport<PeerMessage<M>>,
    ) -> PeerConnectionState<M> {
        info!(target: LOG_NET_PEER, "Connected to peer {}", self.peer_id);

        match connection.send(PeerMessage::Ping).await {
            Ok(()) => PeerConnectionState::Connected(connection),
            Err(e) => self.disconnect(e),
        }
    }

    fn disconnect(&self, error: anyhow::Error) -> PeerConnectionState<M> {
        info!(target: LOG_NET_PEER, "Disconnected from peer {}: {}", self.peer_id, error);

        PEER_DISCONNECT_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str])
            .inc();

        PeerConnectionState::Disconnected(api_networking_backoff())
    }

    async fn send_message_connected(
        &mut self,
        mut connection: AnyFramedTransport<PeerMessage<M>>,
        peer_message: PeerMessage<M>,
    ) -> PeerConnectionState<M> {
        PEER_MESSAGES_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str, "outgoing"])
            .inc();

        if let Err(e) = connection.send(peer_message).await {
            return self.disconnect(e);
        }

        match connection.flush().await {
            Ok(()) => PeerConnectionState::Connected(connection),
            Err(e) => self.disconnect(e),
        }
    }

    async fn state_transition_disconnected(
        &mut self,
        mut backoff: FibonacciBackoff,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            maybe_connection = self.incoming_connections.recv() => {
                PEER_CONNECT_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();

                self.connect(maybe_connection?).await
            },
            () = sleep(backoff.next().expect("Unlimited retries")), if self.our_id < self.peer_id => {
                // to prevent "reconnection ping-pongs", only the side with lower PeerId is responsible for reconnecting
                match self.try_reconnect().await {
                    Ok(connection) => {
                        PEER_CONNECT_COUNT
                            .with_label_values(&[&self.our_id_str, &self.peer_id_str, "outgoing"])
                            .inc();

                        self.connect(connection).await
                    }
                    Err(..) => PeerConnectionState::Disconnected(backoff),
                }
            },
        })
    }

    async fn try_reconnect(&self) -> Result<AnyFramedTransport<PeerMessage<M>>, anyhow::Error> {
        let addr = self.peer_address.with_port_or_known_default();
        debug!(
            target: LOG_NET_PEER,
            our_id = ?self.our_id,
            peer = ?self.peer_id,
            addr = %&addr,
            "Trying to reconnect"
        );
        let (connected_peer, conn) = self
            .connect
            .connect_framed(addr.clone(), self.peer_id)
            .await?;

        if connected_peer == self.peer_id {
            Ok(conn)
        } else {
            warn!(
                target: LOG_NET_PEER,
                our_id = ?self.our_id,
                peer = ?self.peer_id,
                peer_self_id=?connected_peer,
                %addr,
                "Peer identified itself incorrectly"
            );
            Err(anyhow::anyhow!(
                "Peer identified itself incorrectly: {:?}",
                connected_peer
            ))
        }
    }
}

impl<M> PeerConnection<M>
where
    M: Debug + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        our_id: PeerId,
        peer_id: PeerId,
        peer_address: SafeUrl,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_group: &TaskGroup,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1024);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(1024);

        task_group.spawn_cancellable(
            format!("io-thread-peer-{peer_id}"),
            Self::run_io_thread(
                incoming_sender,
                outgoing_receiver,
                our_id,
                peer_id,
                peer_address,
                connect,
                incoming_connections,
                status_channels,
            ),
        );

        PeerConnection {
            outgoing: outgoing_sender,
            incoming: incoming_receiver,
        }
    }

    async fn send(&self, msg: M) {
        self.outgoing.send(msg).await.ok();
    }

    fn try_send(&self, msg: M) {
        self.outgoing.try_send(msg).ok();
    }

    async fn receive(&mut self) -> Cancellable<M> {
        self.incoming.recv().await.map_err(|_| Cancelled)
    }

    #[allow(clippy::too_many_arguments)] // TODO: consider refactoring
    #[instrument(
        name = "peer_io_thread",
        target = LOG_NET_PEER,
        skip_all,
        // `id` so it doesn't conflict with argument names otherwise will not be shown
        fields(id = %peer_id)
    )]
    async fn run_io_thread(
        incoming: async_channel::Sender<M>,
        outgoing: async_channel::Receiver<M>,
        our_id: PeerId,
        peer_id: PeerId,
        peer_address: SafeUrl,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    ) {
        info!(target: LOG_NET_PEER, "Starting peer connection state machine {}", peer_id);

        let mut state_machine = PeerConnectionStateMachine {
            common: CommonPeerConnectionState {
                incoming,
                outgoing,
                our_id_str: our_id.to_string(),
                our_id,
                peer_id_str: peer_id.to_string(),
                peer_id,
                peer_address,
                connect,
                incoming_connections,
                status_channels,
            },
            state: PeerConnectionState::Disconnected(api_networking_backoff()),
        };

        while let Some(sm) = state_machine.state_transition().await {
            state_machine = sm;
        }

        info!(target: LOG_NET_PEER, "Shutting down peer connection state machine {}", peer_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use anyhow::{ensure, Context as _};
    use fedimint_api_client::api::PeerConnectionStatus;
    use fedimint_core::task::TaskGroup;
    use fedimint_core::util::{backoff_util, retry};
    use fedimint_core::PeerId;
    use tokio::sync::RwLock;

    use crate::net::connect::mock::{MockNetwork, StreamReliability};
    use crate::net::connect::Connector;
    use crate::net::peers::{NetworkConfig, ReconnectPeerConnections};

    #[test_log::test(tokio::test)]
    async fn test_connect() {
        let task_group = TaskGroup::new();

        {
            async fn wait_for_connection(
                name: &str,
                status_channels: &Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
            ) {
                retry(
                    format!("wait for client {name}"),
                    backoff_util::aggressive_backoff(),
                    || async {
                        let status = status_channels.read().await;
                        ensure!(status.len() == 2);
                        Ok(())
                    },
                )
                .await
                .context("peer couldn't connect")
                .unwrap();
            }

            let net = MockNetwork::new();

            let peers = [
                "http://127.0.0.1:1000",
                "http://127.0.0.1:2000",
                "http://127.0.0.1:3000",
            ]
            .iter()
            .enumerate()
            .map(|(idx, &peer)| {
                let cfg = peer.parse().unwrap();
                (PeerId::from(idx as u16 + 1), cfg)
            })
            .collect::<HashMap<_, _>>();

            let peers_ref = &peers;
            let net_ref = &net;
            let build_peers = |bind: &'static str, id: u16, task_group: TaskGroup| async move {
                let cfg = NetworkConfig {
                    identity: PeerId::from(id),
                    p2p_bind_addr: bind.parse().unwrap(),
                    peers: peers_ref.clone(),
                };
                let connect = net_ref
                    .connector(cfg.identity, StreamReliability::MILDLY_UNRELIABLE)
                    .into_dyn();
                let status_channels = Arc::new(RwLock::new(BTreeMap::new()));
                let connection = ReconnectPeerConnections::<u64>::new(
                    cfg,
                    connect,
                    &task_group,
                    Arc::clone(&status_channels),
                )
                .await;

                (connection, status_channels)
            };

            let (_peers_a, peer_status_client_a) =
                build_peers("127.0.0.1:1000", 1, task_group.clone()).await;
            let (_peers_b, peer_status_client_b) =
                build_peers("127.0.0.1:2000", 2, task_group.clone()).await;

            wait_for_connection("a", &peer_status_client_a).await;
            wait_for_connection("b", &peer_status_client_b).await;

            let (_peers_c, peer_status_client_c) =
                build_peers("127.0.0.1:3000", 3, task_group.clone()).await;

            wait_for_connection("c", &peer_status_client_c).await;
        }

        task_group.shutdown_join_all(None).await.unwrap();
    }
}
