//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::peers::IPeerConnections`] and
//! its main implementation is [`ReconnectPeerConnections`], see these for
//! details.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::ensure;
use async_trait::async_trait;
use fedimint_api_client::api::P2PConnectionStatus;
use fedimint_core::net::peers::{IPeerConnections, Recipient};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::backoff_util::{api_networking_backoff, FibonacciBackoff};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{info, instrument, warn};

use crate::metrics::{PEER_CONNECT_COUNT, PEER_DISCONNECT_COUNT, PEER_MESSAGES_COUNT};
use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;

#[derive(Clone)]
pub struct ReconnectPeerConnections<M> {
    connections: HashMap<PeerId, PeerConnection<M>>,
}

#[derive(Clone)]
struct PeerConnection<M> {
    outgoing: async_channel::Sender<M>,
    incoming: async_channel::Receiver<M>,
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
    incoming_sender: async_channel::Sender<M>,
    outgoing_receiver: async_channel::Receiver<M>,
    our_id: PeerId,
    our_id_str: String,
    peer_id: PeerId,
    peer_id_str: String,
    peer_address: SafeUrl,
    connect: SharedAnyConnector<PeerMessage<M>>,
    incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    status_channel: Option<watch::Sender<P2PConnectionStatus>>,
}
enum PeerConnectionState<M> {
    Disconnected(FibonacciBackoff),
    Connected(AnyFramedTransport<PeerMessage<M>>),
}

impl<M: Send + 'static> ReconnectPeerConnections<M> {
    /// Creates a new `ReconnectPeerConnections` connection manager from a
    /// network config and a [`Connector`](crate::net::connect::Connector).
    /// See [`ReconnectPeerConnections`] for requirements on the
    /// `Connector`.
    #[instrument(skip_all)]
    pub(crate) async fn new(
        cfg: NetworkConfig,
        connector: AnyConnector<PeerMessage<M>>,
        task_group: &TaskGroup,
        mut status_channels: Option<BTreeMap<PeerId, watch::Sender<P2PConnectionStatus>>>,
    ) -> Self {
        let connector: SharedAnyConnector<PeerMessage<M>> = connector.into();
        let mut connection_senders = HashMap::new();
        let mut connections = HashMap::new();

        for (peer, peer_address) in cfg.peers.iter().filter(|(&peer, _)| peer != cfg.identity) {
            let (connection_sender, connection_receiver) = tokio::sync::mpsc::channel(16);

            let connection = PeerConnection::new(
                cfg.identity,
                *peer,
                peer_address.clone(),
                connector.clone(),
                connection_receiver,
                status_channels.as_mut().map(|channels| {
                    channels
                        .remove(peer)
                        .expect("No p2p status sender for peer {peer}")
                }),
                task_group,
            );

            connection_senders.insert(*peer, connection_sender);
            connections.insert(*peer, connection);
        }

        let mut listener = connector
            .listen(cfg.p2p_bind_addr)
            .await
            .expect("Could not bind to port");

        task_group.spawn_cancellable("handle-incoming-p2p-connections", async move {
            info!(target: LOG_NET_PEER, "Shutting down task listening for p2p connections");

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
                    Err(e) => {
                        warn!(target: LOG_NET_PEER, "Error while opening incoming connection: {}", e);
                    }
                }
            }

            info!(target: LOG_NET_PEER, "Shutting down task listening for p2p connections");
        });

        ReconnectPeerConnections { connections }
    }
}

#[async_trait]
impl<M: Clone + Send + 'static> IPeerConnections<M> for ReconnectPeerConnections<M> {
    async fn send(&self, recipient: Recipient, msg: M) {
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

    async fn receive(&self) -> Option<(PeerId, M)> {
        select_all(self.connections.iter().map(|(&peer, connection)| {
            Box::pin(async move { connection.receive().await.map(|message| (peer, message)) })
        }))
        .await
        .0
    }
}

impl<M> PeerConnectionStateMachine<M> {
    async fn state_transition(mut self) -> Option<Self> {
        match self.state {
            PeerConnectionState::Disconnected(disconnected) => {
                let state = self
                    .common
                    .state_transition_disconnected(disconnected)
                    .await?;

                if let Some(channel) = &self.common.status_channel {
                    channel.send(P2PConnectionStatus::Connected).ok();
                }

                Some(PeerConnectionStateMachine {
                    common: self.common,
                    state,
                })
            }
            PeerConnectionState::Connected(connected) => {
                let state = self.common.state_transition_connected(connected).await?;

                if let Some(channel) = &self.common.status_channel {
                    channel.send(P2PConnectionStatus::Disconnected).ok();
                }

                Some(PeerConnectionStateMachine {
                    common: self.common,
                    state,
                })
            }
        }
    }
}

impl<M> CommonPeerConnectionState<M> {
    async fn state_transition_connected(
        &mut self,
        mut connection: AnyFramedTransport<PeerMessage<M>>,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            maybe_msg = self.outgoing_receiver.recv() => {
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

                            if self.incoming_sender.send(msg).await.is_err(){
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
                    Err(..) => PeerConnectionState::Disconnected(backoff)
                }
            },
        })
    }

    async fn try_reconnect(&self) -> Result<AnyFramedTransport<PeerMessage<M>>, anyhow::Error> {
        info!(target: LOG_NET_PEER, "Attempting to reconnect to peer {}", self.peer_id);

        let (connected_peer, conn) = self
            .connect
            .connect_framed(self.peer_address.with_port_or_known_default(), self.peer_id)
            .await?;

        ensure!(
            connected_peer == self.peer_id,
            "Peer incorrectly identified as: {connected_peer}",
        );

        Ok(conn)
    }
}

impl<M: Send + 'static> PeerConnection<M> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        our_id: PeerId,
        peer_id: PeerId,
        peer_address: SafeUrl,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_channel: Option<watch::Sender<P2PConnectionStatus>>,
        task_group: &TaskGroup,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1024);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(1024);

        task_group.spawn_cancellable(format!("io-thread-peer-{peer_id}"), async move {
            info!(target: LOG_NET_PEER, "Starting peer connection state machine {}", peer_id);

            let mut state_machine = PeerConnectionStateMachine {
                common: CommonPeerConnectionState {
                    incoming_sender,
                    outgoing_receiver,
                    our_id_str: our_id.to_string(),
                    our_id,
                    peer_id_str: peer_id.to_string(),
                    peer_id,
                    peer_address,
                    connect,
                    incoming_connections,
                    status_channel,
                },
                state: PeerConnectionState::Disconnected(api_networking_backoff()),
            };

            while let Some(sm) = state_machine.state_transition().await {
                state_machine = sm;
            }

            info!(target: LOG_NET_PEER, "Shutting down peer connection state machine {}", peer_id);
        });

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

    async fn receive(&self) -> Option<M> {
        self.incoming.recv().await.ok()
    }
}
