use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_api_client::api::PeerConnectionStatus;
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::peers::{IP2PConnections, Recipient};
use fedimint_core::task::{Cancellable, TaskGroup, TaskHandle};
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use iroh_net::discovery::local_swarm_discovery::LocalSwarmDiscovery;
use iroh_net::discovery::pkarr::{PkarrPublisher, PkarrResolver};
use iroh_net::discovery::ConcurrentDiscovery;
use iroh_net::endpoint::{Connection, Endpoint, Incoming};
use iroh_net::key::SecretKey;
use iroh_net::NodeId;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;
use tracing::{info, trace, warn};

const FEDIMINT_ALPN: &[u8] = "FEDIMINT_ALPN".as_bytes();

/// Specifies the network configuration for federation-internal communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Our federation member's identity
    pub identity: PeerId,
    /// The secret key for our own Iroh Endpoint
    pub secret_key: SecretKey,
    /// Map of all peers' connection information we want to be connected to
    pub peers: BTreeMap<PeerId, NodeId>,
}

impl NetworkConfig {
    pub fn new(secret_key: SecretKey, peers: BTreeMap<PeerId, NodeId>) -> Self {
        let identity = peers
            .iter()
            .filter(|entry| entry.1 == &secret_key.public())
            .next()
            .expect("Our public key is not part of the keyset")
            .0
            .clone();

        Self {
            identity,
            secret_key,
            peers: peers
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
        }
    }
}

/// Connection manager that automatically reconnects to peers
#[derive(Clone)]
pub struct IrohPeerConnections {
    connections: BTreeMap<PeerId, PeerConnection>,
}

impl IrohPeerConnections {
    pub async fn new(
        cfg: NetworkConfig,
        task_group: &TaskGroup,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    ) -> anyhow::Result<Self> {
        let endpoint = Endpoint::builder()
            .discovery(match is_running_in_test_env() {
                true => Box::new(LocalSwarmDiscovery::new(cfg.secret_key.public())?),
                false => Box::new(ConcurrentDiscovery::from_services(vec![
                    Box::new(PkarrPublisher::n0_dns(cfg.secret_key.clone())),
                    Box::new(PkarrResolver::n0_dns()),
                ])),
            })
            .secret_key(cfg.secret_key.clone())
            .alpns(vec![FEDIMINT_ALPN.to_vec()])
            .bind()
            .await?;

        let mut connection_senders = BTreeMap::new();
        let mut connections = BTreeMap::new();

        for (peer_id, peer_node_id) in cfg.peers.iter() {
            assert_ne!(peer_id, &cfg.identity);

            let (connection_sender, connection_receiver) = mpsc::channel::<Connection>(32);

            let connection = PeerConnection::new(
                endpoint.clone(),
                cfg.identity,
                *peer_id,
                *peer_node_id,
                connection_receiver,
                status_channels.clone(),
                task_group,
            );

            connection_senders.insert(*peer_id, connection_sender);
            connections.insert(*peer_id, connection);

            status_channels
                .write()
                .await
                .insert(*peer_id, PeerConnectionStatus::Disconnected);
        }

        task_group.spawn("listen task", |handle| {
            Self::run_listen_task(cfg, endpoint, connection_senders, handle)
        });

        Ok(IrohPeerConnections { connections })
    }

    async fn run_listen_task(
        cfg: NetworkConfig,
        endpoint: Endpoint,
        mut senders: BTreeMap<PeerId, Sender<Connection>>,
        task_handle: TaskHandle,
    ) {
        let mut shutdown_rx = task_handle.make_shutdown_rx();

        while !task_handle.is_shutting_down() {
            tokio::select! {
                incoming =  endpoint.accept() => {
                    match incoming {
                        Some(incoming) => {
                            if let Err(e) = Self::handle_connection(&cfg, incoming, &mut senders).await {
                                warn!(target:LOG_NET_PEER, "Failed to handle incoming connection {e}");
                            }
                        }
                        None => return,
                    }

                               },
                () = &mut shutdown_rx => { return },
            };
        }
    }

    async fn handle_connection(
        cfg: &NetworkConfig,
        incoming: Incoming,
        senders: &mut BTreeMap<PeerId, Sender<Connection>>,
    ) -> anyhow::Result<()> {
        let connection = incoming.accept()?.await?;

        let node_id = iroh_net::endpoint::get_remote_node_id(&connection)?;

        let peer_id = cfg
            .peers
            .iter()
            .find(|entry| entry.1 == &node_id)
            .context("NodeId is unknown")?
            .0;

        senders
            .get_mut(peer_id)
            .expect("Connection sender is missing")
            .send(connection)
            .await
            .context("Could not send incoming connection to peer io task")
    }

    fn send(&self, message: Vec<u8>, recipient: Recipient) {
        match recipient {
            Recipient::Everyone => {
                for connection in self.connections.values() {
                    connection.send(message.clone());
                }
            }
            Recipient::Peer(peer) => {
                if let Some(connection) = self.connections.get(&peer) {
                    connection.send(message);
                } else {
                    trace!(target: LOG_NET_PEER,peer = ?peer, "Can not send message to unknown peer");
                }
            }
        }
    }

    async fn receive(&mut self) -> (PeerId, Vec<u8>) {
        if self.connections.is_empty() {
            std::future::pending::<()>().await;
        }

        let futures = self.connections.iter_mut().map(|(&peer, connection)| {
            Box::pin(async move {
                if let Some(message) = connection.receive().await {
                    return (peer, message);
                }

                std::future::pending::<(PeerId, Vec<u8>)>().await
            })
        });

        select_all(futures).await.0
    }
}

#[async_trait]
impl IP2PConnections for IrohPeerConnections {
    fn send(&self, recipient: Recipient, message: Vec<u8>) {
        self.send(message, recipient)
    }

    async fn receive(&mut self) -> Cancellable<(PeerId, Vec<u8>)> {
        Ok(self.receive().await)
    }

    fn clone_box(&self) -> Box<dyn IP2PConnections + Send + 'static> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
struct PeerConnection {
    outgoing: async_channel::Sender<Vec<u8>>,
    incoming: async_channel::Receiver<Vec<u8>>,
}

impl PeerConnection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        endpoint: Endpoint,
        our_id: PeerId,
        peer_id: PeerId,
        peer_node_id: NodeId,
        incoming_connections: Receiver<Connection>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_group: &TaskGroup,
    ) -> PeerConnection {
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1024);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(1024);

        task_group.spawn(
            format!("io-thread-peer-{peer_id}"),
            move |handle| async move {
                Self::run_connection_state_machine(
                    endpoint,
                    incoming_sender,
                    outgoing_receiver,
                    our_id,
                    peer_id,
                    peer_node_id,
                    incoming_connections,
                    status_channels,
                    &handle,
                )
                .await;
            },
        );

        PeerConnection {
            outgoing: outgoing_sender,
            incoming: incoming_receiver,
        }
    }

    fn send(&self, message: Vec<u8>) {
        if self.outgoing.try_send(message).is_err() {
            warn!(target: LOG_NET_PEER, "Could not send outgoing message since the channel is full");
        }
    }

    async fn receive(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await.ok()
    }

    async fn run_connection_state_machine(
        endpoint: Endpoint,
        incoming: async_channel::Sender<Vec<u8>>,
        outgoing: async_channel::Receiver<Vec<u8>>,
        our_id: PeerId,
        peer: PeerId,
        node_id: NodeId,
        incoming_connections: Receiver<Connection>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_handle: &TaskHandle,
    ) {
        info!(target: LOG_NET_PEER, "Starting connection state machine for peer {peer}");

        let mut state_machine = ConnectionSM {
            common: ConnectionSMCommon {
                endpoint,
                incoming,
                outgoing,
                our_id,
                peer,
                node_id,
                incoming_connections,
                status_channels,
            },
            state: ConnectionSMState::Disconnected(Instant::now()),
        };

        while !task_handle.is_shutting_down() {
            tokio::select! {
                new_state =  state_machine.state_transition() => {
                    if let Some(new_state) = new_state {
                        state_machine = new_state;
                    } else {
                        break;
                    }
                },
                () = task_handle.make_shutdown_rx() => {
                    break;
                },
            }
        }

        info!(target: LOG_NET_PEER, "Shutting down connection state machine for peer {peer}");
    }
}

struct ConnectionSM {
    common: ConnectionSMCommon,
    state: ConnectionSMState,
}

struct ConnectionSMCommon {
    endpoint: Endpoint,
    incoming: async_channel::Sender<Vec<u8>>,
    outgoing: async_channel::Receiver<Vec<u8>>,
    our_id: PeerId,
    peer: PeerId,
    node_id: NodeId,
    incoming_connections: Receiver<Connection>,
    status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
}

enum ConnectionSMState {
    Disconnected(Instant),
    Connected(Connection),
}

impl ConnectionSM {
    async fn state_transition(mut self) -> Option<Self> {
        match self.state {
            ConnectionSMState::Disconnected(reconnect_at) => {
                let state = self
                    .common
                    .state_transition_disconnected(reconnect_at)
                    .await?;

                if let ConnectionSMState::Connected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer, PeerConnectionStatus::Connected);
                }

                Some(ConnectionSM {
                    common: self.common,
                    state,
                })
            }
            ConnectionSMState::Connected(connection) => {
                let state = self.common.state_transition_connected(connection).await?;

                if let ConnectionSMState::Disconnected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer, PeerConnectionStatus::Disconnected);
                };

                Some(ConnectionSM {
                    common: self.common,
                    state,
                })
            }
        }
    }
}

impl ConnectionSMCommon {
    async fn state_transition_connected(
        &mut self,
        connection: Connection,
    ) -> Option<ConnectionSMState> {
        tokio::select! {
            message = self.outgoing.recv() => {
                match self.send_message(&connection, message.ok()?).await {
                    Ok(()) => Some(ConnectionSMState::Connected(connection)),
                    Err(e) => Some(self.disconnected(e)),
                }
            },
            connection = self.incoming_connections.recv() => {
                Some(self.connected(connection?))
            },
            stream = connection.accept_uni() => {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(e) => return Some(self.disconnected(e.into())),
                };

               let message = match stream.read_to_end(100_000).await {
                    Ok(message) => message,
                    Err(e) => return Some(self.disconnected(e.into())),
                };


                if self.incoming.try_send(message).is_err(){
                    warn!(target: LOG_NET_PEER, "Could not relay incoming message");
                }

                Some(ConnectionSMState::Connected(connection))
            },
        }
    }

    fn connected(&mut self, connection: Connection) -> ConnectionSMState {
        info!(target:LOG_NET_PEER, "Peer {} is connected", self.peer);

        ConnectionSMState::Connected(connection)
    }

    fn disconnected(&self, error: anyhow::Error) -> ConnectionSMState {
        info!(target: LOG_NET_PEER, "Peer {} is disconnected: {}", self.peer, error);

        ConnectionSMState::Disconnected(Instant::now())
    }

    async fn send_message(&self, connection: &Connection, message: Vec<u8>) -> anyhow::Result<()> {
        let mut sink = connection.open_uni().await?;

        sink.write_all(&message).await?;

        sink.finish()?;

        Ok(())
    }

    async fn state_transition_disconnected(
        &mut self,
        reconnect_at: Instant,
    ) -> Option<ConnectionSMState> {
        tokio::select! {
            connection = self.incoming_connections.recv() => {
                Some(self.connected(connection?))
            },
            // to prevent "reconnection ping-pongs", only the side with lower PeerId is responsible for reconnecting
            () = tokio::time::sleep_until(reconnect_at), if self.our_id < self.peer => {
                Some(self.reconnect().await)
            },
        }
    }

    async fn reconnect(&mut self) -> ConnectionSMState {
        match self
            .endpoint
            .connect_by_node_id(self.node_id, FEDIMINT_ALPN)
            .await
        {
            Ok(connection) => return self.connected(connection),
            Err(e) => warn!(
                target: LOG_NET_PEER,
                "Failed to connect to peer {} : {}",
                self.peer, e
            ),
        }

        ConnectionSMState::Disconnected(Instant::now() + Duration::from_secs(10))
    }
}
