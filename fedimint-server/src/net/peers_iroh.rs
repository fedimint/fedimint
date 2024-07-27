//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::peers::IPeerConnections`] and
//! its main implementation is [`ReconnectPeerConnections`], see these for
//! details.

use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fedimint_api_client::api::PeerConnectionStatus;
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use iroh_net::defaults::DEFAULT_STUN_PORT;
use iroh_net::endpoint::{Connecting, Connection, Endpoint};
use iroh_net::key::SecretKey;
use iroh_net::relay::{RelayMap, RelayMode, RelayNode, RelayUrl};
use iroh_net::{NodeAddr, NodeId};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;
use tracing::{info, instrument, trace, warn};

use crate::consensus::aleph_bft::Recipient;
use crate::metrics::{PEER_CONNECT_COUNT, PEER_DISCONNECT_COUNT, PEER_MESSAGES_COUNT};

const FEDIMINT_P2P_ALPN: &[u8] = "FEDIMINT_P2P".as_bytes();

/// Hostname of the default NA relay.
const NA_RELAY_HOSTNAME: &str = "https://use1-1.relay.iroh.network.";
/// Hostname of the default EU relay.
const EU_RELAY_HOSTNAME: &str = "https://euw1-1.relay.iroh.network.";
/// Hostname of the default Asia-Pacific relay.
const AP_RELAY_HOSTNAME: &str = "https://aps1-1.relay.iroh.network.";

const RELAY_URLS: [&str; 3] = [NA_RELAY_HOSTNAME, EU_RELAY_HOSTNAME, AP_RELAY_HOSTNAME];

#[derive(Clone)]
struct PeerConnection {
    outgoing: async_channel::Sender<Vec<u8>>,
    incoming: async_channel::Receiver<Vec<u8>>,
}

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
    fn new(secret_key: SecretKey, peers: BTreeMap<PeerId, NodeId>) -> Self {
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

/// Calculates delays for reconnecting to peers
#[derive(Debug, Clone, Copy)]
pub struct DelayCalculator {
    min_retry_duration_ms: u64,
    max_retry_duration_ms: u64,
}

impl DelayCalculator {
    /// Production defaults will try to reconnect fast but then fallback to
    /// larger values if the error persists
    const PROD_MAX_RETRY_DURATION_MS: u64 = 10_000;
    const PROD_MIN_RETRY_DURATION_MS: u64 = 10;

    /// For tests we don't want low min/floor delays because they can generate
    /// too much logging/warnings and make debugging harder
    const TEST_MAX_RETRY_DURATION_MS: u64 = 10_000;
    const TEST_MIN_RETRY_DURATION_MS: u64 = 2_000;

    pub const PROD_DEFAULT: Self = Self {
        min_retry_duration_ms: Self::PROD_MIN_RETRY_DURATION_MS,
        max_retry_duration_ms: Self::PROD_MAX_RETRY_DURATION_MS,
    };

    pub const TEST_DEFAULT: Self = Self {
        min_retry_duration_ms: Self::TEST_MIN_RETRY_DURATION_MS,
        max_retry_duration_ms: Self::TEST_MAX_RETRY_DURATION_MS,
    };

    const BASE_MS: u64 = 4;

    // exponential back-off with jitter
    pub fn reconnection_delay(&self, disconnect_count: u64) -> Duration {
        let exponent = disconnect_count.try_into().unwrap_or(u32::MAX);
        // initial value
        let delay_ms = Self::BASE_MS.saturating_pow(exponent);
        // sets a floor using the min_retry_duration_ms
        let delay_ms = max(delay_ms, self.min_retry_duration_ms);
        // sets a ceiling using the max_retry_duration_ms
        let delay_ms = min(delay_ms, self.max_retry_duration_ms);
        // add a small jitter of up to 10% to smooth out the load on the target peer if
        // many peers are reconnecting at the same time
        let jitter_max = delay_ms / 10;
        let jitter_ms = thread_rng().gen_range(0..max(jitter_max, 1));
        let delay_secs = delay_ms.saturating_add(jitter_ms) as f64 / 1000.0;
        Duration::from_secs_f64(delay_secs)
    }
}

/// Connection manager that automatically reconnects to peers
#[derive(Clone)]
pub struct IrohPeerConnections {
    connections: HashMap<PeerId, PeerConnection>,
}

impl IrohPeerConnections {
    /// Creates a new `ReconnectPeerConnections` connection manager from a
    /// network config and a [`Connector`](crate::net::connect::Connector).
    /// See [`ReconnectPeerConnections`] for requirements on the
    /// `Connector`.
    #[instrument(skip_all)]
    pub(crate) async fn new(
        cfg: NetworkConfig,
        delay_calculator: DelayCalculator,
        task_group: &TaskGroup,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    ) -> anyhow::Result<Self> {
        let relay_nodes = RELAY_URLS.iter().map(|relay_url| RelayNode {
            url: RelayUrl::from_str(&relay_url).expect("Relay url is invalid"),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        });

        let endpoint = Endpoint::builder()
            .secret_key(cfg.secret_key.clone())
            .alpns(vec![FEDIMINT_P2P_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(
                RelayMap::from_nodes(relay_nodes).expect("Failed to create relay map"),
            ))
            .bind(0)
            .await?;

        let mut connection_senders = HashMap::new();
        let mut connections = HashMap::new();

        for (peer_id, peer_node_id) in cfg.peers.iter() {
            assert_ne!(peer_id, &cfg.identity);

            let (connection_sender, connection_receiver) = mpsc::channel::<Connection>(32);

            let connection = PeerConnection::new(
                endpoint.clone(),
                cfg.identity,
                *peer_id,
                *peer_node_id,
                delay_calculator,
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
        mut senders: HashMap<PeerId, Sender<Connection>>,
        task_handle: TaskHandle,
    ) {
        let mut shutdown_rx = task_handle.make_shutdown_rx();

        while !task_handle.is_shutting_down() {
            tokio::select! {
                connecting =  endpoint.accept() => {
                    match connecting {
                        Some(connecting) => {
                            if let Err(e) = Self::handle_connection(&cfg, connecting, &mut senders).await {
                                warn!("Failed to handle incoming connection {e}");
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
        connecting: Connecting,
        senders: &mut HashMap<PeerId, Sender<Connection>>,
    ) -> anyhow::Result<()> {
        let connection = connecting.await?;

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

    pub fn send(&self, message: Vec<u8>, recipient: Recipient) {
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
        // if all peers banned (or just solo-federation), just hang here as there's
        // never going to be any message. This avoids panic on `select_all` with
        // no futures.
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

impl PeerConnection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        endpoint: Endpoint,
        our_id: PeerId,
        peer_id: PeerId,
        peer_node_id: NodeId,
        delay_calculator: DelayCalculator,
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
                    delay_calculator,
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

    #[allow(clippy::too_many_arguments)] // TODO: consider refactoring
    #[instrument(
        name = "peer_io_thread",
        target = "net::peer",
        skip_all,
        // `id` so it doesn't conflict with argument names otherwise will not be shown
        fields(id = %peer_id)
    )]
    async fn run_connection_state_machine(
        endpoint: Endpoint,
        incoming: async_channel::Sender<Vec<u8>>,
        outgoing: async_channel::Receiver<Vec<u8>>,
        our_id: PeerId,
        peer_id: PeerId,
        peer_node_id: NodeId,
        delay_calculator: DelayCalculator,
        incoming_connections: Receiver<Connection>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_handle: &TaskHandle,
    ) {
        info!(target: LOG_NET_PEER, "Starting connection state machine for peer {peer_id}");

        let mut state_machine = ConnectionSM {
            common: ConnectionSMCommon {
                endpoint,
                incoming,
                outgoing,
                our_id_str: our_id.to_string(),
                our_id,
                peer_id_str: peer_id.to_string(),
                peer_id,
                peer_node_id,
                delay_calculator,
                incoming_connections,
                status_channels,
            },
            state: ConnectionSMState::Disconnected(ConnectionSMStateDisconnected {
                reconnect_at: Instant::now(),
                reconnect_counter: 0,
            }),
        };

        while !task_handle.is_shutting_down() {
            if let Some(new_state) = state_machine.state_transition(task_handle).await {
                state_machine = new_state;
            } else {
                break;
            }
        }

        info!(target: LOG_NET_PEER, "Shutting down connection state machine for peer {peer_id}");
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
    our_id_str: String,
    peer_id: PeerId,
    peer_id_str: String,
    peer_node_id: NodeId,
    delay_calculator: DelayCalculator,
    incoming_connections: Receiver<Connection>,
    status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
}

struct ConnectionSMStateDisconnected {
    reconnect_at: Instant,
    reconnect_counter: u64,
}

struct ConnectionSMStateConnected {
    connection: Connection,
}

enum ConnectionSMState {
    Disconnected(ConnectionSMStateDisconnected),
    Connected(ConnectionSMStateConnected),
}

impl ConnectionSM {
    async fn state_transition(mut self, task_handle: &TaskHandle) -> Option<Self> {
        match self.state {
            ConnectionSMState::Disconnected(disconnected) => {
                let state = self
                    .common
                    .state_transition_disconnected(disconnected, task_handle)
                    .await?;

                if let ConnectionSMState::Connected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer_id, PeerConnectionStatus::Connected);
                }

                Some(ConnectionSM {
                    common: self.common,
                    state,
                })
            }
            ConnectionSMState::Connected(connected) => {
                let state = self
                    .common
                    .state_transition_connected(connected, task_handle)
                    .await?;

                if let ConnectionSMState::Disconnected(..) = state {
                    self.common
                        .status_channels
                        .write()
                        .await
                        .insert(self.common.peer_id, PeerConnectionStatus::Disconnected);
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
        connected: ConnectionSMStateConnected,
        task_handle: &TaskHandle,
    ) -> Option<ConnectionSMState> {
        tokio::select! {
            message = self.outgoing.recv() => {
                match self.send_message(connected, message.ok()?).await {
                    Ok(connected) => Some(ConnectionSMState::Connected(connected)),
                    Err(e) => Some(self.disconnected(e)),
                }
            },
            connection = self.incoming_connections.recv() => {
                Some(self.connected(connection?))
            },
            stream = connected.connection.accept_uni() => {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(e) => return Some(self.disconnected(e.into())),
                };

               let message = match stream.read_to_end(100_000).await {
                    Ok(message) => message,
                    Err(e) => return Some(self.disconnected(e.into())),
                };

                PEER_MESSAGES_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();

                if self.incoming.try_send(message).is_err(){
                    warn!(target: LOG_NET_PEER, "Could not relay incoming message");
                }

                Some(ConnectionSMState::Connected(connected))
            },
            () = task_handle.make_shutdown_rx() => {
                None
            },
        }
    }

    fn connected(&mut self, connection: Connection) -> ConnectionSMState {
        info!("Peer {} is connected", self.peer_id);

        ConnectionSMState::Connected(ConnectionSMStateConnected { connection })
    }

    fn disconnected(&self, error: anyhow::Error) -> ConnectionSMState {
        info!(target: LOG_NET_PEER, "Peer {} is disconnected: {}", self.peer_id, error);

        PEER_DISCONNECT_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str])
            .inc();

        ConnectionSMState::Disconnected(ConnectionSMStateDisconnected {
            reconnect_at: Instant::now() + self.delay_calculator.reconnection_delay(0),
            reconnect_counter: 0,
        })
    }

    async fn send_message(
        &self,
        connected: ConnectionSMStateConnected,
        message: Vec<u8>,
    ) -> anyhow::Result<ConnectionSMStateConnected> {
        PEER_MESSAGES_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str, "outgoing"])
            .inc();

        let mut sink = connected.connection.open_uni().await?;

        sink.write_all(&message).await?;

        sink.finish().await?;

        Ok(connected)
    }

    async fn state_transition_disconnected(
        &mut self,
        disconnected: ConnectionSMStateDisconnected,
        task_handle: &TaskHandle,
    ) -> Option<ConnectionSMState> {
        tokio::select! {
            connection = self.incoming_connections.recv() => {
                let connection = connection?;

                PEER_CONNECT_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();

                Some(self.connected(connection))
            },
            // to prevent "reconnection ping-pongs", only the side with lower PeerId is responsible for reconnecting
            () = tokio::time::sleep_until(disconnected.reconnect_at), if self.our_id < self.peer_id => {
                Some(self.reconnect(disconnected).await)
            },
            () = task_handle.make_shutdown_rx() => {
                None
            },
        }
    }

    async fn reconnect(
        &mut self,
        disconnected: ConnectionSMStateDisconnected,
    ) -> ConnectionSMState {
        for relay in RELAY_URLS {
            let addr = NodeAddr::from_parts(
                self.peer_node_id,
                Some(RelayUrl::from_str(relay).expect("Relay url is invalid")),
                Vec::new(),
            );

            if let Ok(connection) = self.endpoint.connect(addr, FEDIMINT_P2P_ALPN).await {
                return self.connected(connection);
            };
        }

        let failed_reconnect_counter = disconnected.reconnect_counter + 1;

        ConnectionSMState::Disconnected(ConnectionSMStateDisconnected {
            reconnect_at: Instant::now()
                + self
                    .delay_calculator
                    .reconnection_delay(failed_reconnect_counter),
            reconnect_counter: failed_reconnect_counter,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use fedimint_core::task::TaskGroup;
    use fedimint_core::PeerId;
    use iroh_net::key::SecretKey;
    use iroh_net::NodeId;
    use tokio::sync::RwLock;

    use super::{DelayCalculator, IrohPeerConnections, NetworkConfig};
    use crate::consensus::aleph_bft::Recipient;

    #[tokio::test]
    async fn test_iroh_peer_connections() -> anyhow::Result<()> {
        let secret_keys = (0_u16..7)
            .map(|i| (PeerId::from(i), SecretKey::generate()))
            .collect::<BTreeMap<PeerId, SecretKey>>();

        let public_keys = secret_keys
            .iter()
            .map(|(peer_id, sk)| (*peer_id, sk.public()))
            .collect::<BTreeMap<PeerId, NodeId>>();

        let task_group = TaskGroup::new();
        let mut connections = BTreeMap::new();

        for (peer_id, sk) in secret_keys {
            let connection = IrohPeerConnections::new(
                NetworkConfig::new(sk, public_keys.clone()),
                DelayCalculator::TEST_DEFAULT,
                &task_group,
                Arc::new(RwLock::new(BTreeMap::new())),
            )
            .await?;

            connections.insert(peer_id, connection);
        }

        for i in 0_u16..7 {
            let message = i.to_be_bytes().to_vec();

            connections
                .get(&PeerId::from(i))
                .expect("Peer {i} should exist")
                .send(message.clone(), Recipient::Everyone);

            for (receiver_id, connection) in &mut connections {
                if receiver_id != &PeerId::from(i) {
                    let (origin_id, msg) = connection.receive().await;

                    println!(
                        "Peer {:?} received {:?} from {:?}",
                        receiver_id, msg, origin_id
                    );

                    assert_eq!(origin_id, PeerId::from(i));
                    assert_eq!(msg, message)
                }
            }
        }

        Ok(())
    }
}
