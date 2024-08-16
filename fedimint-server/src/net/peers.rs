//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::peers::IPeerConnections`] and
//! its main implementation is [`ReconnectPeerConnections`], see these for
//! details.

use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_api_client::api::PeerConnectionStatus;
use fedimint_core::net::peers::IPeerConnections;
use fedimint_core::task::{sleep_until, Cancellable, Cancelled, TaskGroup, TaskHandle};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, info, instrument, trace, warn};

use crate::consensus::aleph_bft::Recipient;
use crate::metrics::{
    PEER_BANS_COUNT, PEER_CONNECT_COUNT, PEER_DISCONNECT_COUNT, PEER_MESSAGES_COUNT,
};
use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;

/// Every how many seconds to send an empty message to our peer if we sent no
/// messages during that time. This helps with reducing the amount of messages
/// that need to be re-sent in case of very one-sided communication.
const PING_INTERVAL: Duration = Duration::from_secs(10);

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
    self_id: PeerId,
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

struct CommonPeerConnectionState<M> {
    incoming: async_channel::Sender<M>,
    outgoing: async_channel::Receiver<M>,
    our_id: PeerId,
    our_id_str: String,
    peer_id: PeerId,
    peer_id_str: String,
    peer_address: SafeUrl,
    delay_calculator: DelayCalculator,
    connect: SharedAnyConnector<PeerMessage<M>>,
    incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
}

struct DisconnectedPeerConnectionState {
    reconnect_at: Instant,
    failed_reconnect_counter: u64,
}

struct ConnectedPeerConnectionState<M> {
    connection: AnyFramedTransport<PeerMessage<M>>,
    next_ping: Instant,
}

enum PeerConnectionState<M> {
    Disconnected(DisconnectedPeerConnectionState),
    Connected(ConnectedPeerConnectionState<M>),
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
        delay_calculator: DelayCalculator,
        connect: PeerConnector<T>,
        task_group: &TaskGroup,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    ) -> Self {
        let shared_connector: SharedAnyConnector<PeerMessage<T>> = connect.into();
        let mut connection_senders = HashMap::new();
        let mut connections = HashMap::new();
        let self_id = cfg.identity;

        for (peer, peer_address) in cfg.peers.iter().filter(|(&peer, _)| peer != cfg.identity) {
            let (connection_sender, connection_receiver) =
                tokio::sync::mpsc::channel::<AnyFramedTransport<PeerMessage<T>>>(4);

            let connection = PeerConnection::new(
                cfg.identity,
                *peer,
                peer_address.clone(),
                delay_calculator,
                shared_connector.clone(),
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

        task_group.spawn("listen task", move |handle| {
            Self::run_listen_task(cfg, shared_connector, connection_senders, handle)
        });

        ReconnectPeerConnections {
            connections,
            self_id,
        }
    }

    async fn run_listen_task(
        cfg: NetworkConfig,
        connect: SharedAnyConnector<PeerMessage<T>>,
        mut connection_senders: HashMap<PeerId, Sender<AnyFramedTransport<PeerMessage<T>>>>,
        task_handle: TaskHandle,
    ) {
        let mut listener = connect
            .listen(cfg.p2p_bind_addr)
            .await
            .with_context(|| anyhow::anyhow!("Failed to listen on {}", cfg.p2p_bind_addr))
            .expect("Could not bind port");

        let mut shutdown_rx = task_handle.make_shutdown_rx();

        while !task_handle.is_shutting_down() {
            let new_connection = tokio::select! {
                maybe_msg = listener.next() => { maybe_msg },
                () = &mut shutdown_rx => { break; },
            };

            let (peer, connection) = match new_connection.expect("Listener closed") {
                Ok(connection) => connection,
                Err(e) => {
                    warn!(target: LOG_NET_PEER, mint = ?cfg.identity, err = %e, "Error while opening incoming connection");
                    continue;
                }
            };

            let err = connection_senders
                .get_mut(&peer)
                .expect("Authenticating connectors should not return unknown peers")
                .send(connection)
                .await
                .is_err();

            if err {
                warn!(
                    target: LOG_NET_PEER,
                    ?peer,
                    "Could not send incoming connection to peer io task (possibly banned)"
                );
            }
        }
    }
    pub fn send_sync(&self, msg: &T, recipient: Recipient) {
        match recipient {
            Recipient::Everyone => {
                for connection in self.connections.values() {
                    connection.send(msg.clone());
                }
            }
            Recipient::Peer(peer) => {
                if let Some(connection) = self.connections.get(&peer) {
                    connection.send(msg.clone());
                } else {
                    trace!(target: LOG_NET_PEER,peer = ?peer, "Not sending message to unknown peer (maybe banned)");
                }
            }
        }
    }
}

#[async_trait]
impl<T> IPeerConnections<T> for ReconnectPeerConnections<T>
where
    T: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Unpin + Send + Sync + 'static,
{
    #[must_use]
    async fn send(&mut self, peers: &[PeerId], msg: T) -> Cancellable<()> {
        for peer_id in peers {
            trace!(target: LOG_NET_PEER, ?peer_id, "Sending message to");
            if let Some(peer) = self.connections.get_mut(peer_id) {
                peer.send(msg.clone());
            } else {
                trace!(target: LOG_NET_PEER,peer = ?peer_id, "Not sending message to unknown peer (maybe banned)");
            }
        }
        Ok(())
    }

    async fn receive(&mut self) -> Cancellable<(PeerId, T)> {
        // if all peers banned (or just solo-federation), just hang here as there's
        // never going to be any message. This avoids panic on `select_all` with
        // no futures.
        if self.connections.is_empty() {
            std::future::pending::<()>().await;
        }

        let futures_non_banned = self.connections.iter_mut().map(|(&peer, connection)| {
            let receive_future = async move {
                let msg = connection.receive().await;
                (peer, msg)
            };
            Box::pin(receive_future)
        });

        let first_response = select_all(futures_non_banned).await;

        first_response.0 .1.map(|v| (first_response.0 .0, v))
    }

    async fn ban_peer(&mut self, peer: PeerId) {
        self.connections.remove(&peer);
        PEER_BANS_COUNT
            .with_label_values(&[&self.self_id.to_string(), &peer.to_string()])
            .inc();
        warn!(target: LOG_NET_PEER, "Peer {} banned.", peer);
    }
}

impl<M> PeerConnectionStateMachine<M>
where
    M: Debug + Clone,
{
    async fn run(mut self, task_handle: &TaskHandle) {
        let peer = self.common.peer_id;

        // Note: `state_transition` internally uses channel operations (`send` and
        // `recv`) which will disconnect when other tasks are shutting down
        // returning here, so we probably don't need any `timeout` here.
        while !task_handle.is_shutting_down() {
            if let Some(new_self) = self.state_transition(task_handle).await {
                self = new_self;
            } else {
                break;
            }
        }
        info!(
            target: LOG_NET_PEER,
            ?peer,
            "Shutting down peer connection state machine"
        );
    }

    async fn state_transition(self, task_handle: &TaskHandle) -> Option<Self> {
        let PeerConnectionStateMachine { mut common, state } = self;

        match state {
            PeerConnectionState::Disconnected(disconnected) => {
                let new_state = common
                    .state_transition_disconnected(disconnected, task_handle)
                    .await;

                if let Some(PeerConnectionState::Connected(..)) = new_state {
                    common
                        .status_channels
                        .write()
                        .await
                        .insert(common.peer_id, PeerConnectionStatus::Connected);
                }

                new_state
            }
            PeerConnectionState::Connected(connected) => {
                let new_state = common
                    .state_transition_connected(connected, task_handle)
                    .await;

                if let Some(PeerConnectionState::Disconnected(..)) = new_state {
                    common
                        .status_channels
                        .write()
                        .await
                        .insert(common.peer_id, PeerConnectionStatus::Disconnected);
                };

                new_state
            }
        }
        .map(|new_state| PeerConnectionStateMachine {
            common,
            state: new_state,
        })
    }
}

impl<M> CommonPeerConnectionState<M>
where
    M: Debug + Clone,
{
    async fn state_transition_connected(
        &mut self,
        mut connected: ConnectedPeerConnectionState<M>,
        task_handle: &TaskHandle,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            maybe_msg = self.outgoing.recv() => {
                if let Ok(msg) = maybe_msg {
                    self.send_message_connected(connected, PeerMessage::Message(msg)).await
                } else {
                    debug!(target: LOG_NET_PEER, "Exiting peer connection IO task - parent disconnected");
                    return None;
                }
            },
            new_connection_res = self.incoming_connections.recv() => {
                if let Some(new_connection) = new_connection_res {
                    debug!(target: LOG_NET_PEER, "Replacing existing connection");
                    self.connect(new_connection, 0).await
                } else {
                    debug!(
                    target: LOG_NET_PEER,
                        "Exiting peer connection IO task - parent disconnected");
                    return None;
                }
            },
            Some(message_res) = connected.connection.next() => {
                match message_res {
                    Ok(peer_message) => {
                        if let PeerMessage::Message(msg) = peer_message {
                            PEER_MESSAGES_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();
                            if self.incoming.try_send(msg).is_err(){
                                debug!(target: LOG_NET_PEER, "Could not relay incoming message since the channel is full");
                            }
                        }

                        PeerConnectionState::Connected(connected)
                    },
                    Err(e) => self.disconnect_err(&e, 0),
                }
            },
            () = sleep_until(connected.next_ping) => {
                trace!(target: LOG_NET_PEER, our_id = ?self.our_id, peer = ?self.peer_id, "Sending ping");
                self.send_message_connected(connected, PeerMessage::Ping)
                    .await
            },
            () = task_handle.make_shutdown_rx() => {
                return None;
            },
        })
    }

    async fn connect(
        &mut self,
        mut new_connection: AnyFramedTransport<PeerMessage<M>>,
        disconnect_count: u64,
    ) -> PeerConnectionState<M> {
        debug!(target: LOG_NET_PEER,
            our_id = ?self.our_id,
            peer = ?self.peer_id, %disconnect_count,
            "Initializing new connection");
        match new_connection.send(PeerMessage::Ping).await {
            Ok(()) => PeerConnectionState::Connected(ConnectedPeerConnectionState {
                connection: new_connection,
                next_ping: Instant::now(),
            }),
            Err(e) => self.disconnect_err(&e, disconnect_count),
        }
    }

    fn disconnect(&self, mut disconnect_count: u64) -> PeerConnectionState<M> {
        PEER_DISCONNECT_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str])
            .inc();
        disconnect_count += 1;

        let reconnect_at = {
            let delay = self.delay_calculator.reconnection_delay(disconnect_count);
            let delay_secs = delay.as_secs_f64();
            debug!(
                target: LOG_NET_PEER,
                %disconnect_count,
                our_id = ?self.our_id,
                peer = ?self.peer_id,
                delay_secs,
                "Scheduling reopening of connection"
            );
            Instant::now() + delay
        };

        PeerConnectionState::Disconnected(DisconnectedPeerConnectionState {
            reconnect_at,
            failed_reconnect_counter: disconnect_count,
        })
    }

    fn disconnect_err(&self, err: &anyhow::Error, disconnect_count: u64) -> PeerConnectionState<M> {
        debug!(target: LOG_NET_PEER,
            our_id = ?self.our_id,
            peer = ?self.peer_id, %err, %disconnect_count, "Peer disconnected");

        self.disconnect(disconnect_count)
    }

    async fn send_message_connected(
        &mut self,
        mut connected: ConnectedPeerConnectionState<M>,
        peer_message: PeerMessage<M>,
    ) -> PeerConnectionState<M> {
        PEER_MESSAGES_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str, "outgoing"])
            .inc();

        if let Err(e) = connected.connection.send(peer_message).await {
            return self.disconnect_err(&e, 0);
        }

        connected.next_ping = Instant::now() + PING_INTERVAL;

        match connected.connection.flush().await {
            Ok(()) => PeerConnectionState::Connected(connected),
            Err(e) => self.disconnect_err(&e, 0),
        }
    }

    async fn state_transition_disconnected(
        &mut self,
        disconnected: DisconnectedPeerConnectionState,
        task_handle: &TaskHandle,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            new_connection_res = self.incoming_connections.recv() => {
                if let Some(new_connection) = new_connection_res {
                    PEER_CONNECT_COUNT.with_label_values(&[&self.our_id_str, &self.peer_id_str, "incoming"]).inc();
                    self.receive_connection(disconnected, new_connection).await
                } else {
                    debug!(target: LOG_NET_PEER, "Exiting peer connection IO task - parent disconnected");
                    return None;
                }
            },
            () = tokio::time::sleep_until(disconnected.reconnect_at), if self.our_id < self.peer_id => {
                // to prevent "reconnection ping-pongs", only the side with lower PeerId is responsible for reconnecting
                self.reconnect(disconnected).await
            },
            () = task_handle.make_shutdown_rx() => {
                return None;
            },
        })
    }

    async fn receive_connection(
        &mut self,
        disconnect: DisconnectedPeerConnectionState,
        new_connection: AnyFramedTransport<PeerMessage<M>>,
    ) -> PeerConnectionState<M> {
        self.connect(new_connection, disconnect.failed_reconnect_counter)
            .await
    }

    async fn reconnect(
        &mut self,
        disconnected: DisconnectedPeerConnectionState,
    ) -> PeerConnectionState<M> {
        match self.try_reconnect().await {
            Ok(conn) => {
                PEER_CONNECT_COUNT
                    .with_label_values(&[&self.our_id_str, &self.peer_id_str, "outgoing"])
                    .inc();
                self.connect(conn, disconnected.failed_reconnect_counter)
                    .await
            }
            Err(e) => self.disconnect_err(&e, disconnected.failed_reconnect_counter),
        }
    }

    async fn try_reconnect(&self) -> Result<AnyFramedTransport<PeerMessage<M>>, anyhow::Error> {
        debug!(target: LOG_NET_PEER, our_id = ?self.our_id, peer = ?self.peer_id, "Trying to reconnect");
        let (connected_peer, conn) = self
            .connect
            .connect_framed(self.peer_address.with_port_or_known_default(), self.peer_id)
            .await?;

        if connected_peer == self.peer_id {
            Ok(conn)
        } else {
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
        delay_calculator: DelayCalculator,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_group: &TaskGroup,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1024);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(1024);

        task_group.spawn(
            format!("io-thread-peer-{peer_id}"),
            move |handle| async move {
                Self::run_io_thread(
                    incoming_sender,
                    outgoing_receiver,
                    our_id,
                    peer_id,
                    peer_address,
                    delay_calculator,
                    connect,
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

    fn send(&self, msg: M) {
        if self.outgoing.try_send(msg).is_err() {
            debug!(target: LOG_NET_PEER, "Could not send outgoing message since the channel is full");
        }
    }

    async fn receive(&mut self) -> Cancellable<M> {
        self.incoming.recv().await.map_err(|_| Cancelled)
    }

    #[allow(clippy::too_many_arguments)] // TODO: consider refactoring
    #[instrument(
        name = "peer_io_thread",
        target = "net::peer",
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
        delay_calculator: DelayCalculator,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
        task_handle: &TaskHandle,
    ) {
        let common = CommonPeerConnectionState {
            incoming,
            outgoing,
            our_id_str: our_id.to_string(),
            our_id,
            peer_id_str: peer_id.to_string(),
            peer_id,
            peer_address,
            delay_calculator,
            connect,
            incoming_connections,
            status_channels,
        };
        let initial_state = PeerConnectionState::Disconnected(DisconnectedPeerConnectionState {
            reconnect_at: Instant::now(),
            failed_reconnect_counter: 0,
        });

        let state_machine = PeerConnectionStateMachine {
            common,
            state: initial_state,
        };

        state_machine.run(task_handle).await;
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

    use super::DelayCalculator;
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
                let status_channels = Default::default();
                let connection = ReconnectPeerConnections::<u64>::new(
                    cfg,
                    DelayCalculator::TEST_DEFAULT,
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

        task_group.shutdown();
        task_group.join_all(None).await.unwrap();
    }

    #[test]
    fn test_delay_calculator() {
        let c = DelayCalculator::TEST_DEFAULT;
        for i in 1..=20 {
            println!("{}: {:?}", i, c.reconnection_delay(i));
        }
        assert!((2000..3000).contains(&c.reconnection_delay(1).as_millis()));
        assert!((10000..11000).contains(&c.reconnection_delay(10).as_millis()));
        let c = DelayCalculator::PROD_DEFAULT;
        for i in 1..=20 {
            println!("{}: {:?}", i, c.reconnection_delay(i));
        }
        assert!((10..20).contains(&c.reconnection_delay(1).as_millis()));
        assert!((10000..11000).contains(&c.reconnection_delay(10).as_millis()));
    }
}
