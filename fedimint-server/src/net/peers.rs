//! Implements a connection manager for communication with other federation members
//!
//! The main interface is [`PeerConnections`] and its main implementation is
//! [`ReconnectPeerConnections`], see these for details.

use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_api::PeerId;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use hbbft::Target;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;

use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;
use crate::net::queue::{MessageId, MessageQueue, UniqueMessage};

/// Maximum connection failures we consider for our back-off strategy
const MAX_FAIL_RECONNECT_COUNTER: u64 = 300;

/// Owned [`PeerConnections`] trait object type
pub type AnyPeerConnections<M> = Box<dyn PeerConnections<M> + Send + Unpin + 'static>;

/// Owned [`Connector`](crate::net::connect::Connector) trait object used by
/// [`ReconnectPeerConnections`]
pub type PeerConnector<M> = AnyConnector<PeerMessage<M>>;

/// Connection manager that tries to keep connections open to all peers
///
/// Production implementations of this trait have to ensure that:
/// * Connections to peers are authenticated and encrypted
/// * Messages are received exactly once and in the order they were sent
/// * Connections are reopened when closed
/// * Messages are cached in case of short-lived network interruptions and resent on reconnect, this
///   avoids the need to rejoin the consensus, which is more tricky.
///
/// In case of longer term interruptions the message cache has to be dropped to avoid DoS attacks.
/// The thus disconnected peer will need to rejoin the consensus at a later time.  
#[async_trait]
pub trait PeerConnections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    /// Send a message to a target, either all peers or a specific one.
    ///
    /// The message is sent immediately and cached if the peer is reachable and only cached
    /// otherwise.
    async fn send(&mut self, target: Target<PeerId>, msg: T);

    /// Await receipt of a message from any connected peer.
    async fn receive(&mut self) -> (PeerId, T);

    /// Removes a peer connection in case of misbehavior
    async fn ban_peer(&mut self, peer: PeerId);

    /// Converts the struct to a `PeerConnection` trait object
    fn into_dyn(self) -> AnyPeerConnections<T>
    where
        Self: Sized + Send + Unpin + 'static,
    {
        Box::new(self)
    }
}

/// Connection manager that automatically reconnects to peers
///
/// `ReconnectPeerConnections` is based on a [`Connector`](crate::net::connect::Connector) object
/// which is used to open [`FramedTransport`](crate::net::framed::FramedTransport) connections. For
/// production deployments the `Connector` has to ensure that connections are authenticated and
/// encrypted.
pub struct ReconnectPeerConnections<T> {
    connections: HashMap<PeerId, PeerConnection<T>>,
    _listen_task: JoinHandle<()>,
}

struct PeerConnection<T> {
    outgoing: Sender<T>,
    incoming: Receiver<T>,
    _io_task: JoinHandle<()>,
}

/// Specifies the network configuration for federation-internal communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Our federation member's identity
    pub identity: PeerId,
    /// Our listen address for incoming connections from other federation members
    pub bind_addr: String,
    /// Map of all peers' connection information we want to be connected to
    pub peers: HashMap<PeerId, ConnectionConfig>,
}

/// Information needed to connect to one other federation member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// The peer's hbbft network address and port (e.g. `10.42.0.10:4000`)
    pub hbbft_addr: String,
    /// The peer's websocket network address and port (e.g. `ws://10.42.0.10:5000`)
    pub api_addr: Url,
}

/// Internal message type for [`ReconnectPeerConnections`], just public because it appears in the
/// public interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMessage<M> {
    msg: UniqueMessage<M>,
    ack: Option<MessageId>,
}

struct PeerConnectionStateMachine<M> {
    common: CommonPeerConnectionState<M>,
    state: PeerConnectionState<M>,
}

struct CommonPeerConnectionState<M> {
    resend_queue: MessageQueue<M>,
    incoming: Sender<M>,
    outgoing: Receiver<M>,
    peer: PeerId,
    cfg: ConnectionConfig,
    connect: SharedAnyConnector<PeerMessage<M>>,
    incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    last_received: Option<MessageId>,
}

struct DisconnectedPeerConnectionState {
    reconnect_at: Instant,
    failed_reconnect_counter: u64,
}

struct ConnectedPeerConnectionState<M> {
    connection: AnyFramedTransport<PeerMessage<M>>,
}

enum PeerConnectionState<M> {
    Disconnected(DisconnectedPeerConnectionState),
    Connected(ConnectedPeerConnectionState<M>),
}

impl<T: 'static> ReconnectPeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync,
{
    /// Creates a new `ReconnectPeerConnections` connection manager from a network config and a
    /// [`Connector`](crate::net::connect::Connector). See [`ReconnectPeerConnections`] for
    /// requirements on the `Connector`.
    #[instrument(skip_all)]
    pub async fn new(cfg: NetworkConfig, connect: PeerConnector<T>) -> Self {
        info!("Starting mint {}", cfg.identity);

        let shared_connector: SharedAnyConnector<PeerMessage<T>> = connect.into();

        let (connection_senders, connections) = cfg
            .peers
            .iter()
            .filter(|(&peer, _)| peer != cfg.identity)
            .map(|(&peer, cfg)| {
                let (connection_sender, connection_receiver) =
                    tokio::sync::mpsc::channel::<AnyFramedTransport<PeerMessage<T>>>(4);
                (
                    (peer, connection_sender),
                    (
                        peer,
                        PeerConnection::new(
                            peer,
                            cfg.clone(),
                            shared_connector.clone(),
                            connection_receiver,
                        ),
                    ),
                )
            })
            .unzip();

        let listen_task = tokio::spawn(Self::run_listen_task(
            cfg,
            shared_connector,
            connection_senders,
        ));

        ReconnectPeerConnections {
            connections,
            _listen_task: listen_task,
        }
    }

    async fn run_listen_task(
        cfg: NetworkConfig,
        connect: SharedAnyConnector<PeerMessage<T>>,
        mut connection_senders: HashMap<PeerId, Sender<AnyFramedTransport<PeerMessage<T>>>>,
    ) {
        let mut listener = connect
            .listen(cfg.bind_addr.clone())
            .await
            .expect("Could not bind port");

        loop {
            let (peer, connection) = match listener.next().await.expect("Listener closed") {
                Ok(connection) => connection,
                Err(e) => {
                    error!(mint = ?cfg.identity, err = %e, "Error while opening incoming connection");
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
                    ?peer,
                    "Could not send incoming connection to peer io task (possibly banned)"
                );
            }
        }
    }
}

#[async_trait]
impl<T> PeerConnections<T> for ReconnectPeerConnections<T>
where
    T: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Unpin + Send + Sync + 'static,
{
    async fn send(&mut self, target: Target<PeerId>, msg: T) {
        trace!(?target, "Sending message to");
        match target {
            Target::AllExcept(not_to) => {
                for (peer, connection) in &mut self.connections {
                    if !not_to.contains(peer) {
                        connection.send(msg.clone()).await;
                    }
                }
            }
            Target::Nodes(peer_ids) => {
                for peer_id in peer_ids {
                    if let Some(peer) = self.connections.get_mut(&peer_id) {
                        peer.send(msg.clone()).await;
                    } else {
                        trace!(peer = ?peer_id, "Not sending message to unknown peer (maybe banned)");
                    }
                }
            }
        }
    }

    async fn receive(&mut self) -> (PeerId, T) {
        // TODO: optimize, don't throw away remaining futures

        let futures_non_banned = self.connections.iter_mut().map(|(&peer, connection)| {
            let receive_future = async move {
                let msg = connection.receive().await;
                (peer, msg)
            };
            Box::pin(receive_future)
        });

        select_all(futures_non_banned).await.0
    }

    async fn ban_peer(&mut self, peer: PeerId) {
        self.connections.remove(&peer);
        warn!("Peer {} banned.", peer);
    }
}

impl<M> PeerConnectionStateMachine<M>
where
    M: Debug + Clone,
{
    async fn run(mut self) {
        loop {
            self = self.state_transition().await;
        }
    }

    async fn state_transition(self) -> Self {
        let PeerConnectionStateMachine { mut common, state } = self;

        let new_state = match state {
            PeerConnectionState::Disconnected(disconnected) => {
                common.state_transition_disconnected(disconnected).await
            }
            PeerConnectionState::Connected(connected) => {
                common.state_transition_connected(connected).await
            }
        };

        PeerConnectionStateMachine {
            common,
            state: new_state,
        }
    }
}

impl<M> CommonPeerConnectionState<M>
where
    M: Debug + Clone,
{
    async fn state_transition_connected(
        &mut self,
        mut connected: ConnectedPeerConnectionState<M>,
    ) -> PeerConnectionState<M> {
        tokio::select! {
            maybe_msg = self.outgoing.recv() => {
                let msg = maybe_msg.expect("Peer connection was dropped");
                self.send_message_connected(connected, msg).await
            },
            new_connection_res = self.incoming_connections.recv() => {
                let new_connection = new_connection_res.expect("Listener task died");
                warn!("Replacing existing connection");
                self.connect(new_connection, 0).await
            },
            Some(msg_res) = connected.connection.next() => {
                self.receive_message(connected, msg_res).await
            },
        }
    }

    async fn connect(
        &mut self,
        mut new_connection: AnyFramedTransport<PeerMessage<M>>,
        disconnect_count: u64,
    ) -> PeerConnectionState<M> {
        debug!(peer = ?self.peer, "Received incoming connection");
        match self.resend_buffer_contents(&mut new_connection).await {
            Ok(()) => PeerConnectionState::Connected(ConnectedPeerConnectionState {
                connection: new_connection,
            }),
            Err(e) => self.disconnect_err(e, disconnect_count),
        }
    }

    async fn resend_buffer_contents(
        &self,
        connection: &mut AnyFramedTransport<PeerMessage<M>>,
    ) -> Result<(), anyhow::Error> {
        for msg in self.resend_queue.iter().cloned() {
            connection
                .send(PeerMessage {
                    msg,
                    ack: self.last_received,
                })
                .await?
        }

        Ok(())
    }

    fn disconnect(&self, mut disconnect_count: u64) -> PeerConnectionState<M> {
        disconnect_count += 1;

        let reconnect_at = {
            let scaling_factor = disconnect_count as f64;
            let delay: f64 = thread_rng().gen_range(1.0 * scaling_factor, 4.0 * scaling_factor);
            debug!(delay, "Scheduling reopening of connection");
            Instant::now() + Duration::from_secs_f64(delay)
        };

        PeerConnectionState::Disconnected(DisconnectedPeerConnectionState {
            reconnect_at,
            failed_reconnect_counter: min(disconnect_count, MAX_FAIL_RECONNECT_COUNTER),
        })
    }

    fn disconnect_err(&self, err: anyhow::Error, disconnect_count: u64) -> PeerConnectionState<M> {
        warn!(peer = ?self.peer, %err, %disconnect_count, "Some error occurred, disconnecting");
        self.disconnect(disconnect_count)
    }

    async fn send_message_connected(
        &mut self,
        mut connected: ConnectedPeerConnectionState<M>,
        msg: M,
    ) -> PeerConnectionState<M> {
        let umsg = self.resend_queue.push(msg);
        trace!(?self.peer, id = ?umsg.id, "Sending outgoing message");

        match connected
            .connection
            .send(PeerMessage {
                msg: umsg,
                ack: self.last_received,
            })
            .await
        {
            Ok(()) => PeerConnectionState::Connected(connected),
            Err(e) => self.disconnect_err(e, 0),
        }
    }

    async fn receive_message(
        &mut self,
        connected: ConnectedPeerConnectionState<M>,
        msg_res: Result<PeerMessage<M>, anyhow::Error>,
    ) -> PeerConnectionState<M> {
        match self.receive_message_inner(msg_res).await {
            Ok(()) => PeerConnectionState::Connected(connected),
            Err(e) => {
                self.last_received = None;
                self.disconnect_err(e, 0)
            }
        }
    }

    async fn receive_message_inner(
        &mut self,
        msg_res: Result<PeerMessage<M>, anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        let PeerMessage { msg, ack } = msg_res?;
        trace!(peer = ?self.peer, id = ?msg.id, "Received incoming message");

        let expected = self
            .last_received
            .map(|last_id| last_id.increment())
            .unwrap_or(msg.id);

        if msg.id < expected {
            info!(?expected, received = ?msg.id, "Received old message");
            return Ok(());
        }

        if msg.id > expected {
            warn!(?expected, received = ?msg.id, "Received message from the future");
            return Err(anyhow::anyhow!("Received message from the future"));
        }

        debug_assert_eq!(expected, msg.id, "someone removed the check above");
        self.last_received = Some(expected);
        if let Some(ack) = ack {
            self.resend_queue.ack(ack);
        }

        self.incoming
            .send(msg.msg)
            .await
            .expect("Peer connection went away");

        Ok(())
    }

    async fn state_transition_disconnected(
        &mut self,
        disconnected: DisconnectedPeerConnectionState,
    ) -> PeerConnectionState<M> {
        tokio::select! {
            maybe_msg = self.outgoing.recv() => {
                let msg = maybe_msg.expect("Peer connection was dropped");
                self.send_message(disconnected, msg).await
            },
            new_connection_res = self.incoming_connections.recv() => {
                let new_connection = new_connection_res.expect("Listener task died");
                self.receive_connection(disconnected, new_connection).await
            },
            () = tokio::time::sleep_until(disconnected.reconnect_at) => {
                self.reconnect(disconnected).await
            }
        }
    }

    async fn send_message(
        &mut self,
        disconnected: DisconnectedPeerConnectionState,
        msg: M,
    ) -> PeerConnectionState<M> {
        let umsg = self.resend_queue.push(msg);
        trace!(id = ?umsg.id, "Queueing outgoing message");
        PeerConnectionState::Disconnected(disconnected)
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
                self.connect(conn, disconnected.failed_reconnect_counter)
                    .await
            }
            Err(e) => self.disconnect_err(e, disconnected.failed_reconnect_counter),
        }
    }

    async fn try_reconnect(&self) -> Result<AnyFramedTransport<PeerMessage<M>>, anyhow::Error> {
        debug!("Trying to reconnect");
        let addr = &self.cfg.hbbft_addr;
        let (connected_peer, conn) = self.connect.connect_framed(addr.clone(), self.peer).await?;

        if connected_peer == self.peer {
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
    fn new(
        id: PeerId,
        cfg: ConnectionConfig,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = tokio::sync::mpsc::channel::<M>(1024);
        let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::channel::<M>(1024);

        let io_thread = tokio::spawn(Self::run_io_thread(
            incoming_sender,
            outgoing_receiver,
            id,
            cfg,
            connect,
            incoming_connections,
        ));

        PeerConnection {
            outgoing: outgoing_sender,
            incoming: incoming_receiver,
            _io_task: io_thread,
        }
    }

    async fn send(&mut self, msg: M) {
        self.outgoing.send(msg).await.expect("io task died");
    }

    async fn receive(&mut self) -> M {
        self.incoming.recv().await.expect("io task died")
    }

    #[instrument(skip_all, fields(peer))]
    async fn run_io_thread(
        incoming: Sender<M>,
        outgoing: Receiver<M>,
        peer: PeerId,
        cfg: ConnectionConfig,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    ) {
        let common = CommonPeerConnectionState {
            resend_queue: Default::default(),
            incoming,
            outgoing,
            peer,
            cfg,
            connect,
            incoming_connections,
            last_received: None,
        };
        let initial_state = common.disconnect(0);

        let state_machine = PeerConnectionStateMachine {
            common,
            state: initial_state,
        };

        state_machine.run().await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::iter::FromIterator;
    use std::time::Duration;

    use fedimint_api::PeerId;
    use futures::Future;
    use hbbft::Target;
    use tracing_subscriber::EnvFilter;
    use url::Url;

    use crate::net::connect::mock::MockNetwork;
    use crate::net::connect::Connector;
    use crate::net::peers::{
        ConnectionConfig, NetworkConfig, PeerConnections, ReconnectPeerConnections,
    };

    async fn timeout<F, T>(f: F) -> Option<T>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_secs(100), f).await.ok()
    }

    #[tokio::test]
    async fn test_connect() {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info,fedimint::net=trace")),
            )
            .init();

        let net = MockNetwork::new();

        let peers = ["a", "b", "c"]
            .iter()
            .enumerate()
            .map(|(idx, &peer)| {
                let cfg = ConnectionConfig {
                    hbbft_addr: peer.to_string(),
                    api_addr: Url::parse(format!("http://{}", peer).as_str())
                        .expect("Could not parse Url"),
                };
                (PeerId::from(idx as u16 + 1), cfg)
            })
            .collect::<HashMap<_, _>>();

        let peers_ref = &peers;
        let net_ref = &net;
        let build_peers = |bind: &'static str, id: u16| async move {
            let cfg = NetworkConfig {
                identity: PeerId::from(id),
                bind_addr: bind.to_string(),
                peers: peers_ref.clone(),
            };
            let connect = net_ref.connector(cfg.identity).into_dyn();
            ReconnectPeerConnections::<u64>::new(cfg, connect).await
        };

        let mut peers_a = build_peers("a", 1).await;
        let mut peers_b = build_peers("b", 2).await;

        peers_a
            .send(Target::Nodes(BTreeSet::from_iter([PeerId::from(2)])), 42)
            .await;
        let recv = timeout(peers_b.receive()).await.unwrap();
        assert_eq!(recv.0, PeerId::from(1));
        assert_eq!(recv.1, 42);

        peers_a
            .send(Target::Nodes(BTreeSet::from_iter([PeerId::from(3)])), 21)
            .await;

        let mut peers_c = build_peers("c", 3).await;
        let recv = timeout(peers_c.receive()).await.unwrap();
        assert_eq!(recv.0, PeerId::from(1));
        assert_eq!(recv.1, 21);
    }
}
