//! Implements a connection manager for communication with other federation members
//!
//! The main interface is [`fedimint_api::net::peers::IPeerConnections`] and its main implementation is
//! [`ReconnectPeerConnections`], see these for details.

use std::cmp::min;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::ops::Sub;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::net::peers::IPeerConnections;
use fedimint_api::task::{TaskGroup, TaskHandle};
use fedimint_api::PeerId;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use hbbft::Target;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;

use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;
use crate::net::queue::{MessageId, MessageQueue, UniqueMessage};

/// Maximum connection failures we consider for our back-off strategy
const MAX_FAIL_RECONNECT_COUNTER: u64 = 300;

/// Owned [`Connector`](crate::net::connect::Connector) trait object used by
/// [`ReconnectPeerConnections`]
pub type PeerConnector<M> = AnyConnector<PeerMessage<M>>;

/// Connection manager that automatically reconnects to peers
///
/// `ReconnectPeerConnections` is based on a [`Connector`](crate::net::connect::Connector) object
/// which is used to open [`FramedTransport`](crate::net::framed::FramedTransport) connections. For
/// production deployments the `Connector` has to ensure that connections are authenticated and
/// encrypted.
pub struct ReconnectPeerConnections<T> {
    connections: HashMap<PeerId, PeerConnection<T>>,
}

struct PeerConnection<T> {
    outgoing: Sender<T>,
    incoming: Receiver<T>,
}

/// Specifies the network configuration for federation-internal communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Our federation member's identity
    pub identity: PeerId,
    /// Our listen address for incoming connections from other federation members
    pub bind_addr: SocketAddr,
    /// Map of all peers' connection information we want to be connected to
    pub peers: HashMap<PeerId, Url>,
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
    peer_address: Url,
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
    pub async fn new(
        cfg: NetworkConfig,
        connect: PeerConnector<T>,
        task_group: &mut TaskGroup,
    ) -> Self {
        let shared_connector: SharedAnyConnector<PeerMessage<T>> = connect.into();

        let (connection_senders, connections) = cfg
            .peers
            .iter()
            .filter(|(&peer, _)| peer != cfg.identity)
            .map(|(&peer, peer_address)| {
                let (connection_sender, connection_receiver) =
                    tokio::sync::mpsc::channel::<AnyFramedTransport<PeerMessage<T>>>(4);
                (
                    (peer, connection_sender),
                    (
                        peer,
                        PeerConnection::new(
                            peer,
                            peer_address.clone(),
                            shared_connector.clone(),
                            connection_receiver,
                            task_group,
                        ),
                    ),
                )
            })
            .unzip();

        task_group
            .spawn("listen task", move |handle| {
                Self::run_listen_task(cfg, shared_connector, connection_senders, handle)
            })
            .await;

        ReconnectPeerConnections { connections }
    }

    async fn run_listen_task(
        cfg: NetworkConfig,
        connect: SharedAnyConnector<PeerMessage<T>>,
        mut connection_senders: HashMap<PeerId, Sender<AnyFramedTransport<PeerMessage<T>>>>,
        task_handle: TaskHandle,
    ) {
        let mut listener = connect
            .listen(cfg.bind_addr)
            .await
            .expect("Could not bind port");

        let mut shutdown_rx = task_handle.make_shutdown_rx().await;

        while !task_handle.is_shutting_down() {
            let new_connection = tokio::select! {
                maybe_msg = listener.next() => { maybe_msg },
                _ = &mut shutdown_rx => { break; },
            };

            let (peer, connection) = match new_connection.expect("Listener closed") {
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

pub trait PeerSlice {
    fn peers(&self, all_peers: &BTreeSet<PeerId>) -> Vec<PeerId>;
}

impl PeerSlice for Target<PeerId> {
    fn peers(&self, all_peers: &BTreeSet<PeerId>) -> Vec<PeerId> {
        let set = match self {
            Target::AllExcept(exclude) => all_peers.sub(exclude),
            Target::Nodes(include) => include.clone(),
        };

        set.into_iter().collect()
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
            trace!(?peer_id, "Sending message to");
            if let Some(peer) = self.connections.get_mut(peer_id) {
                peer.send(msg.clone()).await?;
            } else {
                trace!(peer = ?peer_id, "Not sending message to unknown peer (maybe banned)");
            }
        }
        Ok(())
    }

    async fn receive(&mut self) -> Cancellable<(PeerId, T)> {
        // TODO: optimize, don't throw away remaining futures

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
        warn!("Peer {} banned.", peer);
    }
}

impl<M> PeerConnectionStateMachine<M>
where
    M: Debug + Clone,
{
    async fn run(mut self, task_handle: &TaskHandle) {
        let peer = self.common.peer;

        // Note: `state_transition` internally uses channel operations (`send` and `recv`)
        // which will disconnect when other tasks are shutting down returning here,
        // so we probably don't need any `timeout` here.
        while !task_handle.is_shutting_down() {
            if let Some(new_self) = self.state_transition(task_handle).await {
                self = new_self;
            } else {
                break;
            }
        }
        info!(?peer, "Shutting down peer connection state machine");
    }

    async fn state_transition(self, task_handle: &TaskHandle) -> Option<Self> {
        let PeerConnectionStateMachine { mut common, state } = self;

        match state {
            PeerConnectionState::Disconnected(disconnected) => {
                common
                    .state_transition_disconnected(disconnected, task_handle)
                    .await
            }
            PeerConnectionState::Connected(connected) => {
                common
                    .state_transition_connected(connected, task_handle)
                    .await
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
                match maybe_msg {
                    Some(msg) => {
                        self.send_message_connected(connected, msg).await
                    },
                    None => {
                        debug!("Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            new_connection_res = self.incoming_connections.recv() => {
                match new_connection_res {
                    Some(new_connection) => {
                        warn!("Replacing existing connection");
                        self.connect(new_connection, 0).await
                    },
                    None => {
                        debug!("Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            Some(msg_res) = connected.connection.next() => {
                self.receive_message(connected, msg_res).await
            },
            _ = task_handle.make_shutdown_rx().await => {
                return None;
            },
        })
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
            let delay: f64 = thread_rng().gen_range(1.0 * scaling_factor..4.0 * scaling_factor);
            debug!(delay, "Scheduling reopening of connection");
            Instant::now() + Duration::from_secs_f64(delay)
        };

        PeerConnectionState::Disconnected(DisconnectedPeerConnectionState {
            reconnect_at,
            failed_reconnect_counter: min(disconnect_count, MAX_FAIL_RECONNECT_COUNTER),
        })
    }

    fn disconnect_err(&self, err: anyhow::Error, disconnect_count: u64) -> PeerConnectionState<M> {
        debug!(peer = ?self.peer, %err, %disconnect_count, "Peer disconnected");
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

        if self.incoming.send(msg.msg).await.is_err() {
            // ignore error - if the other side is not there,
            // it means we're are probably shutting down
            debug!("Could not deliver message to recipient - probably shutting down");
        }

        Ok(())
    }

    async fn state_transition_disconnected(
        &mut self,
        disconnected: DisconnectedPeerConnectionState,
        task_handle: &TaskHandle,
    ) -> Option<PeerConnectionState<M>> {
        Some(tokio::select! {
            maybe_msg = self.outgoing.recv() => {
                match maybe_msg {
                    Some(msg) => {
                        self.send_message(disconnected, msg).await}
                    None => {
                        debug!("Exiting peer connection IO task - parent disconnected");
                        return None;
                    }
                }
            },
            new_connection_res = self.incoming_connections.recv() => {
                match new_connection_res {
                    Some(new_connection) => {
                        self.receive_connection(disconnected, new_connection).await
                    },
                    None => {
                        debug!("Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            () = tokio::time::sleep_until(disconnected.reconnect_at) => {
                self.reconnect(disconnected).await
            },
            _ = task_handle.make_shutdown_rx().await => {
                return None;
            },
        })
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
        let addr = self.peer_address.clone();
        let (connected_peer, conn) = self.connect.connect_framed(addr, self.peer).await?;

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
        peer_address: Url,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        task_group: &mut TaskGroup,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = tokio::sync::mpsc::channel::<M>(1024);
        let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::channel::<M>(1024);

        futures::executor::block_on(task_group.spawn(
            format!("io-thread-peer-{}", id),
            move |handle| async move {
                Self::run_io_thread(
                    incoming_sender,
                    outgoing_receiver,
                    id,
                    peer_address,
                    connect,
                    incoming_connections,
                    &handle,
                )
                .await
            },
        ));

        PeerConnection {
            outgoing: outgoing_sender,
            incoming: incoming_receiver,
        }
    }

    async fn send(&mut self, msg: M) -> Cancellable<()> {
        self.outgoing.send(msg).await.map_err(|_e| Cancelled)
    }

    async fn receive(&mut self) -> Cancellable<M> {
        self.incoming.recv().await.ok_or(Cancelled)
    }

    #[instrument(skip_all, fields(peer))]
    async fn run_io_thread(
        incoming: Sender<M>,
        outgoing: Receiver<M>,
        peer: PeerId,
        peer_address: Url,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        task_handle: &TaskHandle,
    ) {
        let common = CommonPeerConnectionState {
            resend_queue: Default::default(),
            incoming,
            outgoing,
            peer,
            peer_address,
            connect,
            incoming_connections,
            last_received: None,
        };
        let initial_state = common.disconnect(0);

        let state_machine = PeerConnectionStateMachine {
            common,
            state: initial_state,
        };

        state_machine.run(task_handle).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use fedimint_api::task::TaskGroup;
    use fedimint_api::PeerId;
    use futures::Future;

    use crate::net::connect::mock::MockNetwork;
    use crate::net::connect::Connector;
    use crate::net::peers::{IPeerConnections, NetworkConfig, ReconnectPeerConnections};

    async fn timeout<F, T>(f: F) -> Option<T>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_secs(100), f).await.ok()
    }

    #[test_log::test(tokio::test)]
    async fn test_connect() {
        let task_group = TaskGroup::new();

        {
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
            let build_peers = move |bind: &'static str, id: u16, mut task_group: TaskGroup| async move {
                let cfg = NetworkConfig {
                    identity: PeerId::from(id),
                    bind_addr: bind.parse().unwrap(),
                    peers: peers_ref.clone(),
                };
                let connect = net_ref.connector(cfg.identity).into_dyn();
                ReconnectPeerConnections::<u64>::new(cfg, connect, &mut task_group).await
            };

            let mut peers_a = build_peers("127.0.0.1:1000", 1, task_group.clone()).await;
            let mut peers_b = build_peers("127.0.0.1:2000", 2, task_group.clone()).await;

            peers_a.send(&[PeerId::from(2)], 42).await.unwrap();
            let recv = timeout(peers_b.receive()).await.unwrap().unwrap();
            assert_eq!(recv.0, PeerId::from(1));
            assert_eq!(recv.1, 42);

            peers_a.send(&[PeerId::from(3)], 21).await.unwrap();

            let mut peers_c = build_peers("127.0.0.1:3000", 3, task_group.clone()).await;
            let recv = timeout(peers_c.receive()).await.unwrap().unwrap();
            assert_eq!(recv.0, PeerId::from(1));
            assert_eq!(recv.1, 21);
        }

        task_group.shutdown().await;
        task_group.join_all(None).await.unwrap();
    }
}
