//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::peers::IPeerConnections`] and
//! its main implementation is [`ReconnectPeerConnectionsReliable`], see these
//! for details.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::ops::Sub;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_core::api::PeerConnectionStatus;
use fedimint_core::cancellable::{Cancellable, Cancelled};
use fedimint_core::net::peers::IPeerConnections;
use fedimint_core::task::{sleep_until, TaskGroup, TaskHandle};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_logging::LOG_NET_PEER;
use futures::future::select_all;
use futures::{SinkExt, StreamExt};
use hbbft::Target;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, info, instrument, trace, warn};

use crate::net::connect::{AnyConnector, SharedAnyConnector};
use crate::net::framed::AnyFramedTransport;
use crate::net::peers::{DelayCalculator, NetworkConfig};
use crate::net::queue::{MessageId, MessageQueue, UniqueMessage};

/// Every how many seconds to send an empty message to our peer if we sent no
/// messages during that time. This helps with reducing the amount of messages
/// that need to be re-sent in case of very one-sided communication.
const PING_INTERVAL: Duration = Duration::from_secs(10);

/// Owned [`Connector`](crate::net::connect::Connector) trait object used by
/// [`ReconnectPeerConnectionsReliable`]
pub type PeerConnector<M> = AnyConnector<PeerMessage<M>>;

/// Connection manager that automatically reconnects to peers
///
/// `ReconnectPeerConnections` is based on a
/// [`Connector`](crate::net::connect::Connector) object which is used to open
/// [`FramedTransport`](crate::net::framed::FramedTransport) connections. For
/// production deployments the `Connector` has to ensure that connections are
/// authenticated and encrypted.
pub struct ReconnectPeerConnectionsReliable<T> {
    connections: HashMap<PeerId, PeerConnection<T>>,
}

struct PeerConnection<T> {
    outgoing: Sender<T>,
    incoming: Receiver<T>,
}

/// Internal message type for [`ReconnectPeerConnectionsReliable`], just public
/// because it appears in the public interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMessage<M> {
    msg: Option<UniqueMessage<M>>,
    ack: Option<MessageId>,
}

struct PeerConnectionStateMachine<M> {
    common: CommonPeerConnectionState<M>,
    state: PeerConnectionState<M>,
}

struct PeerStatusQuery {
    response_sender: oneshot::Sender<PeerConnectionStatus>,
}

type PeerStatusChannelSender = Sender<PeerStatusQuery>;
type PeerStatusChannelReceiver = Receiver<PeerStatusQuery>;

/// Keeps the references to a `PeerStatusChannelSender` for each `PeerId`, which
/// can be used to ask the corresponding `PeerConnectionStateMachine` for the
/// current `PeerConnectionStatus`
#[derive(Clone)]
pub struct PeerStatusChannels(HashMap<PeerId, PeerStatusChannelSender>);

impl PeerStatusChannels {
    pub async fn get_all_status(&self) -> HashMap<PeerId, anyhow::Result<PeerConnectionStatus>> {
        let results = self.0.iter().map(|(peer_id, sender)| async {
            let (response_sender, response_receiver) = oneshot::channel();
            let query = PeerStatusQuery { response_sender };
            let sender_response = sender
                .send(query)
                .await
                .map_err(|_| anyhow::anyhow!("channel closed while querying peer status"));
            match sender_response {
                Ok(()) => {
                    let status = response_receiver
                        .await
                        .map_err(|_| anyhow::anyhow!("channel closed while receiving peer status"));
                    (*peer_id, status)
                }
                Err(e) => (*peer_id, Err(e)),
            }
        });
        futures::future::join_all(results)
            .await
            .into_iter()
            .collect()
    }
}

struct CommonPeerConnectionState<M> {
    resend_queue: MessageQueue<M>,
    incoming: Sender<M>,
    outgoing: Receiver<M>,
    our_id: PeerId,
    peer_id: PeerId,
    peer_address: SafeUrl,
    delay_calculator: DelayCalculator,
    connect: SharedAnyConnector<PeerMessage<M>>,
    incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
    last_received: Option<MessageId>,
    status_query_receiver: PeerStatusChannelReceiver,
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

impl<T: 'static> ReconnectPeerConnectionsReliable<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync,
{
    /// Creates a new `ReconnectPeerConnections` connection manager from a
    /// network config and a [`Connector`](crate::net::connect::Connector).
    /// See [`ReconnectPeerConnectionsReliable`] for requirements on the
    /// `Connector`.
    #[instrument(skip_all)]
    pub(crate) async fn new(
        cfg: NetworkConfig,
        delay_calculator: DelayCalculator,
        connect: PeerConnector<T>,
        task_group: &mut TaskGroup,
    ) -> (Self, PeerStatusChannels) {
        let shared_connector: SharedAnyConnector<PeerMessage<T>> = connect.into();
        let mut connection_senders = HashMap::new();
        let mut status_query_senders = HashMap::new();
        let mut connections = HashMap::new();

        for (peer, peer_address) in cfg.peers.iter().filter(|(&peer, _)| peer != cfg.identity) {
            let (connection_sender, connection_receiver) =
                tokio::sync::mpsc::channel::<AnyFramedTransport<PeerMessage<T>>>(4);
            let (status_query_sender, status_query_receiver) =
                tokio::sync::mpsc::channel::<PeerStatusQuery>(1); // better block the sender than flood the receiver

            let connection = PeerConnection::new(
                cfg.identity,
                *peer,
                peer_address.clone(),
                delay_calculator,
                shared_connector.clone(),
                connection_receiver,
                status_query_receiver,
                task_group,
            )
            .await;

            connection_senders.insert(*peer, connection_sender);
            status_query_senders.insert(*peer, status_query_sender);
            connections.insert(*peer, connection);
        }
        task_group
            .spawn("listen task", move |handle| {
                Self::run_listen_task(cfg, shared_connector, connection_senders, handle)
            })
            .await;
        (
            ReconnectPeerConnectionsReliable { connections },
            PeerStatusChannels(status_query_senders),
        )
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
            .with_context(|| anyhow::anyhow!("Failed to listen on {}", cfg.bind_addr))
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
impl<T> IPeerConnections<T> for ReconnectPeerConnectionsReliable<T>
where
    T: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Unpin + Send + Sync + 'static,
{
    #[must_use]
    async fn send(&mut self, peers: &[PeerId], msg: T) -> Cancellable<()> {
        for peer_id in peers {
            trace!(target: LOG_NET_PEER, ?peer_id, "Sending message to");
            if let Some(peer) = self.connections.get_mut(peer_id) {
                peer.send(msg.clone()).await?;
            } else {
                trace!(target: LOG_NET_PEER,peer = ?peer_id, "Not sending message to unknown peer (maybe banned)");
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
                        debug!(target: LOG_NET_PEER, "Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            new_connection_res = self.incoming_connections.recv() => {
                match new_connection_res {
                    Some(new_connection) => {
                        debug!(target: LOG_NET_PEER, "Replacing existing connection");
                        self.connect(new_connection, 0).await
                    },
                    None => {
                        debug!(
                        target: LOG_NET_PEER,
                            "Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            Some(status_query) = self.status_query_receiver.recv() => {
                if status_query.response_sender.send(PeerConnectionStatus::Connected).is_err() {
                    let peer_id = self.peer_id;
                    debug!(target: LOG_NET_PEER, %peer_id, "Could not send peer status response: receiver dropped");
                }
                PeerConnectionState::Connected(connected)
            },
            Some(msg_res) = connected.connection.next() => {
                self.receive_message(connected, msg_res).await
            },
            _ = sleep_until(connected.next_ping.into()) => {
                self.send_ping(connected).await
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
        debug!(target: LOG_NET_PEER,
            our_id = ?self.our_id,
            peer = ?self.peer_id, %disconnect_count,
            resend_queue_len = self.resend_queue.queue.len(),
            "Initializing new connection");
        match self.resend_buffer_contents(&mut new_connection).await {
            Ok(()) => PeerConnectionState::Connected(ConnectedPeerConnectionState {
                connection: new_connection,
                next_ping: Instant::now(),
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
                    msg: Some(msg),
                    ack: self.last_received,
                })
                .await?
        }

        Ok(())
    }

    fn disconnect(&self, mut disconnect_count: u64) -> PeerConnectionState<M> {
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

    fn disconnect_err(&self, err: anyhow::Error, disconnect_count: u64) -> PeerConnectionState<M> {
        debug!(target: LOG_NET_PEER,
            our_id = ?self.our_id,
            peer = ?self.peer_id, %err, %disconnect_count, "Peer disconnected");
        self.disconnect(disconnect_count)
    }

    async fn send_message_connected(
        &mut self,
        connected: ConnectedPeerConnectionState<M>,
        msg: M,
    ) -> PeerConnectionState<M> {
        let umsg = self.resend_queue.push(msg);
        trace!(target: LOG_NET_PEER, peer = ?self.peer_id, id = ?umsg.id, "Sending outgoing message");

        self.send_message_connected_inner(connected, Some(umsg))
            .await
    }

    async fn send_ping(
        &mut self,
        connected: ConnectedPeerConnectionState<M>,
    ) -> PeerConnectionState<M> {
        trace!(target: LOG_NET_PEER, our_id = ?self.our_id, peer = ?self.peer_id, "Sending ping");
        self.send_message_connected_inner(connected, None).await
    }

    async fn send_message_connected_inner(
        &mut self,
        mut connected: ConnectedPeerConnectionState<M>,
        maybe_msg: Option<UniqueMessage<M>>,
    ) -> PeerConnectionState<M> {
        if let Err(e) = connected
            .connection
            .send(PeerMessage {
                msg: maybe_msg,
                ack: self.last_received,
            })
            .await
        {
            return self.disconnect_err(e, 0);
        }

        connected.next_ping = Instant::now() + PING_INTERVAL;

        match connected.connection.flush().await {
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

        // Process ACK no matter if we received a message or not
        if let Some(ack) = ack {
            trace!(target: LOG_NET_PEER, our_id = ?self.our_id, peer = ?self.peer_id, ?ack, "Received ACK for sent message");
            self.resend_queue.ack(ack);
        }

        if let Some(msg) = msg {
            trace!(target: LOG_NET_PEER, peer = ?self.peer_id, id = ?msg.id, "Received incoming message");

            let expected = self
                .last_received
                .map(|last_id| last_id.increment())
                .unwrap_or(msg.id);

            if msg.id < expected {
                info!(target: LOG_NET_PEER,
                    ?expected, received = ?msg.id, "Received old message");
                return Ok(());
            }

            if msg.id > expected {
                warn!(target: LOG_NET_PEER, ?expected, received = ?msg.id, "Received message from the future");
                return Err(anyhow::anyhow!("Received message from the future"));
            }

            self.last_received = Some(expected);

            debug_assert_eq!(expected, msg.id, "someone removed the check above");
            if self.incoming.send(msg.msg).await.is_err() {
                // ignore error - if the other side is not there,
                // it means we're are probably shutting down
                debug!(
                    target: LOG_NET_PEER,
                    "Could not deliver message to recipient - probably shutting down"
                );
            }
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
                        debug!(target: LOG_NET_PEER, "Exiting peer connection IO task - parent disconnected");
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
                        debug!(target: LOG_NET_PEER, "Exiting peer connection IO task - parent disconnected");
                        return None;
                    },
                }
            },
            Some(status_query) = self.status_query_receiver.recv() => {
                if status_query.response_sender.send(PeerConnectionStatus::Disconnected).is_err() {
                    let peer_id = self.peer_id;
                    debug!(target: LOG_NET_PEER, %peer_id, "Could not send peer status response: receiver dropped");
                }
                PeerConnectionState::Disconnected(disconnected)
            },
            () = tokio::time::sleep_until(disconnected.reconnect_at), if self.our_id < self.peer_id => {
                // to prevent "reconnection ping-pongs", only the side with lower PeerId is responsible for reconnecting
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
        trace!(target: LOG_NET_PEER, id = ?umsg.id, "Queueing outgoing message");
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
        debug!(target: LOG_NET_PEER, our_id = ?self.our_id, peer = ?self.peer_id, "Trying to reconnect");
        let addr = self.peer_address.clone();
        let (connected_peer, conn) = self.connect.connect_framed(addr, self.peer_id).await?;

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
    async fn new(
        our_id: PeerId,
        peer_id: PeerId,
        peer_address: SafeUrl,
        delay_calculator: DelayCalculator,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_query_receiver: PeerStatusChannelReceiver,
        task_group: &mut TaskGroup,
    ) -> PeerConnection<M> {
        let (outgoing_sender, outgoing_receiver) = tokio::sync::mpsc::channel::<M>(1024);
        let (incoming_sender, incoming_receiver) = tokio::sync::mpsc::channel::<M>(1024);

        task_group
            .spawn(
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
                        status_query_receiver,
                        &handle,
                    )
                    .await
                },
            )
            .await;

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

    #[allow(clippy::too_many_arguments)] // TODO: consider refactoring
    #[instrument(skip_all, fields(peer))]
    async fn run_io_thread(
        incoming: Sender<M>,
        outgoing: Receiver<M>,
        our_id: PeerId,
        peer_id: PeerId,
        peer_address: SafeUrl,
        delay_calculator: DelayCalculator,
        connect: SharedAnyConnector<PeerMessage<M>>,
        incoming_connections: Receiver<AnyFramedTransport<PeerMessage<M>>>,
        status_query_receiver: PeerStatusChannelReceiver,
        task_handle: &TaskHandle,
    ) {
        let common = CommonPeerConnectionState {
            resend_queue: Default::default(),
            incoming,
            outgoing,
            our_id,
            peer_id,
            peer_address,
            delay_calculator,
            connect,
            incoming_connections,
            status_query_receiver,
            last_received: None,
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
    use std::collections::HashMap;
    use std::time::Duration;

    use fedimint_core::task::TaskGroup;
    use fedimint_core::PeerId;
    use futures::Future;

    use super::DelayCalculator;
    use crate::fedimint_core::net::peers::IPeerConnections;
    use crate::net::connect::mock::{MockNetwork, StreamReliability};
    use crate::net::connect::Connector;
    use crate::net::peers::NetworkConfig;
    use crate::net::peers_reliable::ReconnectPeerConnectionsReliable;

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
                let connect = net_ref
                    .connector(cfg.identity, StreamReliability::MILDLY_UNRELIABLE)
                    .into_dyn();
                ReconnectPeerConnectionsReliable::<u64>::new(
                    cfg,
                    DelayCalculator::TEST_DEFAULT,
                    connect,
                    &mut task_group,
                )
                .await
            };

            let (mut peers_a, peer_status_client_a) =
                build_peers("127.0.0.1:1000", 1, task_group.clone()).await;
            let (mut peers_b, peer_status_client_b) =
                build_peers("127.0.0.1:2000", 2, task_group.clone()).await;

            peers_a.send(&[PeerId::from(2)], 42).await.unwrap();
            let recv = timeout(peers_b.receive()).await.unwrap().unwrap();
            assert_eq!(recv.0, PeerId::from(1));
            assert_eq!(recv.1, 42);
            let status = peer_status_client_a.get_all_status().await;
            assert_eq!(status.len(), 2);
            assert!(status.values().all(|s| s.is_ok()));

            peers_a.send(&[PeerId::from(3)], 21).await.unwrap();
            let status = peer_status_client_b.get_all_status().await;
            assert_eq!(status.len(), 2);
            assert!(status.values().all(|s| s.is_ok()));

            let (mut peers_c, peer_status_client_c) =
                build_peers("127.0.0.1:3000", 3, task_group.clone()).await;
            let recv = timeout(peers_c.receive())
                .await
                .expect("time out")
                .expect("stream closed");
            assert_eq!(recv.0, PeerId::from(1));
            assert_eq!(recv.1, 21);
            let status = peer_status_client_c.get_all_status().await;
            assert_eq!(status.len(), 2);
            assert!(status.values().all(|s| s.is_ok()));
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
