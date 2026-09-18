//! Implements a connection manager for communication with other federation
//! members
//!
//! The main interface is [`fedimint_core::net::IP2PConnections`] and
//! its main implementation is [`ReconnectP2PConnections`], see these for
//! details.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::anyhow;
use async_channel::{Receiver, Sender, bounded};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::net::{IP2PConnections, Recipient};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::util::backoff_util::{FibonacciBackoff, api_networking_backoff};
use fedimint_logging::{LOG_CONSENSUS, LOG_NET_PEER};
use fedimint_server_core::dashboard_ui::P2PConnectionStatus;
use futures::future::select_all;
use futures::{FutureExt, StreamExt};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::metrics::{PEER_CONNECT_COUNT, PEER_DISCONNECT_COUNT, PEER_MESSAGES_COUNT};
use crate::net::p2p_connection::{DynConnectionStatusUpdates, DynP2PConnection};
use crate::net::p2p_connector::DynP2PConnector;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2PConnectionState {
    /// Current connection metadata, or `None` if disconnected.
    pub connected: Option<P2PConnectionStatus>,
    /// Last disconnect/connect error observed while disconnected.
    pub last_error: Option<String>,
}

pub type P2PStatusSenders = BTreeMap<PeerId, watch::Sender<P2PConnectionState>>;
pub type P2PStatusReceivers = BTreeMap<PeerId, watch::Receiver<P2PConnectionState>>;

pub fn p2p_status_channels(peers: Vec<PeerId>) -> (P2PStatusSenders, P2PStatusReceivers) {
    let mut senders = BTreeMap::new();
    let mut receivers = BTreeMap::new();

    for peer in peers {
        let (sender, receiver) = watch::channel(P2PConnectionState {
            connected: None,
            last_error: None,
        });

        senders.insert(peer, sender);
        receivers.insert(peer, receiver);
    }

    (senders, receivers)
}

#[derive(Clone)]
pub struct ReconnectP2PConnections<M> {
    connections: BTreeMap<PeerId, P2PConnection<M>>,
}

impl<M: Send + 'static> ReconnectP2PConnections<M> {
    pub fn new(
        identity: PeerId,
        connector: DynP2PConnector<M>,
        task_group: &TaskGroup,
        status_senders: P2PStatusSenders,
        max_connection_age: Option<Duration>,
    ) -> Self {
        let mut connection_senders = BTreeMap::new();
        let mut connections = BTreeMap::new();

        for peer_id in connector.peers() {
            assert_ne!(peer_id, identity);

            let (connection_sender, connection_receiver) = bounded(4);

            let connection = P2PConnection::new(
                identity,
                peer_id,
                connector.clone(),
                connection_receiver,
                status_senders
                    .get(&peer_id)
                    .expect("No p2p status sender for peer")
                    .clone(),
                max_connection_age,
                task_group,
            );

            connection_senders.insert(peer_id, connection_sender);
            connections.insert(peer_id, connection);
        }

        task_group.spawn_cancellable("handle-incoming-p2p-connections", async move {
            info!(target: LOG_NET_PEER, "Starting listening task for p2p connections");

            loop {
                match connector.accept().await {
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
                        warn!(target: LOG_NET_PEER, our_id = %identity, err = %err.fmt_compact_anyhow(), "Error while opening incoming connection");
                    }
                }
            }

            info!(target: LOG_NET_PEER, "Shutting down listening task for p2p connections");
        });

        ReconnectP2PConnections { connections }
    }
}

#[async_trait]
impl<M: Clone + Send + 'static> IP2PConnections<M> for ReconnectP2PConnections<M> {
    fn send(&self, recipient: Recipient, message: M) {
        match recipient {
            Recipient::Everyone => {
                for connection in self.connections.values() {
                    connection.try_send(message.clone());
                }
            }
            Recipient::Peer(peer) => match self.connections.get(&peer) {
                Some(connection) => {
                    connection.try_send(message);
                }
                _ => {
                    warn!(target: LOG_NET_PEER, "No connection for peer {peer}");
                }
            },
        }
    }

    async fn receive(&self) -> Option<(PeerId, M)> {
        select_all(self.connections.iter().map(|(&peer, connection)| {
            Box::pin(connection.receive().map(move |m| m.map(|m| (peer, m))))
        }))
        .await
        .0
    }

    async fn receive_from_peer(&self, peer: PeerId) -> Option<M> {
        self.connections
            .get(&peer)
            .expect("No connection found for peer")
            .receive()
            .await
    }
}

#[derive(Clone)]
struct P2PConnection<M> {
    outgoing_sender: Sender<M>,
    incoming_receiver: Receiver<M>,
}

impl<M: Send + 'static> P2PConnection<M> {
    fn new(
        our_id: PeerId,
        peer_id: PeerId,
        connector: DynP2PConnector<M>,
        incoming_connections: Receiver<DynP2PConnection<M>>,
        status_sender: watch::Sender<P2PConnectionState>,
        max_connection_age: Option<Duration>,
        task_group: &TaskGroup,
    ) -> P2PConnection<M> {
        // We use small message queues here to avoid outdated messages such as requests
        // for signed session outcomes to queue up while a peer is disconnected. The
        // consensus expects an unreliable networking layer and will resend lost
        // messages accordingly. Furthermore, during the DKG there will never be more
        // than two messages in those channels at once, due to its sequential
        // nature there.
        let (outgoing_sender, outgoing_receiver) = bounded(5);
        let (incoming_sender, incoming_receiver) = bounded(5);

        task_group.spawn_cancellable(
            format!("io-state-machine-{peer_id}"),
            async move {
                info!(target: LOG_NET_PEER, "Starting peer connection state machine");

                let mut state_machine = P2PConnectionStateMachine {
                    common: P2PConnectionSMCommon {
                        incoming_sender,
                        outgoing_receiver,
                        our_id_str: our_id.to_string(),
                        our_id,
                        peer_id_str: peer_id.to_string(),
                        peer_id,
                        connector,
                        incoming_connections,
                        status_sender,
                        max_connection_age,
                        connection_deadline: None,
                    },
                    state: P2PConnectionSMState::Disconnected {
                        backoff: api_networking_backoff(),
                        last_error: None,
                    },
                };

                while let Some(sm) = state_machine.state_transition().await {
                    state_machine = sm;
                }

                info!(target: LOG_NET_PEER, "Shutting down peer connection state machine");
            }
            .instrument(info_span!("io-state-machine", ?peer_id)),
        );

        P2PConnection {
            outgoing_sender,
            incoming_receiver,
        }
    }

    fn try_send(&self, message: M) {
        if self.outgoing_sender.try_send(message).is_err() {
            debug!(target: LOG_NET_PEER, "Outgoing message channel is full");
        }
    }

    async fn receive(&self) -> Option<M> {
        self.incoming_receiver.recv().await.ok()
    }
}

struct P2PConnectionStateMachine<M> {
    state: P2PConnectionSMState<M>,
    common: P2PConnectionSMCommon<M>,
}

struct P2PConnectionSMCommon<M> {
    incoming_sender: async_channel::Sender<M>,
    outgoing_receiver: async_channel::Receiver<M>,
    our_id: PeerId,
    our_id_str: String,
    peer_id: PeerId,
    peer_id_str: String,
    connector: DynP2PConnector<M>,
    incoming_connections: Receiver<DynP2PConnection<M>>,
    status_sender: watch::Sender<P2PConnectionState>,
    /// Drop a connection once it exceeds this age so it is re-established;
    /// disabled if `None`.
    max_connection_age: Option<Duration>,
    /// Point in time at which the current connection exceeds the maximum
    /// age; set whenever a new connection is established.
    connection_deadline: Option<Instant>,
}

enum P2PConnectionSMState<M> {
    Disconnected {
        backoff: FibonacciBackoff,
        last_error: Option<String>,
    },
    Connected(DynP2PConnection<M>),
}

/// How often live connection metadata (currently only the round-trip time) is
/// re-published while a connection stays up.
const METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Why the send half of the connection stopped.
enum SendHalt<M> {
    /// The state machine is shutting down.
    Shutdown,
    /// The connection failed and should be re-established.
    Failed(anyhow::Error),
    /// The peer opened a replacement connection that supersedes this one.
    Replaced(DynP2PConnection<M>),
    /// The connection exceeded the maximum age and should be re-established.
    MaxAge,
}

impl<M: Send + 'static> P2PConnectionStateMachine<M> {
    async fn state_transition(mut self) -> Option<Self> {
        match self.state {
            P2PConnectionSMState::Disconnected {
                backoff,
                last_error,
            } => {
                self.common.status_sender.send_replace(P2PConnectionState {
                    connected: None,
                    last_error,
                });

                self.common.transition_disconnected(backoff).await
            }
            P2PConnectionSMState::Connected(connection) => {
                // Subscribe before taking the snapshot so an update racing with
                // the snapshot remains queued for the connected transition.
                let status_updates = connection.connection_status_updates();

                self.common.refresh_status(&connection);

                self.common
                    .transition_connected(connection, status_updates)
                    .await
            }
        }
        .map(|state| P2PConnectionStateMachine {
            common: self.common,
            state,
        })
    }
}

impl<M: Send + 'static> P2PConnectionSMCommon<M> {
    async fn transition_connected(
        &mut self,
        connection: DynP2PConnection<M>,
        mut status_updates: Option<DynConnectionStatusUpdates>,
    ) -> Option<P2PConnectionSMState<M>> {
        // The send and receive halves are driven as two long-lived futures that
        // are never cancelled part-way through a message. Multiplexing a single
        // send and a single receive in one `select!` meant that a send parked on
        // transport flow control could no longer poll `receive`, so two peers
        // that both started writing a message larger than the transport window
        // deadlocked permanently and silently.
        //
        // Interleaving reads inside the parked send is *not* sufficient: it just
        // turns a write/write deadlock into a read/read one. The halves have to
        // be genuinely concurrent.
        //
        // Replacement connections and the max-age deadline are observed inside
        // the send half, between messages, so they can never cancel a send that
        // is already in flight.
        let send_loop = Self::send_loop(
            &connection,
            &self.outgoing_receiver,
            &self.incoming_connections,
            self.connection_deadline,
            &self.our_id_str,
            &self.peer_id_str,
        );
        let receive_loop = Self::receive_loop(
            &connection,
            &self.incoming_sender,
            &self.our_id_str,
            &self.peer_id_str,
        );

        tokio::pin!(send_loop, receive_loop);

        loop {
            tokio::select! {
                halt = &mut send_loop => {
                    return match halt {
                        SendHalt::Shutdown => None,
                        SendHalt::Failed(e) => Some(self.disconnect(e)),
                        SendHalt::MaxAge => {
                            Some(self.disconnect(anyhow!("Connection exceeded the maximum age")))
                        }
                        SendHalt::Replaced(connection) => {
                            info!(target: LOG_NET_PEER, "Connected to peer");

                            self.connection_deadline =
                                self.max_connection_age.map(|age| Instant::now() + age);

                            Some(P2PConnectionSMState::Connected(connection))
                        }
                    };
                },
                e = &mut receive_loop => {
                    return Some(self.disconnect(e));
                },
                Some(()) = async {
                    match status_updates.as_mut() {
                        Some(status_updates) => status_updates.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.refresh_status(&connection);
                },
                () = sleep(METADATA_REFRESH_INTERVAL) => {
                    // Connection metadata used to be refreshed as a side effect
                    // of every message, which the long-lived halves no longer
                    // provide. Only `rtt` needs this; transport changes still
                    // arrive on the status update stream above.
                    self.refresh_status(&connection);
                },
            }
        }
    }

    /// Drains the outgoing queue onto the connection. Replacement connections
    /// and the max-age deadline are observed here, between sends, so they can
    /// never cancel the non-cancel-safe `send` and silently drop a message
    /// that the DKG would not resend. Only a failure of the connection itself
    /// can still lose the message in flight; the networking layer is
    /// unreliable by design.
    async fn send_loop(
        connection: &DynP2PConnection<M>,
        outgoing_receiver: &Receiver<M>,
        incoming_connections: &Receiver<DynP2PConnection<M>>,
        connection_deadline: Option<Instant>,
        our_id_str: &str,
        peer_id_str: &str,
    ) -> SendHalt<M> {
        loop {
            // All branches are cancel-safe: `recv` on an async channel does not
            // take an item unless it completes and the timer holds no state.
            let message = tokio::select! {
                message = outgoing_receiver.recv() => match message {
                    Ok(message) => message,
                    Err(..) => return SendHalt::Shutdown,
                },
                connection = incoming_connections.recv() => return match connection {
                    Ok(connection) => SendHalt::Replaced(connection),
                    Err(..) => SendHalt::Shutdown,
                },
                () = async {
                    match connection_deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => return SendHalt::MaxAge,
            };

            PEER_MESSAGES_COUNT
                .with_label_values(&[our_id_str, peer_id_str, "outgoing"])
                .inc();

            if let Err(e) = connection.send(message).await {
                return SendHalt::Failed(e);
            }
        }
    }

    /// Drains the connection into the incoming queue. Only returns when the
    /// connection fails.
    async fn receive_loop(
        connection: &DynP2PConnection<M>,
        incoming_sender: &Sender<M>,
        our_id_str: &str,
        peer_id_str: &str,
    ) -> anyhow::Error {
        loop {
            let mut frame = match connection.receive().await {
                Ok(frame) => frame,
                Err(e) => return e,
            };

            match frame.read_to_end().await {
                Ok(message) => {
                    PEER_MESSAGES_COUNT
                        .with_label_values(&[our_id_str, peer_id_str, "incoming"])
                        .inc();

                    if incoming_sender.try_send(message).is_err() {
                        debug!(target: LOG_NET_PEER, "Incoming message channel is full");
                    }
                }
                Err(e) => return e,
            }
        }
    }

    /// Publishes a fresh metadata snapshot for the live connection.
    ///
    /// Refreshing in place rather than re-entering the connected state means a
    /// send already in flight is never cancelled by a status event.
    fn refresh_status(&self, connection: &DynP2PConnection<M>) {
        let status = P2PConnectionStatus {
            conn_type: connection
                .connection_type()
                .or_else(|| self.connector.connection_type(self.peer_id)),
            rtt: connection.rtt(),
        };

        self.status_sender.send_replace(P2PConnectionState {
            connected: Some(status),
            last_error: None,
        });
    }

    fn disconnect(&self, error: anyhow::Error) -> P2PConnectionSMState<M> {
        let last_error = error.fmt_compact_anyhow().to_string();

        info!(
            target: LOG_NET_PEER,
            error = %last_error,
            "Disconnected from peer"
        );

        PEER_DISCONNECT_COUNT
            .with_label_values(&[&self.our_id_str, &self.peer_id_str])
            .inc();

        P2PConnectionSMState::Disconnected {
            backoff: api_networking_backoff(),
            last_error: Some(last_error),
        }
    }

    async fn transition_disconnected(
        &mut self,
        mut backoff: FibonacciBackoff,
    ) -> Option<P2PConnectionSMState<M>> {
        tokio::select! {
            connection = self.incoming_connections.recv() => {
                PEER_CONNECT_COUNT
                    .with_label_values(&[self.our_id_str.as_str(), self.peer_id_str.as_str(), "incoming"])
                    .inc();

                info!(target: LOG_NET_PEER, "Connected to peer");

                self.connection_deadline = self.max_connection_age.map(|age| Instant::now() + age);

                Some(P2PConnectionSMState::Connected(connection.ok()?))
            },
            // to prevent "reconnection ping-pongs", only the side with lower PeerId reconnects
            () = sleep(backoff.next().expect("Unlimited retries")), if self.our_id < self.peer_id => {
                info!(target: LOG_NET_PEER, "Attempting to reconnect to peer");

                match self.connector.connect(self.peer_id).await {
                    Ok(connection) => {
                        PEER_CONNECT_COUNT
                            .with_label_values(&[self.our_id_str.as_str(), self.peer_id_str.as_str(), "outgoing"])
                            .inc();

                        info!(target: LOG_NET_PEER, "Connected to peer");

                        self.connection_deadline = self.max_connection_age.map(|age| Instant::now() + age);

                        Some(P2PConnectionSMState::Connected(connection))
                    }
                    Err(e) => {
                        let last_error = e.fmt_compact_anyhow().to_string();

                        warn!(
                            target: LOG_CONSENSUS,
                            error = %last_error,
                            "Failed to connect to peer"
                        );

                        Some(P2PConnectionSMState::Disconnected {
                            backoff,
                            last_error: Some(last_error),
                        })
                    }
                }
            },
        }
    }
}
