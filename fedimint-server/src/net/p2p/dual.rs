//! Experimental sender-owned lifecycle. Futures belong to slots, not detached
//! tasks: retiring a slot drops its future, so stale completions cannot affect
//! a replacement. The legacy bidirectional lifecycle stays in the parent
//! module.

use std::future::pending;

use anyhow::anyhow;
use fedimint_core::task::sleep;
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_logging::LOG_NET_PEER;
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, info};

use super::{
    METADATA_REFRESH_INTERVAL, P2PConnectionSMCommon, P2PConnectionSMState, P2PConnectionState,
};
use crate::metrics::PEER_MESSAGES_COUNT;
use crate::net::p2p_connection::DynP2PConnection;
use crate::net::p2p_connector::P2PProtocol;

/// One independently owned application direction and its long-lived IO future.
struct Slot<M> {
    /// Live connection, also used for the outgoing metadata snapshot.
    connection: DynP2PConnection<M>,
    /// Completes on failure (or sender-owned age retirement).
    io: BoxFuture<'static, anyhow::Error>,
}

impl<M: Send + 'static> P2PConnectionSMCommon<M> {
    /// Run two independent slots, with exactly one application queue consumer.
    pub(super) async fn transition_dual(
        &mut self,
        outgoing: Option<DynP2PConnection<M>>,
        incoming: Option<DynP2PConnection<M>>,
    ) -> Option<P2PConnectionSMState<M>> {
        let mut outgoing = outgoing.map(|connection| self.outgoing_slot(connection));
        let mut incoming = incoming.map(|connection| self.incoming_slot(connection));
        let lower = self.our_id < self.peer_id;
        let mut reverse_allowed = incoming.is_some();
        let mut backoff = api_networking_backoff();
        let mut dialing: Option<BoxFuture<'static, anyhow::Result<DynP2PConnection<M>>>> = None;
        let mut last_error = None;
        let mut refresh = tokio::time::interval(METADATA_REFRESH_INTERVAL);

        loop {
            if outgoing.is_none() && dialing.is_none() && (lower || reverse_allowed) {
                let connector = self.connector.clone();
                let peer = self.peer_id;
                let delay = backoff.next().expect("Unlimited retries");
                dialing = Some(
                    async move {
                        sleep(delay).await;
                        if lower {
                            connector.connect(peer).await
                        } else {
                            connector.connect_dual(peer).await
                        }
                    }
                    .boxed(),
                );
            }

            if let (Some(outgoing), Some(_)) = (&outgoing, &incoming) {
                // Existing dashboard fields describe the outgoing session.
                self.refresh_status(&outgoing.connection);
            } else {
                self.status_sender.send_replace(P2PConnectionState {
                    connected: None,
                    last_error: last_error.clone(),
                });
            }

            tokio::select! {
                // Observe a ready EOF before considering a replacement candidate.
                biased;
                error = async {
                    match &mut incoming {
                        Some(slot) => (&mut slot.io).await,
                        None => pending().await,
                    }
                } => {
                    info!(target: LOG_NET_PEER, direction = "incoming", protocol = "dual-v1",
                        error = %error.fmt_compact_anyhow(), "P2P session ended");
                    incoming = None;
                    last_error = Some(error.fmt_compact_anyhow().to_string());
                }
                error = async {
                    match &mut outgoing {
                        Some(slot) => (&mut slot.io).await,
                        None => pending().await,
                    }
                } => {
                    info!(target: LOG_NET_PEER, direction = "outgoing", protocol = "dual-v1",
                        error = %error.fmt_compact_anyhow(), "P2P session ended");
                    outgoing = None;
                    last_error = Some(error.fmt_compact_anyhow().to_string());
                }
                result = async {
                    match &mut dialing {
                        Some(future) => future.await,
                        None => pending().await,
                    }
                } => {
                    dialing = None;
                    match result {
                        Ok(connection) if connection.protocol() == P2PProtocol::DualV1 => {
                            outgoing = Some(self.outgoing_slot(connection));
                            backoff = api_networking_backoff();
                        }
                        Ok(connection) if lower => {
                            // Positive legacy negotiation, never a timeout heuristic.
                            self.connection_deadline =
                                self.max_connection_age.map(|age| Instant::now() + age);
                            return Some(P2PConnectionSMState::Connected(connection));
                        }
                        Ok(_) => {
                            // An old TLS listener can accept a dual-only offer without
                            // selecting ALPN. Drop that stale reverse attempt, revoke
                            // permission even if an old incoming slot still looks live,
                            // and wait for fresh authenticated discovery.
                            reverse_allowed = false;
                            last_error = Some("Reverse dial negotiated legacy; waiting for discovery".to_owned());
                        }
                        Err(error) => {
                            if incoming.is_none() {
                                reverse_allowed = false;
                            }
                            last_error = Some(error.fmt_compact_anyhow().to_string());
                        }
                    }
                }
                candidate = self.incoming_connections.recv() => {
                    let connection = candidate.ok()?;
                    match connection.protocol() {
                        P2PProtocol::DualV1 if incoming.is_none() => {
                            incoming = Some(self.incoming_slot(connection));
                            reverse_allowed = true;
                        }
                        P2PProtocol::Legacy if !lower => {
                            // Only an old lower peer normally dials. Release both
                            // obsolete dual slots before the legacy consumer starts.
                            self.connection_deadline =
                                self.max_connection_age.map(|age| Instant::now() + age);
                            return Some(P2PConnectionSMState::Connected(connection));
                        }
                        _ => {
                            debug!(target: LOG_NET_PEER, protocol = ?connection.protocol(),
                                "Rejecting duplicate or unexpected incoming session");
                        }
                    }
                }
                _ = refresh.tick() => {}
            }
        }
    }

    /// The outgoing monitor runs even while idle or parked inside a send.
    fn outgoing_slot(&self, connection: DynP2PConnection<M>) -> Slot<M> {
        let outgoing_receiver = self.outgoing_receiver.clone();
        let deadline = self.max_connection_age.map(|age| Instant::now() + age);
        let our_id = self.our_id_str.clone();
        let peer_id = self.peer_id_str.clone();
        let io_connection = connection.clone();
        Slot {
            connection,
            io: async move {
                let send = async {
                    loop {
                        let message = tokio::select! {
                            message = outgoing_receiver.recv() => match message {
                                Ok(message) => message,
                                Err(_) => return anyhow!("Outgoing queue closed"),
                            },
                            () = async {
                                match deadline {
                                    Some(deadline) => sleep_until(deadline).await,
                                    None => pending().await,
                                }
                            } => return anyhow!("Outgoing session exceeded the maximum age"),
                        };
                        PEER_MESSAGES_COUNT.with_label_values(&[our_id.as_str(), peer_id.as_str(), "outgoing"]).inc();
                        if let Err(error) = io_connection.send(message).await {
                            return error;
                        }
                    }
                };
                tokio::select! {
                    error = send => error,
                    result = io_connection.receive() => match result {
                        Err(error) => error,
                        Ok(_) => anyhow!("Application frame received on sender-owned outgoing session"),
                    },
                }
            }.boxed(),
        }
    }

    /// Receivers never rotate the remote sender's session based on local age.
    fn incoming_slot(&self, connection: DynP2PConnection<M>) -> Slot<M> {
        let sender = self.incoming_sender.clone();
        let our_id = self.our_id_str.clone();
        let peer_id = self.peer_id_str.clone();
        let io_connection = connection.clone();
        Slot {
            connection,
            io: async move { Self::receive_loop(&io_connection, &sender, &our_id, &peer_id).await }
                .boxed(),
        }
    }
}
