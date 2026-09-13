//! Frozen behavioral fixture extracted from `net/p2p.rs` at
//! 46b195b5210908d43dd9276de236dbf1edc516e7. This does NOT call the new
//! manager, inspect its protocol tag, or negotiate dual sessions.
//!
//! Only status/metrics/logging, multi-peer dispatch and optional max-age are
//! omitted. Keep lower-ID dialing, replacement between sends, backoff, bounded
//! lossy queues and concurrent send/receive unchanged for mixed-peer tests.

use std::sync::Arc;

use async_channel::{Receiver, Sender};
use fedimint_core::PeerId;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::backoff_util::api_networking_backoff;

use crate::net::p2p_connection::DynP2PConnection;
use crate::net::p2p_connector::DynP2PConnector;

/// Single-peer old-manager fixture.
pub(super) struct LegacyManager {
    /// Original bounded outgoing queue.
    pub send: Sender<Vec<u8>>,
    /// Original bounded incoming queue.
    pub receive: Receiver<Vec<u8>>,
}

impl LegacyManager {
    pub(super) fn new(
        id: PeerId,
        peer: PeerId,
        connector: DynP2PConnector<Vec<u8>>,
        tasks: &TaskGroup,
    ) -> Self {
        let (send, outgoing) = async_channel::bounded(5);
        let (incoming, receive) = async_channel::bounded(5);
        let (candidates, accepted) = async_channel::bounded(4);
        let listener = Arc::clone(&connector);
        tasks.spawn_cancellable("frozen-old-listener", async move {
            loop {
                if let Ok((_, connection)) = listener.accept().await
                    && candidates.send(connection).await.is_err()
                {
                    return;
                }
            }
        });
        tasks.spawn_cancellable("frozen-old-manager", async move {
            let mut connection: Option<DynP2PConnection<Vec<u8>>> = None;
            let mut backoff = api_networking_backoff();
            loop {
                let Some(current) = connection.take() else {
                    connection = tokio::select! {
                        candidate = accepted.recv() => candidate.ok(),
                        () = sleep(backoff.next().expect("Unlimited retries")), if id < peer => {
                            connector.connect(peer).await.ok()
                        }
                    };
                    continue;
                };
                let send_loop = async {
                    loop {
                        let message = tokio::select! {
                            message = outgoing.recv() => match message {
                                Ok(message) => message,
                                Err(_) => return None,
                            },
                            replacement = accepted.recv() => return replacement.ok(),
                        };
                        if current.send(message).await.is_err() {
                            return None;
                        }
                    }
                };
                let receive_loop = async {
                    loop {
                        let Ok(mut frame) = current.receive().await else {
                            return;
                        };
                        let Ok(message) = frame.read_to_end().await else {
                            return;
                        };
                        let _ = incoming.try_send(message);
                    }
                };
                connection = tokio::select! {
                    replacement = send_loop => replacement,
                    () = receive_loop => None,
                };
                backoff = api_networking_backoff();
            }
        });
        Self { send, receive }
    }
}
