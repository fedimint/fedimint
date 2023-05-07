use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use async_trait::async_trait;
use fedimint_core::cancellable::{Cancellable, Cancelled};
use fedimint_core::net::peers::{IMuxPeerConnections, PeerConnections};
use fedimint_logging::LOG_NET_PEER;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::PeerId;

/// TODO: Use proper ModuleId after modularization is complete
pub type ModuleId = String;
pub type ModuleIdRef<'a> = &'a str;

/// Amount of per-peer messages after which we will stop throwing them away.
///
/// It's hard to predict how many messages is too many, but we have
/// to draw the line somewhere.
pub const MAX_PEER_OUT_OF_ORDER_MESSAGES: u64 = 10000;

/// A `Msg` that can target a specific destination module
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleMultiplexed<MuxKey, Msg> {
    pub key: MuxKey,
    pub msg: Msg,
}

struct ModuleMultiplexerOutOfOrder<MuxKey, Msg> {
    /// Cached messages per `ModuleId` waiting for callback
    msgs: HashMap<MuxKey, VecDeque<(PeerId, Msg)>>,
    /// Callback queue from tasks that want to receive
    callbacks: HashMap<MuxKey, VecDeque<oneshot::Sender<(PeerId, Msg)>>>,
    /// Track pending messages per peer to avoid a potential DoS
    peer_counts: HashMap<PeerId, u64>,
}

impl<MuxKey, Msg> Default for ModuleMultiplexerOutOfOrder<MuxKey, Msg> {
    fn default() -> Self {
        Self {
            msgs: Default::default(),
            callbacks: Default::default(),
            peer_counts: Default::default(),
        }
    }
}

/// A wrapper around `AnyPeerConnections` multiplexing communication between
/// multiple modules over it
///
/// This works by addressing each module when sending, and handling buffering
/// messages received out of order until they are requested.
///
/// This type is thread-safe and can be cheaply cloned.
#[derive(Clone)]
pub struct PeerConnectionMultiplexer<MuxKey, Msg> {
    /// Sender of send requests
    send_requests_tx: Sender<(Vec<PeerId>, MuxKey, Msg)>,
    /// Sender of receive callbacks
    receive_callbacks_tx: Sender<Callback<MuxKey, Msg>>,
    /// Sender of peer bans
    peer_bans_tx: Sender<PeerId>,
}

type Callback<MuxKey, Msg> = (MuxKey, oneshot::Sender<(PeerId, Msg)>);

impl<MuxKey, Msg> PeerConnectionMultiplexer<MuxKey, Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send + Debug + 'static,
    MuxKey: Serialize + DeserializeOwned + Unpin + Send + Debug + Eq + Hash + Clone + 'static,
{
    pub fn new(connections: PeerConnections<ModuleMultiplexed<MuxKey, Msg>>) -> Self {
        let (send_requests_tx, send_requests_rx) = channel(1000);
        let (receive_callbacks_tx, receive_callbacks_rx) = channel(1000);
        let (peer_bans_tx, peer_bans_rx) = channel(1000);

        tokio::spawn(Self::run(
            connections,
            Default::default(),
            send_requests_rx,
            receive_callbacks_rx,
            peer_bans_rx,
        ));

        Self {
            send_requests_tx,
            receive_callbacks_tx,
            peer_bans_tx,
        }
    }

    async fn run(
        mut connections: PeerConnections<ModuleMultiplexed<MuxKey, Msg>>,
        mut out_of_order: ModuleMultiplexerOutOfOrder<MuxKey, Msg>,
        mut send_requests_rx: Receiver<(Vec<PeerId>, MuxKey, Msg)>,
        mut receive_callbacks_rx: Receiver<Callback<MuxKey, Msg>>,
        mut peer_bans_rx: Receiver<PeerId>,
    ) -> Cancellable<()> {
        loop {
            let mut key_inserted: Option<MuxKey> = None;
            tokio::select! {
                 // Send requests are forwarded to underlying connections
                 send_request = send_requests_rx.recv() => {
                    let (peers, key, msg) = send_request.ok_or(Cancelled)?;
                    connections.send(&peers, ModuleMultiplexed { key, msg }).await?;
                }
                // Ban requests are forwarded to underlying connections
                peer_ban = peer_bans_rx.recv() => {
                    let peer = peer_ban.ok_or(Cancelled)?;
                    connections.ban_peer(peer).await;
                }
                // Receive callbacks are added to callback queue by key
                receive_callback = receive_callbacks_rx.recv() => {
                    let (key, callback) = receive_callback.ok_or(Cancelled)?;
                    out_of_order.callbacks.entry(key.clone()).or_default().push_back(callback);
                    key_inserted = Some(key);
                }
                // Actual received messages are added message queue by key
                receive = connections.receive() => {
                    let (peer, ModuleMultiplexed { key, msg }) = receive?;
                    let peer_pending = out_of_order.peer_counts.entry(peer).or_default();
                    // We limit our messages from any given peer to avoid OOM
                    // In practice this would halt DKG
                    if *peer_pending > MAX_PEER_OUT_OF_ORDER_MESSAGES {
                        warn!(
                            target: LOG_NET_PEER,
                            "Peer {peer} has {peer_pending} pending messages. Dropping new message."
                        );
                    } else {
                        *peer_pending += 1;
                        out_of_order.msgs.entry(key.clone()).or_default().push_back((peer, msg));
                        key_inserted = Some(key);
                    }
                }
            }

            // If a key was inserted, check to see if we can fulfill a callback
            if let Some(key) = key_inserted {
                let callbacks = out_of_order.callbacks.entry(key.clone()).or_default();
                let msgs = out_of_order.msgs.entry(key.clone()).or_default();

                if !callbacks.is_empty() && !msgs.is_empty() {
                    let callback = callbacks.pop_front().expect("checked");
                    let (peer, msg) = msgs.pop_front().expect("checked");
                    let peer_pending = out_of_order.peer_counts.entry(peer).or_default();
                    *peer_pending -= 1;
                    callback.send((peer, msg)).map_err(|_| Cancelled)?;
                }
            }
        }
    }
}

#[async_trait]
impl<MuxKey, Msg> IMuxPeerConnections<MuxKey, Msg> for PeerConnectionMultiplexer<MuxKey, Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send + Debug,
    MuxKey: Serialize + DeserializeOwned + Unpin + Send + Debug + Eq + Hash + Clone,
{
    async fn send(&self, peers: &[PeerId], key: MuxKey, msg: Msg) -> Cancellable<()> {
        debug!("Sending to {peers:?}/{key:?}, {msg:?}");
        self.send_requests_tx
            .send((peers.to_vec(), key, msg))
            .await
            .map_err(|_e| Cancelled)
    }

    /// Await receipt of a message from any connected peer.
    async fn receive(&self, key: MuxKey) -> Cancellable<(PeerId, Msg)> {
        let (callback_tx, callback_rx) = oneshot::channel();
        self.receive_callbacks_tx
            .send((key, callback_tx))
            .await
            .map_err(|_e| Cancelled)?;
        callback_rx.await.map_err(|_e| Cancelled)
    }

    async fn ban_peer(&self, peer: PeerId) {
        // We don't return a `Cancellable` for bans
        let _ = self.peer_bans_tx.send(peer).await;
    }
}

#[cfg(test)]
pub mod test {
    use std::time::Duration;

    use fedimint_core::net::peers::fake::make_fake_peer_connection;
    use fedimint_core::net::peers::IMuxPeerConnections;
    use fedimint_core::task::TaskGroup;
    use fedimint_core::PeerId;
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};
    use tokio::time::sleep;

    use crate::multiplexed::PeerConnectionMultiplexer;

    /// Send over many messages a multiplexed fake link
    ///
    /// Some things this is checking for:
    ///
    /// * no message were missed
    /// * messages arrived in order (from PoW of each module)
    /// * nothing deadlocked somewhere.
    #[test_log::test(tokio::test)]
    async fn test_multiplexer() {
        const NUM_MODULES: usize = 128;
        const NUM_MSGS_PER_MODULE: usize = 128;
        const NUM_REPEAT_TEST: usize = 10;

        for _ in 0..NUM_REPEAT_TEST {
            let mut task_group = TaskGroup::new();
            let task_handle = task_group.make_handle();

            let peer1 = PeerId::from(0);
            let peer2 = PeerId::from(1);

            let (conn1, conn2) = make_fake_peer_connection(peer1, peer2, 1000, task_handle.clone());
            let (conn1, conn2) = (
                PeerConnectionMultiplexer::new(conn1).into_dyn(),
                PeerConnectionMultiplexer::new(conn2).into_dyn(),
            );

            let mut modules: Vec<_> = (0..NUM_MODULES).collect();
            modules.shuffle(&mut thread_rng());

            for mux_key in modules.clone() {
                let conn1 = conn1.clone();
                let task_handle = task_handle.clone();
                task_group
                    .spawn(format!("sender-{mux_key}"), move |_| async move {
                        for msg_i in 0..NUM_MSGS_PER_MODULE {
                            // add some random jitter
                            if OsRng.gen() {
                                // Note that randomized sleep in sender is larger than
                                // in receiver, to avoid just running with always full
                                // queues.
                                sleep(Duration::from_millis(2)).await;
                            }
                            if task_handle.is_shutting_down() {
                                break;
                            }
                            conn1.send(&[peer2], mux_key, msg_i).await.unwrap();
                        }
                    })
                    .await;
            }

            modules.shuffle(&mut thread_rng());
            for mux_key in modules.clone() {
                let conn2 = conn2.clone();
                task_group
                    .spawn(format!("receiver-{mux_key}"), move |_| async move {
                        for msg_i in 0..NUM_MSGS_PER_MODULE {
                            // add some random jitter
                            if OsRng.gen() {
                                sleep(Duration::from_millis(1)).await;
                            }
                            assert_eq!(conn2.receive(mux_key).await.unwrap(), (peer1, msg_i));
                        }
                    })
                    .await;
            }

            task_group.join_all(None).await.expect("no failures");
        }
    }
}
