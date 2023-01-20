use std::fmt::Debug;
use std::hash::Hash;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::net::peers::{IMuxPeerConnections, PeerConnections};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{sync::Mutex, time::sleep};
use tracing::{debug, error};

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
    /// Messages per `ModuleId` in a queue each
    msgs: HashMap<MuxKey, VecDeque<(PeerId, Msg)>>,
    /// Track pending messages per peer to avoid a potential DoS
    peer_counts: HashMap<PeerId, u64>,
}

impl<MuxKey, Msg> Default for ModuleMultiplexerOutOfOrder<MuxKey, Msg> {
    fn default() -> Self {
        Self {
            msgs: Default::default(),
            peer_counts: Default::default(),
        }
    }
}

/// Shared, mutable (wrapped in mutex) data of [`PeerConnectionMultiplexer`].
struct ModuleMultiplexerInner<MuxKey, Msg> {
    /// Underlying connection pool
    connections: Mutex<PeerConnections<ModuleMultiplexed<MuxKey, Msg>>>,
    /// Messages that arrived before an interested thread asked for them
    out_of_order: Mutex<ModuleMultiplexerOutOfOrder<MuxKey, Msg>>,
}

/// A wrapper around `AnyPeerConnections` multiplexing communication between multiple modules over it
///
/// This works by addressing each module when sending, and handling buffering messages received
/// out of order until they are requested.
///
/// This type is thread-safe and can be cheaply cloned.
#[derive(Clone)]
pub struct PeerConnectionMultiplexer<MuxKey, Msg> {
    inner: Arc<ModuleMultiplexerInner<MuxKey, Msg>>,
}

impl<MuxKey, Msg> PeerConnectionMultiplexer<MuxKey, Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send + Debug,
    MuxKey: Serialize + DeserializeOwned + Unpin + Send + Debug + Eq + Hash + Clone,
{
    pub fn new(connections: PeerConnections<ModuleMultiplexed<MuxKey, Msg>>) -> Self {
        Self {
            inner: Arc::new(ModuleMultiplexerInner {
                connections: Mutex::new(connections),
                out_of_order: Default::default(),
            }),
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
        self.inner
            .connections
            .lock()
            .await
            .send(peers, ModuleMultiplexed { key, msg })
            .await
    }

    /// Await receipt of a message from any connected peer.
    //
    // TODO: I don't think this is cancelation-correct. --dpc
    async fn receive(&self, key: MuxKey) -> Cancellable<(PeerId, Msg)> {
        loop {
            // Note: tokio locks are FIFO, so no need to sleep between loop iterations,
            // as each thread should get a chance to check for a message.
            // However, there is a one minor problem with this implementation -
            // other threads can only check if there is something for them,
            // when
            // Note: Naive implementation could have some subtle problems. If
            // one lock was used, either other threads could not check `out_of_order`
            // while some thread is blocked (and holding the lock) in `recv`,
            // or there would be subtle errors where a thread could miss a newly
            // received item and go into `recv`, possibly blocking indefinitely
            // if no more messages are being delivered.
            let mut out_of_order = self.inner.out_of_order.lock().await;
            if let Some(queue) = out_of_order.msgs.get_mut(&key) {
                if let Some(existing) = queue.pop_front() {
                    *out_of_order
                        .peer_counts
                        .get_mut(&existing.0)
                        .expect("peer must have an entry if had a message already") -= 1;
                    return Ok(existing);
                }
            }

            // try lock is used to avoid a deadlock (see below)
            if let Ok(mut connections) = self.inner.connections.try_lock() {
                // `out_of_order` lock guard is dropped *after* we obtained `connections`,
                // guaranteeing that new elements could have been added to `out_of_order`
                // since we've last checked.
                drop(out_of_order);

                let (peer, new_msg) = connections.receive().await?;
                if key == new_msg.key {
                    return Ok((peer, new_msg.msg));
                }

                // Since all other threads holding `out_of_order` use `connections.try_lock`,
                // and release `out_of_order`, we are guaranteed to get this lock and not
                // deadlock.
                // TODO: Can drop `new_msg` on cancelation. Which we currently don't do, but
                // worth mentioning. --dpc
                let mut out_of_order = self.inner.out_of_order.lock().await;
                // TODO: use `raw_entry` to avoid clone once stable
                let peer_msgs_pending_count = out_of_order.peer_counts.entry(peer).or_default();
                if *peer_msgs_pending_count < MAX_PEER_OUT_OF_ORDER_MESSAGES {
                    *peer_msgs_pending_count += 1;
                    out_of_order
                        .msgs
                        .entry(new_msg.key.clone())
                        .or_default()
                        .push_back((peer, new_msg.msg));
                } else {
                    error!("Peer {peer} has already {peer_msgs_pending_count} pending out of order messages. Droping new message.");
                }
            } else {
                drop(out_of_order);
                // Sleep just enough to not hog the CPU continously.
                // TODO: 99% this can be done better with `CondVar`, but
                // it's not essential RN
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    async fn ban_peer(&self, peer: PeerId) {
        self.inner.connections.lock().await.ban_peer(peer).await;
    }
}

#[cfg(test)]
pub mod test {
    use std::time::Duration;

    use fedimint_api::net::peers::fake::make_fake_peer_connection;
    use fedimint_api::net::peers::IMuxPeerConnections;
    use fedimint_api::task::TaskGroup;
    use fedimint_api::PeerId;
    use rand::rngs::OsRng;
    use rand::Rng;
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

            for mux_key in 0..NUM_MODULES {
                let (conn1, conn2) = (conn1.clone(), conn2.clone());
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
            drop(conn1);
            drop(conn2);

            task_group.join_all(None).await.expect("no failures");
        }
    }
}
