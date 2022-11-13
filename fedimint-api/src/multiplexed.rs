#![cfg_attr(target_family = "wasm", allow(unused))]
use std::fmt::Debug;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(not(target_family = "wasm"))]
use tokio::{sync::Mutex, time::sleep};
#[cfg(target_family = "wasm")]
type Mutex<T> = std::marker::PhantomData<T>;

use tracing::{debug, error};

use crate::{cancellable::Cancellable, net::peers::PeerConnections, PeerId};

/// TODO: Use proper ModuleId after modularization is complete
pub type ModuleId = String;
pub type ModuleIdRef<'a> = &'a str;

/// A `Msg` that can target a specific destination module
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleMultiplexed<Msg> {
    pub module: String,
    pub msg: Msg,
}

struct ModuleMultiplexerOutOfOrder<Msg> {
    /// Messages per `ModuleId` in a queue each
    msgs: HashMap<ModuleId, VecDeque<(PeerId, Msg)>>,
    /// Track pending messages per peer to avoid a potential DoS
    peer_counts: HashMap<PeerId, u64>,
}

impl<Msg> Default for ModuleMultiplexerOutOfOrder<Msg> {
    fn default() -> Self {
        Self {
            msgs: Default::default(),
            peer_counts: Default::default(),
        }
    }
}

/// Shared, mutable (wrapped in mutex) data of [`ModuleMultiplexer`].
struct ModuleMultiplexerInner<Msg> {
    /// Underlying connection pool
    connections: Mutex<PeerConnections<ModuleMultiplexed<Msg>>>,
    /// Messages that arrived before an interested thread asked for them
    out_of_order: Mutex<ModuleMultiplexerOutOfOrder<Msg>>,
}

/// A wrapper around `AnyPeerConnections` multiplexing communication between multiple modules over it
///
/// This works by addressing each module when sending, and handling buffering messages received
/// out of order until they are requested.
///
/// This type is thread-safe and can be cheaply cloned.
#[derive(Clone)]
#[cfg(not(target_family = "wasm"))]
pub struct ModuleMultiplexer<Msg> {
    inner: Arc<ModuleMultiplexerInner<Msg>>,
}

#[cfg(target_family = "wasm")]
pub struct ModuleMultiplexer<Msg> {
    inner: std::marker::PhantomData<Msg>,
}

impl<Msg> ModuleMultiplexer<Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send + Debug,
{
    #[cfg(not(target_family = "wasm"))]
    pub fn new(connections: PeerConnections<ModuleMultiplexed<Msg>>) -> Self {
        Self {
            inner: Arc::new(ModuleMultiplexerInner {
                connections: Mutex::new(connections),
                out_of_order: Default::default(),
            }),
        }
    }

    #[cfg(target_family = "wasm")]
    pub fn new(connections: PeerConnections<ModuleMultiplexed<Msg>>) -> Self {
        unimplemented!();
    }

    #[cfg(not(target_family = "wasm"))]
    pub async fn send(&self, peers: &[PeerId], module: &str, msg: Msg) -> Cancellable<()> {
        debug!("Sending to {peers:?}: to {module}, {msg:?}");
        self.inner
            .connections
            .lock()
            .await
            .send(
                peers,
                ModuleMultiplexed {
                    module: module.into(),
                    msg,
                },
            )
            .await
    }

    #[cfg(target_family = "wasm")]
    pub async fn send(&self, peers: &[PeerId], module: &str, msg: Msg) -> Cancellable<()> {
        unimplemented!();
    }

    #[cfg(not(target_family = "wasm"))]
    /// Await receipt of a message from any connected peer.
    pub async fn receive(&self, module: &str) -> Cancellable<(PeerId, Msg)> {
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
            if let Some(queue) = out_of_order.msgs.get_mut(module) {
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
                if module == new_msg.module {
                    return Ok((peer, new_msg.msg));
                }

                // Since all other threads holding `out_of_order` use `connections.try_lock`,
                // and release `out_of_order`, we are guaranteed to get this lock and not
                // deadlock.
                let mut out_of_order = self.inner.out_of_order.lock().await;
                // TODO: use `raw_entry` to avoid clone once stable
                let peer_msgs_pending_count = out_of_order.peer_counts.entry(peer).or_default();
                if *peer_msgs_pending_count < 1000 {
                    *peer_msgs_pending_count += 1;
                    out_of_order
                        .msgs
                        .entry(new_msg.module.to_owned())
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

    #[cfg(target_family = "wasm")]
    pub async fn receive(&self, module: &str) -> Cancellable<(PeerId, Msg)> {
        unimplemented!();
    }
}
