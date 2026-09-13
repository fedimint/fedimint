//! Deterministic slot lifetime and stale TLS reverse-dial regressions.

use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_server_core::dashboard_ui::ConnectionType;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

use super::{P2PConnectionState, Transport, connected, transports};
use crate::net::p2p::{P2PConnectionSMCommon, P2PConnectionSMState, P2PConnectionStateMachine};
use crate::net::p2p_connection::{DynIP2PFrame, DynP2PConnection, IP2PConnection, IP2PFrame};
use crate::net::p2p_connector::{DynP2PConnector, IP2PConnector, P2PProtocol};

/// A dual connection with independently controllable application and EOF
/// events.
struct Controlled {
    /// Frames delivered on its application read direction.
    frames: async_channel::Receiver<Vec<u8>>,
    /// Signals a parked send started.
    started: Arc<Notify>,
    /// Releases a parked send.
    release: Arc<Notify>,
    /// Allows outgoing monitor failure while the send is parked.
    close: Arc<Notify>,
}

#[async_trait]
impl IP2PConnection<Vec<u8>> for Controlled {
    fn protocol(&self) -> P2PProtocol {
        P2PProtocol::DualV1
    }
    async fn send(&self, _: Vec<u8>) -> anyhow::Result<()> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<Vec<u8>>> {
        tokio::select! {
            frame = self.frames.recv() => Ok(Frame(frame?).into_dyn()),
            () = self.close.notified() => Err(anyhow!("controlled EOF")),
        }
    }
    fn rtt(&self) -> Option<Duration> {
        None
    }
}

struct Frame(Vec<u8>);

#[async_trait]
impl IP2PFrame<Vec<u8>> for Frame {
    async fn read_to_end(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.0))
    }
}

/// External controls carry no reference to the connection itself.
struct Control {
    frames: async_channel::Sender<Vec<u8>>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    close: Arc<Notify>,
}

fn controlled() -> (DynP2PConnection<Vec<u8>>, Control) {
    let (frames, receiver) = async_channel::bounded(5);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let close = Arc::new(Notify::new());
    (
        Controlled {
            frames: receiver,
            started: started.clone(),
            release: release.clone(),
            close: close.clone(),
        }
        .into_dyn(),
        Control {
            frames,
            started,
            release,
            close,
        },
    )
}

struct Pending;

#[async_trait]
impl IP2PConnector<Vec<u8>> for Pending {
    fn peers(&self) -> Vec<PeerId> {
        vec![PeerId::from(0)]
    }
    async fn connect(&self, _: PeerId) -> anyhow::Result<DynP2PConnection<Vec<u8>>> {
        pending().await
    }
    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<Vec<u8>>)> {
        pending().await
    }
    fn connection_type(&self, _: PeerId) -> Option<ConnectionType> {
        None
    }
}

struct Harness {
    send: async_channel::Sender<Vec<u8>>,
    receive: async_channel::Receiver<Vec<u8>>,
    candidates: async_channel::Sender<DynP2PConnection<Vec<u8>>>,
    status: watch::Receiver<P2PConnectionState>,
    tasks: TaskGroup,
}

impl Harness {
    fn new(
        connector: DynP2PConnector<Vec<u8>>,
        outgoing: Option<DynP2PConnection<Vec<u8>>>,
        incoming: DynP2PConnection<Vec<u8>>,
        max_connection_age: Option<Duration>,
    ) -> Self {
        let (send, outgoing_receiver) = async_channel::bounded(5);
        let (incoming_sender, receive) = async_channel::bounded(5);
        let (candidates, incoming_connections) = async_channel::bounded(4);
        let (status_sender, status) = watch::channel(P2PConnectionState {
            connected: None,
            last_error: None,
        });
        let tasks = TaskGroup::new();
        tasks.spawn_cancellable("dual-lifecycle-test", async move {
            let mut machine = P2PConnectionStateMachine {
                state: P2PConnectionSMState::Dual {
                    outgoing,
                    incoming: Some(incoming),
                },
                common: P2PConnectionSMCommon {
                    incoming_sender,
                    outgoing_receiver,
                    our_id: PeerId::from(1),
                    our_id_str: "1".to_owned(),
                    peer_id: PeerId::from(0),
                    peer_id_str: "0".to_owned(),
                    connector,
                    incoming_connections,
                    status_sender,
                    max_connection_age,
                    connection_deadline: None,
                },
            };
            while let Some(next) = machine.state_transition().await {
                machine = next;
            }
        });
        Self {
            send,
            receive,
            candidates,
            status,
            tasks,
        }
    }

    async fn disconnected(&mut self) {
        timeout(Duration::from_secs(3), async {
            loop {
                if self.status.borrow_and_update().connected.is_none() {
                    return;
                }
                self.status.changed().await.expect("manager alive");
            }
        })
        .await
        .expect("directional failure clears readiness");
    }
}

#[tokio::test]
async fn stale_tls_reverse_drops_legacy_and_waits_for_fresh_discovery() -> anyhow::Result<()> {
    let [old_lower, new_higher] = transports::pair(Transport::Tls, [false, true]).await?;
    let (incoming, _incoming_control) = controlled();
    let mut harness = Harness::new(new_higher.clone(), None, incoming, None);
    assert!(harness.status.borrow().connected.is_none());
    // Simulate a lower peer downgraded to its original empty-ALPN TLS config,
    // while the higher peer's old incoming TCP session still appears live.
    let (peer, stale) = timeout(Duration::from_secs(3), old_lower.accept()).await??;
    assert_eq!(peer, PeerId::from(1));
    assert_eq!(stale.protocol(), P2PProtocol::Legacy);
    assert!(
        timeout(Duration::from_secs(3), stale.receive())
            .await?
            .is_err()
    );
    timeout(Duration::from_secs(3), async {
        loop {
            if harness
                .status
                .borrow_and_update()
                .last_error
                .as_ref()
                .is_some_and(|error| error.contains("waiting for discovery"))
            {
                break;
            }
            harness.status.changed().await.expect("manager alive");
        }
    })
    .await?;
    sleep(Duration::from_millis(600)).await;
    assert_eq!(
        new_higher.attempts.load(Ordering::SeqCst),
        1,
        "no repeat stale reverse loop"
    );

    // The old lower peer reconnects normally, with no change to its framing.
    let (lower, (peer, accepted)) =
        tokio::try_join!(old_lower.connect(PeerId::from(1)), new_higher.accept(),)?;
    assert_eq!(peer, PeerId::from(0));
    harness.candidates.send(accepted).await?;
    connected(&mut harness.status).await;
    lower.send(vec![1, 2, 3]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), harness.receive.recv()).await??,
        vec![1, 2, 3]
    );
    harness.send.send(vec![4, 5, 6]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), async {
            lower.receive().await?.read_to_end().await
        })
        .await??,
        vec![4, 5, 6]
    );
    assert_eq!(new_higher.attempts.load(Ordering::SeqCst), 1);
    harness
        .tasks
        .shutdown_join_all(Some(Duration::from_secs(3)))
        .await?;
    Ok(())
}

#[tokio::test]
async fn parked_send_keeps_incoming_running_and_outgoing_eof_monitor_live() -> anyhow::Result<()> {
    let (outgoing, out) = controlled();
    let (incoming, inc) = controlled();
    let mut harness = Harness::new(Pending.into_dyn(), Some(outgoing), incoming, None);
    connected(&mut harness.status).await;
    harness.send.send(vec![1]).await?;
    timeout(Duration::from_secs(3), out.started.notified()).await?;
    inc.frames.send(vec![2]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), harness.receive.recv()).await??,
        vec![2]
    );
    out.close.notify_one();
    harness.disconnected().await;
    // Outgoing failure did not cancel the independent incoming slot.
    inc.frames.send(vec![3]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), harness.receive.recv()).await??,
        vec![3]
    );
    harness
        .tasks
        .shutdown_join_all(Some(Duration::from_secs(3)))
        .await?;
    Ok(())
}

#[tokio::test]
async fn dual_age_is_sender_owned_and_still_waits_for_parked_send() -> anyhow::Result<()> {
    let (outgoing, out) = controlled();
    let (incoming, inc) = controlled();
    let mut harness = Harness::new(
        Pending.into_dyn(),
        Some(outgoing),
        incoming,
        Some(Duration::from_millis(100)),
    );
    connected(&mut harness.status).await;
    harness.send.send(vec![1]).await?;
    timeout(Duration::from_secs(3), out.started.notified()).await?;
    sleep(Duration::from_millis(200)).await;
    assert!(
        harness.status.borrow().connected.is_some(),
        "age does not cancel a parked send"
    );
    inc.frames.send(vec![2]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), harness.receive.recv()).await??,
        vec![2]
    );
    out.release.notify_one();
    harness.disconnected().await;
    inc.frames.send(vec![3]).await?;
    assert_eq!(
        timeout(Duration::from_secs(3), harness.receive.recv()).await??,
        vec![3]
    );
    harness
        .tasks
        .shutdown_join_all(Some(Duration::from_secs(3)))
        .await?;
    Ok(())
}
