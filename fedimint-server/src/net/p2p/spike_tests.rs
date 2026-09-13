//! Real transport feasibility tests. `legacy` freezes the old lifecycle rather
//! than exercising two copies of the new manager with a forced protocol tag.

mod legacy;
mod lifecycle;
mod transports;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::net::{IP2PConnections, Recipient};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_server_core::dashboard_ui::ConnectionType;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

use super::{P2PConnectionState, ReconnectP2PConnections, p2p_status_channels};
use crate::net::p2p_connection::{DynIP2PFrame, DynP2PConnection, IP2PConnection};
use crate::net::p2p_connector::{DynP2PConnector, IP2PConnector, P2PProtocol};

#[tokio::test]
async fn tls_retained_half_open_incoming_blocks_replacement_until_eof() -> anyhow::Result<()> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let proxy_tasks = TaskGroup::new();
    let blackhole = Arc::new(transports::Blackhole::default());
    let [a, b] = transports::blackhole_pair(&proxy_tasks, blackhole.clone()).await?;
    let tasks = TaskGroup::new();
    let (ma, mut sa) = manager(0, true, a.clone(), &tasks);
    let (mb, mut sb) = manager(1, true, b.clone(), &tasks);
    connected(&mut sa).await;
    connected(&mut sb).await;
    exchange(&ma, &mb, 100).await;
    blackhole.freeze.notify_one();
    timeout(Duration::from_secs(3), blackhole.frozen.notified()).await?;
    a.outgoing(0).close.notify_one();
    // Observe, rather than repair, this feasibility limitation: successful
    // reconnect handshakes are rejected while the old receive slot has no EOF.
    sleep(Duration::from_millis(600)).await;
    assert!(a.outgoing_count() > 1, "sender tried reconnecting");
    assert_eq!(b.outgoing_count(), 1, "opposite session was retained");
    assert_eq!(
        b.incoming.lock().expect("test mutex")[0]
            .dropped
            .load(Ordering::SeqCst),
        0
    );
    mb.send(PeerId::from(0), vec![9]);
    assert_eq!(
        timeout(Duration::from_secs(3), ma.receive(PeerId::from(1))).await?,
        vec![9]
    );
    // Releasing the proxy finally makes the old EOF visible; ordinary
    // sender-owned retries then converge without replacing a live receiver.
    blackhole.release.notify_one();
    timeout(Duration::from_secs(10), async {
        loop {
            ma.send(PeerId::from(1), vec![8]);
            if let Ok(message) =
                timeout(Duration::from_millis(100), mb.receive(PeerId::from(0))).await
            {
                assert_eq!(message, vec![8]);
                break;
            }
        }
    })
    .await?;
    tasks
        .shutdown_join_all(Some(Duration::from_secs(3)))
        .await?;
    proxy_tasks
        .shutdown_join_all(Some(Duration::from_secs(3)))
        .await?;
    Ok(())
}

/// Test transport and old/new fixture selection.
#[derive(Clone, Copy, Debug)]
enum Transport {
    Tls,
    Iroh,
}

/// A session control never holds the underlying connection alive.
#[derive(Default)]
struct Session {
    /// Inject local failure; dropping the slot then closes the real transport.
    close: Notify,
    /// Set when every manager-owned connection handle was released.
    dropped: AtomicUsize,
}

/// Records session ownership without adding another queue consumer.
struct TrackedConnection {
    /// Actual TLS or Iroh session.
    inner: DynP2PConnection<Vec<u8>>,
    /// Out-of-band failure injection.
    session: Arc<Session>,
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.session.dropped.store(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl IP2PConnection<Vec<u8>> for TrackedConnection {
    fn protocol(&self) -> P2PProtocol {
        self.inner.protocol()
    }

    async fn send(&self, message: Vec<u8>) -> anyhow::Result<()> {
        self.inner.send(message).await
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<Vec<u8>>> {
        tokio::select! {
            result = self.inner.receive() => result,
            () = self.session.close.notified() => Err(anyhow!("Injected session failure")),
        }
    }

    fn rtt(&self) -> Option<Duration> {
        self.inner.rtt()
    }

    fn connection_type(&self) -> Option<ConnectionType> {
        self.inner.connection_type()
    }
}

/// Counts dial attempts and records sessions, including rejected duplicates.
struct TrackedConnector {
    /// Real authenticated connector.
    inner: DynP2PConnector<Vec<u8>>,
    /// Attempts, including handshakes that fail.
    attempts: AtomicUsize,
    /// Completed outgoing sessions.
    outgoing: Mutex<Vec<Arc<Session>>>,
    /// Authenticated incoming sessions.
    incoming: Mutex<Vec<Arc<Session>>>,
}

impl TrackedConnector {
    fn new(inner: DynP2PConnector<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            attempts: AtomicUsize::new(0),
            outgoing: Mutex::new(Vec::new()),
            incoming: Mutex::new(Vec::new()),
        })
    }

    fn track(
        connection: DynP2PConnection<Vec<u8>>,
        sessions: &Mutex<Vec<Arc<Session>>>,
    ) -> DynP2PConnection<Vec<u8>> {
        let session = Arc::new(Session::default());
        sessions.lock().expect("test mutex").push(session.clone());
        TrackedConnection {
            inner: connection,
            session,
        }
        .into_dyn()
    }

    fn outgoing_count(&self) -> usize {
        self.outgoing.lock().expect("test mutex").len()
    }

    fn outgoing(&self, index: usize) -> Arc<Session> {
        self.outgoing.lock().expect("test mutex")[index].clone()
    }
}

#[async_trait]
impl IP2PConnector<Vec<u8>> for TrackedConnector {
    fn peers(&self) -> Vec<PeerId> {
        self.inner.peers()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<Vec<u8>>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(Self::track(self.inner.connect(peer).await?, &self.outgoing))
    }

    async fn connect_dual(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<Vec<u8>>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(Self::track(
            self.inner.connect_dual(peer).await?,
            &self.outgoing,
        ))
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<Vec<u8>>)> {
        let (peer, connection) = self.inner.accept().await?;
        Ok((peer, Self::track(connection, &self.incoming)))
    }

    fn connection_type(&self, peer: PeerId) -> Option<ConnectionType> {
        self.inner.connection_type(peer)
    }
}

/// Both sides use the same API here but different implementations underneath.
enum Manager {
    New(ReconnectP2PConnections<Vec<u8>>),
    Old(legacy::LegacyManager),
}

impl Manager {
    fn send(&self, peer: PeerId, message: Vec<u8>) {
        match self {
            Self::New(manager) => manager.send(Recipient::Peer(peer), message),
            Self::Old(manager) => manager.send.try_send(message).expect("test queue space"),
        }
    }

    async fn receive(&self, peer: PeerId) -> Vec<u8> {
        match self {
            Self::New(manager) => manager
                .receive_from_peer(peer)
                .await
                .expect("manager alive"),
            Self::Old(manager) => manager.receive.recv().await.expect("manager alive"),
        }
    }
}

fn manager(
    id: u16,
    new: bool,
    connector: Arc<TrackedConnector>,
    tasks: &TaskGroup,
) -> (Manager, watch::Receiver<P2PConnectionState>) {
    let peer = PeerId::from(1 - id);
    let (senders, mut receivers) = p2p_status_channels(vec![peer]);
    let status = receivers.remove(&peer).expect("status exists");
    let manager = if new {
        Manager::New(ReconnectP2PConnections::new(
            PeerId::from(id),
            connector,
            tasks,
            senders,
            None,
        ))
    } else {
        Manager::Old(legacy::LegacyManager::new(
            PeerId::from(id),
            peer,
            connector,
            tasks,
        ))
    };
    (manager, status)
}

async fn connected(status: &mut watch::Receiver<P2PConnectionState>) {
    timeout(Duration::from_secs(15), async {
        loop {
            if status.borrow_and_update().connected.is_some() {
                return;
            }
            status.changed().await.expect("manager alive");
        }
    })
    .await
    .expect("both application directions become ready");
}

async fn exchange(a: &Manager, b: &Manager, size: usize) {
    // Above the TCP/QUIC flow-control window; simultaneous sends must not
    // starve either long-lived receive future.
    a.send(PeerId::from(1), vec![42; size]);
    b.send(PeerId::from(0), vec![43; size]);
    let (at_a, at_b) = timeout(Duration::from_secs(15), async {
        tokio::join!(a.receive(PeerId::from(1)), b.receive(PeerId::from(0)))
    })
    .await
    .expect("bidirectional delivery");
    assert_eq!(at_a, vec![43; size]);
    assert_eq!(at_b, vec![42; size]);
}

#[tokio::test]
async fn mixed_frozen_legacy_and_dual_real_transports() -> anyhow::Result<()> {
    for transport in [Transport::Tls, Transport::Iroh] {
        for new in [[false, false], [true, false], [false, true], [true, true]] {
            let [a, b] = transports::pair(transport, new).await?;
            let tasks = TaskGroup::new();
            let (ma, mut sa) = manager(0, new[0], a.clone(), &tasks);
            let (mb, mut sb) = manager(1, new[1], b.clone(), &tasks);
            if new[0] {
                connected(&mut sa).await;
            }
            if new[1] {
                connected(&mut sb).await;
            }
            if !new[0] && !new[1] {
                timeout(Duration::from_secs(15), async {
                    while a.outgoing_count() == 0 {
                        sleep(Duration::from_millis(10)).await;
                    }
                })
                .await?;
            }
            exchange(&ma, &mb, 2_000_000).await;
            assert_eq!(a.outgoing_count(), 1, "{transport:?} {new:?}");
            assert_eq!(
                b.outgoing_count(),
                usize::from(new == [true, true]),
                "{transport:?} {new:?}"
            );
            assert_eq!(
                b.attempts.load(Ordering::SeqCst),
                usize::from(new == [true, true])
            );
            tasks
                .shutdown_join_all(Some(Duration::from_secs(5)))
                .await?;
            assert_eq!(a.outgoing(0).dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn dual_idle_closure_reconnects_only_its_sender_and_rejects_duplicates() -> anyhow::Result<()>
{
    for transport in [Transport::Tls, Transport::Iroh] {
        let [a, b] = transports::pair(transport, [true, true]).await?;
        let tasks = TaskGroup::new();
        let (ma, mut sa) = manager(0, true, a.clone(), &tasks);
        let (mb, mut sb) = manager(1, true, b.clone(), &tasks);
        connected(&mut sa).await;
        connected(&mut sb).await;
        exchange(&ma, &mb, 10).await;

        // A real extra authenticated session must be rejected, not replace
        // either installed direction. Keep its sender handle until EOF.
        let duplicate = a.inner.connect_dual(PeerId::from(1)).await?;
        assert_eq!(duplicate.protocol(), P2PProtocol::DualV1);
        assert!(
            timeout(Duration::from_secs(5), duplicate.receive())
                .await?
                .is_err()
        );
        exchange(&ma, &mb, 10).await;
        assert_eq!(b.outgoing_count(), 1);
        assert_eq!(a.outgoing_count(), 1);

        for (owner, opposite, status) in [(&a, &b, &mut sa), (&b, &a, &mut sb)] {
            let original_count = owner.outgoing_count();
            let opposite_count = opposite.outgoing_count();
            let opposite_session = opposite.outgoing(opposite_count - 1);
            owner.outgoing(original_count - 1).close.notify_one();
            timeout(Duration::from_secs(15), async {
                while owner.outgoing_count() == original_count {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            connected(status).await;
            // A successful handshake is not an application admission ACK;
            // wait for the receiver to install the slot before this one-shot.
            sleep(Duration::from_millis(50)).await;
            exchange(&ma, &mb, 100).await;
            assert_eq!(opposite.outgoing_count(), opposite_count);
            assert_eq!(opposite_session.dropped.load(Ordering::SeqCst), 0);
        }
        tasks
            .shutdown_join_all(Some(Duration::from_secs(5)))
            .await?;
    }
    Ok(())
}
