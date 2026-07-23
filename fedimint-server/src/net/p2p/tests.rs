use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::{PeerId, runtime};
use fedimint_server_core::dashboard_ui::{ConnectionType, P2PConnectionStatus};
use futures::{StreamExt, future, stream};
use tokio::sync::{Notify, broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::{
    P2PConnectionSMCommon, P2PConnectionSMState, P2PConnectionState, P2PConnectionStateMachine,
};
use crate::net::p2p_connection::{
    DynConnectionStatusUpdates, DynIP2PFrame, DynP2PConnection, IP2PConnection,
};
use crate::net::p2p_connector::{DynP2PConnector, IP2PConnector};

#[derive(Clone, Copy)]
enum UpdateStream {
    Events,
    ClosedOnceThenPending,
}

#[derive(Clone)]
struct FakeConnectionControl {
    status: Arc<Mutex<Option<ConnectionType>>>,
    update_during_snapshot: Arc<Mutex<Option<ConnectionType>>>,
    updates: broadcast::Sender<()>,
    subscriptions: Arc<AtomicUsize>,
    update_stream_polls: Arc<AtomicUsize>,
    disconnect: Arc<Notify>,
    update_stream: UpdateStream,
}

impl FakeConnectionControl {
    fn new(status: ConnectionType) -> Self {
        Self::from_status(Some(status))
    }

    fn from_status(status: Option<ConnectionType>) -> Self {
        let (updates, _) = broadcast::channel(8);
        Self {
            status: Arc::new(Mutex::new(status)),
            update_during_snapshot: Arc::new(Mutex::new(None)),
            updates,
            subscriptions: Arc::new(AtomicUsize::new(0)),
            update_stream_polls: Arc::new(AtomicUsize::new(0)),
            disconnect: Arc::new(Notify::new()),
            update_stream: UpdateStream::Events,
        }
    }

    fn with_closed_update_stream(mut self) -> Self {
        self.update_stream = UpdateStream::ClosedOnceThenPending;
        self
    }

    fn unknown() -> Self {
        Self::from_status(None)
    }

    fn update_status(&self, status: ConnectionType) {
        *self.status.lock().expect("status mutex poisoned") = Some(status);
        let _ = self.updates.send(());
    }

    fn update_status_during_next_snapshot(&self, status: ConnectionType) {
        *self
            .update_during_snapshot
            .lock()
            .expect("snapshot mutex poisoned") = Some(status);
    }

    fn disconnect(&self) {
        self.disconnect.notify_one();
    }

    fn subscriptions(&self) -> usize {
        self.subscriptions.load(Ordering::Relaxed)
    }
}

struct FakeConnection {
    control: FakeConnectionControl,
}

impl FakeConnection {
    fn new(control: FakeConnectionControl) -> Self {
        Self { control }
    }
}

#[async_trait]
impl IP2PConnection<u64> for FakeConnection {
    async fn send(&mut self, _message: u64) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<DynIP2PFrame<u64>> {
        self.control.disconnect.notified().await;
        Err(anyhow!("fake connection disconnected"))
    }

    fn rtt(&self) -> Option<Duration> {
        None
    }

    fn connection_type(&self) -> Option<ConnectionType> {
        let status = *self.control.status.lock().expect("status mutex poisoned");
        if let Some(next_status) = self
            .control
            .update_during_snapshot
            .lock()
            .expect("snapshot mutex poisoned")
            .take()
        {
            *self.control.status.lock().expect("status mutex poisoned") = Some(next_status);
            let _ = self.control.updates.send(());
        }
        status
    }

    fn connection_status_updates(&self) -> Option<DynConnectionStatusUpdates> {
        let subscription = self.control.subscriptions.fetch_add(1, Ordering::Relaxed);
        match self.control.update_stream {
            UpdateStream::Events => {
                let receiver = self.control.updates.subscribe();
                Some(
                    stream::unfold(receiver, |mut receiver| async move {
                        match receiver.recv().await {
                            Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                                Some(((), receiver))
                            }
                            Err(broadcast::error::RecvError::Closed) => None,
                        }
                    })
                    .boxed(),
                )
            }
            UpdateStream::ClosedOnceThenPending if subscription == 0 => {
                let polls = self.control.update_stream_polls.clone();
                Some(
                    stream::poll_fn(move |_| {
                        polls.fetch_add(1, Ordering::Relaxed);
                        Poll::Ready(None)
                    })
                    .boxed(),
                )
            }
            UpdateStream::ClosedOnceThenPending => Some(stream::pending().boxed()),
        }
    }
}

struct PendingConnector {
    fallback: Option<ConnectionType>,
}

#[async_trait]
impl IP2PConnector<u64> for PendingConnector {
    fn peers(&self) -> Vec<PeerId> {
        vec![PeerId::from(0)]
    }

    async fn connect(&self, _peer: PeerId) -> anyhow::Result<DynP2PConnection<u64>> {
        future::pending().await
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<u64>)> {
        future::pending().await
    }

    fn connection_type(&self, _peer: PeerId) -> Option<ConnectionType> {
        self.fallback
    }
}

struct StatusMachineHarness {
    connection_sender: async_channel::Sender<DynP2PConnection<u64>>,
    status_receiver: watch::Receiver<P2PConnectionState>,
    _outgoing_sender: async_channel::Sender<u64>,
    _incoming_receiver: async_channel::Receiver<u64>,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum ExpectedStatus {
    Connected(ConnectionType),
    Disconnected,
}

impl StatusMachineHarness {
    fn spawn(connection: FakeConnection) -> Self {
        Self::spawn_with_fallback(connection, None)
    }

    fn spawn_with_fallback(connection: FakeConnection, fallback: Option<ConnectionType>) -> Self {
        let (connection_sender, incoming_connections) = async_channel::bounded(4);
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(5);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(5);
        let (status_sender, status_receiver) = watch::channel(P2PConnectionState {
            connected: None,
            last_error: None,
        });
        let connector: DynP2PConnector<u64> = Arc::new(PendingConnector { fallback });
        let mut state_machine = P2PConnectionStateMachine {
            state: P2PConnectionSMState::Connected(Box::new(connection)),
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
            },
        };
        let task = runtime::spawn("p2p-status-machine-test", async move {
            while let Some(next) = state_machine.state_transition().await {
                state_machine = next;
            }
        });

        Self {
            connection_sender,
            status_receiver,
            _outgoing_sender: outgoing_sender,
            _incoming_receiver: incoming_receiver,
            task,
        }
    }

    async fn wait_for_status(&mut self, expected: ExpectedStatus) {
        timeout(Duration::from_secs(1), async {
            loop {
                let matches = match (
                    expected,
                    self.status_receiver.borrow_and_update().connected.as_ref(),
                ) {
                    (ExpectedStatus::Disconnected, None) => true,
                    (ExpectedStatus::Connected(expected), Some(actual)) => {
                        actual.conn_type == Some(expected)
                    }
                    _ => false,
                };
                if matches {
                    return;
                }
                self.status_receiver
                    .changed()
                    .await
                    .expect("status sender remains alive");
            }
        })
        .await
        .expect("expected connection status update");
    }

    fn current_status(&mut self) -> Option<P2PConnectionStatus> {
        self.status_receiver.borrow_and_update().connected.clone()
    }
}

impl Drop for StatusMachineHarness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn status_event_refreshes_connection_metadata_without_p2p_message() {
    let control = FakeConnectionControl::new(ConnectionType::Relay);
    let mut harness = StatusMachineHarness::spawn(FakeConnection::new(control.clone()));
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Relay))
        .await;

    control.update_status(ConnectionType::Direct);
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Direct))
        .await;
}

#[tokio::test]
async fn connector_status_remains_fallback_for_unknown_live_connection() {
    let control = FakeConnectionControl::unknown();
    let mut harness = StatusMachineHarness::spawn_with_fallback(
        FakeConnection::new(control),
        Some(ConnectionType::Relay),
    );

    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Relay))
        .await;
}

#[tokio::test]
async fn subscribes_before_snapshot_to_close_status_update_race() {
    let control = FakeConnectionControl::new(ConnectionType::Relay);
    control.update_status_during_next_snapshot(ConnectionType::Direct);
    let mut harness = StatusMachineHarness::spawn(FakeConnection::new(control.clone()));

    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Direct))
        .await;
    assert!(control.subscriptions() >= 2);
}

#[tokio::test]
async fn superseded_connection_events_do_not_replace_current_status() {
    let old_control = FakeConnectionControl::new(ConnectionType::Relay);
    let mut harness = StatusMachineHarness::spawn(FakeConnection::new(old_control.clone()));
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Relay))
        .await;

    let new_control = FakeConnectionControl::new(ConnectionType::Direct);
    harness
        .connection_sender
        .send(Box::new(FakeConnection::new(new_control)))
        .await
        .expect("state machine receives replacement connection");
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Direct))
        .await;

    assert_eq!(old_control.updates.receiver_count(), 0);
    old_control.update_status(ConnectionType::Mixed);
    assert_eq!(
        harness.current_status().and_then(|status| status.conn_type),
        Some(ConnectionType::Direct)
    );
}

#[tokio::test]
async fn disconnect_clears_status_and_drops_old_updates() {
    let control = FakeConnectionControl::new(ConnectionType::Relay);
    let mut harness = StatusMachineHarness::spawn(FakeConnection::new(control.clone()));
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Relay))
        .await;

    control.disconnect();
    harness.wait_for_status(ExpectedStatus::Disconnected).await;

    assert_eq!(control.updates.receiver_count(), 0);
    control.update_status(ConnectionType::Direct);
    assert_eq!(harness.current_status(), None);
}

#[tokio::test]
async fn closed_status_stream_does_not_spin() {
    let control = FakeConnectionControl::new(ConnectionType::Relay).with_closed_update_stream();
    let mut harness = StatusMachineHarness::spawn(FakeConnection::new(control.clone()));
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Relay))
        .await;

    timeout(Duration::from_secs(1), async {
        while control.update_stream_polls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed update stream was polled");
    assert_eq!(control.subscriptions(), 1);

    control.disconnect();
    harness.wait_for_status(ExpectedStatus::Disconnected).await;
    assert_eq!(harness.current_status(), None);
}
