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
    DynConnectionStatusUpdates, DynIP2PFrame, DynP2PConnection, IP2PConnection, IP2PFrame,
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
    async fn send(&self, _message: u64) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<u64>> {
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
            state: P2PConnectionSMState::Connected(Arc::new(connection)),
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
                max_connection_age: None,
                connection_deadline: None,
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

    // An update emitted while the initial snapshot is taken must still be seen.
    // The connected state now holds one subscription for the lifetime of the
    // connection and refreshes in place, rather than re-entering (and so
    // re-subscribing) once per status event.
    harness
        .wait_for_status(ExpectedStatus::Connected(ConnectionType::Direct))
        .await;
    assert!(control.subscriptions() >= 1);
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
        .send(Arc::new(FakeConnection::new(new_control)))
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

/// A frame that yields a single pre-baked message.
struct FakeFrame(u64);

#[async_trait]
impl IP2PFrame<u64> for FakeFrame {
    async fn read_to_end(&mut self) -> anyhow::Result<u64> {
        Ok(self.0)
    }
}

/// A connection whose `send` cannot complete until `receive` has been served at
/// least once. This is the shape of transport flow control: the peer has to
/// drain our stream before our write can finish.
struct FlowControlledConnection {
    /// Granted by `receive`, awaited by `send`.
    window: Arc<Notify>,
    frames: async_channel::Receiver<u64>,
    /// Number of sends that made it past the window wait.
    sends_completed: Arc<AtomicUsize>,
}

#[async_trait]
impl IP2PConnection<u64> for FlowControlledConnection {
    async fn send(&self, _message: u64) -> anyhow::Result<()> {
        self.window.notified().await;

        self.sends_completed.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<u64>> {
        let message = self
            .frames
            .recv()
            .await
            .map_err(|_| anyhow!("frame channel closed"))?;

        self.window.notify_one();

        Ok(FakeFrame(message).into_dyn())
    }

    fn rtt(&self) -> Option<Duration> {
        None
    }

    fn connection_type(&self) -> Option<ConnectionType> {
        Some(ConnectionType::Direct)
    }
}

/// Regression test for a p2p deadlock: when send and receive were multiplexed
/// in a single `select!`, a send parked on transport flow control could no
/// longer poll `receive`, so the window never reopened. Two peers that both
/// started writing an oversized message hung forever, silently.
#[tokio::test]
async fn receives_while_a_send_is_parked_on_flow_control() {
    let (frame_sender, frames) = async_channel::bounded(1);
    let (connection_sender, incoming_connections) = async_channel::bounded(1);
    let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1);
    let (incoming_sender, incoming_receiver) = async_channel::bounded(1);
    let (status_sender, _status_receiver) = watch::channel(P2PConnectionState {
        connected: None,
        last_error: None,
    });

    let sends_completed = Arc::new(AtomicUsize::new(0));

    let connection = FlowControlledConnection {
        window: Arc::new(Notify::new()),
        frames,
        sends_completed: sends_completed.clone(),
    };

    let mut state_machine = P2PConnectionStateMachine {
        state: P2PConnectionSMState::Connected(Arc::new(connection)),
        common: P2PConnectionSMCommon {
            incoming_sender,
            outgoing_receiver,
            our_id: PeerId::from(1),
            our_id_str: "1".to_owned(),
            peer_id: PeerId::from(0),
            peer_id_str: "0".to_owned(),
            connector: Arc::new(PendingConnector { fallback: None }),
            incoming_connections,
            status_sender,
            max_connection_age: None,
            connection_deadline: None,
        },
    };

    let task = runtime::spawn("p2p-flow-control-test", async move {
        while let Some(next) = state_machine.state_transition().await {
            state_machine = next;
        }
    });

    // Park a send first, so the connection is mid-write when the peer's frame
    // arrives. Only a receive can unblock it.
    outgoing_sender.send(7).await.expect("outgoing queued");
    frame_sender.send(9).await.expect("frame queued");

    let received = timeout(Duration::from_secs(5), incoming_receiver.recv())
        .await
        .expect("receive must be served while the send is parked")
        .expect("incoming channel is open");

    assert_eq!(received, 9);

    // The send can only get past the window wait because the receive was
    // served, so a completed send proves both halves made progress.
    timeout(Duration::from_secs(5), async {
        while sends_completed.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("parked send completes once the window reopens");

    // If the closed frame channel is observed before the closed outgoing
    // channel, the machine transitions to Disconnected instead of shutting
    // down; the connection channel must be closed too for the task to end.
    drop(frame_sender);
    drop(outgoing_sender);
    drop(connection_sender);
    let _ = task.await;
}

/// A replacement connection that arrives while a send is parked must not
/// cancel the in-flight send: the already dequeued message would be silently
/// lost, and e.g. the DKG sends every message exactly once.
#[tokio::test]
async fn replacement_connection_does_not_cancel_in_flight_send() {
    let (frame_sender, frames) = async_channel::bounded(1);
    let (connection_sender, incoming_connections) = async_channel::bounded(1);
    let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1);
    let (incoming_sender, _incoming_receiver) = async_channel::bounded(1);
    let (status_sender, mut status_receiver) = watch::channel(P2PConnectionState {
        connected: None,
        last_error: None,
    });

    let sends_completed = Arc::new(AtomicUsize::new(0));

    let connection = FlowControlledConnection {
        window: Arc::new(Notify::new()),
        frames,
        sends_completed: sends_completed.clone(),
    };

    let mut state_machine = P2PConnectionStateMachine {
        state: P2PConnectionSMState::Connected(Arc::new(connection)),
        common: P2PConnectionSMCommon {
            incoming_sender,
            outgoing_receiver,
            our_id: PeerId::from(1),
            our_id_str: "1".to_owned(),
            peer_id: PeerId::from(0),
            peer_id_str: "0".to_owned(),
            connector: Arc::new(PendingConnector { fallback: None }),
            incoming_connections,
            status_sender,
            max_connection_age: None,
            connection_deadline: None,
        },
    };

    let task = runtime::spawn("p2p-replacement-test", async move {
        while let Some(next) = state_machine.state_transition().await {
            state_machine = next;
        }
    });

    // Park a send on flow control and wait until the message is dequeued, so
    // the send is in flight before the replacement connection arrives.
    outgoing_sender.send(7).await.expect("outgoing queued");
    timeout(Duration::from_secs(5), async {
        while !outgoing_sender.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("send is dequeued and in flight");

    connection_sender
        .send(Arc::new(FakeConnection::new(FakeConnectionControl::new(
            ConnectionType::Relay,
        ))))
        .await
        .expect("replacement queued");

    // Serving a receive reopens the window; the parked send must still be
    // alive to complete despite the queued replacement.
    frame_sender.send(9).await.expect("frame queued");
    timeout(Duration::from_secs(5), async {
        while sends_completed.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("in-flight send completes despite the queued replacement");

    // Only then does the replacement connection take over.
    timeout(Duration::from_secs(5), async {
        loop {
            if status_receiver
                .borrow_and_update()
                .connected
                .as_ref()
                .is_some_and(|status| status.conn_type == Some(ConnectionType::Relay))
            {
                return;
            }
            status_receiver
                .changed()
                .await
                .expect("status sender remains alive");
        }
    })
    .await
    .expect("replacement connection takes over after the send completes");

    drop(frame_sender);
    drop(outgoing_sender);
    drop(connection_sender);
    let _ = task.await;
}
