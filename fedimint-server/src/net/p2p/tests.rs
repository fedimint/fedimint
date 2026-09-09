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
    outgoing_sender: async_channel::Sender<u64>,
    incoming_receiver: async_channel::Receiver<u64>,
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
        Self::spawn_with_max_age(Box::new(connection), fallback, None)
    }

    fn spawn_with_max_age(
        connection: DynP2PConnection<u64>,
        fallback: Option<ConnectionType>,
        max_connection_age: Option<Duration>,
    ) -> Self {
        let (connection_sender, incoming_connections) = async_channel::bounded(4);
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(5);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(5);
        let (status_sender, status_receiver) = watch::channel(P2PConnectionState {
            connected: None,
            last_error: None,
        });
        let connector: DynP2PConnector<u64> = Arc::new(PendingConnector { fallback });
        let mut state_machine = P2PConnectionStateMachine {
            state: P2PConnectionSMState::Connected(connection),
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
                connection_deadline: max_connection_age
                    .map(|age| tokio::time::Instant::now() + age),
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
            outgoing_sender,
            incoming_receiver,
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
    assert_eq!(control.subscriptions(), 1);
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

/// Both operations suspend *inside* the non-cancel-safe part of a message.
struct PausedIoConnection {
    dropped: Arc<AtomicUsize>,
    send_started: async_channel::Sender<u64>,
    finish_send: async_channel::Receiver<()>,
    sends_completed: Arc<AtomicUsize>,
    frame_started: async_channel::Sender<()>,
    finish_frame: async_channel::Receiver<u64>,
}

impl Drop for PausedIoConnection {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl IP2PConnection<u64> for PausedIoConnection {
    async fn send(&self, message: u64) -> anyhow::Result<()> {
        self.send_started.try_send(message)?;
        self.finish_send.recv().await?;
        self.sends_completed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<u64>> {
        Ok(PausedFrame {
            started: self.frame_started.clone(),
            finish: self.finish_frame.clone(),
        }
        .into_dyn())
    }

    fn rtt(&self) -> Option<Duration> {
        None
    }
}

struct PausedFrame {
    started: async_channel::Sender<()>,
    finish: async_channel::Receiver<u64>,
}

#[async_trait]
impl IP2PFrame<u64> for PausedFrame {
    async fn read_to_end(&mut self) -> anyhow::Result<u64> {
        self.started.try_send(())?;
        Ok(self.finish.recv().await?)
    }
}

#[derive(Clone, Copy)]
enum Retirement {
    Replacement,
    MaxAge,
}

struct PausedIoHarness {
    machine: StatusMachineHarness,
    send_started: async_channel::Receiver<u64>,
    finish_send: async_channel::Sender<()>,
    sends_completed: Arc<AtomicUsize>,
    frame_started: async_channel::Receiver<()>,
    finish_frame: async_channel::Sender<u64>,
    connections_dropped: Arc<AtomicUsize>,
}

impl PausedIoHarness {
    async fn spawn(retirement: Retirement) -> Self {
        let (send_started, send_observed) = async_channel::bounded(2);
        let (finish_send, send_finished) = async_channel::bounded(1);
        let (frame_started, frame_observed) = async_channel::bounded(2);
        let (finish_frame, frame_finished) = async_channel::bounded(1);
        let sends_completed = Arc::new(AtomicUsize::new(0));
        let connections_dropped = Arc::new(AtomicUsize::new(0));
        let connection = Box::new(PausedIoConnection {
            dropped: connections_dropped.clone(),
            send_started,
            finish_send: send_finished,
            sends_completed: sends_completed.clone(),
            frame_started,
            finish_frame: frame_finished,
        });
        let max_age = match retirement {
            Retirement::Replacement => None,
            Retirement::MaxAge => Some(Duration::from_secs(60)),
        };
        let machine = StatusMachineHarness::spawn_with_max_age(connection, None, max_age);
        machine
            .outgoing_sender
            .try_send(7)
            .expect("queue first send");
        machine
            .outgoing_sender
            .try_send(8)
            .expect("queue second send");
        // Neither half may prevent the other from reaching its in-flight
        // operation, even while both are parked on transport flow control.
        timeout(Duration::from_secs(1), async {
            assert_eq!(send_observed.recv().await.expect("send started"), 7);
            frame_observed.recv().await.expect("frame read started");
        })
        .await
        .expect("send and frame read must make progress concurrently");
        Self {
            machine,
            send_started: send_observed,
            finish_send,
            sends_completed,
            frame_started: frame_observed,
            finish_frame,
            connections_dropped,
        }
    }

    async fn retire(&self, retirement: Retirement) {
        match retirement {
            Retirement::Replacement => {
                self.machine
                    .connection_sender
                    .try_send(Box::new(FakeConnection::new(FakeConnectionControl::new(
                        ConnectionType::Relay,
                    ))))
                    .expect("queue replacement");
                timeout(Duration::from_secs(1), async {
                    while !self.machine.connection_sender.is_empty() {
                        runtime::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("replacement must be observed while I/O is parked");
            }
            Retirement::MaxAge => {
                tokio::time::advance(Duration::from_secs(60)).await;
                tokio::task::yield_now().await;
            }
        }
    }

    async fn assert_retired(&mut self, retirement: Retirement) {
        self.machine
            .wait_for_status(match retirement {
                Retirement::Replacement => ExpectedStatus::Connected(ConnectionType::Relay),
                Retirement::MaxAge => ExpectedStatus::Disconnected,
            })
            .await;
        assert!(
            self.connections_dropped.load(Ordering::Relaxed) == 1,
            "old connection must be dropped"
        );
        assert!(
            self.send_started.is_closed(),
            "old send future must be dropped"
        );
        assert!(
            self.frame_started.is_closed(),
            "old frame future must be dropped"
        );
        assert!(
            self.send_started.is_empty(),
            "do not start queued sends while retiring"
        );
        assert!(
            self.frame_started.is_empty(),
            "do not accept more frames while retiring"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn retirement_finishes_in_flight_messages() {
    for retirement in [Retirement::Replacement, Retirement::MaxAge] {
        let mut harness = PausedIoHarness::spawn(retirement).await;
        harness.retire(retirement).await;
        tokio::time::advance(super::CONNECTION_DRAIN_TIMEOUT / 2).await;
        assert!(
            harness.connections_dropped.load(Ordering::Relaxed) == 0,
            "allow a grace period"
        );
        harness.finish_send.try_send(()).expect("finish old send");
        harness.finish_frame.try_send(9).expect("finish old frame");
        assert_eq!(
            timeout(
                Duration::from_secs(1),
                harness.machine.incoming_receiver.recv()
            )
            .await
            .expect("finish the in-flight read before retiring")
            .expect("deliver frame"),
            9
        );
        harness.assert_retired(retirement).await;
        assert_eq!(harness.sends_completed.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn retirement_bounds_permanently_parked_io() {
    for retirement in [Retirement::Replacement, Retirement::MaxAge] {
        let mut harness = PausedIoHarness::spawn(retirement).await;
        harness.retire(retirement).await;
        tokio::time::advance(super::CONNECTION_DRAIN_TIMEOUT).await;
        harness.assert_retired(retirement).await;
        assert_eq!(harness.sends_completed.load(Ordering::Relaxed), 0);
        assert!(
            harness.machine.incoming_receiver.is_empty(),
            "no partial frame delivered"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_drops_in_flight_io_during_retirement() {
    let harness = PausedIoHarness::spawn(Retirement::Replacement).await;
    harness.retire(Retirement::Replacement).await;
    harness.machine.task.abort();
    while !harness.machine.task.is_finished() {
        tokio::task::yield_now().await;
    }
    assert!(
        harness.connections_dropped.load(Ordering::Relaxed) == 1,
        "shutdown must not detach I/O"
    );
    assert!(harness.send_started.is_closed());
    assert!(harness.frame_started.is_closed());
}
