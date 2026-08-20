use std::sync::Arc;
use std::time::{Duration, Instant};

use aleph_bft::{DataProvider as _, FinalizationHandler as _, Network as _, NodeIndex};
use fedimint_core::config::P2PMessage;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IRawDatabaseExt as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::peers::fake::make_fake_peer_connection;
use fedimint_core::net::peers::{IP2PConnections, Recipient};
use fedimint_core::runtime::spawn;
use fedimint_core::{NumPeers, PeerId};

use super::{
    IdleControlV1, IdleCoordinator, IdleSessionTasks, SubmissionActivity,
    forward_notified_submissions,
};
use crate::consensus::aleph_bft::data_provider::{DataProvider, UnitData};
use crate::consensus::aleph_bft::finalization_handler::FinalizationHandler;
use crate::consensus::aleph_bft::network::Network;
use crate::consensus::engine::terminate_aleph_session;

#[derive(Clone)]
struct RecordingConnections {
    sent: async_channel::Sender<(Recipient, P2PMessage)>,
}

#[async_trait::async_trait]
impl IP2PConnections<P2PMessage> for RecordingConnections {
    fn send(&self, recipient: Recipient, message: P2PMessage) {
        self.sent.try_send((recipient, message)).ok();
    }

    async fn receive(&self) -> Option<(PeerId, P2PMessage)> {
        std::future::pending().await
    }

    async fn receive_from_peer(&self, _peer: PeerId) -> Option<P2PMessage> {
        std::future::pending().await
    }
}

fn coordinator(enabled: bool) -> IdleCoordinator {
    IdleCoordinator::new(
        enabled,
        false,
        42,
        PeerId::from(0),
        NumPeers::from(4),
        enabled.then(|| Arc::new(SubmissionActivity::default())),
    )
}

fn advertise_all(coordinator: &IdleCoordinator) {
    for peer in 1..4 {
        assert_eq!(
            coordinator.receive(
                PeerId::from(peer),
                IdleControlV1::Capability {
                    protocol: 1,
                    session: 42,
                    boot_id: [peer as u8; 16],
                },
            ),
            None
        );
    }
}

#[test]
fn disabled_mode_never_closes() {
    let coordinator = coordinator(false);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    assert!(coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(coordinator.gate().is_open());
}

#[test]
fn all_capable_idle_closes_and_one_work_opens() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    assert!(!coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(!coordinator.gate().is_open());

    let work = IdleControlV1::Work {
        session: 42,
        boot_id: [7; 16],
        generation: 1,
    };
    assert!(matches!(
        coordinator.receive(PeerId::from(1), work),
        Some(IdleControlV1::Ack { generation: 1, .. })
    ));
    assert!(coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(coordinator.gate().is_open());
}

#[test]
fn mixed_capability_and_wrong_session_fail_open() {
    let coordinator = coordinator(true);
    coordinator.receive(
        PeerId::from(1),
        IdleControlV1::Capability {
            protocol: 1,
            session: 42,
            boot_id: [1; 16],
        },
    );
    coordinator.consider_idle();
    assert!(coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(coordinator.gate().is_open());

    assert_eq!(
        coordinator.receive(
            PeerId::from(1),
            IdleControlV1::Work {
                session: 41,
                boot_id: [1; 16],
                generation: u64::MAX,
            },
        ),
        None
    );
    assert!(
        coordinator
            .state
            .lock()
            .expect("mutex poisoned")
            .peer_work
            .is_empty()
    );
}

#[test]
fn control_codec_is_bounded_and_roundtrips() {
    let message = IdleControlV1::Work {
        session: 42,
        boot_id: [3; 16],
        generation: 9,
    };
    assert_eq!(
        IdleCoordinator::decode(&IdleCoordinator::encode(&message)),
        Some(message)
    );
    assert_eq!(IdleCoordinator::decode(&[0; 129]), None);
    assert_eq!(IdleCoordinator::decode(&[0xff; 8]), None);
}

#[test]
fn leases_expire_and_reboot_generation_wakes_without_quorum() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();

    coordinator.receive(
        PeerId::from(1),
        IdleControlV1::Work {
            session: 42,
            boot_id: [1; 16],
            generation: 99,
        },
    );
    let old_deadline =
        coordinator.state.lock().expect("mutex poisoned").peer_work[&PeerId::from(1)].deadline;
    coordinator.receive(
        PeerId::from(1),
        IdleControlV1::Work {
            session: 42,
            boot_id: [1; 16],
            generation: 98,
        },
    );
    assert_eq!(
        coordinator.state.lock().expect("mutex poisoned").peer_work[&PeerId::from(1)].deadline,
        old_deadline
    );
    {
        let mut state = coordinator.state.lock().expect("mutex poisoned");
        state
            .peer_work
            .get_mut(&PeerId::from(1))
            .expect("work")
            .deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("one second fits");
    }
    coordinator.consider_idle();
    assert!(!coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(!coordinator.gate().is_open());

    coordinator.receive(
        PeerId::from(1),
        IdleControlV1::Work {
            session: 42,
            boot_id: [2; 16],
            generation: 0,
        },
    );
    assert!(coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(coordinator.gate().is_open());
}

#[test]
fn exact_items_retry_only_after_local_batch_finalization() {
    let coordinator = coordinator(true);
    let item = ConsensusItem::Default {
        variant: 7,
        bytes: vec![1, 2, 3],
    };
    assert!(coordinator.admit_item(&item));
    assert!(!coordinator.admit_item(&item));

    let items = vec![item.clone()];
    let batch = UnitData::Batch(items.consensus_encode_to_vec());
    coordinator.batch_created(&batch, &items);
    assert!(!coordinator.admit_item(&item));
    coordinator.batch_finalized(&batch);
    assert!(coordinator.admit_item(&item));
}

#[test]
fn empty_provider_reconciliation_cannot_erase_newer_notification() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    assert!(!coordinator.gate().is_open());

    coordinator
        .submission_activity
        .as_ref()
        .expect("activity")
        .announce();
    coordinator.local_submission_pending();
    coordinator.consider_idle();
    assert!(coordinator.gate().is_open());
    assert!(
        coordinator
            .state
            .lock()
            .expect("mutex poisoned")
            .local_active
    );
}

#[test]
fn finalizing_old_batch_cannot_erase_newer_notification() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    let old_item = ConsensusItem::Default {
        variant: 20,
        bytes: vec![1],
    };
    coordinator
        .submission_activity
        .as_ref()
        .expect("activity")
        .announce();
    coordinator.local_submission_pending();
    assert!(coordinator.admit_item(&old_item));
    let old_items = vec![old_item];
    let old_batch = UnitData::Batch(old_items.consensus_encode_to_vec());
    coordinator.batch_created(&old_batch, &old_items);

    coordinator
        .submission_activity
        .as_ref()
        .expect("activity")
        .announce();
    coordinator.local_submission_pending();
    coordinator.batch_finalized(&old_batch);
    assert!(coordinator.gate().is_open());
    assert!(
        coordinator
            .submission_activity
            .as_ref()
            .expect("activity")
            .has_pending()
    );
    assert!(
        coordinator
            .state
            .lock()
            .expect("mutex poisoned")
            .local_active
    );
}

#[tokio::test]
async fn enqueue_in_progress_survives_session_observer_initialization() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    let activity = coordinator
        .submission_activity
        .as_ref()
        .expect("activity")
        .clone();
    let (producer, submissions) = async_channel::bounded(1);
    let (wake_sender, wake_receiver) = tokio::sync::watch::channel(0);
    let (control_sender, _control_receiver) = async_channel::unbounded();
    let connections = RecordingConnections {
        sent: control_sender,
    }
    .into_dyn();
    let (_shutdown_sender, shutdown) = tokio::sync::watch::channel(None);
    let (_signature_sender, signature) = tokio::sync::watch::channel(None);

    // Match the forwarder's deliberate ordering: announce first, then let the
    // new session initialize while the downstream enqueue is still pending.
    activity.announce();
    wake_sender.send_modify(|generation| *generation += 1);
    let mut tasks = IdleSessionTasks::start(
        coordinator.clone(),
        submissions.clone(),
        Some(wake_receiver),
        connections,
        shutdown,
        signature,
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while !coordinator.gate().is_open() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending announcement opens new session");
    assert!(submissions.is_empty());

    let item = ConsensusItem::Default {
        variant: 21,
        bytes: vec![4],
    };
    producer
        .send(item.clone())
        .await
        .expect("enqueue completes");
    let received = submissions.recv().await.expect("data provider receives");
    assert_eq!(received, item);
    assert!(coordinator.admit_item(&received));
    let items = vec![received];
    let batch = UnitData::Batch(items.consensus_encode_to_vec());
    coordinator.batch_created(&batch, &items);
    coordinator.batch_finalized(&batch);
    assert!(!activity.has_pending());
    assert!(!coordinator.gate().is_open());
    tasks.stop().await;
}

#[test]
fn recovery_and_lifecycle_fail_open() {
    let recovery = IdleCoordinator::new(
        true,
        true,
        42,
        PeerId::from(0),
        NumPeers::from(4),
        Some(Arc::new(SubmissionActivity::default())),
    );
    assert!(!recovery.enabled());

    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.fail_open("test lifecycle");
    coordinator.consider_idle();
    assert!(coordinator.state.lock().expect("mutex poisoned").gate_open);
    assert!(coordinator.gate().is_open());
}

#[test]
fn recovery_consumption_clears_process_wide_submission_activity() {
    let activity = Arc::new(SubmissionActivity::default());
    activity.announce();
    let recovery = IdleCoordinator::new(
        true,
        true,
        42,
        PeerId::from(0),
        NumPeers::from(4),
        Some(activity.clone()),
    );
    let item = ConsensusItem::Default {
        variant: 22,
        bytes: vec![5],
    };
    assert!(recovery.admit_item(&item));
    assert!(!activity.has_pending());

    let normal = IdleCoordinator::new(
        true,
        false,
        43,
        PeerId::from(0),
        NumPeers::from(4),
        Some(activity),
    );
    for peer in 1..4 {
        normal.receive(
            PeerId::from(peer),
            IdleControlV1::Capability {
                protocol: 1,
                session: 43,
                boot_id: [peer as u8; 16],
            },
        );
    }
    normal.consider_idle();
    assert!(!normal.gate().is_open());
}

#[test]
fn capability_lease_expiry_fails_open() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    coordinator
        .state
        .lock()
        .expect("mutex poisoned")
        .capabilities
        .get_mut(&PeerId::from(1))
        .expect("capability")
        .1 = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("one second fits");
    coordinator.consider_idle();
    assert!(coordinator.gate().is_open());
}

#[test]
fn default_envelope_roundtrips_through_outer_codec() {
    let message = P2PMessage::Default {
        variant: super::ALEPH_IDLE_CONTROL_V1,
        bytes: IdleCoordinator::encode(&IdleControlV1::Capability {
            protocol: 1,
            session: 42,
            boot_id: [4; 16],
        }),
    };
    assert_eq!(
        P2PMessage::consensus_decode_whole(
            &message.consensus_encode_to_vec(),
            &ModuleRegistry::default(),
        )
        .expect("default envelope decodes"),
        message
    );
}

#[tokio::test]
async fn session_tasks_stop_joined_without_consuming_handoff_items() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();
    assert!(!coordinator.gate().is_open());

    let (source_sender, source) = async_channel::bounded(2);
    let (wake_sender, wake_receiver) = tokio::sync::watch::channel(0);
    let (control_sender, control_receiver) = async_channel::unbounded();
    let connections = RecordingConnections {
        sent: control_sender,
    }
    .into_dyn();
    let (_shutdown_sender, shutdown) = tokio::sync::watch::channel(None);
    let (_signature_sender, signature) = tokio::sync::watch::channel(None);
    let mut tasks = IdleSessionTasks::start(
        coordinator.clone(),
        source.clone(),
        Some(wake_receiver),
        connections,
        shutdown,
        signature,
    );
    let first = ConsensusItem::Default {
        variant: 1,
        bytes: vec![1],
    };
    source_sender
        .send(first.clone())
        .await
        .expect("source open");
    wake_sender.send_modify(|generation| *generation += 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !coordinator.gate().is_open() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("observer wakes gate");
    assert!(coordinator.gate().is_open());

    let second = ConsensusItem::Default {
        variant: 2,
        bytes: vec![2],
    };
    source_sender
        .send(second.clone())
        .await
        .expect("source open");
    wake_sender.send_modify(|generation| *generation += 1);
    tasks.stop().await;
    assert!(
        wake_sender.is_closed(),
        "joined observer dropped its notification receiver"
    );
    assert!(
        control_receiver.is_closed(),
        "joined control task dropped its connection sender"
    );
    assert_eq!(source.recv().await.expect("first item remains"), first);
    assert_eq!(source.recv().await.expect("second item remains"), second);
}

#[tokio::test]
async fn producer_forwarder_notifies_after_lossless_enqueue() {
    let (producer, source) = async_channel::bounded(2);
    let (forwarded, consumer) = async_channel::bounded(1);
    let (notification, mut wake) = tokio::sync::watch::channel(0);
    let task = spawn(
        "test idle producer notifier",
        forward_notified_submissions(
            source,
            forwarded,
            notification,
            Arc::new(SubmissionActivity::default()),
        ),
    );
    let first = ConsensusItem::Default {
        variant: 11,
        bytes: vec![1],
    };
    let second = ConsensusItem::Default {
        variant: 12,
        bytes: vec![2],
    };
    producer.send(first.clone()).await.expect("producer open");
    producer.send(second.clone()).await.expect("producer open");

    while *wake.borrow_and_update() < 2 {
        wake.changed().await.expect("announcements remain open");
    }
    assert_eq!(consumer.recv().await.expect("first forwarded"), first);
    assert_eq!(consumer.recv().await.expect("second forwarded"), second);
    task.abort();
    assert!(task.await.is_err());
}

#[tokio::test]
async fn aleph_joins_before_session_tasks_stop_at_handoff() {
    let coordinator = coordinator(true);
    let (producer, submissions) = async_channel::bounded(1);
    let (wake_sender, wake_receiver) = tokio::sync::watch::channel(0);
    let (control_sender, control_receiver) = async_channel::unbounded();
    let connections = RecordingConnections {
        sent: control_sender,
    }
    .into_dyn();
    let (_shutdown_sender, shutdown) = tokio::sync::watch::channel(None);
    let (_signature_sender, signature) = tokio::sync::watch::channel(None);
    let mut tasks = IdleSessionTasks::start(
        coordinator,
        submissions.clone(),
        Some(wake_receiver),
        connections,
        shutdown,
        signature,
    );
    let item = ConsensusItem::Default {
        variant: 13,
        bytes: vec![3],
    };
    producer.send(item.clone()).await.expect("producer open");
    wake_sender.send_modify(|generation| *generation += 1);

    let (terminator, terminated) = futures::channel::oneshot::channel();
    let consumer_submissions = submissions.clone();
    let live_consumer = spawn("test live Aleph consumer", async move {
        tokio::select! {
            _ = terminated => {}
            () = async {
                while control_receiver.recv().await.is_ok() {}
            } => {
                consumer_submissions.recv().await.ok();
            }
        }
    });
    terminate_aleph_session(terminator, live_consumer, &mut tasks).await;
    assert_eq!(
        submissions
            .try_recv()
            .expect("successor session retains item"),
        item
    );
}

#[tokio::test]
async fn wired_provider_and_finalizer_reidle_after_local_batch() {
    let coordinator = coordinator(true);
    advertise_all(&coordinator);
    coordinator.consider_idle();

    let (submission_sender, submission_receiver) = async_channel::bounded(2);
    let (_signature_sender, signature_receiver) = tokio::sync::watch::channel(None);
    let (timestamp_sender, _timestamp_receiver) = async_channel::unbounded();
    let mut provider = DataProvider::new(
        submission_receiver,
        signature_receiver,
        timestamp_sender,
        false,
        coordinator.clone(),
    );
    let item = ConsensusItem::Default {
        variant: 3,
        bytes: vec![3],
    };
    submission_sender
        .send(item.clone())
        .await
        .expect("submission queue open");
    coordinator.local_submission_pending();
    let data = provider.get_data().await.expect("provider builds batch");
    assert!(coordinator.gate().is_open());
    assert_eq!(data, UnitData::Batch(vec![item].consensus_encode_to_vec()));

    let (ordered_sender, ordered_receiver) = async_channel::unbounded();
    let mut finalizer = FinalizationHandler::new(ordered_sender, coordinator.clone());
    finalizer.unit_finalized(NodeIndex(0), 1, Some(data.clone()));
    assert_eq!(
        ordered_receiver.recv().await.expect("finalized unit").data,
        Some(data)
    );
    assert!(!coordinator.gate().is_open());
}

#[tokio::test]
async fn network_dispatches_authenticated_control_and_returns_ack() {
    let coordinator = coordinator(true);
    let (local_connections, peer_connections) =
        make_fake_peer_connection(PeerId::from(0), PeerId::from(1), 4);
    let (outcome_sender, _outcome_receiver) = async_channel::unbounded();
    let (signature_sender, _signature_receiver) = async_channel::unbounded();
    let db: Database = MemDatabase::new().into_database();
    let mut network = Network::new(
        local_connections,
        outcome_sender,
        signature_sender,
        db,
        coordinator.clone(),
    );
    let task = spawn("test idle network dispatch", async move {
        let _ = network.next_event().await;
    });

    peer_connections.send(
        Recipient::Peer(PeerId::from(0)),
        P2PMessage::Default {
            variant: super::ALEPH_IDLE_CONTROL_V1,
            bytes: IdleCoordinator::encode(&IdleControlV1::Work {
                session: 42,
                boot_id: [1; 16],
                generation: 7,
            }),
        },
    );
    let (_, ack) = peer_connections.receive().await.expect("peer receives ACK");
    assert!(matches!(
        ack,
        P2PMessage::Default {
            variant: super::ALEPH_IDLE_CONTROL_V1,
            bytes,
        } if matches!(
            IdleCoordinator::decode(&bytes),
            Some(IdleControlV1::Ack { generation: 7, .. })
        )
    ));
    assert!(coordinator.gate().is_open());
    task.abort();
    assert!(task.await.is_err());
}

#[tokio::test]
async fn control_loop_emits_capability_and_work_but_disabled_mode_is_silent() {
    let (sent, received) = async_channel::unbounded();
    let connections = RecordingConnections { sent }.into_dyn();
    let (_shutdown_sender, shutdown) = tokio::sync::watch::channel(None);
    let (_signature_sender, signature) = tokio::sync::watch::channel(None);
    let enabled_coordinator = coordinator(true);
    let task = spawn("test idle control emission", {
        let coordinator = enabled_coordinator.clone();
        let connections = connections.clone();
        async move {
            coordinator
                .run_control_loop(connections, shutdown, signature)
                .await;
        }
    });
    let (recipient, capability) = received.recv().await.expect("capability emitted");
    assert_eq!(recipient, Recipient::Everyone);
    assert!(matches!(
        capability,
        P2PMessage::Default {
            variant: super::ALEPH_IDLE_CONTROL_V1,
            bytes,
        } if matches!(
            IdleCoordinator::decode(&bytes),
            Some(IdleControlV1::Capability { session: 42, .. })
        )
    ));

    enabled_coordinator.local_submission_pending();
    let (_, work) = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .expect("work refresh deadline")
        .expect("work emitted");
    assert!(matches!(
        work,
        P2PMessage::Default {
            variant: super::ALEPH_IDLE_CONTROL_V1,
            bytes,
        } if matches!(
            IdleCoordinator::decode(&bytes),
            Some(IdleControlV1::Work {
                session: 42,
                generation: 1,
                ..
            })
        )
    ));
    task.abort();
    assert!(task.await.is_err());

    let (disabled_sent, disabled_received) = async_channel::unbounded();
    let disabled_connections = RecordingConnections {
        sent: disabled_sent,
    }
    .into_dyn();
    let (_shutdown_sender, shutdown) = tokio::sync::watch::channel(None);
    let (_signature_sender, signature) = tokio::sync::watch::channel(None);
    coordinator(false)
        .run_control_loop(disabled_connections, shutdown, signature)
        .await;
    assert!(disabled_received.is_empty());
}
