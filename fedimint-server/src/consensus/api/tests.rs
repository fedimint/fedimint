use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::thread;
use std::time::Instant;

use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{IDatabaseTransactionOpsCoreTyped as _, IRawDatabaseExt as _};
use fedimint_core::net::guardian_metadata::GuardianMetadata;
use fedimint_core::{BitcoinHash as _, IdxRange, TransactionId};

use super::{
    Database, Duration, LegacyP2PConnectionStatus, MAX_BACKUP_FUTURE_TIMESTAMP_SECS,
    MAX_OUTPUTS_OUTCOMES_BATCH, OutPointRange, P2PConnectionState, P2PConnectionStatus, PeerId,
    SystemTime, backup_timestamp_is_too_far_in_future, checked_outputs_outcomes_count,
    legacy_peer_status, secp256k1, sign_guardian_metadata_preserving_iroh_endpoint, watch,
};
use crate::net::api::guardian_metadata::GuardianMetadataKey;

/// `AWAIT_OUTPUTS_OUTCOMES` is public and unauthenticated, and the range it
/// takes has no validation of its own. A single request used to size a
/// `Vec` from `u64::MAX` indexes.
#[test]
fn outputs_outcomes_range_is_bounded() {
    let txid = TransactionId::from_slice(&[0; 32]).expect("32 bytes is a valid txid");
    let range = |start, end| OutPointRange::new(txid, IdxRange::from(start..end));

    assert_eq!(
        checked_outputs_outcomes_count(range(0, MAX_OUTPUTS_OUTCOMES_BATCH as u64))
            .expect("a range at the limit is served"),
        MAX_OUTPUTS_OUTCOMES_BATCH
    );

    for rejected in [
        range(0, u64::MAX),
        range(0, MAX_OUTPUTS_OUTCOMES_BATCH as u64 + 1),
        // Descending ranges are rejected here rather than left to the
        // iterator's tolerance of them.
        range(u64::MAX, 0),
        range(5, 4),
    ] {
        assert!(
            checked_outputs_outcomes_count(rejected).is_err(),
            "{rejected:?} must be rejected"
        );
    }
}

/// `legacy_peer_status` must never hold two guards on the same watch
/// channel at once. `parking_lot`'s `RwLock` is write-preferring, so the
/// second `borrow()` would block behind a queued writer that can never
/// drain past the first guard, wedging a guardian permanently.
///
/// Hitting the window between two guards is a race, so this hammers it:
/// with the guards overlapping, a writer lands in that window and the
/// reader threads stop making progress long before the deadline.
#[test]
fn legacy_peer_status_does_not_deadlock_against_a_writer() {
    const READERS: usize = 8;
    const READS_PER_THREAD: u64 = 100_000;

    let (p2p_sender, p2p_receiver) = watch::channel(P2PConnectionState {
        connected: None,
        last_error: None,
    });
    let (ci_sender, ci_receiver) = watch::channel(None);
    let stop = Arc::new(AtomicBool::new(false));

    let writers = [
        {
            // The p2p writer is the one observed wedged in production: the
            // connection task calls `send_replace` on every state change.
            let stop = stop.clone();
            thread::spawn(move || {
                let mut connected = false;
                while !stop.load(Relaxed) {
                    connected = !connected;
                    p2p_sender.send_replace(P2PConnectionState {
                        connected: connected.then_some(P2PConnectionStatus {
                            conn_type: None,
                            rtt: None,
                        }),
                        last_error: None,
                    });
                }
            })
        },
        {
            let stop = stop.clone();
            thread::spawn(move || {
                let mut session = 0;
                while !stop.load(Relaxed) {
                    session += 1;
                    ci_sender.send_replace(Some(session));
                }
            })
        },
    ];

    let finished_readers = Arc::new(AtomicUsize::new(0));

    for _ in 0..READERS {
        let p2p_receiver = p2p_receiver.clone();
        let ci_receiver = ci_receiver.clone();
        let finished_readers = finished_readers.clone();

        thread::spawn(move || {
            for _ in 0..READS_PER_THREAD {
                legacy_peer_status(&p2p_receiver, &ci_receiver, u64::MAX);
            }

            finished_readers.fetch_add(1, Relaxed);
        });
    }

    // Deadlocked readers never return, so wait on a counter rather than
    // joining them: this has to fail the test, not hang the suite.
    let deadline = Instant::now() + Duration::from_secs(60);
    while finished_readers.load(Relaxed) < READERS {
        if Instant::now() >= deadline {
            // Stop the writers before failing. The wedged readers can
            // never be joined, so a writer still spinning here would burn
            // a core for the rest of the test binary and slow every test
            // that runs after this one.
            stop.store(true, Relaxed);

            panic!(
                "only {} of {READERS} reader threads finished before the deadline, \
                 which means peer status reads are wedged behind a writer",
                finished_readers.load(Relaxed)
            );
        }

        thread::sleep(Duration::from_millis(10));
    }

    stop.store(true, Relaxed);
    for writer in writers {
        writer.join().expect("writer thread panicked");
    }
}

/// The two watch channels are read once each, and `flagged` is derived
/// from the same `last_contribution` that is reported.
#[test]
fn legacy_peer_status_flags_peers_lagging_the_session_count() {
    let peer_status = |connected: bool, last_contribution, session_count| {
        let (_p2p_sender, p2p_receiver) = watch::channel(P2PConnectionState {
            connected: connected.then_some(P2PConnectionStatus {
                conn_type: None,
                rtt: None,
            }),
            last_error: None,
        });
        let (_ci_sender, ci_receiver) = watch::channel(last_contribution);

        legacy_peer_status(&p2p_receiver, &ci_receiver, session_count)
    };

    let current = peer_status(true, Some(9), 10);
    assert_eq!(
        current.connection_status,
        LegacyP2PConnectionStatus::Connected
    );
    assert_eq!(current.last_contribution, Some(9));
    assert!(!current.flagged, "a peer one behind the session is current");

    assert!(
        peer_status(true, Some(8), 10).flagged,
        "a peer two behind the session is flagged"
    );
    assert!(
        peer_status(true, None, 10).flagged,
        "a peer that has never contributed is flagged"
    );
    assert!(
        !peer_status(true, None, 1).flagged,
        "no peer has contributed to the first session yet"
    );

    assert_eq!(
        peer_status(false, Some(9), 10).connection_status,
        LegacyP2PConnectionStatus::Disconnected
    );
}

#[test]
fn backup_timestamp_future_limit_is_strict() {
    let now = SystemTime::UNIX_EPOCH;
    let at_limit = now
        .checked_add(Duration::from_secs(MAX_BACKUP_FUTURE_TIMESTAMP_SECS))
        .expect("UNIX epoch plus one hour is representable");
    let beyond_limit = at_limit
        .checked_add(Duration::from_nanos(1))
        .expect("one nanosecond past the limit is representable");
    let past = now
        .checked_sub(Duration::from_nanos(1))
        .expect("one nanosecond before the UNIX epoch is representable");

    assert!(!backup_timestamp_is_too_far_in_future(now, now));
    assert!(!backup_timestamp_is_too_far_in_future(past, now));
    assert!(!backup_timestamp_is_too_far_in_future(at_limit, now));
    assert!(backup_timestamp_is_too_far_in_future(beyond_limit, now));
}

#[tokio::test]
async fn admin_metadata_update_preserves_persisted_iroh_endpoint() {
    let db: Database = MemDatabase::new().into_database();
    let identity = PeerId::from(0);
    let broadcast_secret_key = secp256k1::SecretKey::from_slice(&[42; 32]).expect("valid test key");
    let ctx = secp256k1::Secp256k1::new();

    let existing = GuardianMetadata::new(
        vec!["wss://old.example".parse().expect("valid URL")],
        "old-pkarr".to_owned(),
        1,
    )
    .with_iroh_next_endpoint("persisted-iroh-id".to_owned())
    .sign(&ctx, &broadcast_secret_key.keypair(&ctx));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&GuardianMetadataKey(identity), &existing)
        .await;
    dbtx.commit_tx().await;

    let updated = GuardianMetadata::new(
        vec!["wss://new.example".parse().expect("valid URL")],
        "new-pkarr".to_owned(),
        2,
    );
    let signed = sign_guardian_metadata_preserving_iroh_endpoint(
        &db,
        identity,
        &broadcast_secret_key,
        updated,
    )
    .await;

    assert_eq!(
        signed.guardian_metadata().iroh_next_endpoint.as_deref(),
        Some("persisted-iroh-id")
    );
    assert_eq!(
        signed.guardian_metadata().api_urls,
        vec!["wss://new.example".parse().expect("valid URL")]
    );
    assert_eq!(signed.guardian_metadata().pkarr_id_z32, "new-pkarr");
    assert_eq!(
        db.begin_transaction_nc()
            .await
            .get_value(&GuardianMetadataKey(identity))
            .await
            .expect("metadata was persisted")
            .tagged_hash(),
        signed.tagged_hash()
    );
}
