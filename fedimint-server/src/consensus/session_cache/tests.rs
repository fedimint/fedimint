use std::collections::BTreeMap;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use fedimint_core::PeerId;
use fedimint_core::core::{
    DecoderBuilder, DynModuleConsensusItem, IntoDynInstance, ModuleConsensusItem, ModuleInstanceId,
    ModuleKind,
};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use fedimint_core::session_outcome::{
    AcceptedItem, ConsensusItem, SessionOutcome, SignedSessionOutcome,
};
use futures::poll;
use tokio::sync::watch;

use super::{
    CachedSessionOutcome, CompletedSession, OutcomeFormat, await_outcome, load, publish_on_commit,
};
use crate::consensus::db::SignedSessionOutcomeKey;

fn outcome(index: u64, payload_size: usize) -> SignedSessionOutcome {
    let session_outcome = SessionOutcome {
        items: vec![AcceptedItem {
            item: ConsensusItem::Default {
                variant: 99,
                bytes: vec![index as u8; payload_size],
            },
            peer: PeerId::from(0),
        }],
    };
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap());
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest([2; 32]), &key);
    SignedSessionOutcome {
        session_outcome,
        signatures: BTreeMap::from([(PeerId::from(0), signature)]),
    }
}

async fn commit(
    db: &Database,
    sender: &watch::Sender<CompletedSession>,
    index: u64,
) -> SignedSessionOutcome {
    let outcome = outcome(index, 4096);
    let mut dbtx = db.begin_transaction().await;
    assert!(
        dbtx.insert_entry(&SignedSessionOutcomeKey(index), &outcome)
            .await
            .is_none()
    );
    publish_on_commit(&mut dbtx, sender.clone(), index, &outcome);
    dbtx.commit_tx_result().await.unwrap();
    outcome
}

async fn await_signed(
    db: &Database,
    receiver: &watch::Receiver<CompletedSession>,
    index: u64,
) -> Arc<serde_json::Value> {
    await_outcome(db, receiver, index, OutcomeFormat::Signed).await
}

fn assert_encoding(encoded: &serde_json::Value, outcome: &SignedSessionOutcome) {
    assert_eq!(
        *encoded,
        serde_json::to_value(SerdeModuleEncoding::from(outcome)).unwrap()
    );
    assert_eq!(
        serde_json::from_value::<SerdeModuleEncoding<SignedSessionOutcome>>(encoded.clone())
            .unwrap()
            .try_into_inner(&ModuleDecoderRegistry::default())
            .unwrap(),
        *outcome
    );
}

#[tokio::test]
async fn startup_restart_and_exact_old_current_future_outcomes() {
    let db: Database = MemDatabase::new().into();
    let mut pending = db.begin_transaction().await;
    pending
        .insert_entry(
            &crate::consensus::db::AcceptedItemKey(0),
            &outcome(0, 8).session_outcome.items[0],
        )
        .await;
    pending.commit_tx_result().await.unwrap();
    // Accepted items are not completed/signed sessions.
    assert!(load(&db).await.is_none());
    let (sender, receiver) = watch::channel(load(&db).await);
    let mut first = Box::pin(await_signed(&db, &receiver, 0));
    assert!(poll!(&mut first).is_pending());
    let zero = commit(&db, &sender, 0).await;
    let first = first.await;
    assert_eq!(receiver.borrow().as_ref().unwrap().index, 0);
    assert_encoding(&first, &zero);
    let again = await_signed(&db, &receiver, 0).await;
    assert!(Arc::ptr_eq(&first, &again));

    assert_eq!(
        *await_outcome(&db, &receiver, 0, OutcomeFormat::Unsigned).await,
        serde_json::to_value(SerdeModuleEncoding::from(&zero.session_outcome)).unwrap()
    );

    let mut future = Box::pin(await_signed(&db, &receiver, 2));
    assert!(poll!(&mut future).is_pending());
    commit(&db, &sender, 1).await;
    assert!(poll!(&mut future).is_pending());
    let two = commit(&db, &sender, 2).await;
    assert_encoding(future.await.as_ref(), &two);
    assert_encoding(await_signed(&db, &receiver, 0).await.as_ref(), &zero);
    assert_eq!(
        *await_outcome(&db, &receiver, 0, OutcomeFormat::Unsigned).await,
        serde_json::to_value(SerdeModuleEncoding::from(&zero.session_outcome)).unwrap()
    );

    let restarted = load(&db).await.unwrap();
    assert_eq!(restarted.index, 2);
    assert_encoding(&restarted.signed, &two);
    let (_sender, restarted_receiver) = watch::channel(Some(restarted));
    assert_encoding(
        await_signed(&db, &restarted_receiver, 0).await.as_ref(),
        &zero,
    );
    assert_encoding(
        await_signed(&db, &restarted_receiver, 2).await.as_ref(),
        &two,
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
struct TestModuleItem(u64);

impl std::fmt::Display for TestModuleItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ModuleConsensusItem for TestModuleItem {
    const KIND: ModuleKind = ModuleKind::from_static_str("session-cache-test");
}

impl IntoDynInstance for TestModuleItem {
    type DynType = DynModuleConsensusItem;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleConsensusItem::from_typed(instance_id, self)
    }
}

#[tokio::test]
async fn restart_preserves_module_decoder_context() {
    let mut decoder = DecoderBuilder::default();
    decoder.with_decodable_type::<TestModuleItem>();
    let decoders = ModuleDecoderRegistry::new([(42, TestModuleItem::KIND, decoder.build())]);
    let db = Database::new(MemDatabase::new(), decoders.clone());
    let mut outcome = outcome(0, 0);
    outcome.session_outcome.items[0].item = ConsensusItem::Module(TestModuleItem(7).into_dyn(42));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&SignedSessionOutcomeKey(0), &outcome)
        .await;
    dbtx.commit_tx_result().await.unwrap();
    let loaded = load(&db).await.unwrap();
    assert_eq!(
        *loaded.signed,
        serde_json::to_value(SerdeModuleEncoding::from(&outcome)).unwrap()
    );
    let encoded: SerdeModuleEncoding<SignedSessionOutcome> =
        serde_json::from_value((*loaded.signed).clone()).unwrap();
    assert_eq!(encoded.try_into_inner(&decoders).unwrap(), outcome);
    assert!(
        encoded
            .try_into_inner(&ModuleDecoderRegistry::default())
            .is_err()
    );
}

#[tokio::test]
async fn failed_and_dropped_commits_never_publish() {
    let db: Database = MemDatabase::new().into();
    let (sender, mut receiver) = watch::channel(None);
    let mut failed = db.begin_transaction().await;
    let candidate = outcome(0, 8);
    failed
        .insert_entry(&SignedSessionOutcomeKey(0), &candidate)
        .await;
    publish_on_commit(&mut failed, sender.clone(), 0, &candidate);
    assert!(receiver.borrow().is_none());

    // A competing write makes the prepared transaction fail at the actual
    // database commit boundary, not at a mock cache-publication boundary.
    let mut winner = db.begin_transaction().await;
    winner
        .insert_entry(&SignedSessionOutcomeKey(0), &outcome(0, 16))
        .await;
    winner.commit_tx_result().await.unwrap();
    assert!(failed.commit_tx_result().await.is_err());
    assert!(receiver.borrow().is_none());
    assert!(!receiver.has_changed().unwrap());

    let mut dropped = db.begin_transaction().await;
    dropped.ignore_uncommitted();
    dropped
        .insert_entry(&SignedSessionOutcomeKey(1), &candidate)
        .await;
    publish_on_commit(&mut dropped, sender.clone(), 1, &candidate);
    drop(dropped);
    assert!(receiver.borrow().is_none());
    assert!(!receiver.has_changed().unwrap());

    // A restart recovers durable state even if the process stopped before
    // publishing it. A subsequent normal completion publishes one whole view.
    assert_eq!(load(&db).await.unwrap().index, 0);
    let one = commit(&db, &sender, 1).await;
    receiver.changed().await.unwrap();
    let snapshot = receiver.borrow();
    assert_eq!(snapshot.as_ref().unwrap().index + 1, 2);
    assert_encoding(&snapshot.as_ref().unwrap().signed, &one);
}

#[tokio::test]
async fn coalesced_notifications_and_many_waiters_do_not_lose_outcomes() {
    let db: Database = MemDatabase::new().into();
    let (sender, receiver) = watch::channel(None);
    let mut waiters: Vec<_> = (0..64)
        .map(|_| Box::pin(await_signed(&db, &receiver, 0)))
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    let zero = commit(&db, &sender, 0).await;
    let mut shared = None;
    for waiter in waiters {
        let result = waiter.await;
        if let Some(previous) = &shared {
            assert!(Arc::ptr_eq(previous, &result));
        }
        shared = Some(result);
    }
    let weak = Arc::downgrade(shared.as_ref().unwrap());
    drop(shared);

    let mut distant_waiter = Box::pin(await_signed(&db, &receiver, 100));
    assert!(poll!(&mut distant_waiter).is_pending());
    let mut old_waiter = Box::pin(await_signed(&db, &receiver, 1));
    assert!(poll!(&mut old_waiter).is_pending());
    let one = commit(&db, &sender, 1).await;
    commit(&db, &sender, 2).await;
    assert!(weak.upgrade().is_none(), "cache retains only the latest");
    assert!(poll!(&mut distant_waiter).is_pending());
    drop(distant_waiter);
    assert_encoding(old_waiter.await.as_ref(), &one);
    assert_encoding(await_signed(&db, &receiver, 0).await.as_ref(), &zero);

    let other_db: Database = MemDatabase::new().into();
    let (_other_sender, other_receiver) = watch::channel(load(&other_db).await);
    assert!(other_receiver.borrow().is_none());
    assert_eq!(receiver.borrow().as_ref().unwrap().index, 2);

    let mut shutdown_waiter = Box::pin(await_signed(&db, &receiver, 3));
    assert!(poll!(&mut shutdown_waiter).is_pending());
    drop(sender);
    assert!(matches!(poll!(&mut shutdown_waiter), Poll::Pending));
}

/// A reproducible hot-path comparison, not an RSS or end-to-end load claim.
#[tokio::test]
#[ignore = "manual session API cache benchmark"]
async fn benchmark_latest_outcome_and_count() {
    use std::hint::black_box;

    use crate::consensus::engine::get_finished_session_count_static;

    let db: Database = MemDatabase::new().into();
    let (sender, receiver) = watch::channel(None);
    let outcome = outcome(0, 64 * 1024);
    let prepared = CachedSessionOutcome::new(0, &outcome);
    eprintln!(
        "Latest cache JSON payload: signed={} bytes, unsigned={} bytes \
         (excluding Value/Arc metadata); retains no decoded outcome",
        serde_json::to_vec(&*prepared.signed).unwrap().len(),
        serde_json::to_vec(&*prepared.unsigned).unwrap().len(),
    );
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&SignedSessionOutcomeKey(0), &outcome)
        .await;
    publish_on_commit(&mut dbtx, sender, 0, &outcome);
    dbtx.commit_tx_result().await.unwrap();
    let iterations = 10_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let decoded = db
            .begin_transaction_nc()
            .await
            .get_value(&SignedSessionOutcomeKey(0))
            .await
            .unwrap();
        black_box(serde_json::to_value(SerdeModuleEncoding::from(&decoded)).unwrap());
    }
    let baseline_outcome = start.elapsed();
    let start = Instant::now();
    for _ in 0..iterations {
        let cached = await_signed(&db, &receiver, 0).await;
        black_box(serde_json::to_value(cached).unwrap());
    }
    let cached_outcome = start.elapsed();
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(get_finished_session_count_static(&mut db.begin_transaction_nc().await).await);
    }
    let baseline_count = start.elapsed();
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(
            receiver
                .borrow()
                .as_ref()
                .map_or(0, |latest| latest.index + 1),
        );
    }
    let cached_count = start.elapsed();
    eprintln!(
        "{iterations} iterations, 64KiB payload, MemDatabase: \
         outcome baseline={baseline_outcome:?} cached={cached_outcome:?}; \
         count baseline={baseline_count:?} cached={cached_count:?}. \
         Baseline: {iterations} DB reads/decodes per endpoint, \
         {iterations} outcome encodes; cached: zero DB reads/decodes/encodes \
         after initial publication, shared buffers (tested with Arc::ptr_eq). \
         Both outcome paths include the endpoint's owned JSON value construction; \
         transport excluded. Cached path still allocates the response JSON string."
    );
}
