//! Determinism tests for `pick_signing_session`, plus the
//! `dump_database` redaction contract for `FrostSigningNonces`. Each
//! test asserts a specific invariant over synthetic DB state. Built on
//! `MemDatabase` so they run as cheap unit tests.
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use bitcoin::Txid;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt};
use fedimint_core::{PeerId, hex};
use fedimint_walletv2_common::taproot::frost::FrostSigningCommitments;
use frost_secp256k1_tr::keys::{IdentifierList, KeyPackage, SigningShare};
use frost_secp256k1_tr::round1;
use rand::rngs::OsRng;

use super::{FrostSigningNonces, REDACTED_NONCE, pick_signing_session};
use crate::db::{FrostSigningCommitmentsKey, FrostSigningNoncesKey};

const N: usize = 7;
const THRESHOLD: usize = 5;

/// Generates a one-off `SigningShare` we can repeatedly call
/// `commit()` on to mint distinct synthetic commitments.
fn signing_share_for_tests() -> SigningShare {
    let (shares, _pubkey_package) =
        frost_secp256k1_tr::keys::generate_with_dealer(7, 5, IdentifierList::Default, OsRng)
            .expect("trusted dealer key gen");
    let any_share = shares.into_values().next().expect("at least one share");
    let key_package = KeyPackage::try_from(any_share).expect("share -> key_package");
    *key_package.signing_share()
}

/// Mints `count` distinct commitments. Values are real
/// `round1::commit` outputs but their content doesn't matter for
/// `pick_signing_session` — only uniqueness within the per-peer
/// prefix scan.
fn mint_commitments(count: usize) -> Vec<FrostSigningCommitments> {
    let signing_share = signing_share_for_tests();
    let mut rng = rand::rngs::OsRng;
    (0..count)
        .map(|_| {
            let (_nonces, commitments) = round1::commit(&signing_share, &mut rng);
            FrostSigningCommitments(commitments)
        })
        .collect()
}

fn peers(n: usize) -> Vec<PeerId> {
    (0..n)
        .map(|i| PeerId::from_str(&i.to_string()).unwrap())
        .collect()
}

/// Builds a fresh `Database` and seeds it with the given
/// commitment-count per peer (peers not in the map get 0).
async fn db_with_commitments(per_peer: &BTreeMap<PeerId, usize>) -> Database {
    let db = MemDatabase::new().into_database();
    let mut dbtx = db.begin_transaction().await;
    for (&peer_id, &count) in per_peer {
        for c in mint_commitments(count) {
            dbtx.insert_entry(
                &FrostSigningCommitmentsKey {
                    peer_id,
                    frost_commitments: c,
                },
                &(),
            )
            .await;
        }
    }
    dbtx.commit_tx().await;
    db
}

fn dummy_txid(seed: u8) -> Txid {
    use bitcoin::hashes::Hash;
    Txid::from_byte_array([seed; 32])
}

/// Runs `pick_signing_session` against a freshly opened transaction.
async fn run_pick(
    db: &Database,
    all_peers: &[PeerId],
    threshold: usize,
    txid: Txid,
    attempt: u32,
    required_commitments: usize,
    suspects: &BTreeSet<PeerId>,
) -> Option<Vec<PeerId>> {
    let mut dbtx = db.begin_transaction().await;
    pick_signing_session(
        &mut dbtx.to_ref_nc(),
        all_peers,
        threshold,
        txid,
        attempt,
        required_commitments,
        suspects,
    )
    .await
}

/// Asserts that two databases with identical synthetic state produce
/// identical `signing_session` outputs for the same inputs.
#[tokio::test]
async fn pick_deterministic_across_peers() {
    let all_peers = peers(N);
    let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();

    let db_a = db_with_commitments(&counts).await;
    let db_b = db_with_commitments(&counts).await;

    let txid = dummy_txid(1);
    let suspects = BTreeSet::new();

    let a = run_pick(&db_a, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
    let b = run_pick(&db_b, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;

    assert_eq!(a, b);
    assert_eq!(a.as_ref().map(std::vec::Vec::len), Some(THRESHOLD));
}

/// Asserts that `attempt` enters the shuffle seed: same
/// (state, attempt) yields the same session, different attempt
/// yields a different shuffled order.
#[tokio::test]
async fn attempt_drives_shuffle_seed() {
    let all_peers = peers(N);
    let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();
    let db = db_with_commitments(&counts).await;
    let txid = dummy_txid(2);
    let suspects = BTreeSet::new();

    let a0 = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
    let a0_again = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects).await;
    let a1 = run_pick(&db, &all_peers, THRESHOLD, txid, 1, 1, &suspects).await;

    assert_eq!(a0, a0_again);
    let a0 = a0.expect("succeeds with all viable");
    let a1 = a1.expect("succeeds with all viable");
    assert_ne!(a0, a1, "attempt should change shuffled order");
}

/// Asserts that peers below `required_commitments` are excluded from
/// the result.
#[tokio::test]
async fn viable_filter_excludes_underbuffered() {
    let all_peers = peers(N);
    let mut counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 4)).collect();
    let starved = PeerId::from_str("6").unwrap();
    counts.insert(starved, 0);

    let db = db_with_commitments(&counts).await;
    let txid = dummy_txid(3);
    let suspects = BTreeSet::new();

    let session = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 2, &suspects)
        .await
        .expect("six viable peers ≥ threshold");
    assert!(!session.contains(&starved));
    assert_eq!(session.len(), THRESHOLD);
}

/// Asserts that suspects are skipped when enough non-suspect viable
/// peers remain.
#[tokio::test]
async fn suspects_excluded_from_session() {
    let all_peers = peers(N);
    let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 4)).collect();
    let db = db_with_commitments(&counts).await;
    let txid = dummy_txid(4);

    let mut suspects = BTreeSet::new();
    suspects.insert(PeerId::from_str("5").unwrap());
    suspects.insert(PeerId::from_str("6").unwrap());

    let session = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 1, &suspects)
        .await
        .expect("5 non-suspect viable = threshold");
    for s in &suspects {
        assert!(!session.contains(s), "must drop suspect {s}");
    }
}

/// Asserts that the function returns `None` when fewer than
/// `threshold` viable peers exist.
#[tokio::test]
async fn returns_none_when_not_enough_viable() {
    let all_peers = peers(N);
    let mut counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 0)).collect();
    for i in 0..4 {
        counts.insert(PeerId::from_str(&i.to_string()).unwrap(), 8);
    }
    let db = db_with_commitments(&counts).await;
    let txid = dummy_txid(7);
    let suspects = BTreeSet::new();

    let result = run_pick(&db, &all_peers, THRESHOLD, txid, 0, 2, &suspects).await;
    assert!(result.is_none(), "fewer viable than threshold ⇒ None");
}

/// Asserts determinism holds as suspects accumulate across attempts:
/// two identical-state databases walk identical suspect growth and
/// agree at every step.
#[tokio::test]
async fn determinism_holds_across_growing_suspects() {
    let all_peers = peers(N);
    let counts: BTreeMap<_, _> = all_peers.iter().map(|p| (*p, 8)).collect();
    let txid = dummy_txid(8);

    let db_a = db_with_commitments(&counts).await;
    let db_b = db_with_commitments(&counts).await;

    let mut suspects = BTreeSet::new();
    for i in 0..=4 {
        let a = run_pick(&db_a, &all_peers, THRESHOLD, txid, i, 1, &suspects).await;
        let b = run_pick(&db_b, &all_peers, THRESHOLD, txid, i, 1, &suspects).await;
        assert_eq!(a, b, "attempt {i}: results diverge");
        suspects.insert(PeerId::from_str(&i.to_string()).unwrap());
    }
}

/// Regression for the dump-redaction contract: the serde output of a
/// `FrostSigningNonces` value — what `dump_database` emits for the
/// `FrostSigningNonce` prefix — must never contain the secret hiding /
/// binding nonces in any form. A dump captured before a nonce is
/// consumed, plus the signature share later broadcast with it, would
/// otherwise reveal this guardian's long-lived signing share. Goes
/// through a real DB round-trip so the value serialized is the decoded
/// at-rest one, exactly as in the dump.
#[tokio::test]
async fn signing_nonces_dump_never_contains_secret_nonces() {
    let signing_share = signing_share_for_tests();
    let (nonces, commitments) = round1::commit(&signing_share, &mut OsRng);

    let hiding_hex = hex::encode(nonces.hiding().serialize());
    let binding_hex = hex::encode(nonces.binding().serialize());
    let full_hex = hex::encode(nonces.serialize().expect("nonces serialize"));
    let commitments_hex = hex::encode(commitments.serialize().expect("commitments serialize"));

    let db = MemDatabase::new().into_database();
    let key = FrostSigningNoncesKey(FrostSigningCommitments(commitments));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&key, &FrostSigningNonces(nonces))
        .await;
    dbtx.commit_tx().await;

    let value = db
        .begin_transaction_nc()
        .await
        .get_value(&key)
        .await
        .expect("nonce was just stored");

    let json = serde_json::to_string(&value).expect("serialize nonces");
    assert!(!json.contains(&hiding_hex), "hiding nonce leaked: {json}");
    assert!(!json.contains(&binding_hex), "binding nonce leaked: {json}");
    assert!(
        !json.contains(&full_hex),
        "serialized nonces leaked: {json}"
    );
    assert!(
        json.contains(REDACTED_NONCE),
        "missing redaction marker: {json}"
    );
    assert!(
        json.contains(&commitments_hex),
        "public commitment should survive redaction: {json}"
    );

    // `Debug` delegates to frost-core's redacting impl; pin that too so a
    // dependency upgrade can't silently start printing secrets.
    let debug = format!("{value:?}");
    assert!(
        !debug.contains(&hiding_hex),
        "hiding nonce in Debug: {debug}"
    );
    assert!(
        !debug.contains(&binding_hex),
        "binding nonce in Debug: {debug}"
    );
}
