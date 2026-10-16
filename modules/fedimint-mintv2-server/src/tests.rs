use std::pin::pin;

use fedimint_core::bitcoin::hashes::Hash as _;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime::{Duration, timeout};
use fedimint_core::{IdxRange, OutPointRange, TransactionId};
use tbs::BlindedSignatureShare;
use threshold_crypto::group::Curve;
use threshold_crypto::{G1Projective, Scalar};

use crate::await_signature_shares;
use crate::db::BlindedSignatureShareKey;

fn db() -> Database {
    Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
}

fn range(start: u64, end: u64) -> OutPointRange {
    OutPointRange::new(TransactionId::all_zeros(), IdxRange::from(start..end))
}

fn share(i: u64) -> BlindedSignatureShare {
    BlindedSignatureShare((G1Projective::generator() * Scalar::from(i + 1)).to_affine())
}

/// Writes the range's shares the way output processing does: all of them in
/// one transaction.
async fn write_shares(db: &Database, range: OutPointRange) -> Vec<BlindedSignatureShare> {
    let mut dbtx = db.begin_transaction().await;
    let mut shares = Vec::new();

    for (i, out_point) in range.into_iter().enumerate() {
        let share = share(i as u64);
        dbtx.insert_new_entry(&BlindedSignatureShareKey(out_point), &share)
            .await;
        shares.push(share);
    }

    dbtx.commit_tx().await;

    shares
}

#[tokio::test]
async fn shares_requested_before_commitment_arrive_with_it() {
    let db = db();
    let range = range(2, 5);

    let mut wait = pin!(await_signature_shares(&db, range));

    assert!(
        timeout(Duration::from_millis(200), &mut wait)
            .await
            .is_err(),
        "the request must stay pending until the shares are written"
    );

    let shares = write_shares(&db, range).await;

    assert_eq!(
        timeout(Duration::from_secs(5), wait)
            .await
            .expect("the shares resolve the request"),
        shares
    );
}

#[tokio::test]
async fn shares_already_written_are_answered_at_once() {
    let db = db();
    let range = range(0, 3);

    let shares = write_shares(&db, range).await;

    assert_eq!(
        timeout(Duration::from_secs(5), await_signature_shares(&db, range))
            .await
            .expect("written shares are answered without waiting"),
        shares
    );
}

#[tokio::test]
async fn empty_and_descending_ranges_have_no_shares() {
    let db = db();

    for range in [range(3, 3), range(5, 2)] {
        assert_eq!(
            timeout(Duration::from_secs(5), await_signature_shares(&db, range))
                .await
                .expect("a range without outputs is answered without waiting"),
            Vec::new()
        );
    }
}
