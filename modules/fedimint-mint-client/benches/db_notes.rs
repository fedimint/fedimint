use criterion::{criterion_group, criterion_main, Criterion};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::Amount;
use fedimint_mint_client::client_db::{NoteKey, NoteKeyPrefix};
use fedimint_mint_client::SpendableNote;
use fedimint_mint_common::Nonce;
use fedimint_rocksdb::RocksDb;
use futures::StreamExt;
use rand::thread_rng;
use secp256k1::KeyPair;
use tbs::Signature;
use tempfile::tempdir;
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G1Affine, Scalar};

fn load_ecash_notes_from_db(c: &mut Criterion) {
    const NUM_NOTES: u64 = 1000;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    let db_path = tempdir().expect("Failed to create temp dir");
    let rocks_db = RocksDb::open(db_path).expect("Failed to open DB");
    let db = Database::new(rocks_db, Default::default());

    runtime.block_on(async {
        let mut dbtx = db.begin_transaction().await;
        for i in 0..NUM_NOTES {
            let amount = Amount::from_sats(i * 100000);
            let spend_key = KeyPair::new(secp256k1::SECP256K1, &mut thread_rng());

            let note_key = NoteKey {
                amount,
                nonce: Nonce(spend_key.public_key()),
            };
            let note = SpendableNote {
                signature: Signature(
                    (G1Affine::generator() * Scalar::random(&mut thread_rng())).to_affine(),
                ),
                spend_key,
            };

            dbtx.insert_new_entry(&note_key, &note).await;
        }
        dbtx.commit_tx().await;
    });

    c.bench_function("load e-cash notes from DB", |b| {
        b.to_async(&runtime).iter(|| async {
            let mut dbtx = db.begin_transaction_nc().await;
            let notes = dbtx
                .find_by_prefix(&NoteKeyPrefix)
                .await
                .collect::<Vec<_>>()
                .await;
            assert_eq!(notes.len() as u64, NUM_NOTES);
            notes
        })
    });
}

criterion_group!(benches, load_ecash_notes_from_db);
criterion_main!(benches);
