use aleph_bft::{BackupReader as _, BackupWriter as _};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;

use super::{BackupReader, BackupWriter};
use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};

fn unit(byte: u8) -> Vec<u8> {
    vec![byte; 3]
}

async fn stored_rows(db: &Database) -> Vec<(u64, Vec<u8>)> {
    db.begin_transaction_nc()
        .await
        .find_by_prefix(&AlephUnitsPrefix)
        .await
        .map(|(key, unit)| (key.0, unit))
        .collect()
        .await
}

#[tokio::test]
async fn units_of_peers_are_written_with_our_next_unit() {
    let db: Database = MemDatabase::new().into();
    let mut writer = BackupWriter::new(db.clone()).await;

    writer.append(&unit(1), false).await.unwrap();
    writer.append(&unit(2), false).await.unwrap();
    assert!(stored_rows(&db).await.is_empty());

    writer.append(&unit(3), true).await.unwrap();
    assert_eq!(
        stored_rows(&db).await,
        vec![(0, unit(1)), (1, unit(2)), (2, unit(3))]
    );

    writer.append(&unit(4), true).await.unwrap();
    assert_eq!(stored_rows(&db).await.last(), Some(&(3, unit(4))));
}

#[tokio::test]
async fn a_restarted_writer_continues_after_the_stored_units() {
    let db: Database = MemDatabase::new().into();

    let mut writer = BackupWriter::new(db.clone()).await;
    writer.append(&unit(1), true).await.unwrap();
    // Lost with the writer, like the units of peers held at a crash.
    writer.append(&unit(2), false).await.unwrap();
    drop(writer);

    let mut writer = BackupWriter::new(db.clone()).await;
    writer.append(&unit(3), true).await.unwrap();

    assert_eq!(stored_rows(&db).await, vec![(0, unit(1)), (1, unit(3))]);
    assert_eq!(
        BackupReader::new(db.clone()).read().await.unwrap(),
        [unit(1), unit(3)].concat()
    );
    assert!(
        db.begin_transaction_nc()
            .await
            .get_value(&AlephUnitsKey(2))
            .await
            .is_none()
    );
}

/// Older versions stored the replayed units again on every restart.
#[tokio::test]
async fn units_stored_more_than_once_are_loaded_once() {
    let db: Database = MemDatabase::new().into();

    let mut dbtx = db.begin_transaction().await;
    for (index, byte) in [1, 2, 1, 2, 3, 1, 2, 3].into_iter().enumerate() {
        dbtx.insert_new_entry(&AlephUnitsKey(index as u64), &unit(byte))
            .await;
    }
    dbtx.commit_tx().await;

    assert_eq!(
        BackupReader::new(db.clone()).read().await.unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    let mut writer = BackupWriter::new(db.clone()).await;
    writer.append(&unit(4), true).await.unwrap();

    let rows = stored_rows(&db).await;
    assert_eq!(rows.len(), 9);
    assert_eq!(rows.last(), Some(&(8, unit(4))));
}
