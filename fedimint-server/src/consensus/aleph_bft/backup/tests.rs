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

/// AlephBFT hands every unit it replays from the backup to the writer again.
#[tokio::test]
async fn restarts_within_a_session_do_not_store_replayed_units_again() {
    let db: Database = MemDatabase::new().into();

    let mut writer = BackupWriter::new(db.clone()).await;
    for byte in [1, 2, 3] {
        writer.append(&unit(byte)).await.unwrap();
    }

    let mut stored = vec![1, 2, 3];
    for restart in 0..3 {
        assert_eq!(
            BackupReader::new(db.clone()).read().await.unwrap(),
            stored.iter().copied().flat_map(unit).collect::<Vec<_>>()
        );

        // Replay everything loaded, as AlephBFT does after a restart.
        let mut writer = BackupWriter::new(db.clone()).await;
        for &byte in &stored {
            writer.append(&unit(byte)).await.unwrap();
        }
        // The first restart also creates one new unit before the next crash.
        if restart == 0 {
            writer.append(&unit(4)).await.unwrap();
            stored.push(4);
        }
    }

    assert_eq!(
        stored_rows(&db).await,
        vec![(0, unit(1)), (1, unit(2)), (2, unit(3)), (3, unit(4))]
    );
}

/// Databases written before the writer skipped replayed units hold a copy of
/// the session's units per restart.
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
    for byte in [1, 2, 3, 4] {
        writer.append(&unit(byte)).await.unwrap();
    }

    let rows = stored_rows(&db).await;
    assert_eq!(rows.len(), 9);
    assert_eq!(rows.last(), Some(&(8, unit(4))));
}
