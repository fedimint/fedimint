use fedimint_core::db::{Database, IDatabaseTransactionOpsCore};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use tempfile::TempDir;

use super::MemAndRedb;

async fn open_temp_db(temp_path: &str) -> (Database, TempDir) {
    let temp_dir = tempfile::Builder::new()
        .prefix(temp_path)
        .tempdir()
        .unwrap();

    let db_path = temp_dir.path().join("test.redb");
    let locked_db = MemAndRedb::new(&db_path).await.unwrap();

    let database = Database::new(locked_db, ModuleDecoderRegistry::default());
    (database, temp_dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_insert_elements() {
    let (db, _dir) = open_temp_db("fcb-redb-test-insert-elements").await;
    fedimint_core::db::verify_insert_elements(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_nonexisting() {
    let (db, _dir) = open_temp_db("fcb-redb-test-remove-nonexisting").await;
    fedimint_core::db::verify_remove_nonexisting(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_existing() {
    let (db, _dir) = open_temp_db("fcb-redb-test-remove-existing").await;
    fedimint_core::db::verify_remove_existing(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_read_own_writes() {
    let (db, _dir) = open_temp_db("fcb-redb-test-read-own-writes").await;
    fedimint_core::db::verify_read_own_writes(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_prevent_dirty_reads() {
    let (db, _dir) = open_temp_db("fcb-redb-test-prevent-dirty-reads").await;
    fedimint_core::db::verify_prevent_dirty_reads(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_find_by_range() {
    let (db, _dir) = open_temp_db("fcb-redb-test-find-by-range").await;
    fedimint_core::db::verify_find_by_range(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_find_by_prefix() {
    let (db, _dir) = open_temp_db("fcb-redb-test-find-by-prefix").await;
    fedimint_core::db::verify_find_by_prefix(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_commit() {
    let (db, _dir) = open_temp_db("fcb-redb-test-commit").await;
    fedimint_core::db::verify_commit(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_prevent_nonrepeatable_reads() {
    let (db, _dir) = open_temp_db("fcb-redb-test-prevent-nonrepeatable-reads").await;
    fedimint_core::db::verify_prevent_nonrepeatable_reads(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_phantom_entry() {
    let (db, _dir) = open_temp_db("fcb-redb-test-phantom-entry").await;
    fedimint_core::db::verify_phantom_entry(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_write_conflict() {
    let (db, _dir) = open_temp_db("fcb-redb-test-write-conflict").await;
    fedimint_core::db::verify_snapshot_isolation(db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_by_prefix() {
    let (db, _dir) = open_temp_db("fcb-redb-test-remove-by-prefix").await;
    fedimint_core::db::verify_remove_by_prefix(db).await;
}

/// Create a v2 database with redb2, close it, then open with our
/// MemAndRedb (redb3) and verify the data survived the migration.
#[tokio::test(flavor = "multi_thread")]
async fn test_v2_to_v3_migration() {
    let temp_dir = tempfile::Builder::new()
        .prefix("fcb-redb-test-v2-migration")
        .tempdir()
        .unwrap();
    let db_path = temp_dir.path().join("test.redb");

    let table_def: redb2::TableDefinition<&[u8], &[u8]> =
        redb2::TableDefinition::new("fedimint_kv");

    // Write some data using redb2 (v2 format)
    {
        let db = redb2::Database::create(&db_path).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_def).unwrap();
            table
                .insert(b"key1".as_slice(), b"value1".as_slice())
                .unwrap();
            table
                .insert(b"key2".as_slice(), b"value2".as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    // Open with MemAndRedb — should trigger v2->v3 migration
    let locked_db = MemAndRedb::new(&db_path).await.unwrap();
    let db = Database::new(locked_db, ModuleDecoderRegistry::default());

    // Verify data survived
    let mut dbtx = db.begin_transaction_nc().await;
    assert_eq!(
        dbtx.raw_get_bytes(b"key1").await.unwrap(),
        Some(b"value1".to_vec())
    );
    assert_eq!(
        dbtx.raw_get_bytes(b"key2").await.unwrap(),
        Some(b"value2".to_vec())
    );
}
