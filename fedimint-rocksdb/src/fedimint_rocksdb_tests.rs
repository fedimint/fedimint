use fedimint_core::db::{Database, DatabaseError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::{impl_db_lookup, impl_db_record};
use futures::StreamExt;

use super::{RocksDb, RocksDbReadOnly, next_prefix};

fn open_temp_db(temp_path: &str) -> Database {
    let path = tempfile::Builder::new()
        .prefix(temp_path)
        .tempdir()
        .unwrap();

    Database::new(
        RocksDb::build(path.as_ref()).open_blocking().unwrap(),
        ModuleDecoderRegistry::default(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_insert_elements() {
    fedimint_core::db::verify_insert_elements(open_temp_db("fcb-rocksdb-test-insert-elements"))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_nonexisting() {
    fedimint_core::db::verify_remove_nonexisting(open_temp_db(
        "fcb-rocksdb-test-remove-nonexisting",
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_existing() {
    fedimint_core::db::verify_remove_existing(open_temp_db("fcb-rocksdb-test-remove-existing"))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_read_own_writes() {
    fedimint_core::db::verify_read_own_writes(open_temp_db("fcb-rocksdb-test-read-own-writes"))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_prevent_dirty_reads() {
    fedimint_core::db::verify_prevent_dirty_reads(open_temp_db(
        "fcb-rocksdb-test-prevent-dirty-reads",
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_find_by_range() {
    fedimint_core::db::verify_find_by_range(open_temp_db("fcb-rocksdb-test-find-by-range")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_find_by_prefix() {
    fedimint_core::db::verify_find_by_prefix(open_temp_db("fcb-rocksdb-test-find-by-prefix")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_commit() {
    fedimint_core::db::verify_commit(open_temp_db("fcb-rocksdb-test-commit")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_prevent_nonrepeatable_reads() {
    fedimint_core::db::verify_prevent_nonrepeatable_reads(open_temp_db(
        "fcb-rocksdb-test-prevent-nonrepeatable-reads",
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_snapshot_isolation() {
    fedimint_core::db::verify_snapshot_isolation(open_temp_db(
        "fcb-rocksdb-test-snapshot-isolation",
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_phantom_entry() {
    fedimint_core::db::verify_phantom_entry(open_temp_db("fcb-rocksdb-test-phantom-entry")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_write_conflict() {
    fedimint_core::db::expect_write_conflict(open_temp_db("fcb-rocksdb-test-write-conflict")).await;
}

/// Test that concurrent transaction conflicts are handled gracefully
/// with autocommit retry logic instead of panicking.
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_transaction_conflict_with_autocommit() {
    use std::sync::Arc;

    let db = Arc::new(open_temp_db("fcb-rocksdb-test-concurrent-conflict"));

    // Spawn multiple concurrent tasks that all write to the same key
    // This will trigger optimistic transaction conflicts
    let mut handles = Vec::new();

    for i in 0u64..10 {
        let db_clone = Arc::clone(&db);
        let handle = fedimint_core::runtime::spawn("rocksdb-transient-error-test", async move {
            for j in 0u64..10 {
                // Use autocommit which handles retriable errors with retry logic
                let result = db_clone
                    .autocommit::<_, _, std::convert::Infallible>(
                        |dbtx, _| {
                            #[allow(clippy::cast_possible_truncation)]
                            let val = (i * 100 + j) as u8;
                            Box::pin(async move {
                                // All transactions write to the same key to force conflicts
                                dbtx.insert_entry(&TestKey(vec![0]), &TestVal(vec![val]))
                                    .await;
                                Ok(())
                            })
                        },
                        None, // unlimited retries
                    )
                    .await;

                // Should succeed after retries, must NOT panic with "Resource busy"
                assert!(
                    result.is_ok(),
                    "Transaction should succeed after retries, got: {result:?}",
                );
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks - none should panic
    for handle in handles {
        handle.await.expect("Task should not panic");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dbtx_remove_by_prefix() {
    fedimint_core::db::verify_remove_by_prefix(open_temp_db("fcb-rocksdb-test-remove-by-prefix"))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_module_dbtx() {
    fedimint_core::db::verify_module_prefix(open_temp_db("fcb-rocksdb-test-module-prefix")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_module_db() {
    let module_instance_id = 1;
    let path = tempfile::Builder::new()
        .prefix("fcb-rocksdb-test-module-db-prefix")
        .tempdir()
        .unwrap();

    let module_db = Database::new(
        RocksDb::build(path.as_ref()).open_blocking().unwrap(),
        ModuleDecoderRegistry::default(),
    );

    fedimint_core::db::verify_module_db(
        open_temp_db("fcb-rocksdb-test-module-db"),
        module_db.with_prefix_module_id(module_instance_id).0,
    )
    .await;
}

#[test]
fn test_next_prefix() {
    // Note: although we are testing the general case of a vector with N elements,
    // the prefixes currently use N = 1
    assert_eq!(next_prefix(&[1, 2, 3]).unwrap(), vec![1, 2, 4]);
    assert_eq!(next_prefix(&[1, 2, 254]).unwrap(), vec![1, 2, 255]);
    assert_eq!(next_prefix(&[1, 2, 255]).unwrap(), vec![1, 3, 0]);
    assert_eq!(next_prefix(&[1, 255, 255]).unwrap(), vec![2, 0, 0]);
    // this is a "max" prefix
    assert!(next_prefix(&[255, 255, 255]).is_none());
    // these are the common case
    assert_eq!(next_prefix(&[0]).unwrap(), vec![1]);
    assert_eq!(next_prefix(&[254]).unwrap(), vec![255]);
    assert!(next_prefix(&[255]).is_none()); // this is a "max" prefix
}

#[repr(u8)]
#[derive(Clone)]
pub enum TestDbKeyPrefix {
    Test = 254,
    MaxTest = 255,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(super) struct TestKey(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(super) struct TestVal(pub Vec<u8>);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefix;

impl_db_record!(
    key = TestKey,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::Test,
    notify_on_modify = true,
);
impl_db_lookup!(key = TestKey, query_prefix = DbPrefixTestPrefix);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(super) struct TestKey2(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(super) struct TestVal2(pub Vec<u8>);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefixMax;

impl_db_record!(
    key = TestKey2,
    value = TestVal2,
    db_prefix = TestDbKeyPrefix::MaxTest, // max/last prefix
    notify_on_modify = true,
);
impl_db_lookup!(key = TestKey2, query_prefix = DbPrefixTestPrefixMax);

#[tokio::test(flavor = "multi_thread")]
async fn test_retrieve_descending_order() {
    let path = tempfile::Builder::new()
        .prefix("fcb-rocksdb-test-descending-order")
        .tempdir()
        .unwrap();
    {
        let db = Database::new(
            RocksDb::build(&path).open().await.unwrap(),
            ModuleDecoderRegistry::default(),
        );
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&TestKey(vec![0]), &TestVal(vec![3]))
            .await;
        dbtx.insert_entry(&TestKey(vec![254]), &TestVal(vec![1]))
            .await;
        dbtx.insert_entry(&TestKey(vec![255]), &TestVal(vec![2]))
            .await;
        dbtx.insert_entry(&TestKey2(vec![0]), &TestVal2(vec![3]))
            .await;
        dbtx.insert_entry(&TestKey2(vec![254]), &TestVal2(vec![1]))
            .await;
        dbtx.insert_entry(&TestKey2(vec![255]), &TestVal2(vec![2]))
            .await;
        let query = dbtx
            .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(
            query,
            vec![
                (TestKey(vec![255]), TestVal(vec![2])),
                (TestKey(vec![254]), TestVal(vec![1])),
                (TestKey(vec![0]), TestVal(vec![3]))
            ]
        );
        let query = dbtx
            .find_by_prefix_sorted_descending(&DbPrefixTestPrefixMax)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(
            query,
            vec![
                (TestKey2(vec![255]), TestVal2(vec![2])),
                (TestKey2(vec![254]), TestVal2(vec![1])),
                (TestKey2(vec![0]), TestVal2(vec![3]))
            ]
        );
        dbtx.commit_tx().await;
    }
    // Test readonly implementation
    let db_readonly = RocksDbReadOnly::open_read_only(path).await.unwrap();
    let db_readonly = Database::new(db_readonly, ModuleRegistry::default());
    let mut dbtx = db_readonly.begin_transaction_nc().await;
    let query = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        query,
        vec![
            (TestKey(vec![255]), TestVal(vec![2])),
            (TestKey(vec![254]), TestVal(vec![1])),
            (TestKey(vec![0]), TestVal(vec![3]))
        ]
    );
    let query = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefixMax)
        .await
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        query,
        vec![
            (TestKey2(vec![255]), TestVal2(vec![2])),
            (TestKey2(vec![254]), TestVal2(vec![1])),
            (TestKey2(vec![0]), TestVal2(vec![3]))
        ]
    );
}

/// `RocksDB` validates an optimistic transaction at commit time against the
/// write history it still keeps in memory. That history is bounded by
/// `max_write_buffer_size_to_maintain`, which `OptimisticTransactionDB`
/// defaults to `max_write_buffer_number * write_buffer_size` — 4 MiB with
/// our options. Once a transaction's snapshot falls out of that window
/// `RocksDB` can no longer tell whether anything conflicted, and fails the
/// commit with `TryAgain` even though no other transaction ever touched any
/// of its keys.
///
/// This is not a write conflict, and must not be reported as one: the
/// caller has to be able to tell a genuine race from a transaction that
/// was simply held open too long.
///
/// See: <https://github.com/fedimint/fedimint/issues/8872>
#[tokio::test(flavor = "multi_thread")]
async fn test_long_lived_transaction_fails_without_key_overlap() {
    let path = tempfile::Builder::new()
        .prefix("fcb-rocksdb-test-long-lived-transaction")
        .tempdir()
        .unwrap();

    let db = Database::new(
        RocksDb::build(path.as_ref()).open_blocking().unwrap(),
        ModuleDecoderRegistry::default(),
    );

    // A transaction that writes a single key and then stays open, standing in
    // for one that waits on something slow before committing.
    let mut long_lived_dbtx = db.begin_transaction().await;
    long_lived_dbtx
        .insert_entry(&TestKey(vec![0]), &TestVal(vec![0]))
        .await;

    // Unrelated writers commit 8 MiB over keys that are disjoint from the
    // above, which is enough to push the retained history past the snapshot.
    // 6 MiB was the observed threshold, so this leaves some headroom.
    let value = vec![0xab; 64 * 1024];

    for index in 0u32..128 {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(
            &TestKey2(index.to_be_bytes().to_vec()),
            &TestVal2(value.clone()),
        )
        .await;
        dbtx.commit_tx().await;
    }

    let result = long_lived_dbtx.commit_tx_result().await;

    assert!(
        matches!(result, Err(DatabaseError::SnapshotTooOld(_))),
        "expected a stale snapshot, got {result:?}"
    );
}

/// The counterpart to the test above: two transactions writing the *same*
/// key is a genuine conflict, and stays reported as one.
#[tokio::test(flavor = "multi_thread")]
async fn test_same_key_write_is_a_conflict() {
    let path = tempfile::Builder::new()
        .prefix("fcb-rocksdb-test-same-key-write")
        .tempdir()
        .unwrap();

    let db = Database::new(
        RocksDb::build(path.as_ref()).open_blocking().unwrap(),
        ModuleDecoderRegistry::default(),
    );

    let mut first_dbtx = db.begin_transaction().await;
    first_dbtx
        .insert_entry(&TestKey(vec![0]), &TestVal(vec![1]))
        .await;

    let mut second_dbtx = db.begin_transaction().await;
    second_dbtx
        .insert_entry(&TestKey(vec![0]), &TestVal(vec![2]))
        .await;
    second_dbtx.commit_tx().await;

    let result = first_dbtx.commit_tx_result().await;

    assert!(
        matches!(result, Err(DatabaseError::WriteConflict)),
        "expected a write conflict, got {result:?}"
    );
}
