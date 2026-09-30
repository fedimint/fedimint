use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_core::db::DbMigrationFnContext;
use futures::future::ready;
use futures::{Future, FutureExt, StreamExt};
use rand::Rng;
use tokio::join;

use super::{
    Database, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey, DatabaseVersionKeyV0,
    DbMigrationError, DbMigrationFn, apply_migrations, apply_migrations_dbtx,
    create_database_version_dbtx,
};
use crate::core::ModuleKind;
use crate::db::mem_impl::MemDatabase;
use crate::db::{IDatabaseTransactionOps, IDatabaseTransactionOpsCoreTyped, MODULE_GLOBAL_PREFIX};
use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

pub async fn future_returns_shortly<F: Future>(fut: F) -> Option<F::Output> {
    crate::runtime::timeout(Duration::from_millis(10), fut)
        .await
        .ok()
}

#[repr(u8)]
#[derive(Clone)]
pub enum TestDbKeyPrefix {
    Test = 0x42,
    AltTest = 0x43,
    PercentTestKey = 0x25,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub(super) struct TestKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefix;

impl_db_record!(
    key = TestKey,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::Test,
    notify_on_modify = true,
);
impl_db_lookup!(key = TestKey, query_prefix = DbPrefixTestPrefix);

#[derive(Debug, Encodable, Decodable)]
struct TestKeyV0(u64, u64);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefixV0;

impl_db_record!(
    key = TestKeyV0,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::Test,
);
impl_db_lookup!(key = TestKeyV0, query_prefix = DbPrefixTestPrefixV0);

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Encodable, Decodable)]
struct AltTestKey(u64);

#[derive(Debug, Encodable, Decodable)]
struct AltDbPrefixTestPrefix;

impl_db_record!(
    key = AltTestKey,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::AltTest,
);
impl_db_lookup!(key = AltTestKey, query_prefix = AltDbPrefixTestPrefix);

#[derive(Debug, Encodable, Decodable)]
struct PercentTestKey(u64);

#[derive(Debug, Encodable, Decodable)]
struct PercentPrefixTestPrefix;

impl_db_record!(
    key = PercentTestKey,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::PercentTestKey,
);

impl_db_lookup!(key = PercentTestKey, query_prefix = PercentPrefixTestPrefix);
#[derive(Debug, Encodable, Decodable, Eq, PartialEq, PartialOrd, Ord)]
pub(super) struct TestVal(pub u64);

const TEST_MODULE_PREFIX: u16 = 1;
const ALT_MODULE_PREFIX: u16 = 2;

pub async fn verify_insert_elements(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());
    assert!(dbtx.insert_entry(&TestKey(2), &TestVal(3)).await.is_none());
    dbtx.commit_tx().await;

    // Test values were persisted
    let mut dbtx = db.begin_transaction().await;
    assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));
    assert_eq!(dbtx.get_value(&TestKey(2)).await, Some(TestVal(3)));
    dbtx.commit_tx().await;

    // Test overwrites work as expected
    let mut dbtx = db.begin_transaction().await;
    assert_eq!(
        dbtx.insert_entry(&TestKey(1), &TestVal(4)).await,
        Some(TestVal(2))
    );
    assert_eq!(
        dbtx.insert_entry(&TestKey(2), &TestVal(5)).await,
        Some(TestVal(3))
    );
    dbtx.commit_tx().await;

    let mut dbtx = db.begin_transaction().await;
    assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(4)));
    assert_eq!(dbtx.get_value(&TestKey(2)).await, Some(TestVal(5)));
    dbtx.commit_tx().await;
}

pub async fn verify_remove_nonexisting(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    assert_eq!(dbtx.get_value(&TestKey(1)).await, None);
    let removed = dbtx.remove_entry(&TestKey(1)).await;
    assert!(removed.is_none());

    // Commit to suppress the warning message
    dbtx.commit_tx().await;
}

pub async fn verify_remove_existing(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

    assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));

    let removed = dbtx.remove_entry(&TestKey(1)).await;
    assert_eq!(removed, Some(TestVal(2)));
    assert_eq!(dbtx.get_value(&TestKey(1)).await, None);

    // Commit to suppress the warning message
    dbtx.commit_tx().await;
}

pub async fn verify_read_own_writes(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

    assert_eq!(dbtx.get_value(&TestKey(1)).await, Some(TestVal(2)));

    // Commit to suppress the warning message
    dbtx.commit_tx().await;
}

pub async fn verify_prevent_dirty_reads(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());

    // dbtx2 should not be able to see uncommitted changes
    let mut dbtx2 = db.begin_transaction().await;
    assert_eq!(dbtx2.get_value(&TestKey(1)).await, None);

    // Commit to suppress the warning message
    dbtx.commit_tx().await;
}

pub async fn verify_find_by_range(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&TestKey(55), &TestVal(9999)).await;
    dbtx.insert_entry(&TestKey(54), &TestVal(8888)).await;
    dbtx.insert_entry(&TestKey(56), &TestVal(7777)).await;

    dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).await;
    dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).await;

    {
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(2).0;
        module_dbtx
            .insert_entry(&TestKey(300), &TestVal(3000))
            .await;
    }

    dbtx.commit_tx().await;

    // Verify finding by prefix returns the correct set of key pairs
    let mut dbtx = db.begin_transaction_nc().await;

    let returned_keys = dbtx
        .find_by_range(TestKey(55)..TestKey(56))
        .await
        .collect::<Vec<_>>()
        .await;

    let expected = vec![(TestKey(55), TestVal(9999))];

    assert_eq!(returned_keys, expected);

    let returned_keys = dbtx
        .find_by_range(TestKey(54)..TestKey(56))
        .await
        .collect::<Vec<_>>()
        .await;

    let expected = vec![(TestKey(54), TestVal(8888)), (TestKey(55), TestVal(9999))];
    assert_eq!(returned_keys, expected);

    let returned_keys = dbtx
        .find_by_range(TestKey(54)..TestKey(57))
        .await
        .collect::<Vec<_>>()
        .await;

    let expected = vec![
        (TestKey(54), TestVal(8888)),
        (TestKey(55), TestVal(9999)),
        (TestKey(56), TestVal(7777)),
    ];
    assert_eq!(returned_keys, expected);

    let mut module_dbtx = dbtx.with_prefix_module_id(2).0;
    let test_range = module_dbtx
        .find_by_range(TestKey(300)..TestKey(301))
        .await
        .collect::<Vec<_>>()
        .await;
    assert!(test_range.len() == 1);
}

pub async fn verify_find_by_prefix(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&TestKey(55), &TestVal(9999)).await;
    dbtx.insert_entry(&TestKey(54), &TestVal(8888)).await;

    dbtx.insert_entry(&AltTestKey(55), &TestVal(7777)).await;
    dbtx.insert_entry(&AltTestKey(54), &TestVal(6666)).await;
    dbtx.commit_tx().await;

    // Verify finding by prefix returns the correct set of key pairs
    let mut dbtx = db.begin_transaction().await;

    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;

    let expected = vec![(TestKey(54), TestVal(8888)), (TestKey(55), TestVal(9999))];
    assert_eq!(returned_keys, expected);

    let reversed = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    let mut reversed_expected = expected;
    reversed_expected.reverse();
    assert_eq!(reversed, reversed_expected);

    let returned_keys = dbtx
        .find_by_prefix(&AltDbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;

    let expected = vec![
        (AltTestKey(54), TestVal(6666)),
        (AltTestKey(55), TestVal(7777)),
    ];
    assert_eq!(returned_keys, expected);

    let reversed = dbtx
        .find_by_prefix_sorted_descending(&AltDbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    let mut reversed_expected = expected;
    reversed_expected.reverse();
    assert_eq!(reversed, reversed_expected);
}

pub async fn verify_commit(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    assert!(dbtx.insert_entry(&TestKey(1), &TestVal(2)).await.is_none());
    dbtx.commit_tx().await;

    // Verify dbtx2 can see committed transactions
    let mut dbtx2 = db.begin_transaction().await;
    assert_eq!(dbtx2.get_value(&TestKey(1)).await, Some(TestVal(2)));
}

pub async fn verify_prevent_nonrepeatable_reads(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

    let mut dbtx2 = db.begin_transaction().await;

    dbtx2.insert_entry(&TestKey(100), &TestVal(101)).await;

    assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

    dbtx2.commit_tx().await;

    // dbtx should still read None because it is operating over a snapshot
    // of the data when the transaction started
    assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

    let expected_keys = 0;
    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            if key == TestKey(100) {
                assert!(value.eq(&TestVal(101)));
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);
}

pub async fn verify_snapshot_isolation(db: Database) {
    async fn random_yield() {
        let times = if rand::thread_rng().gen_bool(0.5) {
            0
        } else {
            10
        };
        for _ in 0..times {
            tokio::task::yield_now().await;
        }
    }

    // This scenario is taken straight out of https://github.com/fedimint/fedimint/issues/5195 bug
    for i in 0..1000 {
        let base_key = i * 2;
        let tx_accepted_key = base_key;
        let spent_input_key = base_key + 1;

        join!(
            async {
                random_yield().await;
                let mut dbtx = db.begin_transaction().await;

                random_yield().await;
                let a = dbtx.get_value(&TestKey(tx_accepted_key)).await;
                random_yield().await;
                // we have 4 operations that can give you the db key,
                // try all of them
                let s = match i % 5 {
                    0 => dbtx.get_value(&TestKey(spent_input_key)).await,
                    1 => dbtx.remove_entry(&TestKey(spent_input_key)).await,
                    2 => {
                        dbtx.insert_entry(&TestKey(spent_input_key), &TestVal(200))
                            .await
                    }
                    3 => {
                        dbtx.find_by_prefix(&DbPrefixTestPrefix)
                            .await
                            .filter(|(k, _v)| ready(k == &TestKey(spent_input_key)))
                            .map(|(_k, v)| v)
                            .next()
                            .await
                    }
                    4 => {
                        dbtx.find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
                            .await
                            .filter(|(k, _v)| ready(k == &TestKey(spent_input_key)))
                            .map(|(_k, v)| v)
                            .next()
                            .await
                    }
                    _ => {
                        panic!("woot?");
                    }
                };

                match (a, s) {
                    (None, None) | (Some(_), Some(_)) => {}
                    (None, Some(_)) => panic!("none some?! {i}"),
                    (Some(_), None) => panic!("some none?! {i}"),
                }
            },
            async {
                random_yield().await;

                let mut dbtx = db.begin_transaction().await;
                random_yield().await;
                assert_eq!(dbtx.get_value(&TestKey(tx_accepted_key)).await, None);

                random_yield().await;
                assert_eq!(
                    dbtx.insert_entry(&TestKey(spent_input_key), &TestVal(100))
                        .await,
                    None
                );

                random_yield().await;
                assert_eq!(
                    dbtx.insert_entry(&TestKey(tx_accepted_key), &TestVal(100))
                        .await,
                    None
                );
                random_yield().await;
                dbtx.commit_tx().await;
            }
        );
    }
}

pub async fn verify_phantom_entry(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

    dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

    dbtx.commit_tx().await;

    let mut dbtx = db.begin_transaction().await;
    let expected_keys = 2;
    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            match key {
                TestKey(100) => {
                    assert!(value.eq(&TestVal(101)));
                }
                TestKey(101) => {
                    assert!(value.eq(&TestVal(102)));
                }
                _ => {}
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);

    let mut dbtx2 = db.begin_transaction().await;

    dbtx2.insert_entry(&TestKey(102), &TestVal(103)).await;

    dbtx2.commit_tx().await;

    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            match key {
                TestKey(100) => {
                    assert!(value.eq(&TestVal(101)));
                }
                TestKey(101) => {
                    assert!(value.eq(&TestVal(102)));
                }
                _ => {}
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);
}

pub async fn expect_write_conflict(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;
    dbtx.commit_tx().await;

    let mut dbtx2 = db.begin_transaction().await;
    let mut dbtx3 = db.begin_transaction().await;

    dbtx2.insert_entry(&TestKey(100), &TestVal(102)).await;

    // Depending on if the database implementation supports optimistic or
    // pessimistic transactions, this test should generate an error here
    // (pessimistic) or at commit time (optimistic)
    dbtx3.insert_entry(&TestKey(100), &TestVal(103)).await;

    dbtx2.commit_tx().await;
    dbtx3.commit_tx_result().await.expect_err("Expecting an error to be returned because this transaction is in a write-write conflict with dbtx");
}

pub async fn verify_string_prefix(db: Database) {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&PercentTestKey(100), &TestVal(101)).await;

    assert_eq!(
        dbtx.get_value(&PercentTestKey(100)).await,
        Some(TestVal(101))
    );

    dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

    dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

    dbtx.insert_entry(&PercentTestKey(101), &TestVal(100)).await;

    // If the wildcard character ('%') is not handled properly, this will make
    // find_by_prefix return 5 results instead of 4
    dbtx.insert_entry(&TestKey(101), &TestVal(100)).await;

    let expected_keys = 4;
    let returned_keys = dbtx
        .find_by_prefix(&PercentPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            if matches!(key, PercentTestKey(101)) {
                assert!(value.eq(&TestVal(100)));
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);
}

pub async fn verify_remove_by_prefix(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

    dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

    dbtx.commit_tx().await;

    let mut remove_dbtx = db.begin_transaction().await;
    remove_dbtx.remove_by_prefix(&DbPrefixTestPrefix).await;
    remove_dbtx.commit_tx().await;

    let mut dbtx = db.begin_transaction().await;
    let expected_keys = 0;
    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            match key {
                TestKey(100) => {
                    assert!(value.eq(&TestVal(101)));
                }
                TestKey(101) => {
                    assert!(value.eq(&TestVal(102)));
                }
                _ => {}
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);
}

pub async fn verify_module_db(db: Database, module_db: Database) {
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_entry(&TestKey(100), &TestVal(101)).await;

    dbtx.insert_entry(&TestKey(101), &TestVal(102)).await;

    dbtx.commit_tx().await;

    // verify module_dbtx can only read key/value pairs from its own module
    let mut module_dbtx = module_db.begin_transaction().await;
    assert_eq!(module_dbtx.get_value(&TestKey(100)).await, None);

    assert_eq!(module_dbtx.get_value(&TestKey(101)).await, None);

    // verify module_dbtx can read key/value pairs that it wrote
    let mut dbtx = db.begin_transaction().await;
    assert_eq!(dbtx.get_value(&TestKey(100)).await, Some(TestVal(101)));

    assert_eq!(dbtx.get_value(&TestKey(101)).await, Some(TestVal(102)));

    let mut module_dbtx = module_db.begin_transaction().await;

    module_dbtx.insert_entry(&TestKey(100), &TestVal(103)).await;

    module_dbtx.insert_entry(&TestKey(101), &TestVal(104)).await;

    module_dbtx.commit_tx().await;

    let expected_keys = 2;
    let mut dbtx = db.begin_transaction().await;
    let returned_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            match key {
                TestKey(100) => {
                    assert!(value.eq(&TestVal(101)));
                }
                TestKey(101) => {
                    assert!(value.eq(&TestVal(102)));
                }
                _ => {}
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);

    let removed = dbtx.remove_entry(&TestKey(100)).await;
    assert_eq!(removed, Some(TestVal(101)));
    assert_eq!(dbtx.get_value(&TestKey(100)).await, None);

    let mut module_dbtx = module_db.begin_transaction().await;
    assert_eq!(
        module_dbtx.get_value(&TestKey(100)).await,
        Some(TestVal(103))
    );
}

pub async fn verify_module_prefix(db: Database) {
    let mut test_dbtx = db.begin_transaction().await;
    {
        let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX).0;

        test_module_dbtx
            .insert_entry(&TestKey(100), &TestVal(101))
            .await;

        test_module_dbtx
            .insert_entry(&TestKey(101), &TestVal(102))
            .await;
    }

    test_dbtx.commit_tx().await;

    let mut alt_dbtx = db.begin_transaction().await;
    {
        let mut alt_module_dbtx = alt_dbtx.to_ref_with_prefix_module_id(ALT_MODULE_PREFIX).0;

        alt_module_dbtx
            .insert_entry(&TestKey(100), &TestVal(103))
            .await;

        alt_module_dbtx
            .insert_entry(&TestKey(101), &TestVal(104))
            .await;
    }

    alt_dbtx.commit_tx().await;

    // verify test_module_dbtx can only see key/value pairs from its own module
    let mut test_dbtx = db.begin_transaction().await;
    let mut test_module_dbtx = test_dbtx.to_ref_with_prefix_module_id(TEST_MODULE_PREFIX).0;
    assert_eq!(
        test_module_dbtx.get_value(&TestKey(100)).await,
        Some(TestVal(101))
    );

    assert_eq!(
        test_module_dbtx.get_value(&TestKey(101)).await,
        Some(TestVal(102))
    );

    let expected_keys = 2;
    let returned_keys = test_module_dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .fold(0, |returned_keys, (key, value)| async move {
            match key {
                TestKey(100) => {
                    assert!(value.eq(&TestVal(101)));
                }
                TestKey(101) => {
                    assert!(value.eq(&TestVal(102)));
                }
                _ => {}
            }
            returned_keys + 1
        })
        .await;

    assert_eq!(returned_keys, expected_keys);

    let removed = test_module_dbtx.remove_entry(&TestKey(100)).await;
    assert_eq!(removed, Some(TestVal(101)));
    assert_eq!(test_module_dbtx.get_value(&TestKey(100)).await, None);

    // test_dbtx on its own wont find the key because it does not use a module
    // prefix
    let mut test_dbtx = db.begin_transaction().await;
    assert_eq!(test_dbtx.get_value(&TestKey(101)).await, None);

    test_dbtx.commit_tx().await;
}

#[cfg(test)]
#[tokio::test]
pub async fn verify_test_migration() {
    // Insert a bunch of old dummy data that needs to be migrated to a new version
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let expected_test_keys_size: usize = 100;
    let mut dbtx = db.begin_transaction().await;
    for i in 0..expected_test_keys_size {
        dbtx.insert_new_entry(&TestKeyV0(i as u64, (i + 1) as u64), &TestVal(i as u64))
            .await;
    }

    // Will also be migrated to `DatabaseVersionKey`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;
    dbtx.commit_tx().await;

    let mut migrations: BTreeMap<DatabaseVersion, DbMigrationFn<()>> = BTreeMap::new();

    migrations.insert(
        DatabaseVersion(0),
        Box::new(|ctx| migrate_test_db_version_0(ctx).boxed()),
    );

    apply_migrations(&db, (), "TestModule".to_string(), migrations, None, None)
        .await
        .expect("Error applying migrations for TestModule");

    // Verify that the migrations completed successfully
    let mut dbtx = db.begin_transaction().await;

    // Verify that the old `DatabaseVersion` under `DatabaseVersionKeyV0` migrated
    // to `DatabaseVersionKey`
    assert!(
        dbtx.get_value(&DatabaseVersionKey(MODULE_GLOBAL_PREFIX.into()))
            .await
            .is_some()
    );

    // Verify Dummy module migration
    let test_keys = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    let test_keys_size = test_keys.len();
    assert_eq!(test_keys_size, expected_test_keys_size);
    for (key, val) in test_keys {
        assert_eq!(key.0, val.0 + 1);
    }
}

#[cfg(test)]
#[tokio::test]
async fn apply_migrations_rejects_newer_on_disk_version() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let mut dbtx = db.begin_transaction().await;

    // Pretend the code that wrote this database was at version 5.
    create_database_version_dbtx(
        &mut dbtx.to_ref_nc(),
        DatabaseVersion(5),
        None,
        "test".to_owned(),
        true,
    )
    .await;

    // This code knows no migrations at all, i.e. it is at version 0.
    let err = apply_migrations_dbtx(
        &mut dbtx.to_ref_nc(),
        (),
        "test".to_owned(),
        BTreeMap::new(),
        None,
        None,
    )
    .await
    .expect_err("on-disk version 5 must not be accepted by code at version 0");

    assert!(matches!(
        err,
        DbMigrationError::VersionTooHigh {
            on_disk: DatabaseVersion(5),
            target: DatabaseVersion(0),
            ..
        }
    ));
}

#[allow(dead_code)]
async fn migrate_test_db_version_0(
    mut ctx: DbMigrationFnContext<'_, ()>,
) -> Result<(), DbMigrationError> {
    let mut dbtx = ctx.dbtx();
    let example_keys_v0 = dbtx
        .find_by_prefix(&DbPrefixTestPrefixV0)
        .await
        .collect::<Vec<_>>()
        .await;
    dbtx.remove_by_prefix(&DbPrefixTestPrefixV0).await;
    for (key, val) in example_keys_v0 {
        let key_v2 = TestKey(key.1);
        dbtx.insert_new_entry(&key_v2, &val).await;
    }
    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn test_autocommit() {
    use std::marker::PhantomData;
    use std::ops::Range;
    use std::path::Path;

    use async_trait::async_trait;

    use crate::ModuleDecoderRegistry;
    use crate::db::{
        AutocommitError, BaseDatabaseTransaction, DatabaseError, DatabaseResult,
        IDatabaseTransaction, IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase,
        IRawDatabaseTransaction,
    };

    #[derive(Debug)]
    struct FakeDatabase;

    #[async_trait]
    impl IRawDatabase for FakeDatabase {
        type Transaction<'a> = FakeTransaction<'a>;
        async fn begin_transaction(&self) -> FakeTransaction {
            FakeTransaction(PhantomData)
        }

        fn checkpoint(&self, _backup_path: &Path) -> DatabaseResult<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeTransaction<'a>(PhantomData<&'a ()>);

    #[async_trait]
    impl IDatabaseTransactionOpsCore for FakeTransaction<'_> {
        async fn raw_insert_bytes(
            &mut self,
            _key: &[u8],
            _value: &[u8],
        ) -> DatabaseResult<Option<Vec<u8>>> {
            unimplemented!()
        }

        async fn raw_get_bytes(&mut self, _key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
            unimplemented!()
        }

        async fn raw_remove_entry(&mut self, _key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
            unimplemented!()
        }

        async fn raw_find_by_range(
            &mut self,
            _key_range: Range<&[u8]>,
        ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
            unimplemented!()
        }

        async fn raw_find_by_prefix(
            &mut self,
            _key_prefix: &[u8],
        ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
            unimplemented!()
        }

        async fn raw_remove_by_prefix(&mut self, _key_prefix: &[u8]) -> DatabaseResult<()> {
            unimplemented!()
        }

        async fn raw_find_by_prefix_sorted_descending(
            &mut self,
            _key_prefix: &[u8],
        ) -> DatabaseResult<crate::db::PrefixStream<'_>> {
            unimplemented!()
        }
    }

    impl IDatabaseTransactionOps for FakeTransaction<'_> {}

    #[async_trait]
    impl IRawDatabaseTransaction for FakeTransaction<'_> {
        async fn commit_tx(self) -> DatabaseResult<()> {
            use crate::db::DatabaseError;

            Err(DatabaseError::backend(std::io::Error::other(
                "Can't commit!",
            )))
        }
    }

    let db = Database::new(FakeDatabase, ModuleDecoderRegistry::default());
    let err = db
        .autocommit::<_, _, ()>(|_dbtx, _| Box::pin(async { Ok(()) }), Some(5))
        .await
        .unwrap_err();

    match err {
        AutocommitError::CommitFailed {
            attempts: failed_attempts,
            ..
        } => {
            assert_eq!(failed_attempts, 5);
        }
        AutocommitError::ClosureError { .. } => panic!("Closure did not return error"),
    }
}
