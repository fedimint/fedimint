#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228

use std::fmt;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_core::db::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};

pub struct WebDb(webkv::Database);

impl Debug for WebDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("WebDb")
    }
}

pub struct WebDbTransaction(webkv::Transaction);

impl WebDb {
    pub fn new_memory() -> WebDb {
        WebDb(webkv::Database::new(Arc::new(webkv::MemStorage::default())))
    }
}

impl fmt::Debug for WebDbTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebDbTransaction")
    }
}

#[async_trait]
impl IRawDatabase for WebDb {
    type Transaction<'a> = WebDbTransaction;
    async fn begin_transaction<'a>(&'a self) -> WebDbTransaction {
        WebDbTransaction(self.0.transaction())
    }
}

#[async_trait]
impl IDatabaseTransactionOpsCore for WebDbTransaction {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let old_value = self.0.get(key)?;
        self.0.set(key.to_owned(), value.to_owned());
        Ok(old_value)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let old_value = self.0.get(key)?;
        self.0.delete(key.to_owned());
        Ok(old_value)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        Ok(Box::pin(futures::stream::iter(
            self.0.find_by_prefix(key_prefix)?,
        )))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        Ok(Box::pin(futures::stream::iter(
            self.0.find_by_prefix(key_prefix)?.into_iter().rev(),
        )))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
        for (key, _) in self.0.find_by_prefix(key_prefix)? {
            self.0.delete(key);
        }
        Ok(())
    }
}

#[async_trait]
impl IDatabaseTransactionOps for WebDbTransaction {
    async fn set_tx_savepoint(&mut self) -> Result<()> {
        unimplemented!()
    }

    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        unimplemented!()
    }
}

#[async_trait]
impl IRawDatabaseTransaction for WebDbTransaction {
    async fn commit_tx(self) -> Result<()> {
        self.0.commit()
    }
}

#[cfg(test)]
mod fedimint_webkv_tests {
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::{impl_db_lookup, impl_db_record};
    use futures::StreamExt;

    use super::*;

    fn open_temp_db(_temp_path: &str) -> Database {
        Database::new(WebDb::new_memory(), ModuleDecoderRegistry::default())
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
    async fn test_dbtx_find_by_prefix() {
        fedimint_core::db::verify_find_by_prefix(open_temp_db("fcb-rocksdb-test-find-by-prefix"))
            .await;
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

    // #[tokio::test(flavor = "multi_thread")]
    // async fn test_dbtx_rollback_to_savepoint() {
    //     fedimint_core::db::verify_rollback_to_savepoint(open_temp_db(
    //         "fcb-rocksdb-test-rollback-to-savepoint",
    //     ))
    //     .await;
    // }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_phantom_entry() {
        fedimint_core::db::verify_phantom_entry(open_temp_db("fcb-rocksdb-test-phantom-entry"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_write_conflict() {
        fedimint_core::db::expect_write_conflict(open_temp_db("fcb-rocksdb-test-write-conflict"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dbtx_remove_by_prefix() {
        fedimint_core::db::verify_remove_by_prefix(open_temp_db(
            "fcb-rocksdb-test-remove-by-prefix",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_dbtx() {
        fedimint_core::db::verify_module_prefix(open_temp_db("fcb-rocksdb-test-module-prefix"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_module_db() {
        let module_instance_id = 1;
        let _path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-module-db-prefix")
            .tempdir()
            .unwrap();

        let module_db = Database::new(WebDb::new_memory(), ModuleDecoderRegistry::default());

        fedimint_core::db::verify_module_db(
            open_temp_db("fcb-rocksdb-test-module-db"),
            module_db.with_prefix_module_id(module_instance_id),
        )
        .await;
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
        let _path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-descending-order")
            .tempdir()
            .unwrap();
        {
            // TODO: use utility fn from above
            let db = Database::new(WebDb::new_memory(), ModuleDecoderRegistry::default());
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
    }
}
