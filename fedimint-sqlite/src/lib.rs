#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
use std::str::FromStr;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use fedimint_core::db::{
    IDatabase, IDatabaseTransaction, ISingleUseDatabaseTransaction, PrefixStream,
    SingleUseDatabaseTransaction,
};
use futures::stream;
use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Error, Executor, Row, Sqlite, SqlitePool, Transaction};
use tracing::{info, warn};

#[derive(Debug)]
pub struct SqliteDb(SqlitePool);

pub struct SqliteDbTransaction<'a> {
    tx: Transaction<'a, Sqlite>,
    // Set an error flag that indicates the transaction should fail at commit time
    error: bool,
}

impl SqliteDb {
    pub async fn open(connection_string: &str) -> Result<SqliteDb, Error> {
        if !Sqlite::database_exists(connection_string)
            .await
            .unwrap_or(false)
        {
            info!("Creating new sqlite database: {:?}", connection_string);
            match Sqlite::create_database(connection_string).await {
                Ok(_) => {}
                Err(error) => panic!("Could not create SQLite Database: {error}"),
            }
        }

        // Disable statement logging otherwise the queries clutter the log
        let mut opts = SqliteConnectOptions::from_str(connection_string).unwrap();
        opts.disable_statement_logging();
        let db = SqlitePool::connect_with(opts).await?;

        sqlx::query("CREATE TABLE IF NOT EXISTS kv (key BLOB, value BLOB);")
            .execute(&db)
            .await
            .expect("Error while creating the key-value table");

        sqlx::query("CREATE INDEX IF NOT EXISTS key_index ON kv(key);")
            .execute(&db)
            .await
            .expect("Error while creating the key index");

        sqlx::query("CREATE INDEX IF NOT EXISTS hex_index ON kv(hex(key));")
            .execute(&db)
            .await
            .expect("Error while creating the key index");

        Ok(SqliteDb(db))
    }
}

#[async_trait]
impl IDatabase for SqliteDb {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn ISingleUseDatabaseTransaction<'a>> {
        let mut tx = SqliteDbTransaction {
            tx: self.0.begin().await.unwrap(),
            error: false,
        };
        tx.set_tx_savepoint().await;
        let single_use = SingleUseDatabaseTransaction::new(tx);
        Box::new(single_use)
    }
}

#[async_trait]
impl<'a> IDatabaseTransaction<'a> for SqliteDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let val = self.raw_get_bytes(key).await.unwrap();
        let query_prepared = sqlx::query("INSERT INTO kv (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value);
        self.error |= self.tx.execute(query_prepared).await.is_err();
        Ok(val)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let query_prepared =
            sqlx::query("SELECT value FROM kv WHERE key = ? ORDER BY value DESC LIMIT 1").bind(key);
        self.tx
            .fetch_optional(query_prepared)
            .await
            .map(|result| result.map(|result| result.get::<Vec<u8>, &str>("value")))
            .map_err(anyhow::Error::from)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let query_prepared =
            sqlx::query("SELECT rowid, value FROM kv WHERE key = ? ORDER BY value DESC LIMIT 1")
                .bind(key);
        let res = self.tx.fetch_optional(query_prepared).await;
        if let Ok(Some(row)) = res {
            let rowid = row.get::<i64, &str>("rowid");
            let value = row.get::<Vec<u8>, &str>("value");

            let query_prepared = sqlx::query("DELETE FROM kv WHERE rowid = ?").bind(rowid);
            self.error |= self.tx.execute(query_prepared).await.is_err();
            return Ok(Some(value));
        }

        // Didnt find a key to delete
        Ok(None)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixStream<'_> {
        let mut str_prefix = "".to_string();
        for prefix in key_prefix {
            str_prefix = format!("{str_prefix}{prefix:02X?}");
        }
        str_prefix = format!("{}{}", str_prefix, "%");
        let query = "SELECT key, value FROM kv WHERE hex(key) LIKE ? ORDER BY value DESC";
        let query_prepared = sqlx::query(query).bind(str_prefix);
        let results = self.tx.fetch_all(query_prepared).await;

        if results.is_err() {
            warn!("sqlite find_by_prefix failed to retrieve key range. Returning empty iterator");
            return Box::pin(stream::iter(Vec::new()));
        }

        let rows = results.unwrap().into_iter().map(|row| {
            (
                row.get::<Vec<u8>, &str>("key"),
                row.get::<Vec<u8>, &str>("value"),
            )
        });

        Box::pin(stream::iter(rows))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let mut str_prefix = "".to_string();
        for prefix in key_prefix {
            str_prefix = format!("{str_prefix}{prefix:02X?}");
        }
        str_prefix = format!("{}{}", str_prefix, "%");
        let query = "DELETE FROM kv WHERE hex(key) LIKE ?";
        let query_prepared = sqlx::query(query).bind(str_prefix);
        self.error |= self.tx.execute(query_prepared).await.is_err();
        Ok(())
    }

    async fn commit_tx(self) -> Result<()> {
        if self.error {
            return Err(anyhow!("Error occurred during the database transaction"));
        }
        self.tx.commit().await.map_err(anyhow::Error::from)
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        let query_prepared = sqlx::query("ROLLBACK TO SAVEPOINT tx_savepoint");
        self.error |= self.tx.execute(query_prepared).await.is_err();
    }

    async fn set_tx_savepoint(&mut self) {
        let query_prepared = sqlx::query("SAVEPOINT tx_savepoint");
        self.error |= self.tx.execute(query_prepared).await.is_err();
    }
}

#[cfg(test)]
mod fedimint_sqlite_tests {
    use std::fs;

    use fedimint_core::core::ModuleInstanceId;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use rand::rngs::OsRng;
    use rand::RngCore;

    use crate::SqliteDb;

    async fn open_temp_db(db_name: &str) -> Database {
        let dir = format!("/tmp/sqlite-{}/{}", db_name, OsRng.next_u64());
        fs::create_dir_all(&dir).expect("Error creating temporary directory for SQLite");
        let connection_string = format!("sqlite://{}/sqlite-{}.db", dir.as_str(), db_name);
        Database::new(
            SqliteDb::open(connection_string.as_str()).await.unwrap(),
            ModuleDecoderRegistry::default(),
        )
    }

    async fn open_temp_module_db(db_name: &str, module_instance_id: ModuleInstanceId) -> Database {
        let dir = format!("/tmp/sqlite-{}/{}", db_name, OsRng.next_u64());
        fs::create_dir_all(&dir).expect("Error creating temporary directory for SQLite");
        let connection_string = format!("sqlite://{}/sqlite-{}.db", dir.as_str(), db_name);
        Database::new(
            SqliteDb::open(connection_string.as_str()).await.unwrap(),
            ModuleDecoderRegistry::default(),
        )
        .new_isolated(module_instance_id)
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_insert_elements() {
        fedimint_core::db::verify_insert_elements(open_temp_db("insert-elements").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_core::db::verify_remove_nonexisting(open_temp_db("remove-nonexisting").await)
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_existing() {
        fedimint_core::db::verify_remove_existing(open_temp_db("remove-existing").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_read_own_writes() {
        fedimint_core::db::verify_read_own_writes(open_temp_db("read-own-writes").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_dirty_reads() {
        fedimint_core::db::verify_prevent_dirty_reads(open_temp_db("prevent_dirty_reads").await)
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_find_by_prefix() {
        fedimint_core::db::verify_find_by_prefix(open_temp_db("find_by_prefix").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_commit() {
        fedimint_core::db::verify_commit(open_temp_db("commit").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_core::db::verify_prevent_nonrepeatable_reads(
            open_temp_db("prevent-nonrepeatable-reads").await,
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_core::db::verify_rollback_to_savepoint(
            open_temp_db("rollback-to-savepoint").await,
        )
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_phantom_entry() {
        fedimint_core::db::verify_phantom_entry(open_temp_db("phantom-entry").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_write_conflict() {
        fedimint_core::db::expect_write_conflict(open_temp_db("write-conflict").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_sqlite_prefix() {
        fedimint_core::db::verify_string_prefix(open_temp_db("verify-string-prefix").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_by_prefix() {
        fedimint_core::db::verify_remove_by_prefix(open_temp_db("verify-remove-by-prefix").await)
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_dbtx() {
        fedimint_core::db::verify_module_prefix(open_temp_db("verify-module-prefix").await).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_db() {
        fedimint_core::db::verify_module_db(
            open_temp_db("verify-module-db1").await,
            open_temp_module_db("verify-module-db2", 1).await,
        )
        .await;
    }
}
