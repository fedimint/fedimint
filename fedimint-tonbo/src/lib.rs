#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::module_name_repetitions)]

//! A Tonbo-backed database implementation for Fedimint.
//!
//! This crate provides a database backend using Tonbo, an embedded persistent
//! KV database written in Rust. It implements the Fedimint database traits to
//! provide persistent storage.
//!
//! # Limitations
//!
//! - Does not support transaction savepoints
//! - Module isolation (prefix databases) is not implemented

use std::fmt;
use std::ops::{Bound, Range};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use async_stream::stream;
use bytes::Bytes;
use fedimint_core::async_trait_maybe_send;
use fedimint_core::db::{
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use futures::StreamExt;
use macro_rules_attribute::apply;
#[cfg(target_family = "wasm")]
use tonbo::executor::opfs::OpfsExecutor as Executor;
#[cfg(not(target_family = "wasm"))]
use tonbo::executor::tokio::TokioExecutor as Executor;
use tonbo::option::Path as TonboPath;
use tonbo::transaction::Transaction;
use tonbo::{DB, DbOption, Projection, Record};

/// Key-value pair schema for Fedimint storage
#[derive(Record, Debug, Clone)]
pub struct KvPair {
    #[record(primary_key)]
    key: Bytes,
    value: Bytes,
}

/// Tonbo database implementation for Fedimint
pub struct TonboDatabase {
    db: Arc<DB<KvPair, Executor>>,
}

impl TonboDatabase {
    pub async fn new(path: &Path) -> Result<Self> {
        let db_path = TonboPath::new(path)?;

        let options = DbOption::new(db_path, &KvPairSchema);

        #[cfg(not(target_family = "wasm"))]
        let exec = Executor::current();
        #[cfg(target_family = "wasm")]
        let exec = Executor::default();
        let db = DB::new(options, exec, KvPairSchema).await?;

        Ok(Self { db: Arc::new(db) })
    }
}

impl fmt::Debug for TonboDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TonboDatabase").finish()
    }
}

/// Tonbo transaction wrapper for Fedimint
pub struct TonboTransaction<'a> {
    txn: Transaction<'a, KvPair>,
    db: &'a TonboDatabase,
}

impl<'a> fmt::Debug for TonboTransaction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TonboTransaction").finish()
    }
}

impl<'a> TonboTransaction<'a> {
    fn stream_from_range(
        &mut self,
        lower_bound: Bound<Bytes>,
        upper_bound: Bound<Bytes>,
    ) -> PrefixStream {
        Box::pin(stream! {
            let mut stream = self
                .txn
                .scan((lower_bound.as_ref(), upper_bound.as_ref()))
                .take()
                .await
                .expect("db scan error");
            while let Some(result) = stream.next().await {
                let entry = result.expect("invalid value scanning database");
                if let Some(record_ref) = entry.value() {
                    yield (record_ref.key.to_vec(), record_ref.value.expect("value must be present").to_vec());
                }
            }
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for TonboDatabase {
    type Transaction<'a> = TonboTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> TonboTransaction<'a> {
        let txn = self.db.transaction().await;
        TonboTransaction { txn, db: self }
    }

    fn checkpoint(&self, _backup_path: &Path) -> Result<()> {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOpsCore for TonboTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_bytes = Bytes::copy_from_slice(key);

        // First, try to get the old value
        let old_value = match self.txn.get(&key_bytes, Projection::All).await? {
            // TODO: figure out way to value: Option<>
            Some(entry) => entry.get().value.map(|v| v.to_vec()),
            None => None,
        };

        // Insert the new record
        let record = KvPair {
            key: key_bytes,
            value: Bytes::copy_from_slice(value),
        };

        self.txn.insert(record);

        Ok(old_value)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_bytes = Bytes::copy_from_slice(key);

        let result = match self.txn.get(&key_bytes, Projection::All).await? {
            Some(entry) => entry.get().value.map(|v| v.to_vec()),
            None => None,
        };

        Ok(result)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Get the old value first
        let old_value = self.raw_get_bytes(key).await?;

        if old_value.is_some() {
            let key_bytes = Bytes::copy_from_slice(key);
            self.txn.remove(key_bytes);
        }

        Ok(old_value)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let prefix = key_prefix.to_vec();
        let lower_bound = Bound::Included(Bytes::copy_from_slice(&prefix));
        let upper_bound = {
            // add [0, 0, 0, ..., 1] to prefix to get upper bound for scan
            let mut upper_vec = prefix.clone();
            let mut all_255 = true;
            for byte in upper_vec.iter_mut().rev() {
                if *byte == 255 {
                    *byte = 0;
                } else {
                    *byte += 1;
                    all_255 = false;
                    break;
                }
            }
            if !all_255 {
                Bound::Excluded(Bytes::copy_from_slice(&upper_vec))
            } else {
                Bound::Unbounded
            }
        };

        Ok(self.stream_from_range(lower_bound, upper_bound))
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let mut entries = self
            .raw_find_by_prefix(key_prefix)
            .await?
            .collect::<Vec<_>>()
            .await;

        // TODO: optimize: https://github.com/tonbo-io/tonbo/pull/346
        // Sort in descending order
        entries.sort_unstable_by(|a, b| b.0.cmp(&a.0));

        Ok(Box::pin(futures::stream::iter(entries)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> Result<PrefixStream<'_>> {
        Ok(self.stream_from_range(
            Bound::Included(Bytes::copy_from_slice(range.start)),
            Bound::Excluded(Bytes::copy_from_slice(range.end)),
        ))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> Result<()> {
        let keys: Vec<Vec<u8>> = self
            .raw_find_by_prefix(key_prefix)
            .await?
            .map(|(k, _)| k)
            .collect()
            .await;

        for key in keys {
            self.raw_remove_entry(&key).await?;
        }

        Ok(())
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> IDatabaseTransactionOps for TonboTransaction<'a> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        unimplemented!()
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl<'a> IRawDatabaseTransaction for TonboTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
        self.txn.commit().await?;
        self.db.db.flush_wal().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tonbo_tests;
