use std::collections::BTreeMap;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use fedimint_core::db::{
    Database, IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase,
    IRawDatabaseTransaction, PrefixStream,
};
use futures::stream;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseEntry {
    key: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseDump {
    entries: Vec<DatabaseEntry>,
}

#[derive(Debug)]
pub struct TauriDatabase {
    app_handle: AppHandle,
    data_dir: PathBuf,
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

#[derive(Debug)]
enum DatabaseOperation {
    Insert {
        key: Vec<u8>,
        value: Vec<u8>,
        old_value: Option<Vec<u8>>,
    },
    Delete {
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
    },
}
#[derive(Debug)]
pub struct TauriDatabaseTransaction<'a> {
    operations: Vec<DatabaseOperation>,
    tx_data: BTreeMap<Vec<u8>, Vec<u8>>,
    db: &'a TauriDatabase,
    savepoint: BTreeMap<Vec<u8>, Vec<u8>>,
    savepoint_ops_count: usize,
}

impl TauriDatabase {
    pub async fn new(app_handle: AppHandle, client_name: &str) -> Result<Self> {
        let app_data_dir = app_handle
            .path()
            .app_data_dir()
            .context("Failed to get app data directory")?;

        let data_dir = app_data_dir
            .join("fedimint")
            .join("clients")
            .join(client_name);
        fs::create_dir_all(&data_dir)
            .await
            .context("Failed to create data directory")?;

        let db_file = data_dir.join("client.db");
        let mut data = BTreeMap::new();

        if fs::try_exists(&db_file).await? {
            let content = fs::read(&db_file).await?;
            if !content.is_empty() {
                let dump: DatabaseDump = serde_json::from_slice(&content)?;
                for entry in dump.entries {
                    let key = base64::decode(&entry.key)?;
                    let value = base64::decode(&entry.value)?;
                    data.insert(key, value);
                }
            }
        }

        Ok(Self {
            app_handle,
            data_dir,
            data: Arc::new(Mutex::new(data)),
        })
    }

    async fn save_to_disk(&self) -> Result<()> {
        let data = self.data.lock().await;

        let entries = data
            .iter()
            .map(|(key, value)| DatabaseEntry {
                key: base64::encode(key),
                value: base64::encode(value),
            })
            .collect::<Vec<_>>();

        let dump = DatabaseDump { entries };

        let db_file = self.data_dir.join("client.db");
        let temp_file = db_file.with_extension("db.tmp");

        let content = serde_json::to_vec(&dump)?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)
            .await?
            .write_all(&content)
            .await?;
        fs::rename(temp_file, db_file).await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl IRawDatabase for TauriDatabase {
    type Transaction<'a> = TauriDatabaseTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> TauriDatabaseTransaction<'a> {
        let data = self.data.lock().await.clone();

        TauriDatabaseTransaction {
            operations: Vec::new(),
            tx_data: data.clone(),
            db: self,
            savepoint: data,
            savepoint_ops_count: 0,
        }
    }

    fn checkpoint(&self, _: &std::path::Path) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'a> IDatabaseTransactionOpsCore for TauriDatabaseTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let old_value = self.tx_data.get(key).cloned();
        self.tx_data.insert(key.to_vec(), value.to_vec());
        self.operations.push(DatabaseOperation::Insert {
            key: key.to_vec(),
            value: value.to_vec(),
            old_value: old_value.clone(),
        });
        Ok(old_value)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.tx_data.get(key).cloned())
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let old_value = self.tx_data.remove(key);
        self.operations.push(DatabaseOperation::Delete {
            key: key.to_vec(),
            old_value: old_value.clone(),
        });
        Ok(old_value)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> Result<PrefixStream<'_>> {
        let data = self
            .tx_data
            .iter()
            .filter(|(k, _)| k.starts_with(key_prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> Result<PrefixStream<'_>> {
        let data = self
            .tx_data
            .range(range.start.to_vec()..range.end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();

        Ok(Box::pin(stream::iter(data)))
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
        let keys_to_remove = self
            .tx_data
            .keys()
            .filter(|k| k.starts_with(key_prefix))
            .cloned()
            .collect::<Vec<_>>();

        for key in keys_to_remove {
            let old_value = self.tx_data.remove(&key);
            self.operations
                .push(DatabaseOperation::Delete { key, old_value });
        }

        Ok(())
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> Result<PrefixStream<'_>> {
        let mut data = self
            .tx_data
            .iter()
            .filter(|(k, _)| k.starts_with(key_prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();

        data.sort_by(|(a, _), (b, _)| b.cmp(a));

        Ok(Box::pin(stream::iter(data)))
    }
}

#[async_trait::async_trait]
impl<'a> IDatabaseTransactionOps for TauriDatabaseTransaction<'a> {
    async fn rollback_tx_to_savepoint(&mut self) -> Result<()> {
        self.tx_data = self.savepoint.clone();

        self.operations.truncate(self.savepoint_ops_count);

        Ok(())
    }

    async fn set_tx_savepoint(&mut self) -> Result<()> {
        self.savepoint = self.tx_data.clone();
        self.savepoint_ops_count = self.operations.len();
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'a> IRawDatabaseTransaction for TauriDatabaseTransaction<'a> {
    async fn commit_tx(self) -> Result<()> {
        let mut data = self.db.data.lock().await;

        for op in self.operations {
            match op {
                DatabaseOperation::Insert { key, value, .. } => {
                    data.insert(key, value);
                }
                DatabaseOperation::Delete { key, .. } => {
                    data.remove(&key);
                }
            }
        }

        drop(data);

        self.db.save_to_disk().await?;

        Ok(())
    }
}

pub async fn create_database(app_handle: AppHandle, client_name: &str) -> Result<Database> {
    let db = TauriDatabase::new(app_handle, client_name).await?;
    Ok(Database::from(db))
}
