use std::fmt::Debug;
use std::future;
use std::io::{Read, Write};

use async_stream::stream;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::time::now;
use fedimint_core::util::BoxStream;
use futures::{stream, Stream, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{error, instrument, warn};

use crate::db::{
    ChronologicalOperationLogKey, ChronologicalOperationLogKeyPrefix, OperationLogKey,
};
use crate::sm::OperationId;

#[derive(Debug, Clone)]
pub struct OperationLog {
    db: Database,
}

impl OperationLog {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn add_operation_log_entry(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: impl serde::Serialize,
    ) {
        dbtx.insert_new_entry(
            &OperationLogKey { operation_id },
            &OperationLogEntry {
                operation_module_kind: operation_type.to_string(),
                meta: serde_json::to_value(operation_meta)
                    .expect("Can only fail if meta is not serializable"),
                outcome: None,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &ChronologicalOperationLogKey {
                creation_time: now(),
                operation_id,
            },
            &(),
        )
        .await;
    }

    /// Returns the last `limit` operations. To fetch the next page, pass the
    /// last operation's [`ChronologicalOperationLogKey`] as `start_after`.
    pub async fn list_operations(
        &self,
        limit: usize,
        start_after: Option<ChronologicalOperationLogKey>,
    ) -> Vec<(ChronologicalOperationLogKey, OperationLogEntry)> {
        let mut dbtx = self.db.begin_transaction().await;
        let operations: Vec<ChronologicalOperationLogKey> = dbtx
            .find_by_prefix_sorted_descending(&ChronologicalOperationLogKeyPrefix)
            .await
            .map(|(key, _)| key)
            // FIXME: this is a schlemil-the-painter algorithm that will take longer the further
            // back in history one goes. To avoid that I see two options:
            //   1. Add a reference to the previous operation to each operation log entry,
            //      essentially creating a linked list, which seem a little bit inelegant.
            //   2. Add an option to prefix queries that allows to specify a start key
            //
            // The current implementation may also skip operations due to `SystemTime` not being
            // guaranteed to be monotonous. The linked list approach would also fix that.
            .skip_while(move |key| {
                let skip = if let Some(start_after) = start_after {
                    key.creation_time >= start_after.creation_time
                } else {
                    false
                };

                std::future::ready(skip)
            })
            .take(limit)
            .collect::<Vec<_>>()
            .await;

        let mut operation_entries = Vec::with_capacity(operations.len());

        for operation in operations {
            let entry = dbtx
                .get_value(&OperationLogKey {
                    operation_id: operation.operation_id,
                })
                .await
                .expect("Inconsistent DB");
            operation_entries.push((operation, entry));
        }

        operation_entries
    }

    pub async fn get_operation(&self, operation_id: OperationId) -> Option<OperationLogEntry> {
        Self::get_operation_inner(&mut self.db.begin_transaction().await, operation_id).await
    }

    async fn get_operation_inner(
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> Option<OperationLogEntry> {
        dbtx.get_value(&OperationLogKey { operation_id }).await
    }

    /// Sets the outcome of an operation
    #[instrument(skip(db), level = "debug")]
    pub async fn set_operation_outcome(
        db: &Database,
        operation_id: OperationId,
        outcome: &(impl Serialize + Debug),
    ) -> anyhow::Result<()> {
        let outcome_json = serde_json::to_value(outcome).expect("Outcome is not serializable");

        let mut dbtx = db.begin_transaction().await;
        let mut operation = Self::get_operation_inner(&mut dbtx, operation_id)
            .await
            .expect("Operation exists");
        operation.outcome = Some(outcome_json);
        dbtx.insert_entry(&OperationLogKey { operation_id }, &operation)
            .await;
        dbtx.commit_tx_result().await?;

        Ok(())
    }

    /// Tries to set the outcome of an operation, but only logs an error if it
    /// fails and does not return it. Since the outcome can always be recomputed
    /// from an update stream, failing to save it isn't a problem in cases where
    /// we do this merely for caching.
    pub async fn optimistically_set_operation_outcome(
        db: &Database,
        operation_id: OperationId,
        outcome: &(impl Serialize + Debug),
    ) {
        if let Err(e) = Self::set_operation_outcome(db, operation_id, outcome).await {
            warn!("Error setting operation outcome: {e}");
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OperationLogEntry {
    operation_module_kind: String,
    meta: serde_json::Value,
    // TODO: probably change all that JSON to Dyn-types
    pub(crate) outcome: Option<serde_json::Value>,
}

impl OperationLogEntry {
    /// Returns the kind of the module that generated the operation
    pub fn operation_module_kind(&self) -> &str {
        &self.operation_module_kind
    }

    /// Returns the meta data of the operation. This is a JSON value that can be
    /// either returned as a [`serde_json::Value`] or deserialized into a
    /// specific type. The specific type should be named `<Module>OperationMeta`
    /// in the module's client crate. The module can be determined by calling
    /// [`OperationLogEntry::operation_module_kind`].
    pub fn meta<M: DeserializeOwned>(&self) -> M {
        serde_json::from_value(self.meta.clone()).expect("JSON deserialization should not fail")
    }

    /// Returns the last state update of the operation, if any was cached yet.
    /// If this hasn't been the case yet and `None` is returned subscribe to the
    /// appropriate update stream.
    pub fn outcome<D: DeserializeOwned>(&self) -> Option<D> {
        self.outcome.as_ref().map(|outcome| {
            serde_json::from_value(outcome.clone()).expect("JSON deserialization should not fail")
        })
    }

    /// Returns an a [`UpdateStreamOrOutcome`] enum that can be converted into
    /// an update stream for easier handling using
    /// [`UpdateStreamOrOutcome::into_stream`] but can also be matched over to
    /// shortcut the handling of final outcomes.
    pub fn outcome_or_updates<U, S>(
        &self,
        db: &Database,
        operation_id: OperationId,
        stream_gen: impl FnOnce() -> S,
    ) -> UpdateStreamOrOutcome<U>
    where
        U: Clone + Serialize + DeserializeOwned + Debug + MaybeSend + MaybeSync + 'static,
        S: Stream<Item = U> + MaybeSend + 'static,
    {
        match self.outcome::<U>() {
            Some(outcome) => UpdateStreamOrOutcome::Outcome(outcome),
            None => UpdateStreamOrOutcome::UpdateStream(caching_operation_update_stream(
                db.clone(),
                operation_id,
                stream_gen(),
            )),
        }
    }
}

impl Encodable for OperationLogEntry {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.operation_module_kind.consensus_encode(writer)?;
        len += serde_json::to_string(&self.meta)
            .expect("JSON serialization should not fail")
            .consensus_encode(writer)?;
        len += self
            .outcome
            .as_ref()
            .map(|outcome| {
                serde_json::to_string(outcome).expect("JSON serialization should not fail")
            })
            .consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for OperationLogEntry {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_type = String::consensus_decode(r, modules)?;

        let meta_str = String::consensus_decode(r, modules)?;
        let meta = serde_json::from_str(&meta_str).map_err(DecodeError::from_err)?;

        let outcome_str = Option::<String>::consensus_decode(r, modules)?;
        let outcome = outcome_str
            .map(|outcome_str| serde_json::from_str(&outcome_str).map_err(DecodeError::from_err))
            .transpose()?;

        Ok(OperationLogEntry {
            operation_module_kind: operation_type,
            meta,
            outcome,
        })
    }
}

/// Either a stream of operation updates if the operation hasn't finished yet or
/// its outcome otherwise.
pub enum UpdateStreamOrOutcome<U> {
    UpdateStream(BoxStream<'static, U>),
    Outcome(U),
}

impl<U> UpdateStreamOrOutcome<U>
where
    U: MaybeSend + MaybeSync + 'static,
{
    /// Returns a stream no matter if the operation is finished. If there
    /// already is a cached outcome the stream will only return that, otherwise
    /// all updates will be returned until the operation finishes.
    pub fn into_stream(self) -> BoxStream<'static, U> {
        match self {
            UpdateStreamOrOutcome::UpdateStream(stream) => stream,
            UpdateStreamOrOutcome::Outcome(outcome) => {
                Box::pin(stream::once(future::ready(outcome)))
            }
        }
    }
}

/// Wraps an operation update stream such that the last update before it closes
/// is tried to be written to the operation log entry as its outcome.
pub fn caching_operation_update_stream<'a, U, S>(
    db: Database,
    operation_id: OperationId,
    stream: S,
) -> BoxStream<'a, U>
where
    U: Clone + Serialize + Debug + MaybeSend + MaybeSync + 'static,
    S: Stream<Item = U> + MaybeSend + 'a,
{
    let mut stream = Box::pin(stream);
    Box::pin(stream! {
        let mut last_update = None;
        while let Some(update) = stream.next().await {
            yield update.clone();
            last_update = Some(update);
        }

        let Some(last_update) = last_update else {
            error!("Stream ended without any updates, this should not happen!");
            return;
        };

        OperationLog::optimistically_set_operation_outcome(&db, operation_id, &last_update).await;
    })
}

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use futures::stream::StreamExt;
    use serde::{Deserialize, Serialize};

    use super::UpdateStreamOrOutcome;
    use crate::db::ChronologicalOperationLogKey;
    use crate::oplog::{OperationLog, OperationLogEntry};
    use crate::sm::OperationId;

    #[test]
    fn test_operation_log_entry_serde() {
        let op_log = OperationLogEntry {
            operation_module_kind: "test".to_string(),
            meta: serde_json::to_value(()).unwrap(),
            outcome: None,
        };

        op_log.meta::<()>();
    }

    #[test]
    fn test_operation_log_entry_serde_extra_meta() {
        #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
        struct Meta {
            foo: String,
            extra_meta: serde_json::Value,
        }

        let meta = Meta {
            foo: "bar".to_string(),
            extra_meta: serde_json::to_value(()).unwrap(),
        };

        let op_log = OperationLogEntry {
            operation_module_kind: "test".to_string(),
            meta: serde_json::to_value(meta.clone()).unwrap(),
            outcome: None,
        };

        assert_eq!(op_log.meta::<Meta>(), meta);
    }

    #[tokio::test]
    async fn test_operation_log_update() {
        let op_id = OperationId([0x32; 32]);

        let db = Database::new(MemDatabase::new(), Default::default());
        let op_log = OperationLog::new(db.clone());

        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry(&mut dbtx, op_id, "foo", "bar")
            .await;
        dbtx.commit_tx().await;

        let op = op_log.get_operation(op_id).await.expect("op exists");
        assert_eq!(op.outcome, None);

        OperationLog::set_operation_outcome(&db, op_id, &"baz")
            .await
            .unwrap();

        let op = op_log.get_operation(op_id).await.expect("op exists");
        assert_eq!(op.outcome::<String>(), Some("baz".to_string()));

        let update_stream_or_outcome =
            op.outcome_or_updates::<String, _>(&db, op_id, futures::stream::empty);

        assert!(matches!(
            &update_stream_or_outcome,
            UpdateStreamOrOutcome::Outcome(s) if s == "baz"
        ));

        let updates = update_stream_or_outcome
            .into_stream()
            .collect::<Vec<_>>()
            .await;
        assert_eq!(updates, vec!["baz"]);
    }

    #[tokio::test]
    async fn test_operation_log_update_from_stream() {
        let op_id = OperationId([0x32; 32]);

        let db = Database::new(MemDatabase::new(), Default::default());
        let op_log = OperationLog::new(db.clone());

        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry(&mut dbtx, op_id, "foo", "bar")
            .await;
        dbtx.commit_tx().await;

        let op = op_log.get_operation(op_id).await.expect("op exists");

        let updates = vec!["bar".to_owned(), "bob".to_owned(), "baz".to_owned()];
        let update_stream = op
            .outcome_or_updates::<String, _>(&db, op_id, || futures::stream::iter(updates.clone()));

        let received_updates = update_stream.into_stream().collect::<Vec<_>>().await;
        assert_eq!(received_updates, updates);

        let op_updated = op_log.get_operation(op_id).await.expect("op exists");
        assert_eq!(op_updated.outcome::<String>(), Some("baz".to_string()));
    }

    #[tokio::test]
    async fn test_pagination() {
        let db = Database::new(MemDatabase::new(), Default::default());
        let op_log = OperationLog::new(db.clone());

        for operation_idx in 0u8..98 {
            let mut dbtx = db.begin_transaction().await;
            op_log
                .add_operation_log_entry(
                    &mut dbtx,
                    OperationId([operation_idx; 32]),
                    "foo",
                    operation_idx,
                )
                .await;
            dbtx.commit_tx().await;
        }

        fn assert_page_entries(
            page: Vec<(ChronologicalOperationLogKey, OperationLogEntry)>,
            page_idx: u8,
        ) {
            for (entry_idx, (_key, entry)) in page.into_iter().enumerate() {
                let actual_meta = entry.meta::<u8>();
                let expected_meta = 97 - (page_idx * 10 + entry_idx as u8);

                assert_eq!(actual_meta, expected_meta);
            }
        }

        let mut previous_last_element = None;
        for page_idx in 0u8..9 {
            let page = op_log.list_operations(10, previous_last_element).await;
            assert_eq!(page.len(), 10);
            previous_last_element = Some(page[9].0);
            assert_page_entries(page, page_idx);
        }

        let page = op_log.list_operations(10, previous_last_element).await;
        assert_eq!(page.len(), 8);
        assert_page_entries(page, 9);
    }
}
