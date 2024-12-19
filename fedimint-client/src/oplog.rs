use std::collections::HashSet;
use std::fmt::Debug;
use std::future;
use std::io::{Read, Write};
use std::ops::Range;
use std::time::Duration;

use async_stream::stream;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::time::now;
use fedimint_core::util::BoxStream;
use fedimint_logging::LOG_CLIENT;
use futures::{stream, Stream, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing::{error, instrument, warn};

use crate::db::{
    ChronologicalOperationLogKey, ChronologicalOperationLogKeyPrefix, OperationLogKey,
};

#[derive(Debug, Clone)]
pub struct OperationLog {
    db: Database,
    oldest_entry: OnceCell<ChronologicalOperationLogKey>,
}

impl OperationLog {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            oldest_entry: OnceCell::new(),
        }
    }

    /// Will return the oldest operation log key in the database and cache the
    /// result. If no entry exists yet the DB will be queried on each call till
    /// an entry is present.
    async fn get_oldest_operation_log_key(&self) -> Option<ChronologicalOperationLogKey> {
        let mut dbtx = self.db.begin_transaction_nc().await;
        self.oldest_entry
            .get_or_try_init(move || async move {
                dbtx.find_by_prefix(&ChronologicalOperationLogKeyPrefix)
                    .await
                    .map(|(key, ())| key)
                    .next()
                    .await
                    .ok_or(())
            })
            .await
            .ok()
            .copied()
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

    #[deprecated(since = "0.6.0", note = "Use `paginate_operations_rev` instead")]
    pub async fn list_operations(
        &self,
        limit: usize,
        last_seen: Option<ChronologicalOperationLogKey>,
    ) -> Vec<(ChronologicalOperationLogKey, OperationLogEntry)> {
        self.paginate_operations_rev(limit, last_seen).await
    }

    /// Returns the last `limit` operations. To fetch the next page, pass the
    /// last operation's [`ChronologicalOperationLogKey`] as `start_after`.
    pub async fn paginate_operations_rev(
        &self,
        limit: usize,
        last_seen: Option<ChronologicalOperationLogKey>,
    ) -> Vec<(ChronologicalOperationLogKey, OperationLogEntry)> {
        const EPOCH_DURATION: Duration = Duration::from_secs(60 * 60 * 24 * 7);

        let start_after_key = last_seen.unwrap_or_else(|| ChronologicalOperationLogKey {
            // We don't expect any operations from the future to exist, since SystemTime isn't
            // monotone and CI can be overloaded at times we add a small buffer to avoid flakiness
            // in tests.
            creation_time: now() + Duration::from_secs(30),
            operation_id: OperationId([0; 32]),
        });

        let Some(oldest_entry_key) = self.get_oldest_operation_log_key().await else {
            return vec![];
        };

        let mut dbtx = self.db.begin_transaction_nc().await;
        let mut operation_log_keys = Vec::with_capacity(limit);

        // Find all the operation log keys in the requested window. Since we decided to
        // not introduce a find_by_range_rev function we have to jump through some
        // hoops, see also the comments in rev_epoch_ranges.
        // TODO: Implement using find_by_range_rev if ever introduced
        'outer: for key_range_rev in
            rev_epoch_ranges(start_after_key, oldest_entry_key, EPOCH_DURATION)
        {
            let epoch_operation_log_keys_rev = dbtx
                .find_by_range(key_range_rev)
                .await
                .map(|(key, ())| key)
                .collect::<Vec<_>>()
                .await;

            for operation_log_key in epoch_operation_log_keys_rev.into_iter().rev() {
                operation_log_keys.push(operation_log_key);
                if operation_log_keys.len() >= limit {
                    break 'outer;
                }
            }
        }

        debug_assert!(
            operation_log_keys.iter().collect::<HashSet<_>>().len() == operation_log_keys.len(),
            "Operation log keys returned are not unique"
        );

        let mut operation_log_entries = Vec::with_capacity(operation_log_keys.len());
        for operation_log_key in operation_log_keys {
            let operation_log_entry = dbtx
                .get_value(&OperationLogKey {
                    operation_id: operation_log_key.operation_id,
                })
                .await
                .expect("Inconsistent DB");
            operation_log_entries.push((operation_log_key, operation_log_entry));
        }

        operation_log_entries
    }

    pub async fn get_operation(&self, operation_id: OperationId) -> Option<OperationLogEntry> {
        Self::get_operation_inner(
            &mut self.db.begin_transaction_nc().await.into_nc(),
            operation_id,
        )
        .await
    }

    async fn get_operation_inner(
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> Option<OperationLogEntry> {
        dbtx.get_value(&OperationLogKey { operation_id }).await
    }

    /// Sets the outcome of an operation
    #[instrument(target = LOG_CLIENT, skip(db), level = "debug")]
    pub async fn set_operation_outcome(
        db: &Database,
        operation_id: OperationId,
        outcome: &(impl Serialize + Debug),
    ) -> anyhow::Result<()> {
        let outcome_json = serde_json::to_value(outcome).expect("Outcome is not serializable");

        let mut dbtx = db.begin_transaction().await;
        let mut operation = Self::get_operation_inner(&mut dbtx.to_ref_nc(), operation_id)
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
            warn!(
                target: LOG_CLIENT,
                "Error setting operation outcome: {e}"
            );
        }
    }
}

/// Returns an iterator over the ranges of operation log keys, starting from the
/// most recent range and going backwards in time till slightly later than
/// `last_entry`.
///
/// Simplifying keys to integers and assuming a `start_after` of 100, a
/// `last_entry` of 55 and an `epoch_duration` of 10 the ranges would be:
/// ```text
/// [90..100, 80..90, 70..80, 60..70, 50..60]
/// ```
fn rev_epoch_ranges(
    start_after: ChronologicalOperationLogKey,
    last_entry: ChronologicalOperationLogKey,
    epoch_duration: Duration,
) -> impl Iterator<Item = Range<ChronologicalOperationLogKey>> {
    // We want to fetch all operations that were created before `start_after`, going
    // backwards in time. This means "start" generally means a later time than
    // "end". Only when creating a rust Range we have to swap the terminology (see
    // comment there).
    (0..)
        .map(move |epoch| start_after.creation_time - epoch * epoch_duration)
        // We want to get all operation log keys in the range [last_key, start_after). So as
        // long as the start time is greater than the last key's creation time, we have to
        // keep going.
        .take_while(move |&start_time| start_time >= last_entry.creation_time)
        .map(move |start_time| {
            let end_time = start_time - epoch_duration;

            // In the edge case that there were two events logged at exactly the same time
            // we need to specify the correct operation_id for the first key. Otherwise, we
            // could miss entries.
            let start_key = if start_time == start_after.creation_time {
                start_after
            } else {
                ChronologicalOperationLogKey {
                    creation_time: start_time,
                    operation_id: OperationId([0; 32]),
                }
            };

            // We could also special-case the last key here, but it's not necessary, making
            // it last_key if end_time < last_key.creation_time. We know there are no
            // entries beyond last_key though, so the range query will be equivalent either
            // way.
            let end_key = ChronologicalOperationLogKey {
                creation_time: end_time,
                operation_id: OperationId([0; 32]),
            };

            // We want to go backwards using a forward range query. This means we have to
            // swap the start and end keys and then reverse the vector returned by the
            // query.
            Range {
                start: end_key,
                end: start_key,
            }
        })
}

/// Represents an operation triggered by a user, typically related to sending or
/// receiving money.
///
/// There are three levels of introspection possible for `OperationLogEntry`s:
///   1. The [`OperationLogEntry::operation_module_kind`] function returns the
///      kind of the module that created the operation.
///   2. The [`OperationLogEntry::meta`] function returns static meta data that
///      was associated with the operation when it was created. Modules define
///      their own meta structures, so the module kind has to be used to
///      determine the structure of the meta data.
///   3. To find out the current state of the operation there is a two-step
///      process:
///      * First, the [`OperationLogEntry::outcome`] function returns the
///        outcome if the operation finished **and** the update subscription
///        stream has been processed till its end at least once.
///      * If that isn't the case, the [`OperationLogEntry::outcome`] method
///        will return `None` and the appropriate update subscription function
///        has to be called. See the respective client extension trait for these
///        functions.
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
    ///
    /// ## Determining the return type
    /// [`OperationLogEntry::meta`] should tell you the which operation type of
    /// a given module the outcome belongs to. The operation type will have a
    /// corresponding `async fn subscribe_type(&self, operation_id:
    /// OperationId) -> anyhow::Result<UpdateStreamOrOutcome<TypeState>>;`
    /// function that returns a `UpdateStreamOrOutcome<S>` where `S` is the
    /// high-level state the operation is in. If this state is terminal, i.e.
    /// the stream closes after returning it, it will be cached as the `outcome`
    /// of the operation.
    ///
    /// This means the type to be used for deserializing the outcome is `S`,
    /// often called `<OperationType>State`. Alternatively one can also use
    /// [`serde_json::Value`] to get the unstructured data.
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
            error!(
                target: LOG_CLIENT,
                "Stream ended without any updates, this should not happen!"
            );
            return;
        };

        OperationLog::optimistically_set_operation_outcome(&db, operation_id, &last_update).await;
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use fedimint_core::core::OperationId;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{
        Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt,
    };
    use fedimint_core::module::registry::ModuleRegistry;
    use futures::stream::StreamExt;
    use serde::{Deserialize, Serialize};

    use super::UpdateStreamOrOutcome;
    use crate::db::{ChronologicalOperationLogKey, OperationLogKey};
    use crate::oplog::{OperationLog, OperationLogEntry};

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

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let op_log = OperationLog::new(db.clone());

        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
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

        let db = MemDatabase::new().into_database();
        let op_log = OperationLog::new(db.clone());

        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry(&mut dbtx.to_ref_nc(), op_id, "foo", "bar")
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

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let op_log = OperationLog::new(db.clone());

        for operation_idx in 0u8..98 {
            let mut dbtx = db.begin_transaction().await;
            op_log
                .add_operation_log_entry(
                    &mut dbtx.to_ref_nc(),
                    OperationId([operation_idx; 32]),
                    "foo",
                    operation_idx,
                )
                .await;
            dbtx.commit_tx().await;
        }

        let mut previous_last_element = None;
        for page_idx in 0u8..9 {
            let page = op_log
                .paginate_operations_rev(10, previous_last_element)
                .await;
            assert_eq!(page.len(), 10);
            previous_last_element = Some(page[9].0);
            assert_page_entries(page, page_idx);
        }

        let page = op_log
            .paginate_operations_rev(10, previous_last_element)
            .await;
        assert_eq!(page.len(), 8);
        assert_page_entries(page, 9);
    }

    #[tokio::test]
    async fn test_pagination_empty() {
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let op_log = OperationLog::new(db.clone());

        let page = op_log.paginate_operations_rev(10, None).await;
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn test_pagination_multiple_operations_same_time() {
        async fn insert_oplog(dbtx: &mut DatabaseTransaction<'_>, idx: u8, time: u64) {
            let operation_id = OperationId([idx; 32]);
            // Some time in the 2010s
            let creation_time = SystemTime::UNIX_EPOCH
                + Duration::from_secs(60 * 60 * 24 * 365 * 40)
                + Duration::from_secs(time * 60 * 60 * 24);

            dbtx.insert_new_entry(
                &OperationLogKey { operation_id },
                &OperationLogEntry {
                    operation_module_kind: "operation_type".to_string(),
                    meta: serde_json::Value::Null,
                    outcome: None,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &ChronologicalOperationLogKey {
                    creation_time,
                    operation_id,
                },
                &(),
            )
            .await;
        }

        async fn assert_pages(operation_log: &OperationLog, pages: Vec<Vec<u8>>) {
            let mut previous_last_element: Option<ChronologicalOperationLogKey> = None;
            for reference_page in pages {
                let page = operation_log
                    .paginate_operations_rev(10, previous_last_element)
                    .await;
                assert_eq!(page.len(), reference_page.len());
                assert_eq!(
                    page.iter()
                        .map(|(operation_log_key, _)| operation_log_key.operation_id)
                        .collect::<Vec<_>>(),
                    reference_page
                        .iter()
                        .map(|&x| OperationId([x; 32]))
                        .collect::<Vec<_>>()
                );
                previous_last_element = page.last().map(|(key, _)| key).copied();
            }
        }

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let op_log = OperationLog::new(db.clone());

        let mut dbtx = db.begin_transaction().await;
        for operation_idx in 0u8..10 {
            insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 1).await;
        }
        dbtx.commit_tx().await;
        assert_pages(&op_log, vec![vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0], vec![]]).await;

        let mut dbtx = db.begin_transaction().await;
        for operation_idx in 10u8..16 {
            insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 2).await;
        }
        for operation_idx in 16u8..22 {
            insert_oplog(&mut dbtx.to_ref_nc(), operation_idx, 3).await;
        }
        dbtx.commit_tx().await;
        assert_pages(
            &op_log,
            vec![
                vec![21, 20, 19, 18, 17, 16, 15, 14, 13, 12],
                vec![11, 10, 9, 8, 7, 6, 5, 4, 3, 2],
                vec![1, 0],
                vec![],
            ],
        )
        .await;

        let mut dbtx = db.begin_transaction().await;
        for operation_idx in 22u8..31 {
            // 9 times one operation every 10 days
            insert_oplog(
                &mut dbtx.to_ref_nc(),
                operation_idx,
                10 * u64::from(operation_idx),
            )
            .await;
        }
        dbtx.commit_tx().await;
        assert_pages(
            &op_log,
            vec![
                vec![30, 29, 28, 27, 26, 25, 24, 23, 22, 21],
                vec![20, 19, 18, 17, 16, 15, 14, 13, 12, 11],
                vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                vec![0],
                vec![],
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_pagination_empty_then_not() {
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let op_log = OperationLog::new(db.clone());

        let page = op_log.paginate_operations_rev(10, None).await;
        assert!(page.is_empty());

        let mut dbtx = db.begin_transaction().await;
        op_log
            .add_operation_log_entry(&mut dbtx.to_ref_nc(), OperationId([0; 32]), "foo", "bar")
            .await;
        dbtx.commit_tx().await;

        let page = op_log.paginate_operations_rev(10, None).await;
        assert_eq!(page.len(), 1);
    }
}
