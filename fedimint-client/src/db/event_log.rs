//! Client Event Log
//!
//! The goal here is to maintain a single, ordered, append only
//! log of all important client-side events: low or high level,
//! and move as much of coordination between different parts of
//! the system in a natural and decomposed way.
//!
//! Any event log "follower" can just keep going through
//! all events and react to ones it is interested in (and understands),
//! potentially emitting events of its own, and atomically updating persisted
//! event log position ("cursor") of events that were already processed.
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Database, DatabaseKey, DatabaseRecord, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
    NonCommittable,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_CLIENT_EVENT_LOG;
use futures::{Future, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tracing::{debug, trace};

use super::DbKeyPrefix;

pub trait Event: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE: Option<ModuleKind>;
    const KIND: EventKind;
    const PERSIST: bool = true;
}

/// An counter that resets on every restart, that guarantees that
/// [`UnordedEventLogId`]s don't conflict with each other.
static UNORDEREDED_EVENT_LOG_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A self-allocated ID that is mostly ordered
///
/// The goal here is to avoid concurrent database transaction
/// conflicts due the ID allocation. Instead they are picked based on
/// a time and a counter, so they are mostly but not strictly ordered and
/// monotonic, and even more imporantly: not contiguous.
#[derive(Debug, Encodable, Decodable)]
pub struct UnordedEventLogId {
    ts_usecs: u64,
    counter: u64,
}

impl UnordedEventLogId {
    fn new() -> Self {
        Self {
            ts_usecs: u64::try_from(fedimint_core::time::duration_since_epoch().as_micros())
                // This will never happen
                .unwrap_or(u64::MAX),
            counter: UNORDEREDED_EVENT_LOG_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// Ordered, contiguous ID space, which is easy for event log followers to
/// track.
#[derive(
    Copy,
    Clone,
    Debug,
    Encodable,
    Decodable,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub struct EventLogId(u64);

impl EventLogId {
    fn next(self) -> EventLogId {
        Self(self.0 + 1)
    }

    fn saturating_add(self, rhs: u64) -> EventLogId {
        Self(self.0.saturating_add(rhs))
    }
}

impl FromStr for EventLogId {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str(s).map(Self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventKind(Cow<'static, str>);

impl EventKind {
    pub const fn from_static(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl<'s> From<&'s str> for EventKind {
    fn from(value: &'s str) -> Self {
        Self(Cow::Owned(value.to_owned()))
    }
}

impl From<String> for EventKind {
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

#[derive(Debug, Encodable, Decodable, Clone)]
pub struct UnorderedEventLogEntry {
    pub persist: bool,
    pub inner: EventLogEntry,
}

#[derive(Debug, Encodable, Decodable, Clone)]
pub struct EventLogEntry {
    /// Type/kind of the event
    ///
    /// Any part of the client is free to self-allocate identifier, denoting a
    /// certain kind of an event. Notably one event kind have multiple
    /// instances. E.g. "successful wallet deposit" can be an event kind,
    /// and it can happen multiple times with different payloads.
    pub kind: EventKind,

    /// To prevent accidental conflicts between `kind`s, a module kind the
    /// given event kind belong is used as well.
    ///
    /// Note: the meaning of this field is mostly about which part of the code
    /// defines this event kind. Oftentime a core (non-module)-defined event
    /// will refer in some way to a module. It should use a separate `module_id`
    /// field in the `payload`, instead of this field.
    pub module: Option<(ModuleKind, ModuleInstanceId)>,

    /// Timestamp in microseconds after unix epoch
    ts_usecs: u64,

    /// Event-kind specific payload, typically encoded as a json string for
    /// flexibility.
    pub payload: Vec<u8>,
}

impl_db_record!(
    key = UnordedEventLogId,
    value = UnorderedEventLogEntry,
    db_prefix = DbKeyPrefix::UnorderedEventLog,
);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnorderedEventLogIdPrefixAll;

impl_db_lookup!(
    key = UnordedEventLogId,
    query_prefix = UnorderedEventLogIdPrefixAll
);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct EventLogIdPrefixAll;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct EventLogIdPrefix(EventLogId);

impl_db_record!(
    key = EventLogId,
    value = EventLogEntry,
    db_prefix = DbKeyPrefix::EventLog,
);

impl_db_lookup!(key = EventLogId, query_prefix = EventLogIdPrefixAll);

impl_db_lookup!(key = EventLogId, query_prefix = EventLogIdPrefix);

#[apply(async_trait_maybe_send!)]
pub trait DBTransactionEventLogExt {
    async fn log_event_raw(
        &mut self,
        log_ordering_wakeup_tx: watch::Sender<()>,
        kind: EventKind,
        module_kind: Option<ModuleKind>,
        module_id: Option<ModuleInstanceId>,
        payload: Vec<u8>,
        persist: bool,
    );

    /// Log an event log event
    ///
    /// The event will start "unordered", but after it is committed an ordering
    /// task will be notified to "order" it into a final ordered log.
    async fn log_event<E>(
        &mut self,
        log_ordering_wakeup_tx: watch::Sender<()>,
        module_id: Option<ModuleInstanceId>,
        event: E,
    ) where
        E: Event + Send,
    {
        self.log_event_raw(
            log_ordering_wakeup_tx,
            E::KIND,
            E::MODULE,
            module_id,
            serde_json::to_vec(&event).expect("Serialization can't fail"),
            <E as Event>::PERSIST,
        )
        .await;
    }

    /// Next [`EventLogId`] to use for new ordered events.
    ///
    /// Used by ordering task, though might be
    /// useful to get the current count of events.
    async fn get_next_event_log_id(&mut self) -> EventLogId;

    /// Read a part of the event log.
    async fn get_event_log(
        &mut self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<(
        EventLogId,
        EventKind,
        Option<(ModuleKind, ModuleInstanceId)>,
        u64,
        serde_json::Value,
    )>;
}

#[apply(async_trait_maybe_send!)]
impl<'tx, Cap> DBTransactionEventLogExt for DatabaseTransaction<'tx, Cap>
where
    Cap: Send,
{
    async fn log_event_raw(
        &mut self,
        log_ordering_wakeup_tx: watch::Sender<()>,
        kind: EventKind,
        module_kind: Option<ModuleKind>,
        module_id: Option<ModuleInstanceId>,
        payload: Vec<u8>,
        persist: bool,
    ) {
        assert_eq!(
            module_kind.is_some(),
            module_id.is_some(),
            "Events of modules must have module_id set"
        );

        let unordered_id = UnordedEventLogId::new();
        trace!(target: LOG_CLIENT_EVENT_LOG, ?unordered_id, "New unordered event log event");

        if self
            .insert_entry(
                &unordered_id,
                &UnorderedEventLogEntry {
                    persist,
                    inner: EventLogEntry {
                        kind,
                        module: module_kind.map(|kind| (kind, module_id.unwrap())),
                        ts_usecs: unordered_id.ts_usecs,
                        payload,
                    },
                },
            )
            .await
            .is_some()
        {
            panic!("Trying to overwrite event in the client event log");
        }
        self.on_commit(move || {
            let _ = log_ordering_wakeup_tx.send(());
        });
    }

    async fn get_next_event_log_id(&mut self) -> EventLogId {
        self.find_by_prefix_sorted_descending(&EventLogIdPrefixAll)
            .await
            .next()
            .await
            .map(|(k, _v)| k.next())
            .unwrap_or_default()
    }

    async fn get_event_log(
        &mut self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<(
        EventLogId,
        EventKind,
        Option<(ModuleKind, ModuleInstanceId)>,
        u64,
        serde_json::Value,
    )> {
        let pos = pos.unwrap_or_default();
        self.find_by_range(pos..pos.saturating_add(limit))
            .await
            .map(|(k, v)| {
                (
                    k,
                    v.kind,
                    v.module,
                    v.ts_usecs,
                    serde_json::from_slice(&v.payload).unwrap_or_default(),
                )
            })
            .collect()
            .await
    }
}

/// The code that handles new unordered events and rewriters them fully ordered
/// into the final event log.
pub(crate) async fn run_event_log_ordering_task(
    db: Database,
    mut log_ordering_task_wakeup: watch::Receiver<()>,
    log_event_added: watch::Sender<()>,
    log_event_added_transient: broadcast::Sender<EventLogEntry>,
) {
    debug!(target: LOG_CLIENT_EVENT_LOG, "Event log ordering task started");
    let mut next_entry_id = db
        .begin_transaction_nc()
        .await
        .get_next_event_log_id()
        .await;

    loop {
        let mut dbtx = db.begin_transaction().await;

        let unordered_events = dbtx
            .find_by_prefix(&UnorderedEventLogIdPrefixAll)
            .await
            .collect::<Vec<_>>()
            .await;
        trace!(target: LOG_CLIENT_EVENT_LOG, num=unordered_events.len(), "Fetched unordered events");

        for (unordered_id, entry) in &unordered_events {
            assert!(
                dbtx.remove_entry(unordered_id).await.is_some(),
                "Must never fail to remove entry"
            );
            if entry.persist {
                assert!(
                    dbtx.insert_entry(&next_entry_id, &entry.inner)
                        .await
                        .is_none(),
                    "Must never overwrite existing event"
                );
                trace!(target: LOG_CLIENT_EVENT_LOG, ?unordered_id, id=?next_entry_id, "Ordered event log event");
                next_entry_id = next_entry_id.next();
            } else {
                trace!(target: LOG_CLIENT_EVENT_LOG, ?unordered_id, id=?next_entry_id, "Transient event log event");
                dbtx.on_commit({
                    let log_event_added_transient = log_event_added_transient.clone();
                    let entry = entry.inner.clone();

                    move || {
                        // we ignore the no-subscribers
                        let _ = log_event_added_transient.send(entry);
                    }
                });
            }
        }

        // This thread is the only thread deleting already existing element of unordered
        // log and inserting new elements into ordered log, so it should never
        // fail to commit.
        dbtx.commit_tx().await;
        if !unordered_events.is_empty() {
            let _ = log_event_added.send(());
        }

        trace!(target: LOG_CLIENT_EVENT_LOG, "Event log ordering task waits for more events");
        if log_ordering_task_wakeup.changed().await.is_err() {
            break;
        }
    }

    debug!(target: LOG_CLIENT_EVENT_LOG, "Event log ordering task finished");
}

pub async fn handle_events<F, R, K>(
    db: Database,
    pos_key: &K,
    mut log_event_added: watch::Receiver<()>,
    call_fn: F,
) -> anyhow::Result<()>
where
    K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    K: DatabaseRecord<Value = EventLogId>,
    F: Fn(&mut DatabaseTransaction<NonCommittable>, EventLogEntry) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let mut next_key: EventLogId = db
        .begin_transaction_nc()
        .await
        .get_value(pos_key)
        .await
        .unwrap_or_default();

    trace!(target: LOG_CLIENT_EVENT_LOG, ?next_key, "Handling events");

    loop {
        let mut dbtx = db.begin_transaction().await;

        if let Some(event) = dbtx.get_value(&next_key).await {
            (call_fn)(&mut dbtx.to_ref_nc(), event).await?;

            next_key = next_key.next();
            dbtx.insert_entry(pos_key, &next_key).await;

            dbtx.commit_tx().await;
        } else if log_event_added.changed().await.is_err() {
            break Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;

    use anyhow::bail;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::IRawDatabaseExt as _;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::impl_db_record;
    use fedimint_core::task::TaskGroup;
    use tokio::sync::{broadcast, watch};
    use tokio::try_join;
    use tracing::info;

    use super::{
        handle_events, run_event_log_ordering_task, DBTransactionEventLogExt as _, EventLogId,
    };
    use crate::db::event_log::EventKind;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
    pub struct TestLogIdKey;

    impl_db_record!(key = TestLogIdKey, value = EventLogId, db_prefix = 0x00,);

    #[test_log::test(tokio::test)]
    async fn sanity_handle_events() {
        let db = MemDatabase::new().into_database();
        let tg = TaskGroup::new();

        let (log_event_added_tx, log_event_added_rx) = watch::channel(());
        let (log_ordering_wakeup_tx, log_ordering_wakeup_rx) = watch::channel(());
        let (log_event_added_transient_tx, _log_event_added_transient_rx) =
            broadcast::channel(1024);

        tg.spawn_cancellable(
            "event log ordering task",
            run_event_log_ordering_task(
                db.clone(),
                log_ordering_wakeup_rx,
                log_event_added_tx,
                log_event_added_transient_tx,
            ),
        );

        let counter = Arc::new(AtomicU8::new(0));

        let _ = try_join!(
            handle_events(
                db.clone(),
                &TestLogIdKey,
                log_event_added_rx,
                move |_dbtx, event| {
                    let counter = counter.clone();
                    Box::pin(async move {
                        info!("{event:?}");

                        assert_eq!(
                            event.kind,
                            EventKind::from(format!(
                                "{}",
                                counter.load(std::sync::atomic::Ordering::Relaxed)
                            ))
                        );

                        if counter.load(std::sync::atomic::Ordering::Relaxed) == 4 {
                            bail!("Time to wrap up");
                        }
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(())
                    })
                },
            ),
            async {
                for i in 0..=4 {
                    let mut dbtx = db.begin_transaction().await;
                    dbtx.log_event_raw(
                        log_ordering_wakeup_tx.clone(),
                        EventKind::from(format!("{i}")),
                        None,
                        None,
                        vec![],
                        true,
                    )
                    .await;

                    dbtx.commit_tx().await;
                }

                Ok(())
            }
        );
    }
}
