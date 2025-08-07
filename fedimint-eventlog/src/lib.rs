#![allow(clippy::needless_lifetimes)]

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
use fedimint_core::{Amount, apply, async_trait_maybe_send, impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_CLIENT_EVENT_LOG;
use futures::{Future, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tracing::{debug, trace};

/// DB prefixes hardcoded for use of the event log
/// `fedimint-eventlog` was extracted from `fedimint-client` to help
/// include/re-use in other part of the code. But fundamentally its role
/// is to implement event log in the client.
/// There is currently no way to inject the prefixes to use for db records,
/// so we use these constants to keep them in sync. Any other app that will
/// want to store its own even log, will need to use the exact same prefixes,
/// which in practice should not be a problem.
pub const DB_KEY_PREFIX_UNORDERED_EVENT_LOG: u8 = 0x3a;
pub const DB_KEY_PREFIX_EVENT_LOG: u8 = 0x39;
pub const DB_KEY_PREFIX_EVENT_LOG_TRIMABLE: u8 = 0x41;

pub trait Event: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE: Option<ModuleKind>;
    const KIND: EventKind;
    const PERSIST: bool = true;
    const TRIMABLE: bool = false;
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
    pub const LOG_START: EventLogId = EventLogId(0);

    fn next(self) -> EventLogId {
        Self(self.0 + 1)
    }

    pub fn saturating_add(self, rhs: u64) -> EventLogId {
        Self(self.0.saturating_add(rhs))
    }

    pub fn saturating_sub(self, rhs: u64) -> EventLogId {
        Self(self.0.saturating_sub(rhs))
    }
}

impl From<EventLogId> for u64 {
    fn from(value: EventLogId) -> Self {
        value.0
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
    pub flags: u8,
    pub inner: EventLogEntry,
}

impl UnorderedEventLogEntry {
    pub const PERSIST: u8 = 1;
    pub const TRIMABLE: u8 = 2;

    fn persist(&self) -> bool {
        self.flags & Self::PERSIST != 0
    }

    fn trimable(&self) -> bool {
        self.flags & Self::TRIMABLE != 0
    }
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

/// Struct used for processing log entries after they have been persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedLogEntry {
    pub event_id: EventLogId,
    pub event_kind: EventKind,
    pub module: Option<(ModuleKind, u16)>,
    pub timestamp: u64,
    pub value: serde_json::Value,
}

impl_db_record!(
    key = UnordedEventLogId,
    value = UnorderedEventLogEntry,
    db_prefix = DB_KEY_PREFIX_UNORDERED_EVENT_LOG,
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
    db_prefix = DB_KEY_PREFIX_EVENT_LOG,
);

impl_db_lookup!(key = EventLogId, query_prefix = EventLogIdPrefixAll);

impl_db_lookup!(key = EventLogId, query_prefix = EventLogIdPrefix);

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
pub struct EventLogTrimableId(EventLogId);

impl EventLogTrimableId {
    fn next(&self) -> Self {
        Self(self.0.next())
    }

    pub fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }
}

impl From<u64> for EventLogTrimableId {
    fn from(value: u64) -> Self {
        Self(EventLogId(value))
    }
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct EventLogTrimableIdPrefixAll;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct EventLogTrimableIdPrefix(EventLogId);

impl_db_record!(
    key = EventLogTrimableId,
    value = EventLogEntry,
    db_prefix = DB_KEY_PREFIX_EVENT_LOG_TRIMABLE,
);

impl_db_lookup!(
    key = EventLogTrimableId,
    query_prefix = EventLogTrimableIdPrefixAll
);

impl_db_lookup!(
    key = EventLogTrimableId,
    query_prefix = EventLogTrimableIdPrefix
);

#[apply(async_trait_maybe_send!)]
pub trait DBTransactionEventLogExt {
    #[allow(clippy::too_many_arguments)]
    async fn log_event_raw(
        &mut self,
        log_ordering_wakeup_tx: watch::Sender<()>,
        kind: EventKind,
        module_kind: Option<ModuleKind>,
        module_id: Option<ModuleInstanceId>,
        payload: Vec<u8>,
        persist: bool,
        trimable: bool,
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
            <E as Event>::TRIMABLE,
        )
        .await;
    }

    /// Next [`EventLogId`] to use for new ordered events.
    ///
    /// Used by ordering task, though might be
    /// useful to get the current count of events.
    async fn get_next_event_log_id(&mut self) -> EventLogId;

    /// Next [`EventLogTrimableId`] to use for new ordered trimable events
    async fn get_next_event_log_trimable_id(&mut self) -> EventLogTrimableId;

    /// Read a part of the event log.
    async fn get_event_log(
        &mut self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry>;

    async fn get_event_log_trimable(
        &mut self,
        pos: Option<EventLogTrimableId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry>;
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
        trimable: bool,
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
                    flags: if persist {
                        UnorderedEventLogEntry::PERSIST
                    } else {
                        0
                    } | if trimable {
                        UnorderedEventLogEntry::TRIMABLE
                    } else {
                        0
                    },
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
            log_ordering_wakeup_tx.send_replace(());
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

    async fn get_next_event_log_trimable_id(&mut self) -> EventLogTrimableId {
        EventLogTrimableId(
            self.find_by_prefix_sorted_descending(&EventLogTrimableIdPrefixAll)
                .await
                .next()
                .await
                .map(|(k, _v)| k.0.next())
                .unwrap_or_default(),
        )
    }

    async fn get_event_log(
        &mut self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry> {
        let pos = pos.unwrap_or_default();
        self.find_by_range(pos..pos.saturating_add(limit))
            .await
            .map(|(k, v)| PersistedLogEntry {
                event_id: k,
                event_kind: v.kind,
                module: v.module,
                timestamp: v.ts_usecs,
                value: serde_json::from_slice(&v.payload).unwrap_or_default(),
            })
            .collect()
            .await
    }

    async fn get_event_log_trimable(
        &mut self,
        pos: Option<EventLogTrimableId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry> {
        let pos = pos.unwrap_or_default();
        self.find_by_range(pos..pos.saturating_add(limit))
            .await
            .map(|(k, v)| PersistedLogEntry {
                event_id: k.0,
                event_kind: v.kind,
                module: v.module,
                timestamp: v.ts_usecs,
                value: serde_json::from_slice(&v.payload).unwrap_or_default(),
            })
            .collect()
            .await
    }
}

/// The code that handles new unordered events and rewriters them fully ordered
/// into the final event log.
pub async fn run_event_log_ordering_task(
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
    let mut next_entry_id_trimable = db
        .begin_transaction_nc()
        .await
        .get_next_event_log_trimable_id()
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
            if entry.persist() {
                // Non-trimable events get persisted in both the default event log
                // and trimable event log
                if !entry.trimable() {
                    assert!(
                        dbtx.insert_entry(&next_entry_id, &entry.inner)
                            .await
                            .is_none(),
                        "Must never overwrite existing event"
                    );
                    trace!(target: LOG_CLIENT_EVENT_LOG, ?unordered_id, id=?next_entry_id, "Ordered event log event");
                    next_entry_id = next_entry_id.next();
                }

                // Trimable events get persisted only in trimable log
                assert!(
                    dbtx.insert_entry(&next_entry_id_trimable, &entry.inner)
                        .await
                        .is_none(),
                    "Must never overwrite existing event"
                );
                trace!(target: LOG_CLIENT_EVENT_LOG, ?unordered_id, id=?next_entry_id, "Ordered event log event");
                next_entry_id_trimable = next_entry_id_trimable.next();
            } else {
                // Transient events don't get persisted at all
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
            log_event_added.send_replace(());
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

        match dbtx.get_value(&next_key).await {
            Some(event) => {
                (call_fn)(&mut dbtx.to_ref_nc(), event).await?;

                next_key = next_key.next();
                dbtx.insert_entry(pos_key, &next_key).await;

                dbtx.commit_tx().await;
            }
            _ => {
                if log_event_added.changed().await.is_err() {
                    break Ok(());
                }
            }
        }
    }
}

pub async fn handle_trimable_events<F, R, K>(
    db: Database,
    pos_key: &K,
    mut log_event_added: watch::Receiver<()>,
    call_fn: F,
) -> anyhow::Result<()>
where
    K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
    K: DatabaseRecord<Value = EventLogTrimableId>,
    F: Fn(&mut DatabaseTransaction<NonCommittable>, EventLogEntry) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let mut next_key: EventLogTrimableId = db
        .begin_transaction_nc()
        .await
        .get_value(pos_key)
        .await
        .unwrap_or_default();

    trace!(target: LOG_CLIENT_EVENT_LOG, ?next_key, "Handling trimable events");

    loop {
        let mut dbtx = db.begin_transaction().await;

        match dbtx.get_value(&next_key).await {
            Some(event) => {
                (call_fn)(&mut dbtx.to_ref_nc(), event).await?;

                next_key = next_key.next();
                dbtx.insert_entry(pos_key, &next_key).await;

                dbtx.commit_tx().await;
            }
            _ => {
                if log_event_added.changed().await.is_err() {
                    break Ok(());
                }
            }
        }
    }
}

/// Filters the `PersistedLogEntries` by the `EventKind` and
/// `ModuleKind`.
pub fn filter_events_by_kind<'a, I>(
    all_events: I,
    module_kind: ModuleKind,
    event_kind: EventKind,
) -> impl Iterator<Item = &'a PersistedLogEntry> + 'a
where
    I: IntoIterator<Item = &'a PersistedLogEntry> + 'a,
{
    all_events.into_iter().filter(move |e| {
        if let Some((m, _)) = &e.module {
            e.event_kind == event_kind && *m == module_kind
        } else {
            false
        }
    })
}

/// Joins two sets of events on a predicate.
///
/// This function computes a "nested loop join" by first computing the cross
/// product of the start event vector and the success/failure event vectors. The
/// resulting cartesian product is then filtered according to the join predicate
/// supplied in the parameters.
///
/// This function is intended for small data sets. If the data set relations
/// grow, this function should implement a different join algorithm or be moved
/// out of the gateway.
pub fn join_events<'a, L, R, Res>(
    events_l: &'a [&PersistedLogEntry],
    events_r: &'a [&PersistedLogEntry],
    predicate: impl Fn(L, R, u64) -> Option<Res> + 'a,
) -> impl Iterator<Item = Res> + 'a
where
    L: Event,
    R: Event,
{
    events_l
        .iter()
        .cartesian_product(events_r)
        .filter_map(move |(l, r)| {
            if let Some(latency) = r.timestamp.checked_sub(l.timestamp) {
                let event_l: L =
                    serde_json::from_value(l.value.clone()).expect("could not parse JSON");
                let event_r: R =
                    serde_json::from_value(r.value.clone()).expect("could not parse JSON");
                predicate(event_l, event_r, latency)
            } else {
                None
            }
        })
}

/// Helper struct for storing computed data about outgoing and incoming
/// payments.
#[derive(Debug, Default)]
pub struct StructuredPaymentEvents {
    pub latencies: Vec<u64>,
    pub fees: Vec<Amount>,
    pub latencies_failure: Vec<u64>,
}

impl StructuredPaymentEvents {
    pub fn new(
        success_stats: &[(u64, Amount)],
        failure_stats: Vec<u64>,
    ) -> StructuredPaymentEvents {
        let mut events = StructuredPaymentEvents {
            latencies: success_stats.iter().map(|(l, _)| *l).collect(),
            fees: success_stats.iter().map(|(_, f)| *f).collect(),
            latencies_failure: failure_stats,
        };
        events.sort();
        events
    }

    /// Combines this `StructuredPaymentEvents` with the `other`
    /// `StructuredPaymentEvents` by appending all of the internal vectors.
    pub fn combine(&mut self, other: &mut StructuredPaymentEvents) {
        self.latencies.append(&mut other.latencies);
        self.fees.append(&mut other.fees);
        self.latencies_failure.append(&mut other.latencies_failure);
        self.sort();
    }

    /// Sorts this `StructuredPaymentEvents` by sorting all of the internal
    /// vectors.
    fn sort(&mut self) {
        self.latencies.sort_unstable();
        self.fees.sort_unstable();
        self.latencies_failure.sort_unstable();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;

    use anyhow::bail;
    use fedimint_core::db::IRawDatabaseExt as _;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::impl_db_record;
    use fedimint_core::task::TaskGroup;
    use tokio::sync::{broadcast, watch};
    use tokio::try_join;
    use tracing::info;

    use super::{
        DBTransactionEventLogExt as _, EventLogId, handle_events, run_event_log_ordering_task,
    };
    use crate::EventKind;

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
                        false,
                    )
                    .await;

                    dbtx.commit_tx().await;
                }

                Ok(())
            }
        );
    }
}
