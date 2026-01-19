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
use std::time::Duration;
use std::{fmt, ops};

use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Database, IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped, NonCommittable,
    WithDecoders, WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::MaybeSend;
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

/// Minimum age in ID count for trimable events to be deleted
const TRIMABLE_EVENTLOG_MIN_ID_AGE: u64 = 10_000;
/// Minimum age in microseconds for trimable events to be deleted (14 days)
const TRIMABLE_EVENTLOG_MIN_TS_AGE: u64 = 14 * 24 * 60 * 60 * 1_000_000;
/// Maximum number of entries to trim in one operation
const TRIMABLE_EVENTLOG_MAX_TRIMMED_EVENTS: usize = 100_000;

/// Type of persistence the [`Event`] uses.
///
/// As a compromise between richness of events and amount of data to store
/// Fedimint maintains two event logs in parallel:
///
/// * untrimable
/// * trimable
///
/// Untrimable log will append only a subset of events that are infrequent,
/// but important enough to be forever useful, e.g. for processing or debugging
/// of historical events.
///
/// Trimable log will append all persistent events, but will over time remove
/// the oldest ones. It will always retain enough events, that no log follower
/// actively processing it should ever miss any event, but restarting processing
/// from the start (index 0) can't be used for processing historical data.
///
/// Notably the positions in both logs are not interchangeable, so they use
/// different types.
///
/// On top of it, some events are transient and are not persisted at all,
/// and emitted only at runtime.
///
/// Consult [`Event::PERSISTENCE`] to know which event uses which persistence.
pub enum EventPersistence {
    /// Not written anywhere, just broadcasted as notification at runtime
    Transient,
    /// Persised only to log that gets trimmed
    Trimable,
    /// Persisted in both trimmed and untrimmed logs, so potentially
    /// stored forever.
    Persistent,
}

pub trait Event: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE: Option<ModuleKind>;
    const KIND: EventKind;
    const PERSISTENCE: EventPersistence;
}

/// An counter that resets on every restart, that guarantees that
/// [`UnordedEventLogId`]s don't conflict with each other.
static UNORDEREDED_EVENT_LOG_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A self-allocated ID that is mostly ordered
///
/// The goal here is to avoid concurrent database transaction
/// conflicts due the ID allocation. Instead they are picked based on
/// a time and a counter, so they are mostly but not strictly ordered and
/// monotonic, and even more importantly: not contiguous.
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

    pub fn checked_sub(self, rhs: u64) -> Option<EventLogId> {
        self.0.checked_sub(rhs).map(EventLogId)
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

impl fmt::Display for EventLogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Encodable, Decodable, Clone)]
pub struct UnorderedEventLogEntry {
    pub flags: u8,
    pub inner: EventLogEntry,
}

impl UnorderedEventLogEntry {
    pub const FLAG_PERSIST: u8 = 1;
    pub const FLAG_TRIMABLE: u8 = 2;

    fn persist(&self) -> bool {
        self.flags & Self::FLAG_PERSIST != 0
    }

    fn trimable(&self) -> bool {
        self.flags & Self::FLAG_TRIMABLE != 0
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
    pub ts_usecs: u64,

    /// Event-kind specific payload, typically encoded as a json string for
    /// flexibility.
    pub payload: Vec<u8>,
}

impl EventLogEntry {
    pub fn module_kind(&self) -> Option<&ModuleKind> {
        self.module.as_ref().map(|m| &m.0)
    }

    pub fn module_id(&self) -> Option<ModuleInstanceId> {
        self.module.as_ref().map(|m| m.1)
    }

    /// Get the event payload as typed value
    pub fn to_event<E>(&self) -> Option<E>
    where
        E: Event,
    {
        serde_json::from_slice(&self.payload).ok()
    }
}

/// An `EventLogEntry` that was already persisted (so has an id)
#[derive(Debug, Clone)]
pub struct PersistedLogEntry {
    id: EventLogId,
    inner: EventLogEntry,
}

impl Serialize for PersistedLogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PersistedLogEntry", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("kind", &self.inner.kind)?;
        state.serialize_field("module", &self.inner.module)?;
        state.serialize_field("ts_usecs", &self.inner.ts_usecs)?;

        // Try to deserialize payload as JSON, fall back to hex encoding
        let payload_value: serde_json::Value = serde_json::from_slice(&self.inner.payload)
            .unwrap_or_else(|_| serde_json::Value::String(hex::encode(&self.inner.payload)));
        state.serialize_field("payload", &payload_value)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for PersistedLogEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Id,
            Kind,
            Module,
            TsUsecs,
            Payload,
        }

        struct PersistedLogEntryVisitor;

        impl<'de> Visitor<'de> for PersistedLogEntryVisitor {
            type Value = PersistedLogEntry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct PersistedLogEntry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PersistedLogEntry, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut id = None;
                let mut kind = None;
                let mut module = None;
                let mut ts_usecs = None;
                let mut payload = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        Field::Kind => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            kind = Some(map.next_value()?);
                        }
                        Field::Module => {
                            if module.is_some() {
                                return Err(de::Error::duplicate_field("module"));
                            }
                            module = Some(map.next_value()?);
                        }
                        Field::TsUsecs => {
                            if ts_usecs.is_some() {
                                return Err(de::Error::duplicate_field("ts_usecs"));
                            }
                            ts_usecs = Some(map.next_value()?);
                        }
                        Field::Payload => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("payload"));
                            }
                            let value: serde_json::Value = map.next_value()?;
                            payload = Some(serde_json::to_vec(&value).map_err(de::Error::custom)?);
                        }
                    }
                }

                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let kind = kind.ok_or_else(|| de::Error::missing_field("kind"))?;
                let module = module.ok_or_else(|| de::Error::missing_field("module"))?;
                let ts_usecs = ts_usecs.ok_or_else(|| de::Error::missing_field("ts_usecs"))?;
                let payload = payload.ok_or_else(|| de::Error::missing_field("payload"))?;

                Ok(PersistedLogEntry {
                    id,
                    inner: EventLogEntry {
                        kind,
                        module,
                        ts_usecs,
                        payload,
                    },
                })
            }
        }

        const FIELDS: &[&str] = &["id", "kind", "module", "ts_usecs", "payload"];
        deserializer.deserialize_struct("PersistedLogEntry", FIELDS, PersistedLogEntryVisitor)
    }
}

impl PersistedLogEntry {
    pub fn id(&self) -> EventLogId {
        self.id
    }

    pub fn as_raw(&self) -> &EventLogEntry {
        &self.inner
    }
}

impl ops::Deref for PersistedLogEntry {
    type Target = EventLogEntry;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
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

/// Read-only event log operations that work with both read and write
/// transactions
#[apply(async_trait_maybe_send!)]
pub trait DBTransactionEventLogReadExt {
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

/// Write operations for the event log
#[apply(async_trait_maybe_send!)]
pub trait DBTransactionEventLogExt: DBTransactionEventLogReadExt {
    #[allow(clippy::too_many_arguments)]
    async fn log_event_raw(
        &mut self,
        log_ordering_wakeup_tx: watch::Sender<()>,
        kind: EventKind,
        module_kind: Option<ModuleKind>,
        module_id: Option<ModuleInstanceId>,
        payload: Vec<u8>,
        persist: EventPersistence,
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
            <E as Event>::PERSISTENCE,
        )
        .await;
    }
}

/// Implement read operations for any type that supports reading from the
/// database
#[apply(async_trait_maybe_send!)]
impl<'a, T> DBTransactionEventLogReadExt for T
where
    T: IReadDatabaseTransactionOpsTyped<'a> + WithDecoders + MaybeSend,
{
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
            .map(|(k, v)| PersistedLogEntry { id: k, inner: v })
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
            .map(|(k, v)| PersistedLogEntry { id: k.0, inner: v })
            .collect()
            .await
    }
}

/// Implement write operations for WriteDatabaseTransaction
#[apply(async_trait_maybe_send!)]
impl<'tx, Cap> DBTransactionEventLogExt for WriteDatabaseTransaction<'tx, Cap>
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
        persist: EventPersistence,
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
                    flags: match persist {
                        EventPersistence::Transient => 0,
                        EventPersistence::Trimable => UnorderedEventLogEntry::FLAG_TRIMABLE,
                        EventPersistence::Persistent => UnorderedEventLogEntry::FLAG_PERSIST,
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
}

/// Trims old entries from the trimable event log
async fn trim_trimable_log(db: &Database, current_time_usecs: u64) {
    let mut dbtx = db.begin_write_transaction().await;

    let current_trimable_id = dbtx.get_next_event_log_trimable_id().await;
    let min_id_threshold = current_trimable_id
        .0
        .saturating_sub(TRIMABLE_EVENTLOG_MIN_ID_AGE);
    let min_ts_threshold = current_time_usecs.saturating_sub(TRIMABLE_EVENTLOG_MIN_TS_AGE);

    let entries_to_delete: Vec<_> = dbtx
        .find_by_prefix(&EventLogTrimableIdPrefixAll)
        .await
        .take_while(|(id, entry)| {
            let id_old_enough = id.0 <= min_id_threshold;
            let ts_old_enough = entry.ts_usecs <= min_ts_threshold;

            // Continue while both conditions are met
            async move { id_old_enough && ts_old_enough }
        })
        .take(TRIMABLE_EVENTLOG_MAX_TRIMMED_EVENTS)
        .map(|(id, _entry)| id)
        .collect()
        .await;

    for id in &entries_to_delete {
        dbtx.remove_entry(id).await;
    }

    dbtx.commit_tx().await;
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

    let current_time_usecs =
        u64::try_from(fedimint_core::time::duration_since_epoch().as_micros()).unwrap_or(u64::MAX);
    trim_trimable_log(&db, current_time_usecs).await;

    let mut next_entry_id = db
        .begin_read_transaction()
        .await
        .get_next_event_log_id()
        .await;
    let mut next_entry_id_trimable = db
        .begin_read_transaction()
        .await
        .get_next_event_log_trimable_id()
        .await;

    loop {
        let mut dbtx = db.begin_write_transaction().await;

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

/// Persistent tracker of a position in the event log
///
/// During processing of event log the downstream consumer needs to
/// keep track of which event were processed already. It needs to do it
/// atomically and persist it so event in the presence of crashes no
/// event is ever missed or processed twice.
///
/// This trait allows abstracting away where and how is such position stored,
/// e.g. which key exactly is used, in what prefixed namespace etc.
///
/// ## Trimmable vs Non-Trimable log
///
/// See [`EventPersistence`]
#[apply(async_trait_maybe_send!)]
pub trait EventLogNonTrimableTracker {
    // Store position in the event log
    async fn store(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
        pos: EventLogId,
    ) -> anyhow::Result<()>;

    /// Load the last previous stored position (or None if never stored)
    async fn load(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
    ) -> anyhow::Result<Option<EventLogId>>;
}
pub type DynEventLogTracker = Box<dyn EventLogNonTrimableTracker>;

/// Like [`EventLogNonTrimableTracker`] but for trimable event log
#[apply(async_trait_maybe_send!)]
pub trait EventLogTrimableTracker {
    // Store position in the event log
    async fn store(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
        pos: EventLogTrimableId,
    ) -> anyhow::Result<()>;

    /// Load the last previous stored position (or None if never stored)
    async fn load(
        &mut self,
        dbtx: &mut WriteDatabaseTransaction<'_, NonCommittable>,
    ) -> anyhow::Result<Option<EventLogTrimableId>>;
}
pub type DynEventLogTrimableTracker = Box<dyn EventLogTrimableTracker>;

pub async fn handle_events<F, R>(
    db: Database,
    mut tracker: DynEventLogTracker,
    mut log_event_added: watch::Receiver<()>,
    call_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(&mut WriteDatabaseTransaction<'_, NonCommittable>, EventLogEntry) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let mut next_key: EventLogId = tracker
        .load(&mut db.begin_write_transaction().await.to_ref_nc())
        .await?
        .unwrap_or_default();

    trace!(target: LOG_CLIENT_EVENT_LOG, ?next_key, "Handling events");

    loop {
        let mut dbtx = db.begin_write_transaction().await;

        match dbtx.get_value(&next_key).await {
            Some(event) => {
                (call_fn)(&mut dbtx.to_ref_nc(), event).await?;

                next_key = next_key.next();

                tracker.store(&mut dbtx.to_ref_nc(), next_key).await?;

                dbtx.commit_tx().await;
            }
            _ => {
                drop(dbtx);

                if log_event_added.changed().await.is_err() {
                    break Ok(());
                }
            }
        }
    }
}

pub async fn handle_trimable_events<F, R>(
    db: Database,
    mut tracker: DynEventLogTrimableTracker,
    mut log_event_added: watch::Receiver<()>,
    call_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(&mut WriteDatabaseTransaction<'_, NonCommittable>, EventLogEntry) -> R,
    R: Future<Output = anyhow::Result<()>>,
{
    let mut next_key: EventLogTrimableId = tracker
        .load(&mut db.begin_write_transaction().await.to_ref_nc())
        .await?
        .unwrap_or_default();
    trace!(target: LOG_CLIENT_EVENT_LOG, ?next_key, "Handling trimable events");

    loop {
        let mut dbtx = db.begin_write_transaction().await;

        match dbtx.get_value(&next_key).await {
            Some(event) => {
                (call_fn)(&mut dbtx.to_ref_nc(), event).await?;

                next_key = next_key.next();
                tracker.store(&mut dbtx.to_ref_nc(), next_key).await?;

                dbtx.commit_tx().await;
            }
            _ => {
                drop(dbtx);

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
        if let Some((m, _)) = &e.inner.module {
            e.inner.kind == event_kind && *m == module_kind
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
    max_time_distance: Option<Duration>,
    predicate: impl Fn(L, R, Duration) -> Option<Res> + 'a,
) -> impl Iterator<Item = Res> + 'a
where
    L: Event,
    R: Event,
{
    events_l
        .iter()
        .cartesian_product(events_r)
        .filter_map(move |(l, r)| {
            if L::MODULE.as_ref() == l.as_raw().module_kind()
                && L::KIND == l.as_raw().kind
                && R::MODULE.as_ref() == r.as_raw().module_kind()
                && R::KIND == r.as_raw().kind
                && let Some(latency_usecs) = r.inner.ts_usecs.checked_sub(l.inner.ts_usecs)
                && max_time_distance.is_none_or(|max| u128::from(latency_usecs) <= max.as_millis())
                && let Some(l) = l.as_raw().to_event()
                && let Some(r) = r.as_raw().to_event()
            {
                predicate(l, r, Duration::from_millis(latency_usecs))
            } else {
                None
            }
        })
}

/// Helper struct for storing computed data about outgoing and incoming
/// payments.
#[derive(Debug, Default)]
pub struct StructuredPaymentEvents {
    pub latencies_usecs: Vec<u64>,
    pub fees: Vec<Amount>,
    pub latencies_failure: Vec<u64>,
}

impl StructuredPaymentEvents {
    pub fn new(
        success_stats: &[(u64, Amount)],
        failure_stats: Vec<u64>,
    ) -> StructuredPaymentEvents {
        let mut events = StructuredPaymentEvents {
            latencies_usecs: success_stats.iter().map(|(l, _)| *l).collect(),
            fees: success_stats.iter().map(|(_, f)| *f).collect(),
            latencies_failure: failure_stats,
        };
        events.sort();
        events
    }

    /// Combines this `StructuredPaymentEvents` with the `other`
    /// `StructuredPaymentEvents` by appending all of the internal vectors.
    pub fn combine(&mut self, other: &mut StructuredPaymentEvents) {
        self.latencies_usecs.append(&mut other.latencies_usecs);
        self.fees.append(&mut other.fees);
        self.latencies_failure.append(&mut other.latencies_failure);
        self.sort();
    }

    /// Sorts this `StructuredPaymentEvents` by sorting all of the internal
    /// vectors.
    fn sort(&mut self) {
        self.latencies_usecs.sort_unstable();
        self.fees.sort_unstable();
        self.latencies_failure.sort_unstable();
    }
}

#[cfg(test)]
mod tests;
