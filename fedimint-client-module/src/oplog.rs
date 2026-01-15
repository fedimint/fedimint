use std::fmt::Debug;
use std::future;
use std::time::SystemTime;

use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, WriteDatabaseTransaction};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::BoxStream;
use fedimint_core::{apply, async_trait_maybe_send};
use futures::{StreamExt, stream};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Json value using string representation as db encoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct JsonStringed(pub serde_json::Value);

impl Encodable for JsonStringed {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let json_str = serde_json::to_string(&self.0).expect("JSON serialization should not fail");
        json_str.consensus_encode(writer)
    }
}

impl Decodable for JsonStringed {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let json_str = String::consensus_decode_partial(r, modules)?;
        let value = serde_json::from_str(&json_str).map_err(DecodeError::from_err)?;
        Ok(JsonStringed(value))
    }
}

#[apply(async_trait_maybe_send!)]
pub trait IOperationLog {
    async fn get_operation(&self, operation_id: OperationId) -> Option<OperationLogEntry>;

    async fn get_operation_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> Option<OperationLogEntry>;

    async fn add_operation_log_entry_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: serde_json::Value,
    );

    fn outcome_or_updates(
        &self,
        db: &Database,
        operation_id: OperationId,
        operation_log_entry: OperationLogEntry,
        stream_gen: Box<dyn FnOnce() -> BoxStream<'static, serde_json::Value>>,
    ) -> UpdateStreamOrOutcome<serde_json::Value>;
}

/// Represents the outcome of an operation, combining both the outcome value and
/// its timestamp
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq)]
pub struct OperationOutcome {
    pub time: SystemTime,
    pub outcome: JsonStringed,
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
#[derive(Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct OperationLogEntry {
    pub(crate) operation_module_kind: String,
    pub(crate) meta: JsonStringed,
    // TODO: probably change all that JSON to Dyn-types
    pub(crate) outcome: Option<OperationOutcome>,
}

impl OperationLogEntry {
    pub fn new(
        operation_module_kind: String,
        meta: JsonStringed,
        outcome: Option<OperationOutcome>,
    ) -> Self {
        Self {
            operation_module_kind,
            meta,
            outcome,
        }
    }

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
        self.try_meta()
            .expect("JSON deserialization should not fail")
    }

    /// Fallible version of [`OperationLogEntry::meta`]. Used to avoid panics in
    /// the case of failed past migrations, resulting in invalid encodings in
    /// the DB.
    pub fn try_meta<M: DeserializeOwned>(&self) -> Result<M, serde_json::Error> {
        serde_json::from_value(self.meta.0.clone())
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
        self.try_outcome()
            .expect("JSON deserialization should not fail")
    }

    /// Fallible version of [`OperationLogEntry::outcome`]. Used to avoid panics
    /// in the case of failed past migrations, resulting in invalid encodings in
    /// the DB.
    pub fn try_outcome<D: DeserializeOwned>(&self) -> Result<Option<D>, serde_json::Error> {
        self.outcome
            .as_ref()
            .map(|outcome| serde_json::from_value(outcome.outcome.0.clone()))
            .transpose()
    }

    /// Returns the time when the outcome was cached.
    pub fn outcome_time(&self) -> Option<SystemTime> {
        self.outcome.as_ref().map(|o| o.time)
    }

    pub fn set_outcome(&mut self, outcome: impl Into<Option<OperationOutcome>>) {
        self.outcome = outcome.into();
    }
}

/// Either a stream of operation updates if the operation hasn't finished yet or
/// its outcome otherwise.
pub enum UpdateStreamOrOutcome<U> {
    UpdateStream(BoxStream<'static, U>),
    Outcome(U),
}

impl<U: Debug> Debug for UpdateStreamOrOutcome<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateStreamOrOutcome::UpdateStream(_) => write!(f, "UpdateStream"),
            UpdateStreamOrOutcome::Outcome(o) => f.debug_tuple("Outcome").field(o).finish(),
        }
    }
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

    /// Awaits the outcome of the operation update stream, either by returning
    /// the cached value or by consuming the entire stream and returning the
    /// last update.
    pub async fn await_outcome(self) -> Option<U> {
        match self {
            UpdateStreamOrOutcome::Outcome(outcome) => Some(outcome),
            UpdateStreamOrOutcome::UpdateStream(mut stream) => {
                let mut last_update = None;
                while let Some(update) = stream.next().await {
                    last_update = Some(update);
                }
                last_update
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::stream;
    use serde_json::Value;

    use super::*;

    #[tokio::test]
    async fn test_await_outcome_cached() {
        let test_value = serde_json::json!({"status": "completed", "amount": 100});
        let cached_outcome = UpdateStreamOrOutcome::Outcome(test_value.clone());
        let result = cached_outcome.await_outcome().await;
        assert_eq!(result, Some(test_value));
    }

    #[tokio::test]
    async fn test_await_outcome_uncached_with_updates() {
        let update_stream = Box::pin(stream::iter(vec![
            Value::from(0),
            Value::from(1),
            Value::from(2),
        ]));
        let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(update_stream);
        let result = uncached_outcome.await_outcome().await;
        assert_eq!(result, Some(Value::from(2)));
    }

    #[tokio::test]
    async fn test_await_outcome_uncached_empty_stream() {
        let empty_stream = Box::pin(stream::empty::<serde_json::Value>());
        let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(empty_stream);
        let result = uncached_outcome.await_outcome().await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_await_outcome_uncached_single_update() {
        let update_stream = Box::pin(stream::once(async { Value::from(0) }));
        let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(update_stream);
        let result = uncached_outcome.await_outcome().await;
        assert_eq!(result, Some(Value::from(0)));
    }
}
