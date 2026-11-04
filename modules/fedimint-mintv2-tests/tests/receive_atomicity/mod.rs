use std::ops::Range;
use std::path::Path;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_matches::assert_matches;
use fedimint_client::db::OperationLogKey;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::{MemDatabase, MemTransaction};
use fedimint_core::db::{
    DatabaseError, DatabaseKeyPrefix, DatabaseResult, IDatabaseTransactionOps,
    IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseExt, IRawDatabaseTransaction,
    PrefixStream,
};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, apply, async_trait_maybe_send, runtime};
use fedimint_eventlog::{Event, UnorderedEventLogEntry, UnorderedEventLogIdPrefixAll};
use fedimint_mintv2_client::{
    FinalReceiveOperationState, MintClientModule, MintOperationMeta, ReceiveECashError,
    ReceivePaymentEvent, ReceivePaymentStatus,
};
use fedimint_mintv2_common::KIND;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::Semaphore;

use super::{MintEvent, RECEIVE_SK, fixtures, issue_ecash, mint_event_stream, root_secret};

/// Intercept only commits creating the chosen receive operation. Other client
/// background tasks must remain free to use the database.
#[derive(Debug)]
struct ReceiveCommitGate {
    operation_key: Mutex<Vec<u8>>,
    attempts: AtomicUsize,
    reached: Semaphore,
    resume: Semaphore,
}

impl ReceiveCommitGate {
    fn new() -> Self {
        Self {
            operation_key: Mutex::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            reached: Semaphore::new(0),
            resume: Semaphore::new(0),
        }
    }
}

#[derive(Debug)]
struct GatedDatabase {
    inner: MemDatabase,
    gate: Arc<ReceiveCommitGate>,
}

#[derive(Debug)]
struct GatedTransaction<'a> {
    inner: MemTransaction<'a>,
    gate: Arc<ReceiveCommitGate>,
    writes_operation: bool,
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for GatedDatabase {
    type Transaction<'a> = GatedTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        GatedTransaction {
            inner: self.inner.begin_transaction().await,
            gate: self.gate.clone(),
            writes_operation: false,
        }
    }

    fn checkpoint(&self, path: &Path) -> DatabaseResult<()> {
        self.inner.checkpoint(path)
    }
}

#[apply(async_trait_maybe_send!)]
impl IDatabaseTransactionOpsCore for GatedTransaction<'_> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        let is_operation = key == *self.gate.operation_key.lock().unwrap();
        let previous = self.inner.raw_insert_bytes(key, value).await?;
        self.writes_operation |= is_operation && previous.is_none();
        Ok(previous)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.inner.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> DatabaseResult<Option<Vec<u8>>> {
        self.inner.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, prefix: &[u8]) -> DatabaseResult<PrefixStream<'_>> {
        self.inner.raw_find_by_prefix(prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        prefix: &[u8],
    ) -> DatabaseResult<PrefixStream<'_>> {
        self.inner
            .raw_find_by_prefix_sorted_descending(prefix)
            .await
    }

    async fn raw_find_by_range(&mut self, range: Range<&[u8]>) -> DatabaseResult<PrefixStream<'_>> {
        self.inner.raw_find_by_range(range).await
    }

    async fn raw_remove_by_prefix(&mut self, prefix: &[u8]) -> DatabaseResult<()> {
        self.inner.raw_remove_by_prefix(prefix).await
    }
}

impl IDatabaseTransactionOps for GatedTransaction<'_> {}

#[apply(async_trait_maybe_send!)]
impl IRawDatabaseTransaction for GatedTransaction<'_> {
    async fn commit_tx(mut self) -> DatabaseResult<()> {
        if self.writes_operation {
            // Check the actual operation-creation transaction, before it can
            // commit or wake the executor. This fails with the old two-commit
            // receive implementation even if the eventual event log looks fine.
            let events = self
                .inner
                .raw_find_by_prefix(&UnorderedEventLogIdPrefixAll.to_bytes())
                .await?
                .map(|(_, value)| {
                    UnorderedEventLogEntry::consensus_decode_whole(
                        &value,
                        &ModuleDecoderRegistry::default(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
                .await;
            assert!(events.iter().any(|entry| {
                entry.inner.kind == ReceivePaymentEvent::KIND
                    && entry.inner.module_kind() == Some(&KIND)
                    && entry
                        .inner
                        .to_event::<ReceivePaymentEvent>()
                        .is_some_and(|event| {
                            OperationLogKey {
                                operation_id: event.operation_id,
                            }
                            .to_bytes()
                                == *self.gate.operation_key.lock().unwrap()
                        })
            }));

            if self.gate.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                self.gate.reached.add_permits(1);
                self.gate.resume.acquire().await.unwrap().forget();
                return Err(DatabaseError::WriteConflict);
            }
        }
        self.inner.commit_tx().await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_operation_and_event_commit_or_rollback_together() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let sender = fed.new_client().await;
    issue_ecash(&sender, Amount::from_sats(10_000)).await?;

    // Exercise both dropping an in-flight receive and autocommit retrying a
    // failed commit. In both cases the exact same ecash can still be received.
    for cancel in [true, false] {
        let gate = Arc::new(ReceiveCommitGate::new());
        let receiver = fed
            .join_client_with_db(
                GatedDatabase {
                    inner: MemDatabase::new(),
                    gate: gate.clone(),
                }
                .into_database(),
                root_secret(&RECEIVE_SK),
            )
            .await;
        let (_, ecash) = sender
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await?;
        let operation_id = OperationId::from_encodable(&ecash);
        *gate.operation_key.lock().unwrap() = OperationLogKey { operation_id }.to_bytes();
        let custom_meta = serde_json::json!({"atomic": cancel});
        let task = runtime::spawn("receive-atomicity", {
            let receiver = receiver.clone();
            let ecash = ecash.clone();
            let custom_meta = custom_meta.clone();
            async move {
                receiver
                    .get_first_module::<MintClientModule>()
                    .unwrap()
                    .receive(ecash, custom_meta)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(30), gate.reached.acquire())
            .await??
            .forget();

        assert!(
            receiver
                .operation_log()
                .get_operation(operation_id)
                .await
                .is_none()
        );
        assert!(
            !receiver
                .get_event_log(None, 100)
                .await
                .iter()
                .any(|entry| { entry.as_raw().kind == ReceivePaymentEvent::KIND })
        );

        let mint = receiver.get_first_module::<MintClientModule>()?;
        let received_id = if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            mint.receive(ecash.clone(), custom_meta.clone()).await?
        } else {
            gate.resume.add_permits(1);
            task.await??
        };
        assert_eq!(received_id, operation_id);
        assert_eq!(gate.attempts.load(Ordering::SeqCst), 2);
        let operation = receiver
            .operation_log()
            .get_operation(operation_id)
            .await
            .unwrap();
        let MintOperationMeta::Receive {
            ecash: encoded,
            custom_meta: actual_meta,
            ..
        } = operation.meta()
        else {
            panic!("expected receive metadata");
        };
        assert_eq!(encoded, base32::encode_prefixed(FEDIMINT_PREFIX, &ecash));
        assert_eq!(actual_meta, custom_meta);

        let mut events = pin!(mint_event_stream(&receiver));
        let Some(MintEvent::Receive(event)) = events.next().await else {
            panic!("expected receive event before its update");
        };
        assert_eq!(event.operation_id, operation_id);
        assert_eq!(event.amount, ecash.amount());
        assert_matches!(
            mint.await_final_receive_operation_state(operation_id)
                .await?,
            FinalReceiveOperationState::Success
        );
        assert_matches!(
            mint.receive(ecash, Value::Null).await,
            Err(ReceiveECashError::AlreadyReceived)
        );
        let Some(MintEvent::ReceiveUpdate(update)) = events.next().await else {
            panic!("expected receive update without a duplicate start event");
        };
        assert_eq!(update.operation_id, operation_id);
        assert_eq!(update.status, ReceivePaymentStatus::Success);
    }
    Ok(())
}
