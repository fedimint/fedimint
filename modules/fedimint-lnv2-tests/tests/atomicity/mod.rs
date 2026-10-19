use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_client::RootSecret;
use fedimint_client::db::OperationLogKey;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::{MemDatabase, MemTransaction};
use fedimint_core::db::{
    Database, DatabaseError, DatabaseKeyPrefix, DatabaseResult, IDatabaseTransactionOps,
    IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped, IRawDatabase,
    IRawDatabaseTransaction, PrefixStream,
};
use fedimint_core::encoding::Decodable;
use fedimint_core::{apply, async_trait_maybe_send, sats};
use fedimint_eventlog::{
    DB_KEY_PREFIX_UNORDERED_EVENT_LOG, UnorderedEventLogEntry, UnorderedEventLogIdPrefixAll,
};
use fedimint_lnv2_client::{LightningClientModule, SendPaymentError};
use futures::StreamExt;
use tokio::sync::Notify;

use super::{LnEvent, fixtures, ln_event_stream, mock};

/// Intercepts only the commit creating the send operation, not background
/// writes.
#[derive(Debug)]
struct SendCommitProbe {
    operation_id: OperationId,
    attempts: AtomicUsize,
    first_attempt: Notify,
    release: Notify,
}

#[derive(Debug)]
struct ProbedDatabase {
    inner: MemDatabase,
    probe: Arc<SendCommitProbe>,
}

#[derive(Debug)]
struct ProbedTransaction<'a> {
    inner: MemTransaction<'a>,
    probe: &'a SendCommitProbe,
    creates_operation: bool,
    send_event: bool,
}

#[apply(async_trait_maybe_send!)]
impl IRawDatabase for ProbedDatabase {
    type Transaction<'a> = ProbedTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> Self::Transaction<'a> {
        ProbedTransaction {
            inner: self.inner.begin_transaction().await,
            probe: &self.probe,
            creates_operation: false,
            send_event: false,
        }
    }

    fn checkpoint(&self, path: &Path) -> DatabaseResult<()> {
        self.inner.checkpoint(path)
    }
}

#[apply(async_trait_maybe_send!)]
impl IDatabaseTransactionOpsCore for ProbedTransaction<'_> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> DatabaseResult<Option<Vec<u8>>> {
        if key
            == (OperationLogKey {
                operation_id: self.probe.operation_id,
            })
            .to_bytes()
        {
            self.creates_operation = true;
        }
        if key.first() == Some(&DB_KEY_PREFIX_UNORDERED_EVENT_LOG) {
            let entry = UnorderedEventLogEntry::consensus_decode_whole(value, &Default::default())
                .expect("Valid event encoding");
            if let Some(LnEvent::Send(event)) = super::try_parse_ln_event(&entry.inner) {
                self.send_event = event.operation_id == self.probe.operation_id;
            }
        }
        self.inner.raw_insert_bytes(key, value).await
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

impl IDatabaseTransactionOps for ProbedTransaction<'_> {}

#[apply(async_trait_maybe_send!)]
impl IRawDatabaseTransaction for ProbedTransaction<'_> {
    async fn commit_tx(self) -> DatabaseResult<()> {
        if self.creates_operation {
            assert!(
                self.send_event,
                "Send operation committed without its event"
            );
            if self.probe.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                self.probe.first_attempt.notify_one();
                self.probe.release.notified().await;
                return Err(DatabaseError::WriteConflict);
            }
        }
        self.inner.commit_tx().await
    }
}

async fn send_atomicity(cancel_before_commit: bool) -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let invoice = mock::payable_invoice();
    let operation_id = OperationId::from_encodable(&(invoice.clone(), 0u64));
    let probe = Arc::new(SendCommitProbe {
        operation_id,
        attempts: AtomicUsize::new(0),
        first_attempt: Notify::new(),
        release: Notify::new(),
    });
    let db: Database = ProbedDatabase {
        inner: MemDatabase::new(),
        probe: probe.clone(),
    }
    .into();
    let client = fed
        .join_client_with_db(
            db.clone(),
            RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&[42; 64])),
        )
        .await;
    client
        .get_first_module::<fedimint_dummy_client::DummyClientModule>()?
        .mock_receive(sats(10_000), fedimint_core::module::AmountUnit::BITCOIN)
        .await;
    let balance = client.get_balance_for_btc().await?;

    let send = fedimint_core::runtime::spawn("send-atomicity", {
        let client = client.clone();
        async move {
            client
                .get_first_module::<LightningClientModule>()
                .expect("Lightning module exists")
                .send(invoice, Some(mock::gateway()), serde_json::Value::Null)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(30), probe.first_attempt.notified()).await?;

    // Neither the operation, its event, nor the spent balance is visible before
    // commit.
    assert!(
        client
            .operation_log()
            .get_operation(operation_id)
            .await
            .is_none()
    );
    assert_eq!(client.get_balance_for_btc().await?, balance);
    assert!(
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&UnorderedEventLogIdPrefixAll)
            .await
            .all(|(_, entry)| async move {
                !matches!(
                    super::try_parse_ln_event(&entry.inner),
                    Some(LnEvent::Send(_))
                )
            })
            .await
    );

    if cancel_before_commit {
        // Simulate stopping the client after staging all writes but before commit.
        send.abort();
        assert!(send.await.unwrap_err().is_cancelled());
        assert!(
            client
                .operation_log()
                .get_operation(operation_id)
                .await
                .is_none()
        );
        assert_eq!(client.get_balance_for_btc().await?, balance);
    } else {
        // The first commit fails without applying writes; autocommit must retry the
        // pair.
        probe.release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), send).await???,
            operation_id
        );
        assert_eq!(probe.attempts.load(Ordering::SeqCst), 2);
        let events = ln_event_stream(&client);
        tokio::pin!(events);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(30), events.next()).await?,
            Some(LnEvent::Send(event)) if event.operation_id == operation_id
        ));
        assert!(
            client
                .operation_log()
                .get_operation(operation_id)
                .await
                .is_some()
        );
        let sends = client
            .get_event_log(None, 100)
            .await
            .into_iter()
            .filter(|entry| {
                matches!(
                    super::try_parse_ln_event(entry.as_raw()),
                    Some(LnEvent::Send(_))
                )
            })
            .count();
        assert_eq!(sends, 1, "A failed commit must not leave a duplicate event");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_operation_and_event_retry_together() -> anyhow::Result<()> {
    send_atomicity(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn send_operation_and_event_roll_back_together() -> anyhow::Result<()> {
    send_atomicity(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn insufficient_funds_does_not_announce_send() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let invoice = mock::payable_invoice();
    let operation_id = OperationId::from_encodable(&(invoice.clone(), 0u64));
    assert!(matches!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(invoice, Some(mock::gateway()), serde_json::Value::Null)
            .await,
        Err(SendPaymentError::InsufficientFunds(_))
    ));
    assert!(
        client
            .operation_log()
            .get_operation(operation_id)
            .await
            .is_none()
    );
    assert!(client.get_event_log(None, 100).await.iter().all(|entry| {
        !matches!(
            super::try_parse_ln_event(entry.as_raw()),
            Some(LnEvent::Send(_))
        )
    }));
    Ok(())
}
