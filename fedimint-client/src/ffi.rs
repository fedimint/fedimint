use std::sync::Arc;

use fedimint_client_module::OperationId;
use fedimint_client_module::oplog::OperationLogEntry;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::AmountUnit;
use fedimint_core::util::ffi::UniffiError;
use fedimint_core::{Amount, PeerId};
use fedimint_eventlog::{EventLogId, PersistedLogEntry};
use futures::StreamExt;

use crate::db::ChronologicalOperationLogKey;
use crate::{Client, ClientHandle, client};

type Result<T> = std::result::Result<T, UniffiError>;

#[derive(uniffi::Record)]
pub struct ListOperationsResponse {
    pub last_seen: ChronologicalOperationLogKey,
    pub operations: OperationLogEntry,
}

#[uniffi::export(async_runtime = "tokio")]
impl ClientHandle {
    pub async fn get_balance(&self) -> Result<Amount> {
        let client = client_for_handle(self)?;
        Ok(client.get_balance_for_btc().await?)
    }

    #[uniffi::method(name = "subscribe_balance_changes")]
    pub fn subscribe_balance_changes_uniffi(
        &self,
        unit: AmountUnit,
        callback: Box<dyn BalanceChangeCallback>,
    ) -> Result<()> {
        let client = client_for_handle(self)?;
        let task_client = client.clone();
        let _ = client.spawn_cancellable("uniffi-subscribe-balance-changes", async move {
            let mut stream = task_client.subscribe_balance_changes(unit).await;
            while let Some(balance) = stream.next().await {
                callback.on_balance_change(balance);
            }
        });

        Ok(())
    }

    pub async fn get_config(&self) -> Result<ClientConfig> {
        let client = client_for_handle(self)?;
        Ok(client.config().await)
    }

    pub fn get_federation_id(&self) -> Result<FederationId> {
        let client = client_for_handle(self)?;
        Ok(client.federation_id())
    }

    pub async fn get_invite_code(&self, peer: PeerId) -> Result<Option<InviteCode>> {
        let client = client_for_handle(self)?;
        Ok(client.invite_code(peer).await)
    }

    pub async fn get_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<OperationLogEntry>> {
        let client = client_for_handle(self)?;
        let operation = client.operation_log().get_operation(operation_id).await;
        Ok(operation)
    }

    pub async fn list_operations(
        &self,
        limit: Option<u64>,
        last_seen: Option<ChronologicalOperationLogKey>,
    ) -> Result<Vec<ListOperationsResponse>> {
        let client = client_for_handle(self)?;
        let limit = limit
            .unwrap_or(client::DEFAULT_EVENT_LOG_PAGE_SIZE)
            .min(client::MAX_EVENT_LOG_PAGE_SIZE) as usize;
        let operations = client
            .operation_log()
            .paginate_operations_rev(limit, last_seen)
            .await;
        Ok(operations
            .into_iter()
            .map(|(last_seen, operations)| ListOperationsResponse {
                last_seen,
                operations,
            })
            .collect())
    }

    #[uniffi::method(name = "get_event_log")]
    pub async fn get_event_log_uniffi(
        &self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Result<Vec<PersistedLogEntry>> {
        let client = client_for_handle(self)?;
        let limit = limit.min(client::MAX_EVENT_LOG_PAGE_SIZE);
        Ok(client.get_event_log(pos, limit).await)
    }

    pub async fn session_count(&self) -> Result<u64> {
        let client = client_for_handle(self)?;
        Ok(client.fetch_session_count().await?)
    }

    pub fn has_pending_recoveries(&self) -> Result<bool> {
        let client = client_for_handle(self)?;
        Ok(client.has_pending_recoveries())
    }

    #[uniffi::method(name = "wait_for_all_recoveries")]
    pub async fn wait_for_all_recoveries_uniffi(&self) -> Result<()> {
        let client = client_for_handle(self)?;
        client.wait_for_all_recoveries().await?;
        Ok(())
    }

    #[uniffi::method(name = "subscribe_to_recovery_progress")]
    pub fn subscribe_to_recovery_progress_uniffi(
        &self,
        callback: Box<dyn RecoveryProgressCallback>,
    ) -> Result<()> {
        let client = client_for_handle(self)?;
        let task_client = client.clone();
        let _ = client.spawn_cancellable("uniffi-subscribe-recovery-progress", async move {
            let mut stream = task_client.subscribe_to_recovery_progress();
            while let Some((module_id, progress)) = stream.next().await {
                callback.on_recovery_progress(module_id, progress.complete, progress.total);
            }
        });

        Ok(())
    }
}

#[cfg(feature = "uniffi")]
fn client_for_handle(handle: &ClientHandle) -> Result<Arc<Client>> {
    handle
        .inner_arc()
        .ok_or_else(|| UniffiError::General("Client handle is already shut down".to_owned()))
}

#[cfg(feature = "uniffi")]
#[uniffi::export(callback_interface)]
pub trait BalanceChangeCallback: Send + Sync {
    fn on_balance_change(&self, balance: Amount);
}

#[cfg(feature = "uniffi")]
#[uniffi::export(callback_interface)]
pub trait RecoveryProgressCallback: Send + Sync {
    fn on_recovery_progress(&self, module_id: u16, complete: u32, total: u32);
}
