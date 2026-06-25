use std::sync::Arc;

use anyhow::anyhow;
use fedimint_client_module::OperationId;
use fedimint_client_module::oplog::OperationLogEntry;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::AmountUnit;
use fedimint_core::util::ffi::UniffiError;
use fedimint_core::{Amount, PeerId, UnifiedCallback, UnifiedCallbackEvent};
use fedimint_eventlog::{EventLogId, PersistedLogEntry};
use futures::StreamExt;

use crate::{ChronologicalOperationLogKey, Client, ClientHandle, client};

type Result<T> = std::result::Result<T, UniffiError>;

uniffi::custom_type!(OperationLogEntry, String, {
    remote,
    lower: |e| serde_json::to_string(&e).expect("OperationLogEntry always serializes"),
    try_lift: |s| serde_json::from_str(&s).map_err(|e| anyhow!(format!("Failed to parse OperationLogEntry: {e}"))),
});

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

    pub fn subscribe_balance_changes(
        &self,
        unit: AmountUnit,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client = client_for_handle(self)?;
        let task_client = client.clone();
        let _ = client.spawn_cancellable("uniffi-subscribe-balance-changes", async move {
            let mut stream = task_client.subscribe_balance_changes(unit).await;
            while let Some(balance) = stream.next().await {
                let payload = serde_json::json!({ "msats": balance.msats });
                let Ok(payload_json) = serde_json::to_string(&payload) else {
                    continue;
                };
                callback.on_event(unified_callback_event(
                    "fedimint-client",
                    "balance_change",
                    None,
                    payload_json,
                ));
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

    pub async fn get_invite_code(&self, peer: PeerId) -> Option<InviteCode> {
        let client = client_for_handle(self).ok()?;
        client.invite_code(peer).await
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
        let limit = if limit.is_none() && last_seen.is_none() {
            usize::MAX
        } else {
            limit.unwrap_or(usize::MAX as u64) as usize
        };
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
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client = client_for_handle(self)?;
        let task_client = client.clone();
        let _ = client.spawn_cancellable("uniffi-subscribe-recovery-progress", async move {
            let mut stream = task_client.subscribe_to_recovery_progress();
            while let Some((module_id, progress)) = stream.next().await {
                let payload = serde_json::json!({
                    "module_id": module_id,
                    "complete": progress.complete,
                    "total": progress.total,
                });
                let Ok(payload_json) = serde_json::to_string(&payload) else {
                    continue;
                };
                callback.on_event(unified_callback_event(
                    "fedimint-client",
                    "recovery_progress",
                    None,
                    payload_json,
                ));
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
fn unified_callback_event(
    source: &str,
    topic: &str,
    operation_id: Option<OperationId>,
    payload_json: String,
) -> UnifiedCallbackEvent {
    UnifiedCallbackEvent {
        source: source.to_owned(),
        topic: topic.to_owned(),
        operation_id: operation_id.map(|id| id.fmt_full().to_string()),
        payload_json,
    }
}
