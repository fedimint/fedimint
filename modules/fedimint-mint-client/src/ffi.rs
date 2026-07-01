use std::time::Duration;

use fedimint_client::OperationId;
use fedimint_core::util::ffi::UniffiError;
use fedimint_core::{Amount, UnifiedCallback, UnifiedCallbackEvent, runtime};
use futures::StreamExt;

use crate::{
    MintClientModule, OOBNotes, SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
    SpendOOBRefund,
};

type Result<T> = std::result::Result<T, UniffiError>;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NoteDenominationCount {
    pub amount: Amount,
    pub count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SpendNotesResponse {
    pub operation_id: OperationId,
    pub oob_notes: OOBNotes,
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl MintClientModule {
    #[uniffi::method(name = "reissue_notes")]
    pub async fn reissue_notes_uniffi(
        &self,
        oob_notes: OOBNotes,
        extra_meta: String,
    ) -> Result<OperationId> {
        let extra_meta = if extra_meta.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&extra_meta)?
        };
        let operation_id = self.reissue_external_notes(oob_notes, extra_meta).await?;
        Ok(operation_id)
    }

    #[uniffi::method(name = "subscribe_reissue_external_notes")]
    pub async fn subscribe_reissue_external_notes_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let mint = client_ctx.self_ref();
        let updates = mint.subscribe_reissue_external_notes(operation_id).await?;
        runtime::spawn("uniffi-subscribe-reissue-external-notes", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event(
                    "reissue_notes",
                    Some(operation_id),
                    payload_json,
                ));
            }
        });
        Ok(())
    }

    #[uniffi::method(name = "spend_notes")]
    pub async fn spend_notes_uniffi(
        &self,
        amount: Amount,
        try_cancel_after_secs: Option<u64>,
    ) -> Result<SpendNotesResponse> {
        let (operation_id, oob_notes) = self
            .spend_notes_with_selector(
                &SelectNotesWithExactAmount,
                amount,
                try_cancel_after_secs.map(Duration::from_secs),
                false,
                serde_json::Value::Null,
            )
            .await?;
        Ok(SpendNotesResponse {
            operation_id,
            oob_notes,
        })
    }

    pub async fn spend_notes_expert(
        &self,
        amount: Amount,
        try_cancel_after_secs: Option<u64>,
    ) -> Result<SpendNotesResponse> {
        let (operation_id, oob_notes) = self
            .spend_notes_with_selector(
                &SelectNotesWithAtleastAmount,
                amount,
                try_cancel_after_secs.map(Duration::from_secs),
                false,
                serde_json::Value::Null,
            )
            .await?;
        Ok(SpendNotesResponse {
            operation_id,
            oob_notes,
        })
    }

    #[uniffi::method(name = "validate_notes")]
    pub fn validate_notes_uniffi(&self, oob_notes: &OOBNotes) -> Result<Amount> {
        Ok(self.validate_notes(oob_notes)?)
    }

    #[uniffi::method(name = "try_cancel_spend_notes")]
    pub async fn try_cancel_spend_notes_uniffi(&self, operation_id: OperationId) {
        self.try_cancel_spend_notes(operation_id).await;
    }

    pub async fn subscribe_spend_notes_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let mint = client_ctx.self_ref();
        let updates = mint.subscribe_spend_notes(operation_id).await?;
        runtime::spawn("uniffi-subscribe-spend-notes", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event(
                    "spend_notes",
                    Some(operation_id),
                    payload_json,
                ));
            }
        });
        Ok(())
    }

    #[uniffi::method(name = "await_spend_oob_refund")]
    pub async fn await_spend_oob_refund_uniffi(&self, operation_id: OperationId) -> SpendOOBRefund {
        self.await_spend_oob_refund(operation_id).await
    }

    #[uniffi::method(name = "get_note_counts_by_denomination")]
    pub async fn get_note_counts_by_denomination_uniffi(
        &self,
    ) -> Result<Vec<NoteDenominationCount>> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        let note_counts = self.get_note_counts_by_denomination(&mut dbtx).await;
        Ok(note_counts
            .iter()
            .map(|(amount, count)| NoteDenominationCount {
                amount,
                count: count as u64,
            })
            .collect())
    }
}

fn unified_event(
    topic: &str,
    operation_id: Option<OperationId>,
    payload_json: String,
) -> UnifiedCallbackEvent {
    UnifiedCallbackEvent {
        source: "fedimint-mint-client".to_owned(),
        topic: topic.to_owned(),
        operation_id: operation_id.map(|id| id.fmt_full().to_string()),
        payload_json,
    }
}
