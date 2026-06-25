use fedimint_core::core::OperationId;
use fedimint_core::util::ffi::UniffiError;
use fedimint_core::{UnifiedCallback, UnifiedCallbackEvent, runtime};
use fedimint_wallet_common::WalletSummary;
use futures::StreamExt as _;

use crate::{
    PegInRequest, PegInResponse, PegOutRequest, PegOutResponse, WalletClientModule, anyhow,
};

type Result<T> = std::result::Result<T, UniffiError>;

uniffi::custom_type!(WalletSummary, String, {
    remote,
    lower: |v| serde_json::to_string(&v).unwrap(),
    try_lift: |s| serde_json::from_str(&s).map_err(|e| anyhow!(format!("Failed to parse WalletSummary: {e}"))),
});

#[derive(Debug, Clone, uniffi::Record)]
pub struct DepositAddressRecord {
    pub operation_id: OperationId,
    pub address: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct WalletSummaryRecord {
    /// Total spendable on-chain balance in msats
    pub spendable_msats: u64,
    /// Total unconfirmed peg-out balance in msats
    pub unconfirmed_msats: u64,
}

#[uniffi::export(async_runtime = "tokio")]
impl WalletClientModule {
    #[uniffi::method(name = "get_wallet_summary")]
    pub async fn get_wallet_summary_uniffi(&self) -> Result<WalletSummary> {
        Ok(self.get_wallet_summary().await?)
    }

    #[uniffi::method(name = "get_block_count_local")]
    pub async fn get_block_count_local_uniffi(&self) -> Result<u32> {
        Ok(self.get_block_count_local().await?)
    }

    #[uniffi::method(name = "peg_in")]
    pub async fn peg_in_uniffi(&self, req: PegInRequest) -> Result<PegInResponse> {
        let peg_in_response = self.peg_in(req).await?;
        Ok(peg_in_response)
    }

    #[uniffi::method(name = "peg_out")]
    pub async fn peg_out_uniffi(&self, req: PegOutRequest) -> Result<PegOutResponse> {
        Ok(self.peg_out(req).await?)
    }

    /// Subscribe to state updates for a deposit operation. The callback
    /// receives JSON-serialized `DepositStateV2` payloads.
    #[uniffi::method(name = "subscribe_deposit")]
    pub async fn subscribe_deposit_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        runtime::spawn("uniffi-subscribe-deposit", async move {
            let wallet = client_ctx.self_ref();
            let Ok(updates) = wallet.subscribe_deposit(operation_id).await else {
                return;
            };
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event("deposit", Some(operation_id), payload_json));
            }
        });
        Ok(())
    }

    /// Subscribe to state updates for a withdraw operation. The callback
    /// receives JSON-serialized `WithdrawState` payloads.
    #[uniffi::method(name = "subscribe_withdraw")]
    pub async fn subscribe_withdraw_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        runtime::spawn("uniffi-subscribe-withdraw", async move {
            let wallet = client_ctx.self_ref();
            let Ok(updates) = wallet.subscribe_withdraw_updates(operation_id).await else {
                return;
            };
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event("withdraw", Some(operation_id), payload_json));
            }
        });
        Ok(())
    }
}

fn unified_event(
    topic: &str,
    operation_id: Option<OperationId>,
    payload_json: String,
) -> UnifiedCallbackEvent {
    UnifiedCallbackEvent {
        source: "fedimint-wallet-client".to_owned(),
        topic: topic.to_owned(),
        operation_id: operation_id.map(|id| id.fmt_full().to_string()),
        payload_json,
    }
}
