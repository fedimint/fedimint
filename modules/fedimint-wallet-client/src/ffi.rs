use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, OutPoint, Txid};
use fedimint_core::core::OperationId;
use fedimint_core::runtime;
use fedimint_core::util::ffi::UniffiError;
use fedimint_wallet_common::WalletSummary;
use futures::StreamExt as _;
use serde_json::Value;

use crate::{
    DepositStateV2, PegInRequest, PegInResponse, PegOutRequest, PegOutResponse, WalletClientModule,
    WithdrawState, anyhow,
};

type Result<T> = std::result::Result<T, UniffiError>;

/// `uniffi::custom_type!` only accepts a bare identifier for the custom type,
/// so the generic `Address<NetworkUnchecked>` needs a type alias.
type UncheckedAddress = Address<NetworkUnchecked>;

uniffi::custom_type!(UncheckedAddress, String, {
    remote,
    lower: |address| address.assume_checked().to_string(),
    try_lift: |s| UncheckedAddress::from_str(&s).map_err(|e| anyhow!("Failed to parse Address: {e}")),
});

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Value, String, {
    remote,
    lower: |v| serde_json::to_string(&v).expect("Value serialization cannot fail"),
    try_lift: |s| serde_json::from_str::<Value>(&s).map_err(|e| anyhow!("Failed to parse Value: {e}")),
});

uniffi::use_remote_type!(fedimint_wallet_common::OutPoint);

uniffi::use_remote_type!(fedimint_wallet_common::Amount);

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Txid, String, {
    remote,
    lower: |txid| txid.to_string(),
    try_lift: |s| Txid::from_str(&s).map_err(|e| anyhow!("Failed to parse Txid: {e}")),
});

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

    /// Subscribe to state updates for a deposit operation.
    #[uniffi::method(name = "subscribe_deposit")]
    pub async fn subscribe_deposit_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn DepositStateCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let wallet = client_ctx.self_ref();
        let updates = wallet.subscribe_deposit(operation_id).await?;
        runtime::spawn("uniffi-subscribe-deposit", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                callback.on_state(operation_id, state);
            }
        });
        Ok(())
    }

    /// Subscribe to state updates for a withdraw operation.
    #[uniffi::method(name = "subscribe_withdraw")]
    pub async fn subscribe_withdraw_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn WithdrawStateCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let wallet = client_ctx.self_ref();
        let updates = wallet.subscribe_withdraw_updates(operation_id).await?;
        runtime::spawn("uniffi-subscribe-withdraw", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                callback.on_state(operation_id, state);
            }
        });
        Ok(())
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export(callback_interface)]
pub trait DepositStateCallback: Send + Sync {
    fn on_state(&self, operation_id: OperationId, state: DepositStateV2);
}

#[cfg(feature = "uniffi")]
#[uniffi::export(callback_interface)]
pub trait WithdrawStateCallback: Send + Sync {
    fn on_state(&self, operation_id: OperationId, state: WithdrawState);
}
