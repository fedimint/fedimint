use bitcoin::Address;
use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::EventuallyConsistent;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};
use fedimint_wallet_common::PegOutFees;

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64>;
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            "block_height".to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().threshold()),
            "peg_out_fees".to_string(),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }
}
