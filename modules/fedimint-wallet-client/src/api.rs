use bitcoin::Address;
use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::endpoint_constants::{BLOCK_COUNT_ENDPOINT, PEG_OUT_FEES_ENDPOINT};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_wallet_common::PegOutFees;

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64>;
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
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_current_consensus(
            PEG_OUT_FEES_ENDPOINT.to_string(),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }
}
