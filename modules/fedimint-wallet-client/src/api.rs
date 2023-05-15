use bitcoin::Address;
use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
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
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64> {
        // TODO: This is still necessary since the Lightning module also uses this
        // to query the block height. Modules should not be dependent on each other
        // so this should be refactored
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
            .request_with_strategy(
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
        self.request_eventually_consistent(
            "peg_out_fees".to_string(),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }
}
