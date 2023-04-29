use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::{CurrentConsensus, UnionResponses};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};
use fedimint_dummy_common::DummyPrintMoneyRequest;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_DUMMY;

#[apply(async_trait_maybe_send!)]
pub trait DummyFederationApi {
    async fn print_money(&self, request: DummyPrintMoneyRequest) -> FederationResult<()>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> DummyFederationApi for T
    where
        T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn print_money(&self, request: DummyPrintMoneyRequest) -> FederationResult<()> {
        self.request_current_consensus(
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_DUMMY}_print_money"),
            ApiRequestErased::new(request),
        )
            .await
    }
}
