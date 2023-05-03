use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_dummy_common::DummyPrintMoneyRequest;
use secp256k1::XOnlyPublicKey;

#[apply(async_trait_maybe_send!)]
pub trait DummyFederationApi {
    async fn print_money(&self, request: DummyPrintMoneyRequest) -> FederationResult<()>;

    async fn wait_for_money(&self, account: XOnlyPublicKey) -> FederationResult<Amount>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> DummyFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn print_money(&self, request: DummyPrintMoneyRequest) -> FederationResult<()> {
        self.request_current_consensus("print_money".to_string(), ApiRequestErased::new(request))
            .await
    }

    async fn wait_for_money(&self, account: XOnlyPublicKey) -> FederationResult<Amount> {
        self.request_current_consensus("wait_for_money".to_string(), ApiRequestErased::new(account))
            .await
    }
}
