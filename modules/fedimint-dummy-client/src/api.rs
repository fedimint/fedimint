use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::endpoint_constants::{SIGN_MESSAGE_ENDPOINT, WAIT_SIGNED_ENDPOINT};
use fedimint_core::epoch::SerdeSignature;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

#[apply(async_trait_maybe_send!)]
pub trait DummyFederationApi {
    async fn sign_message(&self, message: String) -> FederationResult<()>;

    async fn wait_signed(&self, message: String) -> FederationResult<SerdeSignature>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> DummyFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn sign_message(&self, message: String) -> FederationResult<()> {
        self.request_current_consensus(
            SIGN_MESSAGE_ENDPOINT.to_string(),
            ApiRequestErased::new(message),
        )
        .await
    }

    async fn wait_signed(&self, message: String) -> FederationResult<SerdeSignature> {
        self.request_current_consensus(
            WAIT_SIGNED_ENDPOINT.to_string(),
            ApiRequestErased::new(message),
        )
        .await
    }
}
