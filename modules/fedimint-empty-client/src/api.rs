use fedimint_core::api::IModuleFederationApi;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};

#[apply(async_trait_maybe_send!)]
pub trait DummyFederationApi {}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> DummyFederationApi for T where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static
{
}
