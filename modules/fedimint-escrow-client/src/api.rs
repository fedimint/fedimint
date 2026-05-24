use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::{ApiRequestErased};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_escrow_common::{EscrowContract, EscrowId, GET_CONTRACT_ENDPOINT};

#[apply(async_trait_maybe_send!)]
pub trait EscrowFederationApi {
    async fn get_contract(
        &self,
        escrow_id: EscrowId,
    ) -> FederationResult<Option<EscrowContract>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> EscrowFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn get_contract(
        &self,
        escrow_id: EscrowId,
    ) -> FederationResult<Option<EscrowContract>> {
        self.request_current_consensus(
            GET_CONTRACT_ENDPOINT.to_string(),
            ApiRequestErased::new(escrow_id),
        )
        .await
    }
}