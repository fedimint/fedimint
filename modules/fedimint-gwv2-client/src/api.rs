use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, apply, async_trait_maybe_send};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::endpoint_constants::OUTGOING_CONTRACT_EXPIRATION_ENDPOINT;

#[apply(async_trait_maybe_send!)]
pub trait GatewayFederationApi {
    async fn outgoing_contract_expiration(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<(ContractId, u64)>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> GatewayFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn outgoing_contract_expiration(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<(ContractId, u64)>> {
        self.request_current_consensus(
            OUTGOING_CONTRACT_EXPIRATION_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoint),
        )
        .await
    }
}
