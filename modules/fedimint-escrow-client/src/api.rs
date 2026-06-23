use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_escrow_common::{
    EscrowContract, GET_CONTRACT_ENDPOINT, GET_PENDING_ARBITER_FEE_ENDPOINT, GetContractParams,
    GetPendinFeeParams, LIST_CONTRACT_BY_KEY_ENDPOINT, ListContractParams, PendingArbiterFee,
};

#[apply(async_trait_maybe_send!)]
pub trait EscrowFederationApi {
    async fn get_contract(
        &self,
        params: GetContractParams,
    ) -> FederationResult<Option<EscrowContract>>;
    async fn get_pending_arbiter_fee(
        &self,
        params: GetPendinFeeParams,
    ) -> FederationResult<Option<PendingArbiterFee>>;
    async fn list_contracts_by_key(
        &self,
        params: ListContractParams,
    ) -> FederationResult<Vec<EscrowContract>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> EscrowFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn get_contract(
        &self,
        params: GetContractParams,
    ) -> FederationResult<Option<EscrowContract>> {
        self.request_current_consensus(
            GET_CONTRACT_ENDPOINT.to_string(),
            ApiRequestErased::new(params),
        )
        .await
    }

    async fn get_pending_arbiter_fee(
        &self,
        params: GetPendinFeeParams,
    ) -> FederationResult<Option<PendingArbiterFee>> {
        self.request_current_consensus(
            GET_PENDING_ARBITER_FEE_ENDPOINT.to_string(),
            ApiRequestErased::new(params),
        )
        .await
    }

    async fn list_contracts_by_key(
        &self,
        params: ListContractParams,
    ) -> FederationResult<Vec<EscrowContract>> {
        self.request_current_consensus(
            LIST_CONTRACT_BY_KEY_ENDPOINT.to_string(),
            ApiRequestErased::new(params),
        )
        .await
    }
}
