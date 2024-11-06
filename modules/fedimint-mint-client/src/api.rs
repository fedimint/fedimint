use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_mint_common::endpoint_constants::{BLIND_NONCE_USED_ENDPOINT, NOTE_SPENT_ENDPOINT};
use fedimint_mint_common::{BlindNonce, Nonce};

#[apply(async_trait_maybe_send!)]
pub trait MintFederationApi {
    /// Check if an e-cash  note was already issued for the given blind nonce.
    async fn check_blind_nonce_used(&self, blind_nonce: BlindNonce) -> FederationResult<bool>;

    /// Check if an e-cash note was already spent.
    async fn check_note_spent(&self, nonce: Nonce) -> FederationResult<bool>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> MintFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn check_blind_nonce_used(&self, blind_nonce: BlindNonce) -> FederationResult<bool> {
        self.request_current_consensus(
            BLIND_NONCE_USED_ENDPOINT.to_string(),
            ApiRequestErased::new(blind_nonce),
        )
        .await
    }

    async fn check_note_spent(&self, nonce: Nonce) -> FederationResult<bool> {
        self.request_current_consensus(
            NOTE_SPENT_ENDPOINT.to_string(),
            ApiRequestErased::new(nonce),
        )
        .await
    }
}
