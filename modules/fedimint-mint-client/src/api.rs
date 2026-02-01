use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncodingBase64};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, PeerId, apply, async_trait_maybe_send};
use fedimint_mint_common::endpoint_constants::{
    BLIND_NONCE_USED_ENDPOINT, NOTE_SPENT_ENDPOINT, RECOVERY_BLIND_NONCE_OUTPOINTS_ENDPOINT,
    RECOVERY_COUNT_ENDPOINT, RECOVERY_SLICE_ENDPOINT, RECOVERY_SLICE_HASH_ENDPOINT,
};
use fedimint_mint_common::{BlindNonce, Nonce, RecoveryItem};

#[apply(async_trait_maybe_send!)]
pub trait MintFederationApi {
    async fn check_blind_nonce_used(&self, blind_nonce: BlindNonce) -> FederationResult<bool>;

    async fn check_note_spent(&self, nonce: Nonce) -> FederationResult<bool>;

    /// Returns the total number of recovery items stored on the federation.
    async fn fetch_recovery_count(&self) -> anyhow::Result<u64>;

    /// Returns the consensus hash of recovery items in the range `[start,
    /// end)`.
    async fn fetch_recovery_slice_hash(&self, start: u64, end: u64) -> sha256::Hash;

    /// Fetches recovery items in the range `[start, end)` from a specific peer.
    async fn fetch_recovery_slice(
        &self,
        peer: PeerId,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<RecoveryItem>>;

    /// Returns the outpoints where the given blind nonces were used.
    async fn fetch_blind_nonce_outpoints(
        &self,
        blind_nonces: Vec<BlindNonce>,
    ) -> anyhow::Result<Vec<OutPoint>>;
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

    async fn fetch_recovery_count(&self) -> anyhow::Result<u64> {
        self.request_current_consensus::<u64>(
            RECOVERY_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn fetch_recovery_slice_hash(&self, start: u64, end: u64) -> sha256::Hash {
        self.request_current_consensus_retry(
            RECOVERY_SLICE_HASH_ENDPOINT.to_owned(),
            ApiRequestErased::new((start, end)),
        )
        .await
    }

    async fn fetch_recovery_slice(
        &self,
        peer: PeerId,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<RecoveryItem>> {
        let result = self
            .request_single_peer::<SerdeModuleEncodingBase64<Vec<RecoveryItem>>>(
                RECOVERY_SLICE_ENDPOINT.to_owned(),
                ApiRequestErased::new((start, end)),
                peer,
            )
            .await?;

        Ok(result.try_into_inner(&ModuleRegistry::default())?)
    }

    async fn fetch_blind_nonce_outpoints(
        &self,
        blind_nonces: Vec<BlindNonce>,
    ) -> anyhow::Result<Vec<OutPoint>> {
        self.request_current_consensus::<Vec<OutPoint>>(
            RECOVERY_BLIND_NONCE_OUTPOINTS_ENDPOINT.to_string(),
            ApiRequestErased::new(blind_nonces),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
    }
}
