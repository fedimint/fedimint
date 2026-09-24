use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin_hashes::sha256;
use fedimint_api_client::api::{DynModuleApi, FederationApiExt, FederationResult, ServerError};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{NumPeersExt, OutPointRange, PeerId, apply, async_trait_maybe_send, runtime};
use fedimint_mintv2_common::endpoint_constants::{
    RECOVERY_COUNT_ENDPOINT, RECOVERY_SLICE_ENDPOINT, RECOVERY_SLICE_HASH_ENDPOINT,
    SIGNATURE_SHARES_ENDPOINT, SIGNATURE_SHARES_RECOVERY_ENDPOINT,
};
use fedimint_mintv2_common::{Denomination, RecoveryItem};
use tbs::{BlindedMessage, BlindedSignatureShare, PublicKeyShare};

use crate::NoteIssuanceRequest;
use crate::output::verify_blind_shares;

#[apply(async_trait_maybe_send!)]
pub trait MintV2ModuleApi {
    async fn fetch_signature_shares(
        &self,
        range: OutPointRange,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    ) -> BTreeMap<PeerId, Vec<BlindedSignatureShare>>;

    async fn fetch_signature_shares_recovery(
        &self,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    ) -> BTreeMap<PeerId, Vec<BlindedSignatureShare>>;

    async fn fetch_recovery_count(&self) -> FederationResult<u64>;

    async fn fetch_recovery_slice_hash(&self, start: u64, end: u64) -> sha256::Hash;

    async fn fetch_recovery_slice(
        &self,
        peer: PeerId,
        timeout: Duration,
        start: u64,
        end: u64,
    ) -> Result<Vec<RecoveryItem>, FetchRecoverySliceError>;
}

#[apply(async_trait_maybe_send!)]
impl MintV2ModuleApi for DynModuleApi {
    async fn fetch_signature_shares(
        &self,
        range: OutPointRange,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    ) -> BTreeMap<PeerId, Vec<BlindedSignatureShare>> {
        self.request_with_strategy_retry(
            // This query collects a threshold of 2f + 1 valid blind signature shares
            FilterMapThreshold::new(
                move |peer, signature_shares| {
                    verify_blind_shares(peer, signature_shares, &issuance_requests, &tbs_pks)
                        .map_err(|err| ServerError::InvalidResponse(err.fmt_compact().to_string()))
                },
                self.all_peers().to_num_peers(),
            ),
            SIGNATURE_SHARES_ENDPOINT.to_owned(),
            ApiRequestErased::new(range),
        )
        .await
    }

    async fn fetch_signature_shares_recovery(
        &self,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    ) -> BTreeMap<PeerId, Vec<BlindedSignatureShare>> {
        let blinded_messages: Vec<BlindedMessage> = issuance_requests
            .iter()
            .map(NoteIssuanceRequest::blinded_message)
            .collect();

        self.request_with_strategy_retry(
            // This query collects a threshold of 2f + 1 valid blind signature shares
            FilterMapThreshold::new(
                move |peer, signature_shares| {
                    verify_blind_shares(peer, signature_shares, &issuance_requests, &tbs_pks)
                        .map_err(|err| ServerError::InvalidResponse(err.fmt_compact().to_string()))
                },
                self.all_peers().to_num_peers(),
            ),
            SIGNATURE_SHARES_RECOVERY_ENDPOINT.to_owned(),
            ApiRequestErased::new(blinded_messages),
        )
        .await
    }

    async fn fetch_recovery_count(&self) -> FederationResult<u64> {
        self.request_current_consensus::<u64>(
            RECOVERY_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
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
        timeout: Duration,
        start: u64,
        end: u64,
    ) -> Result<Vec<RecoveryItem>, FetchRecoverySliceError> {
        let result = runtime::timeout(
            timeout,
            self.request_single_peer::<Vec<RecoveryItem>>(
                RECOVERY_SLICE_ENDPOINT.to_owned(),
                ApiRequestErased::new((start, end)),
                peer,
            ),
        )
        .await??;

        Ok(result)
    }
}

/// Why a guardian did not serve a slice of the recovery log.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchRecoverySliceError {
    /// The guardian did not answer in time.
    #[error(transparent)]
    Timeout(#[from] runtime::Elapsed),

    /// The guardian answered with an error.
    #[error(transparent)]
    Peer(#[from] ServerError),
}
