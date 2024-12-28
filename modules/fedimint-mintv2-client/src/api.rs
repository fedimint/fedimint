use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin_hashes::sha256;
use fedimint_api_client::api::{DynModuleApi, FederationApiExt, ServerError};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{NumPeersExt, OutPointRange, PeerId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::endpoint_constants::{
    RECOVERY_COUNT_ENDPOINT, RECOVERY_SLICE_ENDPOINT, RECOVERY_SLICE_HASH_ENDPOINT,
    SIGNATURE_SHARES_ENDPOINT, SIGNATURE_SHARES_RECOVERY_ENDPOINT,
};
use fedimint_mintv2_common::{Denomination, RecoveryItem};
use tbs::{BlindedMessage, BlindedSignatureShare, PublicKeyShare};

use crate::output::verify_blind_shares;
use crate::{NoteIssuanceRequest, issuance};

#[async_trait::async_trait]
pub trait MintV2ModuleApi {
    async fn fetch_signature_shares(
        &self,
        range: OutPointRange,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String>;

    async fn fetch_signature_shares_recovery(
        &self,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String>;

    async fn fetch_recovery_count(&self) -> anyhow::Result<u64>;

    async fn fetch_recovery_slice_hash(&self, start: u64, end: u64) -> sha256::Hash;

    async fn fetch_recovery_slice(
        &self,
        peer: PeerId,
        timeout: Duration,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<RecoveryItem>>;
}

#[async_trait::async_trait]
impl MintV2ModuleApi for DynModuleApi {
    async fn fetch_signature_shares(
        &self,
        range: OutPointRange,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String> {
        let shares = self
            .request_with_strategy_retry(
                // This query collects a threshold of 2f + 1 valid blind signature shares
                FilterMapThreshold::new(
                    move |peer, signature_shares| {
                        verify_blind_shares(
                            peer,
                            signature_shares,
                            &issuance_requests,
                            &tbs_pks,
                            &root_secret,
                        )
                        .map_err(ServerError::InvalidResponse)
                    },
                    self.all_peers().to_num_peers(),
                ),
                SIGNATURE_SHARES_ENDPOINT.to_owned(),
                ApiRequestErased::new(range),
            )
            .await;

        Ok(shares)
    }

    async fn fetch_signature_shares_recovery(
        &self,
        issuance_requests: Vec<NoteIssuanceRequest>,
        tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
        root_secret: DerivableSecret,
    ) -> Result<BTreeMap<PeerId, Vec<BlindedSignatureShare>>, String> {
        let blinded_messages: Vec<BlindedMessage> = issuance_requests
            .iter()
            .map(|req| {
                issuance::blinded_message(&issuance::output_secret(
                    req.denomination,
                    req.tweak,
                    &root_secret,
                ))
            })
            .collect();

        let shares = self
            .request_with_strategy_retry(
                // This query collects a threshold of 2f + 1 valid blind signature shares
                FilterMapThreshold::new(
                    move |peer, signature_shares| {
                        verify_blind_shares(
                            peer,
                            signature_shares,
                            &issuance_requests,
                            &tbs_pks,
                            &root_secret,
                        )
                        .map_err(ServerError::InvalidResponse)
                    },
                    self.all_peers().to_num_peers(),
                ),
                SIGNATURE_SHARES_RECOVERY_ENDPOINT.to_owned(),
                ApiRequestErased::new(blinded_messages),
            )
            .await;

        Ok(shares)
    }

    async fn fetch_recovery_count(&self) -> anyhow::Result<u64> {
        self.request_current_consensus::<u64>(
            RECOVERY_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
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
    ) -> anyhow::Result<Vec<RecoveryItem>> {
        let result = tokio::time::timeout(
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
