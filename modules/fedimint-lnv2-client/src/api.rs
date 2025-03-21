use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi, PeerResult,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT,
    CONSENSUS_BLOCK_COUNT_ENDPOINT, GATEWAYS_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use rand::seq::SliceRandom;

#[apply(async_trait_maybe_send!)]
pub trait LightningFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(
        &self,
        contract_id: &ContractId,
        expiration: u64,
    ) -> Option<OutPoint>;

    async fn await_preimage(&self, contract_id: OutPoint, expiration: u64) -> Option<[u8; 32]>;

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>>;

    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;

    async fn remove_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LightningFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn await_incoming_contract(
        &self,
        contract_id: &ContractId,
        expiration: u64,
    ) -> Option<OutPoint> {
        self.request_current_consensus_retry::<Option<OutPoint>>(
            AWAIT_INCOMING_CONTRACT_ENDPOINT.to_string(),
            ApiRequestErased::new((contract_id, expiration)),
        )
        .await
    }

    async fn await_preimage(&self, outpoint: OutPoint, expiration: u64) -> Option<[u8; 32]> {
        self.request_current_consensus_retry(
            AWAIT_PREIMAGE_ENDPOINT.to_string(),
            ApiRequestErased::new((outpoint, expiration)),
        )
        .await
    }

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>> {
        let gateways: BTreeMap<PeerId, Vec<SafeUrl>> = self
            .request_with_strategy(
                FilterMapThreshold::new(
                    |_, gateways| Ok(gateways),
                    self.all_peers().to_num_peers(),
                ),
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        let mut union = gateways
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<SafeUrl>>()
            .into_iter()
            .collect::<Vec<SafeUrl>>();

        // Shuffling the gateways ensures that payments are distributed over the
        // gateways evenly.
        union.shuffle(&mut rand::thread_rng());

        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>> {
        let gateways = self
            .request_single_peer::<Vec<SafeUrl>>(
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
                peer,
            )
            .await?;

        Ok(gateways)
    }

    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool> {
        let is_new_entry: bool = self
            .request_admin(ADD_GATEWAY_ENDPOINT, ApiRequestErased::new(gateway), auth)
            .await?;

        Ok(is_new_entry)
    }

    async fn remove_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool> {
        let entry_existed: bool = self
            .request_admin(
                REMOVE_GATEWAY_ENDPOINT,
                ApiRequestErased::new(gateway),
                auth,
            )
            .await?;

        Ok(entry_existed)
    }
}
