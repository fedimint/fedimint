use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_api_client::api::{
    CallResultExt as _, FederationApiExt, FederationResult, IModuleFederationApi,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{sleep, MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, NumPeers, NumPeersExt, PeerId};
use fedimint_lnv2_common::endpoint_constants::{
    AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT, CONSENSUS_BLOCK_COUNT_ENDPOINT,
    GATEWAYS_ENDPOINT, OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
};
use fedimint_lnv2_common::ContractId;
use itertools::Itertools;

const RETRY_DELAY: Duration = Duration::from_secs(1);

#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool;

    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]>;

    async fn outgoing_contract_expiration(
        &self,
        contract_id: &ContractId,
    ) -> FederationResult<Option<u64>>;

    async fn fetch_gateways(&self) -> FederationResult<Vec<SafeUrl>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
        .flatten()
    }

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool {
        loop {
            match self
                .request_current_consensus::<Option<ContractId>>(
                    AWAIT_INCOMING_CONTRACT_ENDPOINT.to_string(),
                    ApiRequestErased::new((contract_id, expiration)),
                )
                .await
                .flatten()
            {
                Ok(response) => return response.is_some(),
                Err(error) => error.report_if_important(),
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]> {
        loop {
            match self
                .request_current_consensus(
                    AWAIT_PREIMAGE_ENDPOINT.to_string(),
                    ApiRequestErased::new((contract_id, expiration)),
                )
                .await
                .flatten()
            {
                Ok(expiration) => return expiration,
                Err(error) => error.report_if_important(),
            }

            sleep(RETRY_DELAY).await;
        }
    }

    async fn outgoing_contract_expiration(
        &self,
        contract_id: &ContractId,
    ) -> FederationResult<Option<u64>> {
        self.request_current_consensus(
            OUTGOING_CONTRACT_EXPIRATION_ENDPOINT.to_string(),
            ApiRequestErased::new(contract_id),
        )
        .await
        .flatten()
    }

    async fn fetch_gateways(&self) -> FederationResult<Vec<SafeUrl>> {
        let gateways: BTreeMap<PeerId, Vec<SafeUrl>> = self
            .request_with_strategy(
                FilterMapThreshold::new(
                    |_, gateways| Ok(gateways?),
                    NumPeers::from(self.all_peers().total()),
                ),
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        let mut union = gateways
            .values()
            .flatten()
            .dedup()
            .cloned()
            .collect::<Vec<SafeUrl>>();

        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }
}
