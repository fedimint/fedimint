use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi, ServerResult,
};
#[cfg(feature = "cli")]
use fedimint_core::module::ApiAuth;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::runtime::{Duration, Instant, timeout};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::contracts::IncomingContract;
#[cfg(feature = "cli")]
use fedimint_lnv2_common::endpoint_constants::{ADD_GATEWAY_ENDPOINT, REMOVE_GATEWAY_ENDPOINT};
use fedimint_lnv2_common::endpoint_constants::{
    AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_INCOMING_CONTRACTS_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT,
    CONSENSUS_BLOCK_COUNT_ENDPOINT, GATEWAYS_ENDPOINT, OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use rand::seq::SliceRandom;

#[cfg(test)]
mod tests;

/// How long [`LightningFederationApi::gateways`] keeps waiting for a threshold
/// of guardians to answer once the first guardian has answered.
///
/// Waiting for more answers lets gateways listed by many guardians be ranked
/// above a gateway listed only by the guardian that happened to answer first,
/// while the bound keeps unreachable or failing guardians from stalling
/// gateway selection.
pub const GATEWAYS_GRACE_PERIOD: Duration = Duration::from_secs(5);

#[apply(async_trait_maybe_send!)]
pub trait LightningFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(
        &self,
        contract_id: &ContractId,
        expiration: u64,
    ) -> Option<OutPoint>;

    async fn await_preimage(&self, contract_id: OutPoint, expiration: u64) -> Option<[u8; 32]>;

    async fn await_incoming_contracts(&self, start: u64, n: usize) -> (Vec<IncomingContract>, u64);

    async fn outgoing_contract_expiration(
        &self,
        outpoint: OutPoint,
    ) -> FederationResult<Option<(ContractId, u64)>>;

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>>;

    #[cfg(feature = "cli")]
    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;

    #[cfg(feature = "cli")]
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

    async fn await_incoming_contracts(&self, start: u64, n: usize) -> (Vec<IncomingContract>, u64) {
        self.request_current_consensus_retry(
            AWAIT_INCOMING_CONTRACTS_ENDPOINT.to_string(),
            ApiRequestErased::new((start, n)),
        )
        .await
    }

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

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>> {
        // Unlike `request_with_strategy` this does not give up once `f + 1`
        // guardians have failed: any guardian's list is usable, so the query
        // only fails if every guardian failed.
        let mut requests = self
            .all_peers()
            .iter()
            .map(|peer| async move {
                let response = self
                    .request_single_peer::<Vec<SafeUrl>>(
                        GATEWAYS_ENDPOINT.to_string(),
                        ApiRequestErased::default(),
                        *peer,
                    )
                    .await;

                (*peer, response)
            })
            .collect::<FuturesUnordered<_>>();

        let threshold = self.all_peers().to_num_peers().threshold();
        let mut gateways = BTreeMap::new();
        let mut peer_errors = BTreeMap::new();
        // Starts with the first answer; until then we wait for as long as
        // some guardian may still answer.
        let mut deadline = None;

        while gateways.len() < threshold {
            let next = match deadline {
                Some(deadline) => {
                    match timeout(
                        Instant::saturating_duration_since(&deadline, Instant::now()),
                        requests.next(),
                    )
                    .await
                    {
                        Ok(next) => next,
                        Err(_elapsed) => break,
                    }
                }
                None => requests.next().await,
            };

            let Some((peer, response)) = next else {
                break;
            };

            match response {
                Ok(response) => {
                    gateways.insert(peer, response);

                    deadline.get_or_insert_with(|| Instant::now() + GATEWAYS_GRACE_PERIOD);
                }
                Err(e) => {
                    e.report_if_unusual(peer, "Gateways");

                    peer_errors.insert(peer, e);
                }
            }
        }

        if gateways.is_empty() {
            return Err(FederationError::peer_errors(
                GATEWAYS_ENDPOINT,
                (),
                peer_errors,
            ));
        }

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

        // Gateways listed by more guardians come first, so a gateway listed by
        // a single guardian does not take precedence over the ones the other
        // guardians agree on.
        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>> {
        let gateways = self
            .request_single_peer::<Vec<SafeUrl>>(
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
                peer,
            )
            .await?;

        Ok(gateways)
    }

    #[cfg(feature = "cli")]
    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool> {
        let is_new_entry: bool = self
            .request_admin(ADD_GATEWAY_ENDPOINT, ApiRequestErased::new(gateway), auth)
            .await?;

        Ok(is_new_entry)
    }

    #[cfg(feature = "cli")]
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
