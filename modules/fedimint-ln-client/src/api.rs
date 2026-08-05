use std::collections::{BTreeMap, HashMap};
use std::convert::identity;
use std::time::Duration;

use anyhow::anyhow;
use bitcoin::hashes::sha256::{self, Hash as Sha256Hash};
use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi, ServerError,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::{MaybeSend, MaybeSync, timeout};
use fedimint_core::{NumPeersExt, PeerId, apply, async_trait_maybe_send};
use fedimint_ln_common::contracts::incoming::{IncomingContractAccount, IncomingContractOffer};
use fedimint_ln_common::contracts::{ContractId, DecryptedPreimageStatus, Preimage};
use fedimint_ln_common::federation_endpoint_constants::{
    ACCOUNT_ENDPOINT, AWAIT_ACCOUNT_ENDPOINT, AWAIT_BLOCK_HEIGHT_ENDPOINT, AWAIT_OFFER_ENDPOINT,
    AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT, AWAIT_PREIMAGE_DECRYPTION, BLOCK_COUNT_ENDPOINT,
    GET_DECRYPTED_PREIMAGE_STATUS, LIST_GATEWAYS_ENDPOINT, OFFER_ENDPOINT,
    REGISTER_GATEWAY_ENDPOINT, REMOVE_GATEWAY_CHALLENGE_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_ln_common::{
    ContractAccount, FederationPublicKey, LightningGateway, LightningGatewayAnnouncement,
    RemoveGatewayRequest,
};
use itertools::Itertools;
use tracing::{info, warn};

#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    async fn fetch_consensus_block_count(&self) -> FederationResult<Option<u64>>;

    async fn fetch_contract(
        &self,
        contract: ContractId,
    ) -> FederationResult<Option<ContractAccount>>;

    async fn await_contract(&self, contract: ContractId) -> ContractAccount;

    async fn wait_block_height(&self, block_height: u64);

    async fn wait_outgoing_contract_cancelled(
        &self,
        contract: ContractId,
    ) -> FederationResult<ContractAccount>;

    async fn get_decrypted_preimage_status(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, DecryptedPreimageStatus)>;

    async fn wait_preimage_decrypted(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, Option<Preimage>)>;

    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer>;

    /// `federation_public_key` is needed to check registration proofs, which
    /// has to happen before signed announcements are preferred over unsigned
    /// ones — see
    /// [`LightningGatewayAnnouncement::registration_proof_is_valid`].
    async fn fetch_gateways(
        &self,
        federation_public_key: FederationPublicKey,
    ) -> FederationResult<Vec<LightningGatewayAnnouncement>>;

    async fn register_gateway(
        &self,
        gateway: &LightningGatewayAnnouncement,
    ) -> FederationResult<()>;

    /// Retrieves the map of gateway remove challenges from the server. Each
    /// challenge needs to be signed by the gateway's private key in order
    /// for the registration record to be removed.
    async fn get_remove_gateway_challenge(
        &self,
        gateway_id: PublicKey,
    ) -> BTreeMap<PeerId, Option<sha256::Hash>>;

    /// Removes the gateway's registration record. First checks the provided
    /// signature to verify the gateway authorized the removal of the
    /// registration.
    async fn remove_gateway(&self, remove_gateway_request: RemoveGatewayRequest);

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_count(&self) -> FederationResult<Option<u64>> {
        self.request_current_consensus(
            BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_contract(
        &self,
        contract: ContractId,
    ) -> FederationResult<Option<ContractAccount>> {
        self.request_current_consensus(
            ACCOUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn await_contract(&self, contract: ContractId) -> ContractAccount {
        self.request_current_consensus_retry(
            AWAIT_ACCOUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn wait_block_height(&self, block_height: u64) {
        self.request_current_consensus_retry::<()>(
            AWAIT_BLOCK_HEIGHT_ENDPOINT.to_string(),
            ApiRequestErased::new(block_height),
        )
        .await;
    }

    async fn wait_outgoing_contract_cancelled(
        &self,
        contract: ContractId,
    ) -> FederationResult<ContractAccount> {
        self.request_current_consensus(
            AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn get_decrypted_preimage_status(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, DecryptedPreimageStatus)> {
        self.request_current_consensus(
            GET_DECRYPTED_PREIMAGE_STATUS.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn wait_preimage_decrypted(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, Option<Preimage>)> {
        self.request_current_consensus(
            AWAIT_PREIMAGE_DECRYPTION.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.request_current_consensus(
            AWAIT_OFFER_ENDPOINT.to_string(),
            ApiRequestErased::new(payment_hash),
        )
        .await
    }

    /// There is no consensus within Fedimint on the gateways, each guardian
    /// might be aware of different ones, so we just return the union of all
    /// responses and allow client selection.
    async fn fetch_gateways(
        &self,
        federation_public_key: FederationPublicKey,
    ) -> FederationResult<Vec<LightningGatewayAnnouncement>> {
        let gateway_announcements = self
            .request_with_strategy(
                FilterMapThreshold::new(
                    |_, gateways| Ok(gateways),
                    self.all_peers().to_num_peers(),
                ),
                LIST_GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        // Filter out duplicate gateways so that we don't have to deal with
        // multiple guardians having different TTLs for the same gateway.
        Ok(filter_duplicate_gateways(
            &gateway_announcements,
            federation_public_key,
        ))
    }

    async fn register_gateway(
        &self,
        gateway: &LightningGatewayAnnouncement,
    ) -> FederationResult<()> {
        self.request_current_consensus(
            REGISTER_GATEWAY_ENDPOINT.to_string(),
            ApiRequestErased::new(gateway),
        )
        .await
    }

    async fn get_remove_gateway_challenge(
        &self,
        gateway_id: PublicKey,
    ) -> BTreeMap<PeerId, Option<sha256::Hash>> {
        let mut responses = BTreeMap::new();

        for peer in self.all_peers() {
            // Only wait a second since removing a gateway is "best effort"
            if let Ok(response) = timeout(
                Duration::from_secs(1),
                self.request_single_peer::<Option<sha256::Hash>>(
                    REMOVE_GATEWAY_CHALLENGE_ENDPOINT.to_string(),
                    ApiRequestErased::new(gateway_id),
                    *peer,
                ),
            )
            .await
            .map_err(|e| ServerError::Transport(anyhow!("Request timed out: {e}")))
            .and_then(identity)
            {
                responses.insert(*peer, response);
            }
        }

        responses
    }

    async fn remove_gateway(&self, remove_gateway_request: RemoveGatewayRequest) {
        let gateway_id = remove_gateway_request.gateway_id;

        for peer in self.all_peers() {
            // Only wait a second since removing a gateway is "best effort"
            if let Ok(response) = timeout(
                Duration::from_secs(1),
                self.request_single_peer::<bool>(
                    REMOVE_GATEWAY_ENDPOINT.to_string(),
                    ApiRequestErased::new(remove_gateway_request.clone()),
                    *peer,
                ),
            )
            .await
            .map_err(|e| ServerError::Transport(anyhow!("Request timed out: {e}")))
            .and_then(identity)
            {
                if response {
                    info!("Successfully removed {gateway_id} gateway from peer: {peer}",);
                } else {
                    warn!("Unable to remove gateway {gateway_id} registration from peer: {peer}");
                }
            }
        }
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        Ok(self
            .request_current_consensus::<Option<IncomingContractOffer>>(
                OFFER_ENDPOINT.to_string(),
                ApiRequestErased::new(payment_hash),
            )
            .await?
            .is_some())
    }
}

/// Filter out duplicate gateways. This is necessary because different guardians
/// may have different TTLs for the same gateway, so two
/// `LightningGatewayAnnouncement`s representing the same gateway registration
/// may not be equal.
fn filter_duplicate_gateways(
    gateways: &BTreeMap<PeerId, Vec<LightningGatewayAnnouncement>>,
    federation_public_key: FederationPublicKey,
) -> Vec<LightningGatewayAnnouncement> {
    let gateways_by_gateway_id = gateways
        .values()
        .flatten()
        // Drop forged proofs here, before the preference below acts on them.
        // Otherwise one peer could attach a garbage signature to another
        // gateway's id, evict every honest unsigned announcement for it, and
        // have its own forgery discarded later — removing the gateway entirely.
        .filter(|announcement| announcement.registration_proof_is_valid(federation_public_key))
        .cloned()
        .map(|announcement| (announcement.info.gateway_id, announcement))
        .into_group_map();

    // For each gateway, we may have multiple announcements with different settings
    // and/or TTLs. We want to filter out duplicates in a way that doesn't allow a
    // malicious guardian to override the caller's view of the gateways by
    // returning a gateway with a shorter TTL. Instead, if we receive multiple
    // announcements for the same gateway ID, we only filter out announcements
    // that have the same settings, keeping the one with the longest TTL.
    gateways_by_gateway_id
        .into_values()
        .flat_map(|mut announcements| {
            // Guardians that predate registration proofs cannot reject an
            // unsigned registration overwriting a signed one, so while a
            // federation is mid-upgrade its peers can disagree about a gateway.
            // Trust the peers that have a proof: only the gateway itself can
            // produce one, whereas anyone at all can publish an unsigned
            // announcement.
            if announcements.iter().any(|ann| ann.auth.is_some()) {
                announcements.retain(|ann| ann.auth.is_some());
            }

            let mut gateways: HashMap<LightningGateway, LightningGatewayAnnouncement> =
                HashMap::new();
            for announcement in announcements {
                gateways
                    .entry(announcement.info.clone())
                    .and_modify(|existing| {
                        // Only replace if the TTL is longer than the one we already have
                        if announcement.ttl > existing.ttl {
                            existing.ttl = announcement.ttl;
                        }
                        // Keep the freshest proof, so a replayed older one cannot
                        // displace it.
                        let nonce = |ann: &LightningGatewayAnnouncement| {
                            ann.auth.as_ref().map_or(0, |auth| auth.nonce)
                        };
                        if nonce(&announcement) > nonce(existing) {
                            existing.auth.clone_from(&announcement.auth);
                        }
                    })
                    .or_insert(LightningGatewayAnnouncement {
                        vetted: false,
                        ..announcement
                    });
            }

            gateways.into_values()
        })
        .collect()
}
