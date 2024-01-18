#![warn(missing_docs)]
use std::collections::HashMap;
use std::time::Duration;

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi,
};
use fedimint_core::endpoint_constants::{
    ACCOUNT_ENDPOINT, AWAIT_ACCOUNT_ENDPOINT, AWAIT_BLOCK_HEIGHT_ENDPOINT, AWAIT_OFFER_ENDPOINT,
    AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT, AWAIT_PREIMAGE_DECRYPTION, BLOCK_COUNT_ENDPOINT,
    GET_DECRYPTED_PREIMAGE_STATUS, LIST_GATEWAYS_ENDPOINT, OFFER_ENDPOINT,
    REGISTER_GATEWAY_ENDPOINT,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::UnionResponses;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};
use itertools::Itertools;

use crate::contracts::incoming::{IncomingContractAccount, IncomingContractOffer};
use crate::contracts::outgoing::OutgoingContractAccount;
use crate::contracts::{ContractId, DecryptedPreimageStatus, FundedContract, Preimage};
use crate::{ContractAccount, LightningGateway, LightningGatewayAnnouncement};

/// Trait defining all JSON-RPC commands that can be made to lightning module
/// RPC server
#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    /// Fetch consensus block height of lightning module
    async fn fetch_consensus_block_count(&self) -> FederationResult<Option<u64>>;
    /// Fetch a lightning module [`ContractAccount`] by ID
    async fn fetch_contract(
        &self,
        contract: ContractId,
    ) -> FederationResult<Option<ContractAccount>>;
    /// Await fedration consensus on a lightning module [`ContractAccount`]
    async fn wait_contract(&self, contract: ContractId) -> FederationResult<ContractAccount>;
    /// Wait for a consensus block height to be reached
    async fn wait_block_height(&self, block_height: u64) -> FederationResult<()>;
    /// Wait for the lightning gateway to successfully user client escrow
    /// contract for failed outgoing payment
    async fn wait_outgoing_contract_cancelled(
        &self,
        contract: ContractId,
    ) -> FederationResult<ContractAccount>;
    /// Check whether a threshold-decrypted preimage has been decrypted, is
    /// being decrypted, or hasn't started decryption yet.
    async fn get_decrypted_preimage_status(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, DecryptedPreimageStatus)>;
    /// Waits for preimage decryption to complete
    async fn wait_preimage_decrypted(
        &self,
        contract: ContractId,
    ) -> FederationResult<(IncomingContractAccount, Option<Preimage>)>;
    /// Fetch an [`IncomingContractOffer`]
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer>;
    /// Fetch set of all lightning gateways who have registered with any
    /// guardian in the federation
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGatewayAnnouncement>>;
    /// Register a lightning gateway with each guardian in the federation
    async fn register_gateway(
        &self,
        gateway: &LightningGatewayAnnouncement,
    ) -> FederationResult<()>;
    /// Check whether [`IncomingContractOffer`] exists
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool>;
    /// Fetch [`IncomingContractAccount`] for a given contract ID
    async fn get_incoming_contract(
        &self,
        id: ContractId,
    ) -> FederationResult<IncomingContractAccount>;
    /// Fetch [`OutgoingContractAccount`] for a given contract ID
    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> FederationResult<OutgoingContractAccount>;
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

    async fn wait_contract(&self, contract: ContractId) -> FederationResult<ContractAccount> {
        self.request_current_consensus(
            AWAIT_ACCOUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(contract),
        )
        .await
    }

    async fn wait_block_height(&self, block_height: u64) -> FederationResult<()> {
        self.request_current_consensus(
            AWAIT_BLOCK_HEIGHT_ENDPOINT.to_string(),
            ApiRequestErased::new(block_height),
        )
        .await
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
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGatewayAnnouncement>> {
        let gateway_announcements: Vec<LightningGatewayAnnouncement> = self
            .request_with_strategy(
                UnionResponses::new(self.all_peers().total()),
                LIST_GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        // Filter out duplicate gateways so that we don't have to deal with
        // multiple guardians having different TTLs for the same gateway.
        Ok(filter_duplicate_gateways(gateway_announcements))
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

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        Ok(self
            .request_current_consensus::<Option<IncomingContractOffer>>(
                OFFER_ENDPOINT.to_string(),
                ApiRequestErased::new(payment_hash),
            )
            .await?
            .is_some())
    }

    async fn get_incoming_contract(
        &self,
        id: ContractId,
    ) -> FederationResult<IncomingContractAccount> {
        let account = self.wait_contract(id).await?;
        match account.contract {
            FundedContract::Incoming(c) => Ok(IncomingContractAccount {
                amount: account.amount,
                contract: c.contract,
            }),
            _ => Err(FederationError::general(anyhow::anyhow!(
                "WrongAccountType"
            ))),
        }
    }

    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> FederationResult<OutgoingContractAccount> {
        let account = self.wait_contract(id).await?;
        match account.contract {
            FundedContract::Outgoing(c) => Ok(OutgoingContractAccount {
                amount: account.amount,
                contract: c,
            }),
            _ => Err(FederationError::general(anyhow::anyhow!(
                "WrongAccountType"
            ))),
        }
    }
}

/// Filter out duplicate gateways. This is necessary because different guardians
/// may have different TTLs for the same gateway, so two
/// `LightningGatewayAnnouncement`s representing the same gateway registration
/// may not be equal.
fn filter_duplicate_gateways(
    gateways: Vec<LightningGatewayAnnouncement>,
) -> Vec<LightningGatewayAnnouncement> {
    let gateways_by_gateway_id = gateways
        .into_iter()
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
        .flat_map(|announcements| {
            let mut gateways: HashMap<LightningGateway, Duration> = HashMap::new();
            for announcement in announcements {
                let ttl = announcement.ttl;
                let gateway = announcement.info.clone();
                // Only insert if the TTL is longer than the one we already have
                gateways
                    .entry(gateway)
                    .and_modify(|t| {
                        if ttl > *t {
                            *t = ttl;
                        }
                    })
                    .or_insert(ttl);
            }

            gateways
                .into_iter()
                .map(|(gateway, ttl)| LightningGatewayAnnouncement {
                    info: gateway,
                    ttl,
                    vetted: false,
                })
        })
        .collect()
}
