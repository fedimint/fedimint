use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::secp256k1;
use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi, PeerResult,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::config::FederationId;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{sleep, MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount, NumPeersExt, PeerId};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT,
    CONSENSUS_BLOCK_HEIGHT_ENDPOINT, CREATE_BOLT11_INVOICE_ENDPOINT, GATEWAYS_ENDPOINT,
    OUTGOING_CONTRACT_EXPIRATION_ENDPOINT, REMOVE_GATEWAY_ENDPOINT, ROUTING_INFO_ENDPOINT,
    SEND_PAYMENT_ENDPOINT,
};
use fedimint_lnv2_common::ContractId;
use itertools::Itertools;
use lightning_invoice::Bolt11Invoice;
use secp256k1::schnorr::Signature;

use crate::{
    Bolt11InvoiceDescription, CreateBolt11InvoicePayload, GatewayConnectionError, LightningInvoice,
    RoutingInfo, SendPaymentPayload,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);

#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    async fn consensus_block_height(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool;

    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]>;

    async fn outgoing_contract_expiration(
        &self,
        contract_id: &ContractId,
    ) -> FederationResult<Option<u64>>;

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>>;

    async fn add_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;

    async fn remove_gateway(&self, auth: ApiAuth, gateway: SafeUrl) -> FederationResult<bool>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_height(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_HEIGHT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool {
        loop {
            match self
                .request_current_consensus::<Option<ContractId>>(
                    AWAIT_INCOMING_CONTRACT_ENDPOINT.to_string(),
                    ApiRequestErased::new((contract_id, expiration)),
                )
                .await
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

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>> {
        let gateways = self
            .request_single_peer_typed::<Vec<SafeUrl>>(
                None,
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

#[apply(async_trait_maybe_send!)]
pub trait GatewayConnection: std::fmt::Debug {
    async fn routing_info(
        &self,
        gateway_api: SafeUrl,
        federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, GatewayConnectionError>;

    async fn bolt11_invoice(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: IncomingContract,
        invoice_amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_time: u32,
    ) -> Result<Bolt11Invoice, GatewayConnectionError>;

    async fn send_payment(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, GatewayConnectionError>;
}

#[derive(Debug)]
pub struct RealGatewayConnection;

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for RealGatewayConnection {
    async fn routing_info(
        &self,
        gateway_api: SafeUrl,
        federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, GatewayConnectionError> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join(ROUTING_INFO_ENDPOINT)
                    .expect("'routing_info' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(federation_id)
            .send()
            .await
            .map_err(|e| GatewayConnectionError::Unreachable(e.to_string()))?
            .json::<Option<RoutingInfo>>()
            .await
            .map_err(|e| GatewayConnectionError::Request(e.to_string()))
    }

    async fn bolt11_invoice(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: IncomingContract,
        invoice_amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_time: u32,
    ) -> Result<Bolt11Invoice, GatewayConnectionError> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join(CREATE_BOLT11_INVOICE_ENDPOINT)
                    .expect("'create_bolt11_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&CreateBolt11InvoicePayload {
                federation_id,
                contract,
                invoice_amount,
                description,
                expiry_time,
            })
            .send()
            .await
            .map_err(|e| GatewayConnectionError::Unreachable(e.to_string()))?
            .json::<Bolt11Invoice>()
            .await
            .map_err(|e| GatewayConnectionError::Request(e.to_string()))
    }

    async fn send_payment(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, GatewayConnectionError> {
        reqwest::Client::new()
            .post(
                gateway_api
                    .join(SEND_PAYMENT_ENDPOINT)
                    .expect("'send_payment' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&SendPaymentPayload {
                federation_id,
                contract,
                invoice,
                auth,
            })
            .send()
            .await
            .map_err(|e| GatewayConnectionError::Unreachable(e.to_string()))?
            .json::<Result<[u8; 32], Signature>>()
            .await
            .map_err(|e| GatewayConnectionError::Request(e.to_string()))
    }
}
