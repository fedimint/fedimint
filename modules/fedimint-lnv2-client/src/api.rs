use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use bitcoin30::secp256k1::schnorr::Signature;
use bitcoin30::secp256k1::PublicKey;
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
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CREATE_BOLT11_INVOICE_ENDPOINT, GATEWAYS_ENDPOINT,
    REMOVE_GATEWAY_ENDPOINT, ROUTING_INFO_ENDPOINT, SEND_PAYMENT_ENDPOINT,
};
use fedimint_lnv2_common::ContractId;
use lightning_invoice::Bolt11Invoice;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Bolt11InvoiceDescription, LightningInvoice};

const RETRY_DELAY: Duration = Duration::from_secs(1);

#[apply(async_trait_maybe_send!)]
pub trait LightningFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool;

    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]>;

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
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_secs: u32,
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

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum GatewayConnectionError {
    #[error("The gateway is unreachable: {0}")]
    Unreachable(String),
    #[error("The gateway returned an error for this request: {0}")]
    Request(String),
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
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_secs: u32,
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
                amount,
                description,
                expiry_secs,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateBolt11InvoicePayload {
    pub federation_id: FederationId,
    pub contract: IncomingContract,
    pub amount: Amount,
    pub description: Bolt11InvoiceDescription,
    pub expiry_secs: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SendPaymentPayload {
    pub federation_id: FederationId,
    pub contract: OutgoingContract,
    pub invoice: LightningInvoice,
    pub auth: Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RoutingInfo {
    /// The public key of the gateways lightning node. Since this key signs the
    /// gateways invoices the senders client uses it to differentiate between a
    /// direct swap between fedimints and a lightning swap.
    pub lightning_public_key: PublicKey,
    /// The public key of the gateways client module. This key is used to claim
    /// or cancel outgoing contracts and refund incoming contracts.
    pub module_public_key: PublicKey,
    /// This is the fee the gateway charges for an outgoing payment. The senders
    /// client will use this fee in case of a direct swap.
    pub send_fee_minimum: PaymentFee,
    /// This is the default total fee the gateway recommends for an outgoing
    /// payment in case of a lightning swap. It accounts for the additional fee
    /// required to reliably route this payment over lightning.
    pub send_fee_default: PaymentFee,
    /// This is the minimum expiration delta in block the gateway requires for
    /// an outgoing payment. The senders client will use this expiration delta
    /// in case of a direct swap.
    pub expiration_delta_minimum: u64,
    /// This is the default total expiration the gateway recommends for an
    /// outgoing payment in case of a lightning swap. It accounts for the
    /// additional expiration delta required to successfully route this payment
    /// over lightning.
    pub expiration_delta_default: u64,
    /// This is the fee the gateway charges for an incoming payment.
    pub receive_fee: PaymentFee,
}

impl RoutingInfo {
    pub fn send_parameters(&self, invoice: &Bolt11Invoice) -> (PaymentFee, u64) {
        if invoice.recover_payee_pub_key() == self.lightning_public_key {
            (self.send_fee_minimum.clone(), self.expiration_delta_minimum)
        } else {
            (self.send_fee_default.clone(), self.expiration_delta_default)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PaymentFee {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl PaymentFee {
    /// This is the maximum send fee of one and a half percent plus one hundred
    /// satoshis a correct gateway may recommend as a default. It accounts for
    /// the fee required to reliably route this payment over lightning.
    pub const SEND_FEE_LIMIT: PaymentFee = PaymentFee {
        base: Amount::from_sats(100),
        parts_per_million: 15_000,
    };

    /// This is the maximum receive fee of half of one percent plus fifty
    /// satoshis a correct gateway may recommend as a default.
    pub const RECEIVE_FEE_LIMIT: PaymentFee = PaymentFee {
        base: Amount::from_sats(50),
        parts_per_million: 5_000,
    };

    pub fn add_to(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_add(self.absolute_fee(msats)))
    }

    pub fn subtract_from(&self, msats: u64) -> Amount {
        Amount::from_msats(msats.saturating_sub(self.absolute_fee(msats)))
    }

    fn absolute_fee(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .checked_add(self.base.msats)
            .expect("The division creates sufficient headroom to add the base fee")
    }
}
