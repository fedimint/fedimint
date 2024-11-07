use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::PublicKey;
use fedimint_core::bitcoin_migration::bitcoin32_to_bitcoin30_secp256k1_pubkey;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contracts::{IncomingContract, OutgoingContract};
use crate::endpoint_constants::{
    CREATE_BOLT11_INVOICE_ENDPOINT, ROUTING_INFO_ENDPOINT, SEND_PAYMENT_ENDPOINT,
};
use crate::{Bolt11InvoiceDescription, LightningInvoice};

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
        if invoice.recover_payee_pub_key()
            == bitcoin32_to_bitcoin30_secp256k1_pubkey(&self.lightning_public_key)
        {
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
