use std::ops::Add;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send};
use fedimint_ln_common::client::{GatewayRpcClient, GatewayRpcError};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use serde::{Deserialize, Serialize};

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
    ) -> Result<Option<RoutingInfo>, GatewayRpcError>;

    async fn bolt11_invoice(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: IncomingContract,
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_secs: u32,
    ) -> Result<Bolt11Invoice, GatewayRpcError>;

    async fn send_payment(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        outpoint: OutPoint,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, GatewayRpcError>;
}

#[derive(Debug)]
pub struct RealGatewayConnection;

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for RealGatewayConnection {
    async fn routing_info(
        &self,
        gateway_api: SafeUrl,
        federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, GatewayRpcError> {
        let client = GatewayRpcClient::new(gateway_api, None, None, None)
            .await
            .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
        client.call_post(ROUTING_INFO_ENDPOINT, federation_id).await
    }

    async fn bolt11_invoice(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        contract: IncomingContract,
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_secs: u32,
    ) -> Result<Bolt11Invoice, GatewayRpcError> {
        let client = GatewayRpcClient::new(gateway_api, None, None, None)
            .await
            .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
        client
            .call_post(
                CREATE_BOLT11_INVOICE_ENDPOINT,
                CreateBolt11InvoicePayload {
                    federation_id,
                    contract,
                    amount,
                    description,
                    expiry_secs,
                },
            )
            .await
    }

    async fn send_payment(
        &self,
        gateway_api: SafeUrl,
        federation_id: FederationId,
        outpoint: OutPoint,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, GatewayRpcError> {
        let client = GatewayRpcClient::new(gateway_api, None, None, None)
            .await
            .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
        client
            .call_post(
                SEND_PAYMENT_ENDPOINT,
                SendPaymentPayload {
                    federation_id,
                    outpoint,
                    contract,
                    invoice,
                    auth,
                },
            )
            .await
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
    pub outpoint: OutPoint,
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
            (self.send_fee_minimum, self.expiration_delta_minimum)
        } else {
            (self.send_fee_default, self.expiration_delta_default)
        }
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
    Copy,
)]
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

    /// This is the fee the gateway uses to cover transaction fees with the
    /// federation.
    pub const TRANSACTION_FEE_DEFAULT: PaymentFee = PaymentFee {
        base: Amount::from_sats(2),
        parts_per_million: 3000,
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

impl Add for PaymentFee {
    type Output = PaymentFee;
    fn add(self, rhs: Self) -> Self::Output {
        PaymentFee {
            base: self.base + rhs.base,
            parts_per_million: self.parts_per_million + rhs.parts_per_million,
        }
    }
}

impl From<RoutingFees> for PaymentFee {
    fn from(value: RoutingFees) -> Self {
        PaymentFee {
            base: Amount::from_msats(u64::from(value.base_msat)),
            parts_per_million: u64::from(value.proportional_millionths),
        }
    }
}

impl From<PaymentFee> for RoutingFees {
    fn from(value: PaymentFee) -> Self {
        RoutingFees {
            base_msat: u32::try_from(value.base.msats).expect("base msat was truncated from u64"),
            proportional_millionths: u32::try_from(value.parts_per_million)
                .expect("ppm was truncated from u64"),
        }
    }
}

impl std::fmt::Display for PaymentFee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.base, self.parts_per_million)
    }
}

impl FromStr for PaymentFee {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');
        let base_str = parts
            .next()
            .ok_or(anyhow::anyhow!("Failed to parse base fee"))?;
        let ppm_str = parts.next().ok_or(anyhow::anyhow!("Failed to parse ppm"))?;

        // Ensure no extra parts
        if parts.next().is_some() {
            return Err(anyhow::anyhow!(
                "Failed to parse fees. Expected format <base>,<ppm>"
            ));
        }

        let base = Amount::from_str(base_str)?;
        let parts_per_million = ppm_str.parse::<u64>()?;

        Ok(PaymentFee {
            base,
            parts_per_million,
        })
    }
}
