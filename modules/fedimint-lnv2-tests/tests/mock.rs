use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{SecretKey, SECP256K1};
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_keypair, bitcoin32_to_bitcoin30_secp256k1_secret_key,
    bitcoin32_to_bitcoin30_sha256_hash,
};
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_ln_common::bitcoin;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, GatewayConnectionError, PaymentFee, RoutingInfo,
};
use fedimint_lnv2_common::{Bolt11InvoiceDescription, LightningInvoice};
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, DEFAULT_EXPIRY_TIME,
};

const GATEWAY_SECRET: [u8; 32] = [1; 32];

const PAYABLE_PAYMENT_SECRET: [u8; 32] = [211; 32];

const UNPAYABLE_PAYMENT_SECRET: [u8; 32] = [212; 32];

const GATEWAY_CRASH_PAYMENT_SECRET: [u8; 32] = [213; 32];

pub const MOCK_INVOICE_PREIMAGE: [u8; 32] = [1; 32];

pub fn gateway() -> SafeUrl {
    SafeUrl::parse("https://gateway.xyz").expect("Valid Url")
}

pub fn gateway_keypair() -> Keypair {
    bitcoin30_to_bitcoin32_keypair(
        &SecretKey::from_slice(&GATEWAY_SECRET)
            .expect("32 bytes; within curve order")
            .keypair(SECP256K1),
    )
}

pub fn payable_invoice() -> Bolt11Invoice {
    bolt_11_invoice(PAYABLE_PAYMENT_SECRET, Currency::Regtest)
}

pub fn unpayable_invoice() -> Bolt11Invoice {
    bolt_11_invoice(UNPAYABLE_PAYMENT_SECRET, Currency::Regtest)
}

pub fn crash_invoice() -> Bolt11Invoice {
    bolt_11_invoice(GATEWAY_CRASH_PAYMENT_SECRET, Currency::Regtest)
}

fn bolt_11_invoice(payment_secret: [u8; 32], currency: Currency) -> Bolt11Invoice {
    let sk = SecretKey::new(&mut OsRng);
    let payment_hash = sha256::Hash::hash(&MOCK_INVOICE_PREIMAGE);

    InvoiceBuilder::new(currency)
        .description(String::new())
        .payment_hash(payment_hash)
        .current_timestamp()
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret(payment_secret))
        .amount_milli_satoshis(1_000_000)
        .expiry_time(Duration::from_secs(DEFAULT_EXPIRY_TIME))
        .build_signed(|m| SECP256K1.sign_ecdsa_recoverable(m, &sk))
        .expect("Invoice creation failed")
}

pub fn signet_bolt_11_invoice() -> Bolt11Invoice {
    bolt_11_invoice(PAYABLE_PAYMENT_SECRET, Currency::Signet)
}

#[derive(Debug)]
pub struct MockGatewayConnection {
    keypair: Keypair,
}

impl Default for MockGatewayConnection {
    fn default() -> Self {
        MockGatewayConnection {
            keypair: gateway_keypair(),
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for MockGatewayConnection {
    async fn routing_info(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, GatewayConnectionError> {
        Ok(Some(RoutingInfo {
            lightning_public_key: self.keypair.public_key(),
            module_public_key: self.keypair.public_key(),
            send_fee_default: PaymentFee::SEND_FEE_LIMIT,
            send_fee_minimum: PaymentFee {
                base: Amount::from_sats(50),
                parts_per_million: 5_000,
            },
            expiration_delta_default: 500,
            expiration_delta_minimum: 144,
            receive_fee: PaymentFee::RECEIVE_FEE_LIMIT,
        }))
    }

    async fn bolt11_invoice(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: FederationId,
        contract: IncomingContract,
        invoice_amount: Amount,
        _description: Bolt11InvoiceDescription,
        expiry_time: u32,
    ) -> Result<Bolt11Invoice, GatewayConnectionError> {
        let payment_hash = match contract.commitment.payment_image {
            PaymentImage::Hash(payment_hash) => bitcoin32_to_bitcoin30_sha256_hash(&payment_hash),
            PaymentImage::Point(..) => panic!("PaymentImage is not a payment hash"),
        };

        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description(String::new())
            .payment_hash(payment_hash)
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(invoice_amount.msats)
            .expiry_time(Duration::from_secs(expiry_time as u64))
            .build_signed(|m| {
                SECP256K1.sign_ecdsa_recoverable(
                    m,
                    &bitcoin32_to_bitcoin30_secp256k1_secret_key(&self.keypair.secret_key()),
                )
            })
            .unwrap())
    }

    async fn send_payment(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: FederationId,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        _auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, GatewayConnectionError> {
        match invoice {
            LightningInvoice::Bolt11(invoice) => {
                if *invoice.payment_secret() == PaymentSecret(GATEWAY_CRASH_PAYMENT_SECRET) {
                    return Err(GatewayConnectionError::Unreachable(String::new()));
                }

                if *invoice.payment_secret() == PaymentSecret(UNPAYABLE_PAYMENT_SECRET) {
                    return Ok(Err(self.keypair.sign_schnorr(contract.forfeit_message())));
                }

                Ok(Ok(MOCK_INVOICE_PREIMAGE))
            }
        }
    }
}
