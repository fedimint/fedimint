use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::KeyPair;
use clap::ValueEnum;
use fedimint_client_legacy::modules::ln::contracts::Preimage;
use fedimint_core::{Amount, BitcoinHash};
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use ln_gateway::lnrpc_client::ILnRpcClient;
use rand::rngs::OsRng;
use secp256k1_zkp::SecretKey;

use self::mock::INVALID_INVOICE_DESCRIPTION;

pub mod mock;
pub mod real;

#[async_trait]
pub trait LightningTest: ILnRpcClient {
    /// Creates invoice from the lightning implementation
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice>;

    /// Creates an invoice that is not payable
    fn invalid_invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        // Generate fake node keypair
        let kp = KeyPair::new(&ctx, &mut OsRng);

        // `FakeLightningTest` will fail to pay any invoice with
        // `INVALID_INVOICE_DESCRIPTION` in the description of the invoice.
        Ok(InvoiceBuilder::new(Currency::Regtest)
            .description(INVALID_INVOICE_DESCRIPTION.to_string())
            .payment_hash(sha256::Hash::hash(&Preimage([0; 32]).0))
            .current_timestamp()
            .min_final_cltv_expiry(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &SecretKey::from_keypair(&kp)))
            .unwrap())
    }

    /// Returns the amount that the gateway LN node has sent
    async fn amount_sent(&self) -> Amount;

    /// Is this a LN instance shared with other tests
    fn is_shared(&self) -> bool;
}

#[derive(ValueEnum, Clone, Debug)]
pub enum LightningNodeType {
    Cln,
    Lnd,
}

impl ToString for LightningNodeType {
    fn to_string(&self) -> String {
        match self {
            LightningNodeType::Cln => "cln".to_string(),
            LightningNodeType::Lnd => "lnd".to_string(),
        }
    }
}
