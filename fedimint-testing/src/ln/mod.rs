use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::KeyPair;
use fedimint_core::{Amount, BitcoinHash};
use lightning_invoice::{
    Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret, DEFAULT_EXPIRY_TIME,
};
use ln_gateway::lightning::ILnRpcClient;
use rand::rngs::OsRng;
use secp256k1_zkp::SecretKey;

use self::mock::INVALID_INVOICE_DESCRIPTION;
use crate::gateway::LightningNodeType;

pub mod mock;
pub mod real;

#[async_trait]
pub trait LightningTest: ILnRpcClient {
    /// Creates invoice from the lightning implementation
    async fn invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Bolt11Invoice>;

    /// Creates an invoice that is not payable
    ///
    /// * Mocks use hard-coded invoice description to fail the payment
    /// * Real fixtures won't be able to route to randomly generated node pubkey
    fn unpayable_invoice(
        &self,
        amount: Amount,
        expiry_time: Option<u64>,
    ) -> ln_gateway::Result<Bolt11Invoice> {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        // Generate fake node keypair
        let kp = KeyPair::new(&ctx, &mut OsRng);

        // `FakeLightningTest` will fail to pay any invoice with
        // `INVALID_INVOICE_DESCRIPTION` in the description of the invoice.
        Ok(InvoiceBuilder::new(Currency::Regtest)
            .payee_pub_key(kp.public_key())
            .description(INVALID_INVOICE_DESCRIPTION.to_string())
            .payment_hash(sha256::Hash::hash(&[0; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &SecretKey::from_keypair(&kp)))
            .unwrap())
    }

    /// Is this a LN instance shared with other tests
    fn is_shared(&self) -> bool;

    fn listening_address(&self) -> String;

    fn lightning_node_type(&self) -> LightningNodeType;
}
