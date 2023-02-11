use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Error;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, KeyPair};
use fedimint_api::Amount;
use fedimint_ln::route_hints::RouteHint;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use ln_gateway::ln::{LightningError, LnRpc};
use mint_client::modules::ln::contracts::Preimage;
use rand::rngs::OsRng;

use crate::fixtures::LightningTest;

#[derive(Clone, Debug)]
pub struct FakeLightningTest {
    pub preimage: Preimage,
    pub gateway_node_pub_key: secp256k1::PublicKey,
    gateway_node_sec_key: secp256k1::SecretKey,
    amount_sent: Arc<Mutex<u64>>,
}

impl FakeLightningTest {
    pub fn new() -> Self {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = Arc::new(Mutex::new(0));

        FakeLightningTest {
            preimage: Preimage([1; 32]),
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            gateway_node_pub_key: PublicKey::from_keypair(&kp),
            amount_sent,
        }
    }
}

#[async_trait]
impl LightningTest for FakeLightningTest {
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&self.preimage.0))
            .current_timestamp()
            .min_final_cltv_expiry(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
            .unwrap()
    }

    async fn amount_sent(&self) -> Amount {
        Amount::from_msats(*self.amount_sent.lock().unwrap())
    }

    fn is_shared(&self) -> bool {
        false
    }
}

#[async_trait]
impl LnRpc for FakeLightningTest {
    async fn pubkey(&self) -> Result<PublicKey, LightningError> {
        Ok(self.gateway_node_pub_key)
    }

    async fn pay(
        &self,
        invoice: lightning_invoice::Invoice,
        _max_delay: u64,
        _max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        *self.amount_sent.lock().unwrap() += invoice.amount_milli_satoshis().unwrap();

        Ok(self.preimage.clone())
    }

    async fn route_hints(&self) -> Result<Vec<RouteHint>, Error> {
        Ok(vec![RouteHint(vec![])])
    }
}
