use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::{secp256k1, KeyPair};
use fedimint_api::task::TaskGroup;
use fedimint_ln::contracts::Preimage;
use lightning_invoice::Invoice;
use ln_gateway::{
    client::{GatewayClientBuilder, MemoryDbGatewayClientBuilder},
    config::GatewayConfig,
    ln::{LightningError, LnRpc},
    rpc::GatewayRequest,
    LnGateway,
};
use rand::rngs::OsRng;
use tokio::sync::mpsc;

pub fn fixtures(gw_cfg: GatewayConfig) -> LnGateway {
    let ln_rpc = Arc::new(MockLnRpc::new());

    let client_builder: GatewayClientBuilder = MemoryDbGatewayClientBuilder {}.into();
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, TaskGroup::new())
}

struct MockLnRpc {
    pub preimage: Preimage,
    node_pubkey: secp256k1::PublicKey,
    amount_sent: Arc<Mutex<u64>>,
}

impl MockLnRpc {
    fn new() -> Self {
        let ctx = secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);

        Self {
            preimage: Preimage([1; 32]),
            node_pubkey: secp256k1::PublicKey::from_keypair(&kp),
            amount_sent: Arc::new(Mutex::new(0)),
        }
    }
}

#[async_trait]
impl LnRpc for MockLnRpc {
    async fn pubkey(&self) -> Result<secp256k1::PublicKey, LightningError> {
        Ok(self.node_pubkey)
    }

    async fn pay(
        &self,
        invoice: Invoice,
        _max_delay: u64,
        _max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        *self.amount_sent.lock().unwrap() += invoice.amount_milli_satoshis().unwrap();

        Ok(self.preimage.clone())
    }
}
