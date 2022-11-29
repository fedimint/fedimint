use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{secp256k1, KeyPair};
use fedimint_api::task::TaskGroup;
use fedimint_ln::contracts::Preimage;
use fedimint_testing::btc::{fixtures::FakeBitcoinTest, BitcoinTest};
use lightning_invoice::Invoice;
use ln_gateway::{
    client::{GatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder},
    config::GatewayConfig,
    ln::{LightningError, LnRpc},
    rpc::GatewayRequest,
    LnGateway,
};
use rand::rngs::OsRng;
use tokio::sync::mpsc;

pub struct Fixtures {
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: LnGateway,
    pub task_group: TaskGroup,
}

pub async fn fixtures(gw_cfg: GatewayConfig) -> Result<Fixtures> {
    let task_group = TaskGroup::new();

    let ln_rpc = Arc::new(MockLnRpc::new());

    let client_builder: GatewayClientBuilder =
        StandardGatewayClientBuilder::new(PathBuf::new(), MemDbFactory.into()).into();
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, task_group.clone()).await;
    let bitcoin = Box::new(FakeBitcoinTest::new());

    Ok(Fixtures {
        bitcoin,
        gateway,
        task_group,
    })
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
