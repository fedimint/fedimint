use std::{io::Cursor, net::SocketAddr, ops::Sub, path::PathBuf, str::FromStr, sync::Arc};

use async_trait::async_trait;
use bitcoin::{secp256k1::PublicKey, Address, Transaction};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clightningrpc::LightningRPC;
use cln_rpc::ClnRpc;
use fedimint_api::{config::BitcoindRpcCfg, encoding::Decodable, Amount};
use fedimint_wallet::txoproof::TxOutProof;
use lightning_invoice::Invoice;
use ln_gateway::{
    ln::{LnRpc, LnRpcFactory, LnRpcRef},
    messaging::GatewayMessageChannel,
};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::fixtures::{BitcoinTest, LightningTest};

pub struct RealLightningTest {
    gateway_workdir: PathBuf,
    gateway_bind_addr: SocketAddr,
    gateway_rpc: LightningRPC,
    other_rpc: LightningRPC,
    gateway_initial_balance: Amount,
}

impl LightningTest for RealLightningTest {
    fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let random: u64 = rand::random();
        let invoice = self
            .other_rpc
            .invoice(amount.milli_sat, &random.to_string(), "", expiry_time)
            .unwrap();
        Invoice::from_str(&invoice.bolt11).unwrap()
    }

    fn amount_sent(&self) -> Amount {
        self.gateway_initial_balance
            .sub(Self::channel_balance(&self.gateway_rpc))
    }
}

impl RealLightningTest {
    pub async fn new(
        gateway_workdir: PathBuf,
        gateway_bind_addr: SocketAddr,
        socket_other: PathBuf,
    ) -> Self {
        let other_rpc = LightningRPC::new(socket_other);
        let gateway_rpc = LightningRPC::new(gateway_workdir.clone());
        let gateway_initial_balance = Self::channel_balance(&gateway_rpc);
        RealLightningTest {
            gateway_workdir,
            gateway_bind_addr,
            gateway_rpc,
            other_rpc,
            gateway_initial_balance,
        }
    }
}

#[async_trait]
impl LnRpcFactory for RealLightningTest {
    async fn create(
        &self,
        // TODO: Apply messaging in RealLightningTest scenario
        _messenger: GatewayMessageChannel,
    ) -> Result<Arc<LnRpcRef>, anyhow::Error> {
        let gateway_cln_rpc = ClnRpc::new(self.gateway_workdir.clone())
            .await
            .expect("connect to ln_socket");

        let gateway_pub_key = PublicKey::from_str(&self.gateway_rpc.getinfo().unwrap().id).unwrap();

        Ok(Arc::new(LnRpcRef {
            ln_rpc: Arc::new(Mutex::new(gateway_cln_rpc)) as Arc<dyn LnRpc>,
            bind_addr: self.gateway_bind_addr,
            work_dir: self.gateway_workdir.clone(),
            pub_key: gateway_pub_key,
        }))
    }
}

impl RealLightningTest {
    fn channel_balance(rpc: &LightningRPC) -> Amount {
        let funds: u64 = rpc
            .listfunds()
            .unwrap()
            .channels
            .iter()
            .filter(|channel| channel.short_channel_id.is_some() && channel.connected)
            .map(|channel| channel.our_amount_msat.0)
            .sum();
        Amount::from_msat(funds)
    }
}

// FIXME workaround for bad RPC API, should replace when cln_rpc gets updated
#[derive(Debug, Clone, Serialize)]
struct FundChannelFixed<'a> {
    pub id: &'a str,
    pub amount: u64,
}

pub struct RealBitcoinTest {
    client: Client,
}

impl RealBitcoinTest {
    const ERROR: &'static str = "Bitcoin RPC returned an error";

    pub fn new(rpc_cfg: &BitcoindRpcCfg) -> Self {
        let client = Client::new(
            &(rpc_cfg.btc_rpc_address),
            Auth::UserPass(rpc_cfg.btc_rpc_user.clone(), rpc_cfg.btc_rpc_pass.clone()),
        )
        .expect(Self::ERROR);

        Self { client }
    }
}

impl BitcoinTest for RealBitcoinTest {
    fn mine_blocks(&self, block_num: u64) {
        self.client
            .generate_to_address(block_num, &self.get_new_address())
            .expect(Self::ERROR);
    }

    fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction) {
        let id = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .expect(Self::ERROR);
        self.mine_blocks(1);

        let tx = self
            .client
            .get_raw_transaction(&id, None)
            .expect(Self::ERROR);
        let proof = TxOutProof::consensus_decode(&mut Cursor::new(
            self.client
                .get_tx_out_proof(&[id], None)
                .expect(Self::ERROR),
        ))
        .expect(Self::ERROR);

        (proof, tx)
    }

    fn get_new_address(&self) -> Address {
        self.client.get_new_address(None, None).expect(Self::ERROR)
    }

    fn mine_block_and_get_received(&self, address: &Address) -> Amount {
        self.mine_blocks(1);
        self.client
            .get_received_by_address(address, None)
            .expect(Self::ERROR)
            .into()
    }
}
