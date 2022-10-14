use std::io::Cursor;
use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::{Address, Transaction};
use bitcoincore_rpc::Client;
use bitcoincore_rpc::{Auth, RpcApi};
use clightningrpc::LightningRPC;
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::encoding::Decodable;
use fedimint_api::Amount;
use fedimint_wallet::txoproof::TxOutProof;
use lightning_invoice::Invoice;

use crate::fixtures::{BitcoinTest, LightningTest};

pub struct RealLightningTest {
    rpc_gateway: LightningRPC,
    rpc_other: LightningRPC,
    initial_balance: Amount,
    pub gateway_node_pub_key: secp256k1::PublicKey,
}

impl LightningTest for RealLightningTest {
    fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let random: u64 = rand::random();
        let invoice = self
            .rpc_other
            .invoice(amount.milli_sat, &random.to_string(), "", expiry_time)
            .unwrap();
        Invoice::from_str(&invoice.bolt11).unwrap()
    }

    fn amount_sent(&self) -> Amount {
        self.initial_balance
            .sub(Self::channel_balance(&self.rpc_gateway))
    }
}

impl RealLightningTest {
    pub async fn new(socket_gateway: PathBuf, socket_other: PathBuf) -> Self {
        let rpc_other = LightningRPC::new(socket_other);
        let rpc_gateway = LightningRPC::new(socket_gateway);

        let initial_balance = Self::channel_balance(&rpc_gateway);
        let gateway_node_pub_key =
            secp256k1::PublicKey::from_str(&rpc_gateway.getinfo().unwrap().id).unwrap();

        RealLightningTest {
            rpc_gateway,
            rpc_other,
            initial_balance,
            gateway_node_pub_key,
        }
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
