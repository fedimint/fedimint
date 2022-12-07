use std::collections::BTreeMap;
use std::io::Cursor;

use bitcoin::{Address, Transaction};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::core::Decoder;
use fedimint_api::encoding::Decodable;
use fedimint_api::Amount;
use fedimint_wallet::txoproof::TxOutProof;

use crate::btc::BitcoinTest;

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
        let proof = TxOutProof::consensus_decode(
            &mut Cursor::new(
                self.client
                    .get_tx_out_proof(&[id], None)
                    .expect(Self::ERROR),
            ),
            &BTreeMap::<_, Decoder>::new(),
        )
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
