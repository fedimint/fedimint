use std::io::Cursor;
use std::ops::Sub;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use bitcoin::secp256k1;
use bitcoin::{Address, Transaction};
use bitcoincore_rpc::Client;
use bitcoincore_rpc::{Auth, RpcApi};
use clightningrpc::responses::NetworkAddress;
use clightningrpc::{responses, LightningRPC};
use lightning_invoice::Invoice;
use minimint_api::Amount;
use serde::Serialize;
use tracing::{info, warn};

use minimint_api::encoding::Decodable;
use minimint_wallet::config::WalletConfig;
use minimint_wallet::txoproof::TxOutProof;

use crate::fixture::{BitcoinTest, LightningTest};

pub struct RealLightningTest {
    rpc_gateway: LightningRPC,
    rpc_other: LightningRPC,
    initial_balance: Amount,
    pub gateway_node_pub_key: secp256k1::PublicKey,
}

impl LightningTest for RealLightningTest {
    fn invoice(&self, amount: Amount) -> Invoice {
        let random: u64 = rand::random();
        let invoice = self
            .rpc_other
            .invoice(amount.milli_sat, &random.to_string(), "", None)
            .unwrap();
        Invoice::from_str(&invoice.bolt11).unwrap()
    }

    fn amount_sent(&self) -> Amount {
        self.initial_balance
            .sub(Self::channel_balance(&self.rpc_gateway))
    }
}

impl RealLightningTest {
    pub async fn new(
        socket_gateway: PathBuf,
        socket_other: PathBuf,
        bitcoin: &dyn BitcoinTest,
    ) -> Self {
        let rpc_other = LightningRPC::new(socket_other);
        let mut rpc_gateway = LightningRPC::new(socket_gateway);

        // ensure the lightning node has a channel with > 1M sats
        if Self::channel_balance(&rpc_gateway).milli_sat < 1000 * 1000 * 1000 {
            info!("Attempting to fund new LN channel.");
            Self::fund_channel(&mut rpc_gateway, &rpc_other, bitcoin);
        }
        let initial_balance = Self::channel_balance(&rpc_gateway);
        let gateway_pubkey =
            secp256k1::PublicKey::from_str(&rpc_gateway.getinfo().unwrap().id).unwrap();

        RealLightningTest {
            rpc_gateway,
            rpc_other,
            initial_balance,
            gateway_node_pub_key: gateway_pubkey,
        }
    }
}

impl RealLightningTest {
    fn fund_channel(
        rpc_gateway: &mut LightningRPC,
        rpc_other: &LightningRPC,
        bitcoin: &dyn BitcoinTest,
    ) {
        const FUND_AMOUNT: u64 = 10 * 1000 * 1000;

        let info = rpc_other.getinfo().unwrap();
        let other_ip = match info.binding.first().unwrap() {
            NetworkAddress::Ipv4 { address, port } => format!("{}:{}", address, port),
            address => panic!("Non ipv4 address {:?}", address),
        };
        rpc_gateway.connect(&info.id, Some(&other_ip)).unwrap();

        let funding_address = rpc_gateway.newaddr(None).unwrap().bech32.unwrap();
        bitcoin.send_and_mine_block(
            &Address::from_str(&funding_address).unwrap(),
            bitcoin::Amount::from_sat(FUND_AMOUNT * 2),
        );
        bitcoin.mine_blocks(10);

        loop {
            let fund_channel = FundChannelFixed {
                id: &info.id,
                amount: FUND_AMOUNT,
            };
            let response = rpc_gateway
                .client()
                .send_request::<FundChannelFixed, responses::FundChannel>(
                    "fundchannel",
                    fund_channel,
                )
                .expect("Error requesting funds.")
                .into_result();
            match response {
                Ok(_) => break,
                Err(clightningrpc::Error::Rpc(e)) if e.code == 304 || e.code == 301 => {
                    warn!("LN awaiting block sync, please wait...")
                }
                Err(err) => panic!("Unexpected error {}", err),
            }
            thread::sleep(Duration::from_millis(1000));
        }
        bitcoin.mine_blocks(10);

        loop {
            warn!("LN channel not open yet, please wait...");
            if Self::channel_balance(rpc_gateway) == Amount::from_sat(FUND_AMOUNT) {
                break;
            }
            thread::sleep(Duration::from_millis(1000));
        }
    }

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

    pub fn new(wallet_config: WalletConfig) -> Self {
        let client = Client::new(
            &(wallet_config.btc_rpc_address),
            Auth::UserPass(
                wallet_config.btc_rpc_user.clone(),
                wallet_config.btc_rpc_pass.clone(),
            ),
        )
        .expect(Self::ERROR);

        // ensure we have a wallet with bitcoin
        if client.list_wallets().expect(Self::ERROR).is_empty() {
            client
                .create_wallet("", None, None, None, None)
                .expect(Self::ERROR);
        }

        if client
            .get_balances()
            .expect(Self::ERROR)
            .mine
            .trusted
            .as_btc()
            < 100.0
        {
            let address = client.get_new_address(None, None).expect(Self::ERROR);
            client
                .generate_to_address(200, &address)
                .expect(Self::ERROR);
        }

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
        let proof = TxOutProof::consensus_decode(Cursor::new(
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
