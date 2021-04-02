mod txoproof;

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{Network, Txid};
use bitcoincore_rpc_async::RpcApi;
use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

pub const CONFIRMATION_TARGET: u16 = 24;

#[derive(Copy, Clone, Debug, PartialEq, Ord, PartialOrd, Eq, Serialize, Deserialize)]
pub struct Feerate {
    sats_per_kb: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WalletConsensusItem {
    block_height: u32, // FIXME: use block hash instead, but needs more complicated verification logic
    fee_rate: Feerate,
}

pub struct Wallet<D> {
    cfg: WalletConfig,
    consensus_height: u32,
    last_consensus_height_proposal: u32,
    consensus_feerate: Feerate,
    secp: Secp256k1<All>,
    btc_rpc: bitcoincore_rpc_async::Client,
    db: D,
}

pub struct WalletConfig {
    pub network: Network,
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub signing_key: ExtendedPrivKey,
    pub finalty_delay: u32,
    pub default_fee: Feerate,
}

impl<D> Wallet<D> {
    pub async fn new(
        cfg: WalletConfig,
        btc_rpc: bitcoincore_rpc_async::Client,
        db: D,
    ) -> Result<Self, WalletError> {
        let bitcoind_net = get_network(&btc_rpc).await?;
        if bitcoind_net != cfg.network {
            return Err(WalletError::WrongNetwork(cfg.network, bitcoind_net));
        }

        Ok(Wallet {
            cfg,
            consensus_height: 0,
            last_consensus_height_proposal: 0,
            consensus_feerate: Feerate { sats_per_kb: 1000 },
            secp: Default::default(),
            btc_rpc,
            db,
        })
    }

    pub async fn consensus_proposal(&self) -> Result<WalletConsensusItem, WalletError> {
        let network_height = self.btc_rpc.get_block_count().await? as u32;
        let target_height = network_height.saturating_sub(self.cfg.finalty_delay);

        let proposed_height = if target_height >= self.last_consensus_height_proposal {
            target_height
        } else {
            warn!(
                "The block height shrunk, new proposal would be {}, but we are sticking to our last block height proposal {}.",
                target_height,
                self.last_consensus_height_proposal
            );
            self.last_consensus_height_proposal
        };

        let fee_rate = self
            .btc_rpc
            .estimate_smart_fee(CONFIRMATION_TARGET, None)
            .await?
            .fee_rate
            .map(|per_kb| Feerate {
                sats_per_kb: per_kb.as_sat(),
            })
            .unwrap_or(self.cfg.default_fee);

        Ok(WalletConsensusItem {
            block_height: proposed_height,
            fee_rate,
        })
    }

    pub fn process_consensus_proposals(&mut self, proposals: Vec<WalletConsensusItem>) {
        trace!("Received consensus proposals {:?}", &proposals);

        // TODO: also warn on less than 2/3, that should never happen
        if proposals.is_empty() {
            error!("No proposals were submitted this round");
            return;
        }

        let (height_proposals, fee_proposals) = proposals
            .into_iter()
            .map(|wc| (wc.block_height, wc.fee_rate))
            .unzip();

        self.process_block_height_proposals(height_proposals);
        self.process_fee_proposals(fee_proposals);
    }

    /// # Panics
    /// * If proposals is empty
    fn process_fee_proposals(&mut self, mut proposals: Vec<Feerate>) {
        assert!(!proposals.is_empty());

        proposals.sort();

        let median_proposal = *proposals
            .get(proposals.len() / 2)
            .expect("We checked before that proposals aren't empty");

        self.consensus_feerate = median_proposal;
    }

    /// # Panics
    /// * If proposals is empty
    fn process_block_height_proposals(&mut self, mut proposals: Vec<u32>) {
        assert!(!proposals.is_empty());

        proposals.sort();
        let median_proposal = proposals[proposals.len() / 2];

        if median_proposal >= self.consensus_height {
            debug!("Setting consensus block height to {}", median_proposal);
            self.consensus_height = median_proposal;
        } else {
            warn!(
                   "Median proposed consensus block height shrunk from {} to {}, sticking with old value",
                   self.consensus_height, median_proposal
               );
        }
    }
}

async fn get_network(rpc_client: &bitcoincore_rpc_async::Client) -> Result<Network, WalletError> {
    let bc = rpc_client.get_blockchain_info().await?;
    match bc.chain.as_str() {
        "main" => Ok(Network::Bitcoin),
        "test" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(WalletError::UnknownNetwork(bc.chain)),
    }
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcErrot(bitcoincore_rpc_async::Error),
    #[error("Unknown bitcoin network: {0}")]
    UnknownNetwork(String),
}

impl From<bitcoincore_rpc_async::Error> for WalletError {
    fn from(e: bitcoincore_rpc_async::Error) -> Self {
        WalletError::RpcErrot(e)
    }
}
