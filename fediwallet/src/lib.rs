mod db;

use crate::db::{BlockHashKey, LastBlock, LastBlockKey, UTXOKey};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, BlockHash, Network, OutPoint};
use bitcoincore_rpc_async::{Auth, RpcApi};
use config::{Feerate, WalletConfig};
use database::batch::{Batch, BatchItem, Element};
use database::{BatchDb, BincodeSerialized, Database};
use mint_api::PegInProof;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

pub const CONFIRMATION_TARGET: u16 = 24;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WalletConsensusItem {
    block_height: u32, // FIXME: use block hash instead, but needs more complicated verification logic
    fee_rate: Feerate,
}

pub struct Wallet<D> {
    cfg: WalletConfig,
    last_consensus_height_proposal: u32,
    consensus_feerate: Feerate,
    secp: Secp256k1<All>,
    btc_rpc: bitcoincore_rpc_async::Client,
    db: D,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SpendableUTXO {
    PegIn { tweak: secp256k1::PublicKey },
}

impl<D> Wallet<D>
where
    D: Database + BatchDb + Clone + Send + 'static,
{
    pub async fn new(cfg: WalletConfig, db: D) -> Result<Self, WalletError> {
        let btc_rpc = bitcoincore_rpc_async::Client::new(
            cfg.btc_rpc_address.clone(),
            Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
        )
        .await?;

        let bitcoind_net = get_network(&btc_rpc).await?;
        if bitcoind_net != cfg.network {
            return Err(WalletError::WrongNetwork(cfg.network, bitcoind_net));
        }

        if db
            .get_value::<_, LastBlock>(&LastBlockKey)
            .expect("DB error")
            .is_none()
        {
            info!("Initializing new wallet DB.");
            let genesis = genesis_block(cfg.network);
            db.apply_batch(
                vec![
                    BatchItem::InsertNewElement(Element {
                        key: Box::new(LastBlockKey),
                        value: Box::new(LastBlock(0)),
                    }),
                    BatchItem::InsertNewElement(Element {
                        key: Box::new(BlockHashKey(genesis.block_hash())),
                        value: Box::new(()),
                    }),
                ]
                .iter(),
            )
            .expect("DB error");
        }

        let wallet = Wallet {
            cfg,
            last_consensus_height_proposal: 0,
            consensus_feerate: Feerate { sats_per_kb: 1000 },
            secp: Default::default(),
            btc_rpc,
            db,
        };

        info!(
            "Starting initial wallet sync up to block {}",
            wallet.cfg.start_consensus_height
        );
        wallet
            .sync_up_to_consensus_heigh(wallet.cfg.start_consensus_height)
            .await?;

        Ok(wallet)
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

    pub async fn process_consensus_proposals(
        &mut self,
        proposals: Vec<WalletConsensusItem>,
    ) -> Result<(), WalletError> {
        trace!("Received consensus proposals {:?}", &proposals);

        // TODO: also warn on less than 2/3, that should never happen
        if proposals.is_empty() {
            error!("No proposals were submitted this round");
            return Ok(());
        }

        let (height_proposals, fee_proposals) = proposals
            .into_iter()
            .map(|wc| (wc.block_height, wc.fee_rate))
            .unzip();

        self.process_fee_proposals(fee_proposals);
        self.process_block_height_proposals(height_proposals).await
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
    async fn process_block_height_proposals(
        &mut self,
        mut proposals: Vec<u32>,
    ) -> Result<(), WalletError> {
        assert!(!proposals.is_empty());

        proposals.sort();
        let median_proposal = proposals[proposals.len() / 2];

        if median_proposal >= self.consensus_height() {
            debug!("Setting consensus block height to {}", median_proposal);
            self.sync_up_to_consensus_heigh(median_proposal).await?;
        } else {
            warn!(
                   "Median proposed consensus block height shrunk from {} to {}, sticking with old value",
                   self.consensus_height(), median_proposal
               );
        }

        Ok(())
    }

    pub fn consensus_height(&self) -> u32 {
        self.db
            .get_value::<_, LastBlock>(&LastBlockKey)
            .expect("DB error")
            .expect("ensured by constructor")
            .0
    }

    async fn sync_up_to_consensus_heigh(&self, new_height: u32) -> Result<(), WalletError> {
        let old_height = self.consensus_height();
        if new_height < old_height {
            info!(
                "Nothing to sync, new height ({}) is lower than old height ({}), doing nothing.",
                new_height, old_height
            );
        }

        if new_height == old_height {
            debug!("Height didn't change, still at {}", old_height);
            return Ok(());
        }

        info!(
            "New consensus height {}, syncing up ({} blocks to go)",
            new_height,
            new_height - old_height
        );

        let mut batch = Vec::<BatchItem>::with_capacity((new_height - old_height) as usize + 1);
        for height in (old_height + 1)..=(new_height) {
            if height % 100 == 0 {
                debug!("Caught up to block {}", height);
            }

            // TODO: use batching for mainnet syncing
            trace!("Fetching block hash for block {}", height);
            let block_hash = self.btc_rpc.get_block_hash(height as u64).await?;
            batch.push(BatchItem::InsertNewElement(Element {
                key: Box::new(BlockHashKey(BlockHash::from_inner(block_hash.into_inner()))),
                value: Box::new(()),
            }))
        }
        batch.push(BatchItem::InsertElement(Element {
            key: Box::new(LastBlockKey),
            value: Box::new(LastBlock(new_height)),
        }));

        self.db.apply_batch(batch.iter()).expect("DB error");

        Ok(())
    }

    fn block_is_known(&self, block_hash: BlockHash) -> bool {
        self.db
            .get_value::<_, ()>(&BlockHashKey(block_hash))
            .expect("DB error")
            .is_some()
    }

    pub fn verify_pigin(&self, peg_in_proof: &PegInProof) -> Option<Vec<(OutPoint, Amount)>> {
        if !self.block_is_known(peg_in_proof.proof_block()) {
            return None;
        }

        let our_outputs =
            peg_in_proof.get_our_tweaked_txos(&self.secp, &self.cfg.peg_in_descriptor);

        if our_outputs.len() == 0 {
            return None;
        }

        if our_outputs.iter().any(|(out_point, _)| {
            self.db
                .get_value::<_, BincodeSerialized<SpendableUTXO>>(&UTXOKey(*out_point))
                .expect("DB error")
                .is_some()
        }) {
            return None;
        }

        Some(our_outputs)
    }

    pub fn claim_pegin(&self, peg_in_proof: &PegInProof) -> Option<(Batch, mint_api::Amount)> {
        let our_outputs = self.verify_pigin(peg_in_proof)?;

        let amount: u64 = our_outputs.iter().map(|(_, amt)| amt.as_sat()).sum();
        let fee = self.cfg.per_utxo_fee.as_sat() * our_outputs.len() as u64;
        let issuance_amount = mint_api::Amount::from_sat(amount.saturating_sub(fee));

        let batch = our_outputs
            .into_iter()
            .map(|(out_point, _)| {
                BatchItem::InsertNewElement(Element {
                    key: Box::new(UTXOKey(out_point)),
                    value: Box::new(BincodeSerialized::owned(SpendableUTXO::PegIn {
                        tweak: *peg_in_proof.tweak_contract_key(),
                    })),
                })
            })
            .collect::<Vec<_>>();

        Some((batch, issuance_amount))
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
