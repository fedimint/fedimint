use bdk::bitcoin::Network;
use bdk::blockchain::{Blockchain, ConfigurableBlockchain, ElectrumBlockchain};
use bdk::descriptor::Descriptor as KeyDescriptor;
use bdk::miniscript::descriptor::DescriptorXKey;
use bdk::miniscript::DescriptorPublicKey;
use bdk::signer::Signer;
use bdk::sled::Tree;
use bdk::wallet::coin_selection::{
    BranchAndBoundCoinSelection, CoinSelectionAlgorithm, CoinSelectionResult,
};
use bdk::wallet::tx_builder::TxOrdering;
use bdk::{FeeRate, UTXO};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Amount, Txid};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

pub type Descriptor = KeyDescriptor<DescriptorPublicKey>;

pub struct Wallet {
    wallet: bdk::wallet::Wallet<ElectrumBlockchain, Tree>,
    consensus_height: u32,
    finalty_delay: u32,
    last_proposal: u32,
    signing_key: DescriptorXKey<ExtendedPrivKey>,
    secp: Secp256k1<All>,
}

impl Wallet {
    pub async fn new(
        descriptor: Descriptor,
        db_path: &Path,
        btc_node: &str,
        network: Network,
        finalty_delay: u32,
        signing_key: DescriptorXKey<ExtendedPrivKey>, // change to HSM API
    ) -> Result<Self, WalletError> {
        let db = bdk::sled::open(db_path.join("wallet"))?;
        let wallet_tree = db.open_tree("wallet")?;
        let blockchain =
            ElectrumBlockchain::from_config(&bdk::blockchain::ElectrumBlockchainConfig {
                url: btc_node.to_owned(),
                socks5: None,
                retry: 5, // TODO: make configurable? probably replace with filters
                timeout: Some(5),
            })?;
        let wallet = bdk::wallet::Wallet::new(descriptor, None, network, wallet_tree, blockchain)?;

        let wallet = tokio::task::spawn_blocking(move || -> Result<_, WalletError> {
            wallet.sync(bdk::blockchain::log_progress(), None)?;
            Ok(wallet)
        })
        .await
        .unwrap()?;

        let mut secp = Secp256k1::new();
        secp.randomize(&mut rand::rngs::OsRng::new().unwrap());

        Ok(Wallet {
            wallet,
            consensus_height: 0,
            finalty_delay,
            last_proposal: 0,
            signing_key,
            secp,
        })
    }

    pub fn block_height_proposal(&self) -> Result<u32, WalletError> {
        let network_height = self.wallet.client().get_height()?;
        let target_height = network_height.saturating_sub(self.finalty_delay);

        if target_height >= self.last_proposal {
            Ok(target_height)
        } else {
            warn!(
                "The block height shrunk, new proposal would be {}, but we are sticking to our last block height proposal {}.",
                target_height,
                self.last_proposal
            );
            Ok(self.last_proposal)
        }
    }

    pub fn process_block_height_proposals(&mut self, mut proposals: Vec<u32>) {
        trace!("Received block height proposals {:?}", &proposals);

        // TODO: also warn on less than 2/3, that should never happen
        if proposals.is_empty() {
            error!("No block height proposals were submitted this round");
            return;
        }

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

    pub fn balance(&self) -> Result<Amount, WalletError> {
        // FIXME: use delayed blockchain instead of after-the-fact filtering
        let height_map = self.height_map()?;

        let utxos = self.wallet.list_unspent()?;
        let sats = utxos
            .into_iter()
            .filter(|utxo| {
                height_map
                    .get(&utxo.outpoint.txid)
                    .map(|utxo_height| *utxo_height <= self.consensus_height)
                    .unwrap_or(false) // possibly due to mempool UTXOs that might be returned?
            })
            .map(|utxo| utxo.txout.value)
            .sum();

        Ok(Amount::from_sat(sats))
    }

    pub async fn create_pegout_tx(
        &self,
        recipient: Address,
        amt: Amount,
    ) -> Result<PartiallySignedTransaction, WalletError> {
        let mut tx_builder = self
            .wallet
            .build_tx()
            .coin_selection(self.coin_selection(BranchAndBoundCoinSelection::new(10_000_000))?);

        tx_builder
            .add_recipient(recipient.script_pubkey(), amt.as_sat())
            .enable_rbf()
            .ordering(TxOrdering::BIP69Lexicographic);

        let (mut tx, meta) = tx_builder.finish()?;

        // Make sure we aren't sending more than we want due to some coin selection snafu
        assert_eq!(meta.sent, amt.as_sat());

        self.signing_key.sign(&mut tx, None, &self.secp)?;

        Ok(tx)
    }

    fn coin_selection<S>(
        &self,
        selector: S,
    ) -> Result<ConsensusHeightCoinSelector<S>, WalletError> {
        Ok(ConsensusHeightCoinSelector {
            height_map: self.height_map()?,
            consensus_height: self.consensus_height,
            inner_selector: selector,
        })
    }

    fn height_map(&self) -> Result<HashMap<Txid, u32>, WalletError> {
        Ok(self
            .wallet
            .list_transactions(false)?
            .into_iter()
            .filter_map(|tx| tx.height.map(|height| (tx.txid, height)))
            .collect())
    }
}

#[derive(Debug)]
struct ConsensusHeightCoinSelector<S> {
    height_map: HashMap<Txid, u32>,
    consensus_height: u32,
    inner_selector: S,
}

impl<S: CoinSelectionAlgorithm<D>, D: bdk::database::Database> CoinSelectionAlgorithm<D>
    for ConsensusHeightCoinSelector<S>
{
    fn coin_select(
        &self,
        database: &D,
        required_utxos: Vec<(UTXO, usize)>,
        optional_utxos: Vec<(UTXO, usize)>,
        fee_rate: FeeRate,
        amount_needed: u64,
        fee_amount: f32,
    ) -> Result<CoinSelectionResult, bdk::Error> {
        assert!(required_utxos.is_empty());

        let optional_utxos = optional_utxos
            .into_iter()
            .filter(|(utxo, _)| {
                self.height_map
                    .get(&utxo.outpoint.txid)
                    .map(|utxo_height| *utxo_height <= self.consensus_height)
                    .unwrap_or(false) // possibly due to mempool UTXOs that might be returned?
            })
            .collect();

        self.inner_selector.coin_select(
            database,
            required_utxos,
            optional_utxos,
            fee_rate,
            amount_needed,
            fee_amount,
        )
    }
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Database error: {0:?}")]
    DbError(bdk::sled::Error),
    #[error("Electrum error: {0:?}")]
    BdkError(bdk::Error),
    #[error("Sign error: {0:?}")]
    SignError(bdk::signer::SignerError),
}

impl From<bdk::sled::Error> for WalletError {
    fn from(e: bdk::sled::Error) -> Self {
        WalletError::DbError(e)
    }
}

impl From<bdk::Error> for WalletError {
    fn from(e: bdk::Error) -> Self {
        WalletError::BdkError(e)
    }
}

impl From<bdk::signer::SignerError> for WalletError {
    fn from(e: bdk::signer::SignerError) -> Self {
        WalletError::SignError(e)
    }
}
