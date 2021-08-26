use crate::consensus::ConsensusItem;
use fedimint::{Mint, PartiallySignedRequest};
use fediwallet::{Wallet, WalletConsensusItem};
use mint_api::transaction::Transaction;
use mint_api::{FederationModule, TransactionId};

pub struct ConsensusItems {
    pub transactions: Vec<(u16, Transaction)>,
    pub wallet: Vec<(u16, <Wallet as FederationModule>::ConsensusItem)>,
    // TODO: put txid and output idx into partial sig response
    pub mint: Vec<(u16, <Mint as FederationModule>::ConsensusItem)>,
}

pub trait UnzipConsensus {
    fn unzip_consensus(self) -> ConsensusItems;
}

impl<I> UnzipConsensus for I
where
    I: Iterator<Item = (u16, ConsensusItem)>,
{
    fn unzip_consensus(mut self) -> ConsensusItems {
        let mut transactions = Vec::new();
        let mut wallet = Vec::new();
        let mut mint = Vec::new();

        while let Some((peer, consensus_item)) = self.next() {
            match consensus_item {
                ConsensusItem::Transaction(tx) => {
                    transactions.push((peer, tx));
                }
                ConsensusItem::Mint(mci) => {
                    mint.push((peer, mci));
                }
                ConsensusItem::Wallet(wci) => {
                    wallet.push((peer, wci));
                }
            }
        }

        ConsensusItems {
            transactions,
            wallet,
            mint,
        }
    }
}
