mod conflictfilter;
mod unzip_consensus;

use crate::consensus::conflictfilter::ConflictFilterable;
use crate::consensus::unzip_consensus::{ConsensusItems, UnzipConsensus};
use crate::database::{AllConsensusItemsKeyPrefix, ConsensusItemKeyPrefix, TransactionStatusKey};
use crate::rng::RngGenerator;
use config::ServerConfig;
use database::batch::{BatchItem, BatchTx, DbBatch};
use database::{BincodeSerialized, Database, DatabaseError, RawDatabase};
use fedimint::{Mint, MintError};
use fediwallet::{Wallet, WalletError};
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use mint_api::outcome::{OutputOutcome, TransactionStatus};
use mint_api::transaction::{BlindToken, Input, OutPoint, Output, Transaction, TransactionError};
use mint_api::{Coins, FederationModule, PartialSigResponse, SignRequest, TransactionId};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ConsensusItem {
    Transaction(Transaction),
    Mint(<Mint as FederationModule>::ConsensusItem),
    Wallet(<Wallet as FederationModule>::ConsensusItem),
}

pub type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;
pub type ConsensusOutcome = Batch<Vec<ConsensusItem>, u16>;

pub struct FediMintConsensus<R>
where
    R: RngCore + CryptoRng,
{
    /// Cryptographic random number generator used for everything
    pub rng_gen: Box<dyn RngGenerator<Rng = R>>,
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig, // TODO: make custom config

    /// Our local mint
    pub mint: Mint, // TODO: generate consensus code using Macro, making modules replaceable for testing and easy adaptability
    pub wallet: Wallet,

    /// KV Database into which all state is persisted to recover from in case of a crash
    pub db: Arc<dyn RawDatabase>,
}

impl<R> FediMintConsensus<R>
where
    R: RngCore + CryptoRng,
{
    pub fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        let tx_hash = transaction.tx_hash();
        debug!("Received mint transaction {}", tx_hash);

        transaction.validate_funding(&self.cfg.fee_consensus)?;
        transaction.validate_signature()?;

        for input in &transaction.inputs {
            match input {
                Input::Coins(coins) => {
                    self.mint
                        .validate_input(coins)
                        .map_err(TransactionSubmissionError::InputCoinError)?;
                }
                Input::PegIn(peg_in) => {
                    self.wallet
                        .validate_input(peg_in)
                        .map_err(TransactionSubmissionError::InputPegIn)?;
                }
            }
        }

        for output in &transaction.outputs {
            match output {
                Output::Coins(coins) => {
                    self.mint
                        .validate_output(coins)
                        .map_err(TransactionSubmissionError::OutputCoinError)?;
                }
                Output::PegOut(peg_out) => {
                    self.wallet
                        .validate_output(peg_out)
                        .map_err(TransactionSubmissionError::OutputPegOut)?;
                }
            }
        }

        let new = self
            .db
            .insert_entry(&ConsensusItem::Transaction(transaction), &())
            .expect("DB error");

        if new.is_some() {
            warn!("Added consensus item was already in consensus queue");
        } else {
            // TODO: unify with consensus stuff
            self.db
                .insert_entry(
                    &TransactionStatusKey(tx_hash),
                    &BincodeSerialized::owned(TransactionStatus::AwaitingConsensus),
                )
                .expect("DB error");
        }

        Ok(())
    }

    pub async fn process_consensus_outcome(&self, consensus_outcome: ConsensusOutcome) {
        info!("Processing output of epoch {}", consensus_outcome.epoch);

        let mut db_batch = DbBatch::new();

        let ConsensusItems {
            transactions: transaction_cis,
            wallet: wallet_cis,
            mint: mint_cis,
        } = consensus_outcome
            .contributions
            .into_iter()
            .flat_map(|(peer, cis)| cis.into_iter().map(move |ci| (peer, ci)))
            .unzip_consensus();

        self.wallet
            .begin_consensus_epoch(db_batch.transaction(), wallet_cis, self.rng_gen.get_rng())
            .await;

        // Since the changes to the database will happen all at once we won't be able to handle
        // conflicts between consensus items in one batch there. Thus we need to make sure that
        // all items in a batch are consistent/deterministically filter out inconsistent ones.
        // There are two item types that need checking:
        //  * peg-ins that each peg-in tx is only used to issue coins once
        //  * coin spends to avoid double spends in one batch
        let filtered_transactions = transaction_cis
            .into_iter()
            .filter_conflicts(|(_, tx)| tx)
            .collect::<Vec<_>>();

        // TODO: implement own parallel execution to avoid allocations and get rid of rayon
        let par_db_batches = filtered_transactions
            .into_par_iter()
            .map(|(peer, transaction)| {
                trace!(
                    "Processing transaction {:?} from peer {}",
                    transaction,
                    peer
                );
                let mut db_batch = DbBatch::new();
                db_batch.autocommit(|batch_tx| {
                    batch_tx.append_maybe_delete(ConsensusItem::Transaction(transaction.clone()))
                });
                // TODO: use borrowed transaction
                match self.process_transaction(db_batch.transaction(), transaction.clone()) {
                    Ok(()) => {
                        db_batch.autocommit(|batch_tx| {
                            batch_tx.append_insert(
                                TransactionStatusKey(transaction.tx_hash()),
                                BincodeSerialized::owned(TransactionStatus::Accepted),
                            );
                        });
                    }
                    Err(e) => {
                        warn!("Transaction proposed by peer {} failed: {}", peer, e);
                        db_batch.autocommit(|batch_tx| {
                            batch_tx.append_insert(
                                TransactionStatusKey(transaction.tx_hash()),
                                BincodeSerialized::owned(TransactionStatus::Error(e.to_string())),
                            )
                        });
                    }
                }

                db_batch
            })
            .collect::<Vec<_>>();
        db_batch.autocommit(|tx| tx.append_from_accumulators(par_db_batches.into_iter()));

        // Apply all consensus-critical changes atomically to the DB
        self.db.apply_batch(db_batch).expect("DB error");
    }

    pub async fn get_consensus_proposal(&self) -> Vec<ConsensusItem> {
        self.db
            .find_by_prefix(&AllConsensusItemsKeyPrefix)
            .map(|res| res.map(|(ci, ())| ci))
            .chain(
                self.wallet
                    .consensus_proposal(rand::rngs::OsRng::new().unwrap())
                    .await
                    .into_iter()
                    .map(|wci| Ok(ConsensusItem::Wallet(wci))),
            )
            .collect::<Result<_, DatabaseError>>()
            .expect("DB error")
    }

    fn process_transaction(
        &self,
        mut batch: BatchTx,
        transaction: Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        transaction.validate_funding(&self.cfg.fee_consensus)?;
        transaction.validate_signature()?;

        let tx_hash = transaction.tx_hash();

        for input in transaction.inputs {
            match input {
                Input::Coins(coins) => {
                    self.mint
                        .apply_input(batch.subtransaction(), &coins, self.rng_gen.get_rng())
                        .map_err(TransactionSubmissionError::InputCoinError)?;
                }
                Input::PegIn(peg_in) => {
                    self.wallet
                        .apply_input(batch.subtransaction(), &peg_in, self.rng_gen.get_rng())
                        .map_err(TransactionSubmissionError::InputPegIn)?;
                }
            }
        }

        for (idx, output) in transaction.outputs.into_iter().enumerate() {
            match output {
                Output::Coins(new_tokens) => {}
                Output::PegOut(peg_out) => {
                    self.wallet
                        .apply_output(
                            batch.subtransaction(),
                            &peg_out,
                            OutPoint {
                                txid: tx_hash,
                                out_idx: idx,
                            },
                            self.rng_gen.get_rng(),
                        )
                        .map_err(TransactionSubmissionError::OutputPegOut)?;
                }
            }
        }

        batch.commit();
        Ok(())
    }

    fn tbs_threshold(&self) -> usize {
        self.cfg.peers.len() - self.cfg.max_faulty() - 1
    }
}

fn to_sign_request(coins: Coins<BlindToken>) -> SignRequest {
    SignRequest(
        coins
            .into_iter()
            .map(|(amt, token)| (amt, token.0))
            .collect(),
    )
}

#[derive(Debug, Error)]
pub enum TransactionSubmissionError {
    #[error("High level transaction error: {0}")]
    TransactionError(TransactionError),
    #[error("Input coin error: {0}")]
    InputCoinError(MintError),
    #[error("Input peg-in error: {0}")]
    InputPegIn(WalletError),
    #[error("Output coin error: {0}")]
    OutputCoinError(MintError),
    #[error("Output coin error: {0}")]
    OutputPegOut(WalletError),
}

impl From<TransactionError> for TransactionSubmissionError {
    fn from(e: TransactionError) -> Self {
        TransactionSubmissionError::TransactionError(e)
    }
}
