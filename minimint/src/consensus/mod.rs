#![allow(clippy::let_unit_value)]

mod conflictfilter;
mod interconnect;

use crate::config::ServerConfig;
use crate::consensus::conflictfilter::ConflictFilterable;
use crate::consensus::interconnect::MinimintInterconnect;
use crate::db::{
    AcceptedTransactionKey, DropPeerKey, DropPeerKeyPrefix, ProposedTransactionKey,
    ProposedTransactionKeyPrefix,
};
use crate::outcome::OutputOutcome;
use crate::rng::RngGenerator;
use crate::transaction::{Input, Output, Transaction, TransactionError};
use hbbft::honey_badger::Batch;
use minimint_api::db::batch::{BatchTx, DbBatch};
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{FederationModule, OutPoint, PeerId, TransactionId};
use minimint_derive::UnzipConsensus;
use minimint_ln::{LightningModule, LightningModuleError};
use minimint_mint::{Mint, MintError};
use minimint_wallet::{Wallet, WalletError};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info_span, instrument, trace, warn};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, UnzipConsensus)]
pub enum ConsensusItem {
    Transaction(Transaction),
    Mint(<Mint as FederationModule>::ConsensusItem),
    Wallet(<Wallet as FederationModule>::ConsensusItem),
    LN(<LightningModule as FederationModule>::ConsensusItem),
}

pub type HoneyBadgerMessage = hbbft::honey_badger::Message<PeerId>;
pub type ConsensusOutcome = Batch<Vec<ConsensusItem>, PeerId>;

/// Proposed HBBFT consensus changes including removing peers
#[derive(Debug, Clone)]
pub struct ConsensusProposal {
    pub items: Vec<ConsensusItem>,
    pub drop_peers: Vec<PeerId>,
}

pub struct MinimintConsensus<R>
where
    R: RngCore + CryptoRng,
{
    /// Cryptographic random number generator used for everything
    pub rng_gen: Box<dyn RngGenerator<Rng = R>>,
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig,

    /// Our local mint
    pub mint: Mint, // TODO: generate consensus code using Macro, making modules replaceable for testing and easy adaptability
    pub wallet: Wallet,
    pub ln: LightningModule,

    /// KV Database into which all state is persisted to recover from in case of a crash
    pub db: Arc<dyn Database>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct AcceptedTransaction {
    pub epoch: u64,
    pub transaction: Transaction,
}

#[derive(Debug)]
struct VerificationCaches {
    mint: <Mint as FederationModule>::VerificationCache,
    wallet: <Wallet as FederationModule>::VerificationCache,
    ln: <LightningModule as FederationModule>::VerificationCache,
}

impl<R> MinimintConsensus<R>
where
    R: RngCore + CryptoRng,
{
    pub fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        let tx_hash = transaction.tx_hash();
        debug!(%tx_hash, "Received mint transaction");

        transaction.validate_funding(&self.cfg.fee_consensus)?;

        let mut pub_keys = Vec::new();
        for input in &transaction.inputs {
            let meta = match input {
                Input::Mint(coins) => {
                    let cache = self.mint.build_verification_cache(std::iter::once(coins));
                    self.mint
                        .validate_input(&self.build_interconnect(), &cache, coins)
                        .map_err(TransactionSubmissionError::InputCoinError)?
                }
                Input::Wallet(peg_in) => {
                    let cache = self
                        .wallet
                        .build_verification_cache(std::iter::once(peg_in));
                    self.wallet
                        .validate_input(&self.build_interconnect(), &cache, peg_in)
                        .map_err(TransactionSubmissionError::InputPegIn)?
                }
                Input::LN(input) => {
                    let cache = self.ln.build_verification_cache(std::iter::once(input));
                    self.ln
                        .validate_input(&self.build_interconnect(), &cache, input)
                        .map_err(TransactionSubmissionError::ContractInputError)?
                }
            };
            pub_keys.push(meta.puk_keys);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for output in &transaction.outputs {
            match output {
                Output::Mint(coins) => {
                    self.mint
                        .validate_output(coins)
                        .map_err(TransactionSubmissionError::OutputCoinError)?;
                }
                Output::Wallet(peg_out) => {
                    self.wallet
                        .validate_output(peg_out)
                        .map_err(TransactionSubmissionError::OutputPegOut)?;
                }
                Output::LN(output) => {
                    self.ln
                        .validate_output(output)
                        .map_err(TransactionSubmissionError::ContractOutputError)?;
                }
            }
        }

        let new = self
            .db
            .insert_entry(&ProposedTransactionKey(tx_hash), &transaction)
            .expect("DB error");

        if new.is_some() {
            warn!("Added consensus item was already in consensus queue");
        }

        Ok(())
    }

    #[instrument(skip_all, fields(epoch = consensus_outcome.epoch))]
    pub async fn process_consensus_outcome(&self, consensus_outcome: ConsensusOutcome) {
        let epoch = consensus_outcome.epoch;
        let epoch_peers: HashSet<PeerId> =
            consensus_outcome.contributions.keys().copied().collect();

        let UnzipConsensusItem {
            transaction: transaction_cis,
            wallet: wallet_cis,
            mint: mint_cis,
            ln: ln_cis,
        } = consensus_outcome
            .contributions
            .into_iter()
            .flat_map(|(peer, cis)| cis.into_iter().map(move |ci| (peer, ci)))
            .unzip_consensus_item();

        // Begin consensus epoch
        {
            let mut db_batch = DbBatch::new();
            self.wallet
                .begin_consensus_epoch(db_batch.transaction(), wallet_cis, self.rng_gen.get_rng())
                .await;
            self.mint
                .begin_consensus_epoch(db_batch.transaction(), mint_cis, self.rng_gen.get_rng())
                .await;
            self.ln
                .begin_consensus_epoch(db_batch.transaction(), ln_cis, self.rng_gen.get_rng())
                .await;
            self.db.apply_batch(db_batch).expect("DB error");
        }

        // Process transactions
        {
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

            let mut db_batch = DbBatch::new();
            let caches =
                self.build_verification_caches(filtered_transactions.iter().map(|(_, tx)| tx));
            for (peer, transaction) in filtered_transactions {
                let mut batch_tx = db_batch.transaction();

                let span = info_span!("Processing transaction", %peer);
                // in_scope to make sure that no await is in the middle of the span
                let _enter = span.in_scope(|| {
                    trace!(?transaction);
                    batch_tx.append_maybe_delete(ProposedTransactionKey(transaction.tx_hash()));

                    // TODO: use borrowed transaction
                    match self.process_transaction(
                        batch_tx.subtransaction(),
                        transaction.clone(),
                        &caches,
                    ) {
                        Ok(()) => {
                            batch_tx.append_insert(
                                AcceptedTransactionKey(transaction.tx_hash()),
                                AcceptedTransaction { epoch, transaction },
                            );
                        }
                        Err(error) => {
                            // TODO: log error for user
                            warn!(%error, "Transaction failed");
                        }
                    }
                    batch_tx.commit();
                });
            }
            self.db.apply_batch(db_batch).expect("DB error");
        }

        // End consensus epoch
        {
            let mut db_batch = DbBatch::new();
            let mut drop_peers = Vec::<PeerId>::new();

            let mut drop_wallet = self
                .wallet
                .end_consensus_epoch(&epoch_peers, db_batch.transaction(), self.rng_gen.get_rng())
                .await;

            let mut drop_mint = self
                .mint
                .end_consensus_epoch(&epoch_peers, db_batch.transaction(), self.rng_gen.get_rng())
                .await;

            let mut drop_ln = self
                .ln
                .end_consensus_epoch(&epoch_peers, db_batch.transaction(), self.rng_gen.get_rng())
                .await;

            drop_peers.append(&mut drop_wallet);
            drop_peers.append(&mut drop_mint);
            drop_peers.append(&mut drop_ln);

            let mut batch_tx = db_batch.transaction();
            for peer in drop_peers {
                batch_tx.append_insert(DropPeerKey(peer), ());
            }
            batch_tx.commit();

            self.db.apply_batch(db_batch).expect("DB error");
        }
    }

    pub async fn get_consensus_proposal(&self) -> ConsensusProposal {
        let drop_peers = self
            .db
            .find_by_prefix(&DropPeerKeyPrefix)
            .map(|res| {
                let key = res.expect("DB error").0;
                key.0
            })
            .collect();

        let items = self
            .db
            .find_by_prefix(&ProposedTransactionKeyPrefix)
            .map(|res| {
                let (_key, value) = res.expect("DB error");
                ConsensusItem::Transaction(value)
            })
            .chain(
                self.wallet
                    .consensus_proposal(self.rng_gen.get_rng())
                    .await
                    .into_iter()
                    .map(ConsensusItem::Wallet),
            )
            .chain(
                self.mint
                    .consensus_proposal(self.rng_gen.get_rng())
                    .await
                    .into_iter()
                    .map(ConsensusItem::Mint),
            )
            .chain(
                self.ln
                    .consensus_proposal(self.rng_gen.get_rng())
                    .await
                    .into_iter()
                    .map(ConsensusItem::LN),
            )
            .collect();

        ConsensusProposal { items, drop_peers }
    }

    fn process_transaction(
        &self,
        mut batch: BatchTx,
        transaction: Transaction,
        caches: &VerificationCaches,
    ) -> Result<(), TransactionSubmissionError> {
        transaction.validate_funding(&self.cfg.fee_consensus)?;

        let tx_hash = transaction.tx_hash();

        let mut pub_keys = Vec::new();
        for input in transaction.inputs.iter() {
            let meta = match input {
                Input::Mint(coins) => self
                    .mint
                    .apply_input(
                        &self.build_interconnect(),
                        batch.subtransaction(),
                        coins,
                        &caches.mint,
                    )
                    .map_err(TransactionSubmissionError::InputCoinError)?,
                Input::Wallet(peg_in) => self
                    .wallet
                    .apply_input(
                        &self.build_interconnect(),
                        batch.subtransaction(),
                        peg_in,
                        &caches.wallet,
                    )
                    .map_err(TransactionSubmissionError::InputPegIn)?,
                Input::LN(input) => self
                    .ln
                    .apply_input(
                        &self.build_interconnect(),
                        batch.subtransaction(),
                        input,
                        &caches.ln,
                    )
                    .map_err(TransactionSubmissionError::ContractInputError)?,
            };
            pub_keys.push(meta.puk_keys);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for (idx, output) in transaction.outputs.into_iter().enumerate() {
            let out_point = OutPoint {
                txid: tx_hash,
                out_idx: idx as u64,
            };
            match output {
                Output::Mint(new_tokens) => {
                    self.mint
                        .apply_output(batch.subtransaction(), &new_tokens, out_point)
                        .map_err(TransactionSubmissionError::OutputCoinError)?;
                }
                Output::Wallet(peg_out) => {
                    self.wallet
                        .apply_output(batch.subtransaction(), &peg_out, out_point)
                        .map_err(TransactionSubmissionError::OutputPegOut)?;
                }
                Output::LN(output) => {
                    self.ln
                        .apply_output(batch.subtransaction(), &output, out_point)
                        .map_err(TransactionSubmissionError::ContractOutputError)?;
                }
            }
        }

        batch.commit();
        Ok(())
    }

    pub fn transaction_status(
        &self,
        txid: TransactionId,
    ) -> Option<crate::outcome::TransactionStatus> {
        let accepted: Option<AcceptedTransaction> = self
            .db
            .get_value(&AcceptedTransactionKey(txid))
            .expect("DB error");

        if let Some(accepted_tx) = accepted {
            let outputs = accepted_tx
                .transaction
                .outputs
                .iter()
                .enumerate()
                .map(|(out_idx, output)| {
                    let outpoint = OutPoint {
                        txid,
                        out_idx: out_idx as u64,
                    };
                    match output {
                        Output::Mint(_) => {
                            let outcome = self
                                .mint
                                .output_status(outpoint)
                                .expect("the transaction was processed, so should be known");
                            OutputOutcome::Mint(outcome)
                        }
                        Output::Wallet(_) => {
                            let outcome = self
                                .wallet
                                .output_status(outpoint)
                                .expect("the transaction was processed, so should be known");
                            OutputOutcome::Wallet(outcome)
                        }
                        Output::LN(_) => {
                            let outcome = self
                                .ln
                                .output_status(outpoint)
                                .expect("the transaction was processed, so should be known");
                            OutputOutcome::LN(outcome)
                        }
                    }
                })
                .collect();

            Some(crate::outcome::TransactionStatus::Accepted {
                epoch: accepted_tx.epoch,
                outputs,
            })
        } else {
            None
        }
    }

    fn build_verification_caches<'a>(
        &self,
        transactions: impl Iterator<Item = &'a Transaction> + Clone + Send,
    ) -> VerificationCaches {
        let mint_input_iter = transactions
            .clone()
            .flat_map(|tx| tx.inputs.iter())
            .filter_map(|input| match input {
                Input::Mint(input) => Some(input),
                Input::Wallet(_) => None,
                Input::LN(_) => None,
            });
        let mint_cache = self.mint.build_verification_cache(mint_input_iter);

        let wallet_input_iter = transactions
            .clone()
            .flat_map(|tx| tx.inputs.iter())
            .filter_map(|input| match input {
                Input::Mint(_) => None,
                Input::Wallet(input) => Some(input),
                Input::LN(_) => None,
            });
        let wallet_cache = self.wallet.build_verification_cache(wallet_input_iter);

        let ln_input_iter = transactions
            .flat_map(|tx| tx.inputs.iter())
            .filter_map(|input| match input {
                Input::Mint(_) => None,
                Input::Wallet(_) => None,
                Input::LN(input) => Some(input),
            });
        let ln_cache = self.ln.build_verification_cache(ln_input_iter);

        VerificationCaches {
            mint: mint_cache,
            wallet: wallet_cache,
            ln: ln_cache,
        }
    }

    fn build_interconnect(&self) -> MinimintInterconnect<R> {
        MinimintInterconnect { minimint: self }
    }
}

impl<'a, R: RngCore + CryptoRng> From<&'a MinimintConsensus<R>> for &'a Wallet {
    fn from(fed: &'a MinimintConsensus<R>) -> Self {
        &fed.wallet
    }
}

impl<'a, R: RngCore + CryptoRng> From<&'a MinimintConsensus<R>> for &'a Mint {
    fn from(fed: &'a MinimintConsensus<R>) -> Self {
        &fed.mint
    }
}

impl<'a, R: RngCore + CryptoRng> From<&'a MinimintConsensus<R>> for &'a LightningModule {
    fn from(fed: &'a MinimintConsensus<R>) -> Self {
        &fed.ln
    }
}

#[derive(Debug, Error)]
pub enum TransactionSubmissionError {
    #[error("High level transaction error: {0}")]
    TransactionError(TransactionError),
    #[error("Input coin error: {0}")]
    InputCoinError(MintError),
    #[error("Input peg-in error: {0}")]
    InputPegIn(WalletError),
    #[error("LN contract input error: {0}")]
    ContractInputError(LightningModuleError),
    #[error("Output coin error: {0}")]
    OutputCoinError(MintError),
    #[error("Output coin error: {0}")]
    OutputPegOut(WalletError),
    #[error("LN contract output error: {0}")]
    ContractOutputError(LightningModuleError),
}

impl From<TransactionError> for TransactionSubmissionError {
    fn from(e: TransactionError) -> Self {
        TransactionSubmissionError::TransactionError(e)
    }
}
