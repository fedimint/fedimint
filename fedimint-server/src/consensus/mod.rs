#![allow(clippy::let_unit_value)]

mod conflictfilter;
pub mod debug;
mod interconnect;

use std::collections::{BTreeMap, HashSet};
use std::iter::FromIterator;
use std::sync::Arc;

use fedimint_api::core::ModuleKey;
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::audit::Audit;
use fedimint_api::module::{ModuleError, TransactionItemAmount};
use fedimint_api::server::ServerModule;
use fedimint_api::{Amount, OutPoint, PeerId, ServerModulePlugin, TransactionId};
use fedimint_core::epoch::*;
use fedimint_core::modules::ln::LightningModule;
use fedimint_core::modules::mint::Mint;
use fedimint_core::outcome::TransactionStatus;
use fedimint_wallet::Wallet;
use futures::future::select_all;
use hbbft::honey_badger::Batch;
use rand::rngs::OsRng;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Notify;
use tracing::{debug, error, info_span, instrument, trace, warn};

use crate::config::ServerConfig;
use crate::consensus::conflictfilter::ConflictFilterable;
use crate::consensus::interconnect::FedimintInterconnect;
use crate::db::{
    AcceptedTransactionKey, DropPeerKey, DropPeerKeyPrefix, EpochHistoryKey, LastEpochKey,
    ProposedTransactionKey, ProposedTransactionKeyPrefix, RejectedTransactionKey,
};
use crate::outcome::OutputOutcome;
use crate::rng::RngGenerator;
use crate::transaction::{Input, Output, Transaction, TransactionError};
use crate::OsRngGen;

pub type SerdeConsensusOutcome = Batch<Vec<SerdeConsensusItem>, PeerId>;
pub type ConsensusOutcome = Batch<Vec<ConsensusItem>, PeerId>;
pub type HoneyBadgerMessage = hbbft::honey_badger::Message<PeerId>;

// TODO remove HBBFT `Batch` from `ConsensusOutcome`
#[derive(Debug, Clone)]
pub struct ConsensusOutcomeConversion(pub ConsensusOutcome);

impl PartialEq<Self> for ConsensusOutcomeConversion {
    fn eq(&self, other: &Self) -> bool {
        self.0.epoch.eq(&other.0.epoch) && self.0.contributions.eq(&other.0.contributions)
    }
}

impl From<OutcomeHistory> for ConsensusOutcomeConversion {
    fn from(history: OutcomeHistory) -> Self {
        ConsensusOutcomeConversion(Batch {
            epoch: history.epoch,
            contributions: BTreeMap::from_iter(history.items.into_iter()),
        })
    }
}

/// Proposed HBBFT consensus changes including removing peers
#[derive(Debug, Clone)]
pub struct ConsensusProposal {
    pub items: Vec<ConsensusItem>,
    pub drop_peers: Vec<PeerId>,
}

// TODO: we should make other fields private and get rid of this
#[non_exhaustive]
pub struct FedimintConsensus {
    /// Cryptographic random number generator used for everything
    pub rng_gen: Box<dyn RngGenerator<Rng = OsRng>>,
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig,

    /// Our local mint
    pub wallet: Wallet,
    pub ln: LightningModule,
    pub mint: Mint,

    pub modules: BTreeMap<ModuleKey, ServerModule>,
    /// KV Database into which all state is persisted to recover from in case of a crash
    pub db: Database,

    /// Notifies tasks when there is a new transaction
    pub transaction_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize)]
pub struct AcceptedTransaction {
    pub epoch: u64,
    pub transaction: Transaction,
}

#[derive(Debug)]
struct VerificationCaches {
    mint: <Mint as ServerModulePlugin>::VerificationCache,
    wallet: <Wallet as ServerModulePlugin>::VerificationCache,
    ln: <LightningModule as ServerModulePlugin>::VerificationCache,
}

struct FundingVerifier {
    input_amount: Amount,
    output_amount: Amount,
    fee_amount: Amount,
}

impl FedimintConsensus {
    pub fn new(
        cfg: ServerConfig,
        mint: Mint,
        wallet: Wallet,
        ln: LightningModule,
        db: Database,
    ) -> Self {
        Self {
            rng_gen: Box::new(OsRngGen),
            cfg,
            mint,
            wallet,
            ln,
            modules: BTreeMap::default(),
            db,
            transaction_notify: Arc::new(Notify::new()),
        }
    }

    pub fn register_module(&mut self, module: ServerModule) -> &mut Self {
        if self.modules.insert(module.module_key(), module).is_some() {
            panic!("Must not register modules with key conflict");
        }
        self
    }
}

impl FedimintConsensus {
    pub fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        // we already processed the transaction before the request was received
        if self.transaction_status(transaction.tx_hash()).is_some() {
            return Ok(());
        }

        let tx_hash = transaction.tx_hash();
        debug!(%tx_hash, "Received mint transaction");

        let mut funding_verifier = FundingVerifier::default();

        let mut pub_keys = Vec::new();

        // Create read-only DB tx so that the read state is consistent
        let dbtx = self.db.begin_transaction();

        for input in &transaction.inputs {
            let meta = match input {
                Input::Mint(coins) => {
                    let cache = self.mint.build_verification_cache(std::iter::once(coins));
                    self.mint
                        .validate_input(&self.build_interconnect(), &dbtx, &cache, coins)
                        .map_err(TransactionSubmissionError::InputCoinError)?
                }
                Input::Wallet(peg_in) => {
                    let cache = self
                        .wallet
                        .build_verification_cache(std::iter::once(peg_in));
                    self.wallet
                        .validate_input(&self.build_interconnect(), &dbtx, &cache, peg_in)
                        .map_err(TransactionSubmissionError::InputPegIn)?
                }
                Input::LN(input) => {
                    let cache = self.ln.build_verification_cache(std::iter::once(input));
                    self.ln
                        .validate_input(&self.build_interconnect(), &dbtx, &cache, input)
                        .map_err(TransactionSubmissionError::ContractInputError)?
                }
            };
            pub_keys.push(meta.puk_keys);
            funding_verifier.add_input(meta.amount);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for output in &transaction.outputs {
            let amount = match output {
                Output::Mint(coins) => self
                    .mint
                    .validate_output(coins)
                    .map_err(TransactionSubmissionError::OutputCoinError)?,
                Output::Wallet(peg_out) => self
                    .wallet
                    .validate_output(peg_out)
                    .map_err(TransactionSubmissionError::OutputPegOut)?,
                Output::LN(output) => self
                    .ln
                    .validate_output(output)
                    .map_err(TransactionSubmissionError::ContractOutputError)?,
            };
            funding_verifier.add_output(amount);
        }

        funding_verifier.verify_funding()?;

        futures::executor::block_on(async {
            let mut dbtx = self.db.begin_transaction();
            let new = dbtx
                .insert_entry(&ProposedTransactionKey(tx_hash), &transaction)
                .expect("DB error");
            dbtx.commit_tx().await.expect("DB Error");

            if new.is_some() {
                warn!("Added consensus item was already in consensus queue");
            }
        });

        self.transaction_notify.notify_one();
        Ok(())
    }

    #[instrument(skip_all, fields(epoch = consensus_outcome.epoch))]
    pub async fn process_consensus_outcome(&self, consensus_outcome: ConsensusOutcome) {
        let epoch = consensus_outcome.epoch;
        let epoch_peers: HashSet<PeerId> =
            consensus_outcome.contributions.keys().copied().collect();
        let outcome = consensus_outcome.clone();

        let UnzipConsensusItem {
            epoch_info: _epoch_info_cis,
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
            let mut dbtx = self.db.begin_transaction();
            self.wallet
                .begin_consensus_epoch(&mut dbtx, wallet_cis)
                .await;
            self.mint.begin_consensus_epoch(&mut dbtx, mint_cis).await;
            self.ln.begin_consensus_epoch(&mut dbtx, ln_cis).await;
            dbtx.commit_tx().await.expect("DB Error");
        }

        // Process transactions
        {
            // Since the changes to the database will happen all at once we won't be able to handle
            // conflicts between consensus items in one batch there. Thus we need to make sure that
            // all items in a batch are consistent/deterministically filter out inconsistent ones.
            // There are two item types that need checking:
            //  * peg-ins that each peg-in tx is only used to issue coins once
            //  * coin spends to avoid double spends in one batch
            //  * only one peg-out allowed per epoch
            let (ok_tx, err_tx) = transaction_cis
                .into_iter()
                .filter_conflicts(|(_, tx)| tx)
                .partitioned();

            let mut dbtx = self.db.begin_transaction();

            for transaction in err_tx {
                dbtx.insert_entry(
                    &RejectedTransactionKey(transaction.tx_hash()),
                    &format!("{:?}", TransactionSubmissionError::TransactionConflictError),
                )
                .expect("DB Error");
                dbtx.remove_entry(&ProposedTransactionKey(transaction.tx_hash()))
                    .expect("DB Error");
            }

            let caches = self.build_verification_caches(ok_tx.iter());
            for transaction in ok_tx {
                let span = info_span!("Processing transaction");
                // in_scope to make sure that no await is in the middle of the span
                let _enter = span.in_scope(|| {
                    trace!(?transaction);
                    dbtx.remove_entry(&ProposedTransactionKey(transaction.tx_hash()))
                        .expect("DB Error");

                    // TODO: use borrowed transaction
                    match self.process_transaction(&mut dbtx, transaction.clone(), &caches) {
                        Ok(()) => {
                            dbtx.insert_entry(
                                &AcceptedTransactionKey(transaction.tx_hash()),
                                &AcceptedTransaction { epoch, transaction },
                            )
                            .expect("DB Error");
                        }
                        Err(error) => {
                            dbtx.rollback_tx_to_savepoint();
                            warn!(%error, "Transaction failed");
                            dbtx.insert_entry(
                                &RejectedTransactionKey(transaction.tx_hash()),
                                &format!("{:?}", error),
                            )
                            .expect("DB Error");
                        }
                    }
                });
            }
            dbtx.commit_tx().await.expect("DB Error");
        }

        // End consensus epoch
        {
            let mut dbtx = self.db.begin_transaction();
            let mut drop_peers = Vec::<PeerId>::new();

            self.save_epoch_history(outcome, &mut dbtx, &mut drop_peers);

            let mut drop_wallet = self
                .wallet
                .end_consensus_epoch(&epoch_peers, &mut dbtx)
                .await;

            let mut drop_mint = self.mint.end_consensus_epoch(&epoch_peers, &mut dbtx).await;

            let mut drop_ln = self.ln.end_consensus_epoch(&epoch_peers, &mut dbtx).await;

            drop_peers.append(&mut drop_wallet);
            drop_peers.append(&mut drop_mint);
            drop_peers.append(&mut drop_ln);

            for peer in drop_peers {
                dbtx.insert_entry(&DropPeerKey(peer), &())
                    .expect("DB Error");
            }

            dbtx.commit_tx().await.expect("DB Error");
        }

        let audit = self.audit();
        if audit.sum().milli_sat < 0 {
            panic!(
                "Balance sheet of the fed has gone negative, this should never happen! {}",
                audit
            )
        }
    }

    pub fn epoch_history(&self, epoch: u64) -> Option<EpochHistory> {
        self.db
            .begin_transaction()
            .get_value(&EpochHistoryKey(epoch))
            .unwrap()
    }

    fn save_epoch_history<'a>(
        &self,
        outcome: ConsensusOutcome,
        dbtx: &mut DatabaseTransaction<'a>,
        drop_peers: &mut Vec<PeerId>,
    ) {
        let prev_epoch_key = EpochHistoryKey(outcome.epoch.saturating_sub(1));
        let peers: Vec<PeerId> = outcome.contributions.keys().cloned().collect();
        let maybe_prev_epoch = self
            .db
            .begin_transaction()
            .get_value(&prev_epoch_key)
            .expect("DB error");

        let current = EpochHistory::new(outcome.epoch, outcome.contributions, &maybe_prev_epoch);

        // validate and update sigs on prev epoch
        if let Some(prev_epoch) = maybe_prev_epoch {
            let pks = &self.cfg.epoch_pk_set;

            match current.add_sig_to_prev(pks, prev_epoch) {
                Ok(prev_epoch) => {
                    dbtx.insert_entry(&prev_epoch_key, &prev_epoch)
                        .expect("DB Error");
                }
                Err(EpochVerifyError::NotEnoughValidSigShares(contributing_peers)) => {
                    warn!("Unable to sign epoch {}", prev_epoch_key.0);
                    for peer in peers {
                        if !contributing_peers.contains(&peer) {
                            warn!("Dropping {} for not contributing valid epoch sigs.", peer);
                            drop_peers.push(peer);
                        }
                    }
                }
                Err(_) => panic!("Not possible"),
            }
        }

        dbtx.insert_entry(&LastEpochKey, &EpochHistoryKey(current.outcome.epoch))
            .expect("DB Error");
        dbtx.insert_entry(&EpochHistoryKey(current.outcome.epoch), &current)
            .expect("DB Error");
    }

    pub async fn await_consensus_proposal(&self) {
        select_all(vec![
            self.wallet.await_consensus_proposal(),
            self.ln.await_consensus_proposal(),
            self.mint.await_consensus_proposal(),
        ])
        .await;
    }

    pub async fn get_consensus_proposal(&self) -> ConsensusProposal {
        let drop_peers = self
            .db
            .begin_transaction()
            .find_by_prefix(&DropPeerKeyPrefix)
            .map(|res| {
                let key = res.expect("DB error").0;
                key.0
            })
            .collect();

        let mut items: Vec<ConsensusItem> = self
            .db
            .begin_transaction()
            .find_by_prefix(&ProposedTransactionKeyPrefix)
            .map(|res| {
                let (_key, value) = res.expect("DB error");
                ConsensusItem::Transaction(value)
            })
            .chain(
                self.wallet
                    .consensus_proposal()
                    .await
                    .into_iter()
                    .map(ConsensusItem::Wallet),
            )
            .chain(
                self.mint
                    .consensus_proposal()
                    .await
                    .into_iter()
                    .map(ConsensusItem::Mint),
            )
            .chain(
                self.ln
                    .consensus_proposal()
                    .await
                    .into_iter()
                    .map(ConsensusItem::LN),
            )
            .collect();

        if let Some(epoch) = self
            .db
            .begin_transaction()
            .get_value(&LastEpochKey)
            .unwrap()
        {
            let last_epoch = self
                .db
                .begin_transaction()
                .get_value(&epoch)
                .unwrap()
                .unwrap();
            let sig = self.cfg.epoch_sks.0.sign(last_epoch.hash);
            let item = ConsensusItem::EpochInfo(EpochSignatureShare(sig));
            items.push(item);
        };

        ConsensusProposal { items, drop_peers }
    }

    fn process_transaction<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        transaction: Transaction,
        caches: &VerificationCaches,
    ) -> Result<(), TransactionSubmissionError> {
        let mut funding_verifier = FundingVerifier::default();

        let tx_hash = transaction.tx_hash();

        let mut pub_keys = Vec::new();
        for input in transaction.inputs.iter() {
            let meta = match input {
                Input::Mint(coins) => self
                    .mint
                    .apply_input(&self.build_interconnect(), dbtx, coins, &caches.mint)
                    .map_err(TransactionSubmissionError::InputCoinError)?,
                Input::Wallet(peg_in) => self
                    .wallet
                    .apply_input(&self.build_interconnect(), dbtx, peg_in, &caches.wallet)
                    .map_err(TransactionSubmissionError::InputPegIn)?,
                Input::LN(input) => self
                    .ln
                    .apply_input(&self.build_interconnect(), dbtx, input, &caches.ln)
                    .map_err(TransactionSubmissionError::ContractInputError)?,
            };
            pub_keys.push(meta.puk_keys);
            funding_verifier.add_input(meta.amount);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for (idx, output) in transaction.outputs.into_iter().enumerate() {
            let out_point = OutPoint {
                txid: tx_hash,
                out_idx: idx as u64,
            };
            let amount = match output {
                Output::Mint(new_tokens) => self
                    .mint
                    .apply_output(dbtx, &new_tokens, out_point)
                    .map_err(TransactionSubmissionError::OutputCoinError)?,
                Output::Wallet(peg_out) => self
                    .wallet
                    .apply_output(dbtx, &peg_out, out_point)
                    .map_err(TransactionSubmissionError::OutputPegOut)?,
                Output::LN(output) => self
                    .ln
                    .apply_output(dbtx, &output, out_point)
                    .map_err(TransactionSubmissionError::ContractOutputError)?,
            };
            funding_verifier.add_output(amount);
        }

        funding_verifier.verify_funding()?;

        Ok(())
    }

    pub fn transaction_status(
        &self,
        txid: TransactionId,
    ) -> Option<crate::outcome::TransactionStatus> {
        let accepted: Option<AcceptedTransaction> = self
            .db
            .begin_transaction()
            .get_value(&AcceptedTransactionKey(txid))
            .expect("DB error");

        if let Some(accepted_tx) = accepted {
            let outputs =
                accepted_tx
                    .transaction
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(out_idx, output)| {
                        let outpoint = OutPoint {
                            txid,
                            out_idx: out_idx as u64,
                        };
                        let outcome =
                            match output {
                                Output::Mint(_) => {
                                    let outcome = self.mint.output_status(outpoint).expect(
                                        "the transaction was processed, so should be known",
                                    );
                                    OutputOutcome::Mint(outcome)
                                }
                                Output::Wallet(_) => {
                                    let outcome = self.wallet.output_status(outpoint).expect(
                                        "the transaction was processed, so should be known",
                                    );
                                    OutputOutcome::Wallet(outcome)
                                }
                                Output::LN(_) => {
                                    let outcome = self.ln.output_status(outpoint).expect(
                                        "the transaction was processed, so should be known",
                                    );
                                    OutputOutcome::LN(outcome)
                                }
                            };
                        (&outcome).into()
                    })
                    .collect();

            return Some(crate::outcome::TransactionStatus::Accepted {
                epoch: accepted_tx.epoch,
                outputs,
            });
        }

        let rejected: Option<String> = self
            .db
            .begin_transaction()
            .get_value(&RejectedTransactionKey(txid))
            .expect("DB error");

        if let Some(message) = rejected {
            return Some(TransactionStatus::Rejected(message));
        }

        None
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

    pub fn audit(&self) -> Audit {
        let mut audit = Audit::default();
        self.mint.audit(&mut audit);
        self.ln.audit(&mut audit);
        self.wallet.audit(&mut audit);
        audit
    }

    fn build_interconnect(&self) -> FedimintInterconnect {
        FedimintInterconnect { fedimint: self }
    }
}

impl FundingVerifier {
    fn add_input(&mut self, input_amount: TransactionItemAmount) {
        self.input_amount += input_amount.amount;
        self.fee_amount += input_amount.fee;
    }

    fn add_output(&mut self, output_amount: TransactionItemAmount) {
        self.output_amount += output_amount.amount;
        self.fee_amount += output_amount.fee;
    }

    fn verify_funding(self) -> Result<(), TransactionError> {
        if self.input_amount == (self.output_amount + self.fee_amount) {
            Ok(())
        } else {
            Err(TransactionError::UnbalancedTransaction {
                inputs: self.input_amount,
                outputs: self.output_amount,
                fee: self.fee_amount,
            })
        }
    }
}

impl Default for FundingVerifier {
    fn default() -> Self {
        FundingVerifier {
            input_amount: Amount::ZERO,
            output_amount: Amount::ZERO,
            fee_amount: Amount::ZERO,
        }
    }
}

impl AsRef<Wallet> for FedimintConsensus {
    fn as_ref(&self) -> &Wallet {
        &self.wallet
    }
}

impl AsRef<Mint> for FedimintConsensus {
    fn as_ref(&self) -> &Mint {
        &self.mint
    }
}

impl AsRef<LightningModule> for FedimintConsensus {
    fn as_ref(&self) -> &LightningModule {
        &self.ln
    }
}

impl AsRef<FedimintConsensus> for FedimintConsensus {
    fn as_ref(&self) -> &FedimintConsensus {
        self
    }
}

#[derive(Debug, Error)]
pub enum TransactionSubmissionError {
    #[error("High level transaction error: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("Input coin error: {0}")]
    InputCoinError(ModuleError),
    #[error("Input peg-in error: {0}")]
    InputPegIn(ModuleError),
    #[error("LN contract input error: {0}")]
    ContractInputError(ModuleError),
    #[error("Output coin error: {0}")]
    OutputCoinError(ModuleError),
    #[error("Output coin error: {0}")]
    OutputPegOut(ModuleError),
    #[error("LN contract output error: {0}")]
    ContractOutputError(ModuleError),
    #[error("Transaction conflict error")]
    TransactionConflictError,
}
