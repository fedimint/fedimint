#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod interconnect;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use anyhow::format_err;
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::*;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ServerModuleRegistry};
use fedimint_core::module::{ModuleError, TransactionItemAmount};
use fedimint_core::server::DynVerificationCache;
use fedimint_core::{Amount, NumPeers, OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_CONSENSUS;
use futures::future::select_all;
use futures::StreamExt;
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use thiserror::Error;
use tracing::{error, info_span, instrument, trace, warn, Instrument};

use crate::config::ServerConfig;
use crate::consensus::interconnect::FedimintInterconnect;
use crate::consensus::TransactionSubmissionError::TransactionReplayError;
use crate::db::{
    AcceptedTransactionKey, ClientConfigSignatureKey, ConsensusUpgradeKey, DropPeerKey,
    DropPeerKeyPrefix, EpochHistoryKey, LastEpochKey, RejectedTransactionKey,
};
use crate::net::api::ConsensusApi;
use crate::transaction::{Transaction, TransactionError};

pub type HbbftSerdeConsensusOutcome = hbbft::honey_badger::Batch<Vec<SerdeConsensusItem>, PeerId>;
pub type HbbftConsensusOutcome = hbbft::honey_badger::Batch<Vec<ConsensusItem>, PeerId>;
pub type HbbftMessage = hbbft::honey_badger::Message<PeerId>;

// TODO remove HBBFT `Batch` from `ConsensusOutcome`
#[derive(Debug, Clone)]
pub struct ConsensusOutcomeConversion(pub HbbftConsensusOutcome);

impl PartialEq<Self> for ConsensusOutcomeConversion {
    fn eq(&self, other: &Self) -> bool {
        self.0.epoch.eq(&other.0.epoch) && self.0.contributions.eq(&other.0.contributions)
    }
}

impl From<EpochOutcome> for ConsensusOutcomeConversion {
    fn from(history: EpochOutcome) -> Self {
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
    pub force_new_epoch: bool,
}

/// Events that can be sent from the API to consensus thread
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum ApiEvent {
    Transaction(Transaction),
    UpgradeSignal,
}

// TODO: we should make other fields private and get rid of this
#[non_exhaustive]
pub struct FedimintConsensus {
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig,
    /// Modules config gen information
    pub module_inits: ServerModuleGenRegistry,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Database storing the result of processing consensus outcomes
    pub db: Database,
    /// API for accessing state
    pub api: ConsensusApi,
    /// Cache of `ApiEvent` to include in a proposal
    pub api_event_cache: HashSet<ApiEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct AcceptedTransaction {
    pub epoch: u64,
    pub transaction: Transaction,
}

#[derive(Debug)]
struct VerificationCaches {
    caches: HashMap<ModuleInstanceId, DynVerificationCache>,
}

pub struct FundingVerifier {
    input_amount: Amount,
    output_amount: Amount,
    fee_amount: Amount,
}

impl VerificationCaches {
    fn get_cache(&self, module_key: ModuleInstanceId) -> &DynVerificationCache {
        self.caches
            .get(&module_key)
            .expect("Verification caches were built for all modules")
    }
}

impl FedimintConsensus {
    pub fn decoders(&self) -> ModuleDecoderRegistry {
        self.modules.decoder_registry()
    }

    /// Calculate the result of the `consensus_outcome` and save it/them.
    ///
    /// `reference_rejected_txs` should be `Some` if the `consensus_outcome` is
    /// coming from a a reference (already signed) `OutcomeHistory`, that
    /// contains `rejected_txs`, so we can check it against our own
    /// `rejected_txs` we calculate in this function.
    ///
    /// **Note**: `reference_rejected_txs` **must** come from a
    /// validated/trustworthy source and be correct, or it can cause a
    /// panic.
    #[instrument(skip_all, fields(epoch = consensus_outcome.epoch))]
    pub async fn process_consensus_outcome(
        &self,
        consensus_outcome: HbbftConsensusOutcome,
        reference_rejected_txs: Option<BTreeSet<TransactionId>>,
    ) -> SignedEpochOutcome {
        let epoch_history = self
            .db
            .autocommit(
                |dbtx| {
                    let consensus_outcome = consensus_outcome.clone();
                    let reference_rejected_txs = reference_rejected_txs.clone();
                    let peers: BTreeSet<PeerId> = consensus_outcome.contributions.keys().copied().collect();

                    Box::pin(async move {
                        let epoch = consensus_outcome.epoch;
                        let outcome = consensus_outcome.clone();

                        let UnzipConsensusItem {
                            epoch_outcome_signature_share: _epoch_outcome_signature_share_cis,
                            client_config_signature_share: _client_config_signature_share_cis,
                            transaction: transaction_cis,
                            consensus_upgrade: consensus_upgrade_cis,
                            module: module_cis,
                        } = consensus_outcome
                            .contributions
                            .into_iter()
                            .flat_map(|(peer, cis)| cis.into_iter().map(move |ci| (peer, ci)))
                            .unzip_consensus_item();

                        self.process_module_consensus_items(dbtx, &module_cis, &peers).await;
                        self.process_upgrade_items(dbtx, &consensus_upgrade_cis).await;

                        let rejected_txs = self
                            .process_transactions(dbtx, epoch, &transaction_cis)
                            .await;

                        if let Some(reference_rejected_txs) = reference_rejected_txs.as_ref() {
                            // Result of the consensus are supposed to be deterministic.
                            // If our result is not the same as what the (honest) majority of the federation
                            // signed over, it's a catastrophical bug/mismatch of Federation's fedimintd
                            // implementations.
                            assert_eq!(
                                reference_rejected_txs, &rejected_txs,
                                "rejected_txs mismatch: reference = {reference_rejected_txs:?} != {rejected_txs:?}"
                            );
                        }

                        let epoch_history = self
                            .finalize_process_epoch(dbtx, outcome.clone(), rejected_txs, &peers)
                            .await;
                        Result::<_, ()>::Ok(epoch_history)
                    })
                },
                Some(100),
            )
            .await
            .expect("Committing consensus epoch failed");

        let audit = self.audit().await;
        if audit.sum().milli_sat < 0 {
            panic!("Balance sheet of the fed has gone negative, this should never happen! {audit}")
        }

        epoch_history
    }

    /// Calls `begin_consensus_epoch` on all modules, dispatching their
    /// consensus items
    async fn process_module_consensus_items(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        module_cis: &[(PeerId, fedimint_core::core::DynModuleConsensusItem)],
        consensus_peers: &BTreeSet<PeerId>,
    ) {
        let mut drop_peers = vec![];
        let per_module_cis: HashMap<
            ModuleInstanceId,
            Vec<(PeerId, fedimint_core::core::DynModuleConsensusItem)>,
        > = module_cis
            .iter()
            .cloned()
            .into_group_map_by(|(_peer, mci)| mci.module_instance_id());

        for (module_key, module_cis) in per_module_cis {
            let moduletx = &mut dbtx.with_module_prefix(module_key);
            let mut module_drop_peers = self
                .modules
                .get_expect(module_key)
                .begin_consensus_epoch(moduletx, module_cis, consensus_peers)
                .await;
            drop_peers.append(&mut module_drop_peers);
        }

        for peer in drop_peers {
            dbtx.insert_entry(&DropPeerKey(peer), &()).await;
        }
    }

    /// Applies all valid fedimint transactions to the database transaction
    /// `dbtx` and returns a set of invalid transactions that were filtered
    /// out
    async fn process_transactions(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        epoch: u64,
        transactions: &[(PeerId, Transaction)],
    ) -> BTreeSet<TransactionId> {
        // Process transactions
        let mut rejected_txs: BTreeSet<TransactionId> = BTreeSet::new();

        let caches = self.build_verification_caches(transactions.iter().map(|(_, tx)| tx));
        let mut processed_txs: HashSet<TransactionId> = HashSet::new();

        for (_, transaction) in transactions.iter().cloned() {
            let txid: TransactionId = transaction.tx_hash();
            if !processed_txs.insert(txid) {
                // Avoid processing duplicate tx from different peers
                continue;
            }

            let span = info_span!("Processing transaction");
            async {
                trace!(?transaction);

                dbtx.set_tx_savepoint()
                    .await
                    .expect("Error setting transaction savepoint");
                // TODO: use borrowed transaction
                match self
                    .process_transaction(dbtx, transaction.clone(), &caches)
                    .await
                {
                    Ok(()) => {
                        dbtx.insert_entry(
                            &AcceptedTransactionKey(txid),
                            &AcceptedTransaction { epoch, transaction },
                        )
                        .await;
                    }
                    Err(error) => {
                        rejected_txs.insert(txid);
                        dbtx.rollback_tx_to_savepoint()
                            .await
                            .expect("Error rolling back to transaction savepoint");
                        warn!(target: LOG_CONSENSUS, %error, "Transaction failed");
                        // do not insert a RejectedTransactionKey because there must already be
                        // AcceptedTransactionKey
                        if !matches!(error, TransactionReplayError(_)) {
                            dbtx.insert_entry(&RejectedTransactionKey(txid), &format!("{error:?}"))
                                .await;
                        }
                    }
                }
            }
            .instrument(span)
            .await;
        }

        rejected_txs
    }

    /// Saves the epoch history, calls `end_consensus_epoch` on all modules and
    /// bans misbehaving peers
    async fn finalize_process_epoch(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outcome: HbbftConsensusOutcome,
        rejected_txs: BTreeSet<TransactionId>,
        consensus_peers: &BTreeSet<PeerId>,
    ) -> SignedEpochOutcome {
        let mut drop_peers = Vec::<PeerId>::new();

        self.save_client_config_sig(dbtx, &outcome, &mut drop_peers)
            .await;

        let epoch_history = self
            .save_epoch_history(outcome.clone(), dbtx, &mut drop_peers, rejected_txs)
            .await;

        for (module_key, module) in self.modules.iter_modules() {
            let module_drop_peers = module
                .end_consensus_epoch(consensus_peers, &mut dbtx.with_module_prefix(module_key))
                .await;
            drop_peers.extend(module_drop_peers);
        }

        for peer in drop_peers {
            dbtx.insert_entry(&DropPeerKey(peer), &()).await;
        }

        epoch_history
    }

    /// If the client config hash isn't already signed, aggregate signature
    /// shares from peers dropping those that don't contribute.
    async fn save_client_config_sig(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outcome: &HbbftConsensusOutcome,
        drop_peers: &mut Vec<PeerId>,
    ) {
        let config = self.api.get_config_with_sig(&mut dbtx.get_isolated()).await;

        if config.client_hash_signature.is_none() {
            let maybe_client_hash = config.client.consensus_hash(&self.module_inits.to_common());
            let client_hash = maybe_client_hash.expect("hashes");
            let peers: Vec<PeerId> = outcome.contributions.keys().cloned().collect();
            let mut contributing_peers = HashSet::new();
            let pks = self.cfg.consensus.auth_pk_set.clone();

            let shares: BTreeMap<_, _> = outcome
                .contributions
                .iter()
                .flat_map(|(peer, items)| items.iter().map(|i| (*peer, i)))
                .filter_map(|(peer, item)| match item {
                    ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(sig)) => {
                        Some((peer, sig))
                    }
                    _ => None,
                })
                .filter(|(peer, sig)| {
                    let pub_key = pks.public_key_share(peer.to_usize());
                    pub_key.verify(sig, client_hash)
                })
                .map(|(peer, sig)| {
                    contributing_peers.insert(peer);
                    (peer.to_usize(), sig)
                })
                .collect();

            if let Ok(final_sig) = pks.combine_signatures(shares) {
                assert!(pks.public_key().verify(&final_sig, client_hash));
                let serde_sig = SerdeSignature(final_sig);
                dbtx.insert_entry(&ClientConfigSignatureKey, &serde_sig)
                    .await;
            } else {
                warn!(
                    target: LOG_CONSENSUS,
                    "Did not receive enough valid client config sig shares"
                )
            }

            for peer in peers {
                if !contributing_peers.contains(&peer) {
                    drop_peers.push(peer);
                }
            }
        }
    }

    /// Adds any new upgrade items to the set of signaling peers
    async fn process_upgrade_items(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        upgrade_signals: &[(PeerId, ConsensusUpgrade)],
    ) {
        if !upgrade_signals.is_empty() {
            let maybe_exists = dbtx.get_value(&ConsensusUpgradeKey).await;
            let mut peers = maybe_exists.unwrap_or_default();
            peers.extend(upgrade_signals.iter().map(|(peer, _)| peer));
            dbtx.insert_entry(&ConsensusUpgradeKey, &peers).await;
        }
    }

    /// Returns true if a threshold of peers have signaled to upgrade
    pub async fn is_at_upgrade_threshold(&self) -> bool {
        self.db
            .begin_transaction()
            .await
            .get_value(&ConsensusUpgradeKey)
            .await
            .filter(|peers| peers.len() >= self.cfg.consensus.api_endpoints.threshold())
            .is_some()
    }

    /// Called to remove the upgrade items after the upgrade is complete
    pub async fn remove_upgrade_items(&self, epoch: u64) -> anyhow::Result<()> {
        let last_epoch = self.api.get_epoch_count().await;
        let mut tx = self.db.begin_transaction().await;
        if last_epoch == epoch {
            tx.remove_entry(&ConsensusUpgradeKey).await;
            tx.commit_tx().await;
            Ok(())
        } else {
            Err(format_err!(
                "Wrong upgrade epoch {}, last epoch was {}",
                epoch,
                last_epoch
            ))
        }
    }

    async fn save_epoch_history<'a>(
        &self,
        outcome: HbbftConsensusOutcome,
        dbtx: &mut DatabaseTransaction<'a>,
        drop_peers: &mut Vec<PeerId>,
        rejected_txs: BTreeSet<TransactionId>,
    ) -> SignedEpochOutcome {
        let prev_epoch_key = EpochHistoryKey(outcome.epoch.saturating_sub(1));
        let peers: Vec<PeerId> = outcome.contributions.keys().cloned().collect();
        let maybe_prev_epoch = dbtx.get_value(&prev_epoch_key).await;

        let current = SignedEpochOutcome::new(
            outcome.epoch,
            outcome.contributions,
            rejected_txs,
            maybe_prev_epoch.as_ref(),
        );

        // validate and update sigs on prev epoch
        if let Some(prev_epoch) = maybe_prev_epoch {
            let pks = &self.cfg.consensus.epoch_pk_set;

            match current.add_sig_to_prev(pks, prev_epoch) {
                Ok(prev_epoch) => {
                    dbtx.insert_entry(&prev_epoch_key, &prev_epoch).await;
                }
                Err(EpochVerifyError::NotEnoughValidSigShares(contributing_peers)) => {
                    warn!(
                        target: LOG_CONSENSUS,
                        "Unable to sign epoch {}", prev_epoch_key.0
                    );
                    for peer in peers {
                        if !contributing_peers.contains(&peer) {
                            warn!(
                                target: LOG_CONSENSUS,
                                "Dropping {} for not contributing valid epoch sigs.", peer
                            );
                            drop_peers.push(peer);
                        }
                    }
                }
                Err(_) => panic!("Not possible"),
            }
        }

        dbtx.insert_entry(&LastEpochKey, &EpochHistoryKey(current.outcome.epoch))
            .await;
        dbtx.insert_entry(&EpochHistoryKey(current.outcome.epoch), &current)
            .await;

        current
    }

    pub async fn await_consensus_proposal(&self) {
        let proposal_futures = self
            .modules
            .iter_modules()
            .map(|(module_instance_id, module)| {
                Box::pin(async move {
                    let mut dbtx = self.db.begin_transaction().await;
                    let mut module_dbtx = dbtx.with_module_prefix(module_instance_id);
                    module.await_consensus_proposal(&mut module_dbtx).await
                })
            })
            .collect::<Vec<_>>();

        select_all(proposal_futures).await;
    }

    pub async fn get_consensus_proposal(&self) -> ConsensusProposal {
        let mut dbtx = self.db.begin_transaction().await;

        let drop_peers = dbtx
            .find_by_prefix(&DropPeerKeyPrefix)
            .await
            .map(|(key, _)| key.0)
            .collect()
            .await;

        let mut items: Vec<ConsensusItem> = self
            .api_event_cache
            .iter()
            .cloned()
            .map(|event| match event {
                ApiEvent::Transaction(tx) => ConsensusItem::Transaction(tx),
                ApiEvent::UpgradeSignal => ConsensusItem::ConsensusUpgrade(ConsensusUpgrade),
            })
            .collect();
        let mut force_new_epoch = false;

        for (instance_id, module) in self.modules.iter_modules() {
            let consensus_proposal = module
                .consensus_proposal(&mut dbtx.with_module_prefix(instance_id), instance_id)
                .await;
            if consensus_proposal.forces_new_epoch() {
                force_new_epoch = true;
            }

            items.extend(
                consensus_proposal
                    .into_items()
                    .into_iter()
                    .map(ConsensusItem::Module),
            );
        }

        if let Some(epoch) = dbtx.get_value(&LastEpochKey).await {
            let last_epoch = dbtx.get_value(&epoch).await.unwrap();
            let sig = self.cfg.private.epoch_sks.0.sign(last_epoch.hash);
            let item = ConsensusItem::EpochOutcomeSignatureShare(SerdeSignatureShare(sig));
            items.push(item);
        };

        // Add a signature share for the client config hash if we don't have it signed
        // yet
        let client = self.api.get_config_with_sig(&mut dbtx.get_isolated()).await;
        if client.client_hash_signature.is_none() {
            let maybe_client_hash = client.client.consensus_hash(&self.module_inits.to_common());
            let client_hash = maybe_client_hash.expect("Client config hashes");
            let sig = self.cfg.private.auth_sks.0.sign(client_hash);
            let item = ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(sig));
            items.push(item);
        }

        ConsensusProposal {
            items,
            drop_peers,
            force_new_epoch,
        }
    }

    async fn process_transaction<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        transaction: Transaction,
        caches: &VerificationCaches,
    ) -> Result<(), TransactionSubmissionError> {
        let mut funding_verifier = FundingVerifier::default();

        let tx_hash = transaction.tx_hash();

        if dbtx
            .get_value(&AcceptedTransactionKey(tx_hash))
            .await
            .is_some()
        {
            return Err(TransactionReplayError(tx_hash));
        }

        let mut pub_keys = Vec::new();
        for input in transaction.inputs.iter() {
            let meta = self
                .modules
                .get_expect(input.module_instance_id())
                .apply_input(
                    &FedimintInterconnect {
                        fedimint: &self.api,
                    },
                    &mut dbtx.with_module_prefix(input.module_instance_id()),
                    input,
                    caches.get_cache(input.module_instance_id()),
                )
                .await
                .map_err(|e| TransactionSubmissionError::ModuleError(tx_hash, e))?;
            pub_keys.push(meta.puk_keys);
            funding_verifier.add_input(meta.amount);
        }
        transaction.validate_signature(pub_keys.into_iter().flatten())?;

        for (idx, output) in transaction.outputs.into_iter().enumerate() {
            let out_point = OutPoint {
                txid: tx_hash,
                out_idx: idx as u64,
            };
            let amount = self
                .modules
                .get_expect(output.module_instance_id())
                .apply_output(
                    &mut dbtx.with_module_prefix(output.module_instance_id()),
                    &output,
                    out_point,
                )
                .await
                .map_err(|e| TransactionSubmissionError::ModuleError(tx_hash, e))?;
            funding_verifier.add_output(amount);
        }

        funding_verifier.verify_funding()?;

        Ok(())
    }

    fn build_verification_caches<'a>(
        &self,
        transactions: impl Iterator<Item = &'a Transaction> + Send,
    ) -> VerificationCaches {
        let module_inputs = transactions
            .flat_map(|tx| tx.inputs.iter())
            .cloned()
            .into_group_map_by(|input| input.module_instance_id());

        // TODO: should probably run in parallel, but currently only the mint does
        // anything at all
        let caches = module_inputs
            .into_iter()
            .map(|(module_key, inputs)| {
                let module = self.modules.get_expect(module_key);
                (module_key, module.build_verification_cache(&inputs))
            })
            .collect();

        VerificationCaches { caches }
    }

    pub async fn audit(&self) -> Audit {
        let mut dbtx = self.db.begin_transaction().await;
        let mut audit = Audit::default();
        for (module_instance_id, module) in self.modules.iter_modules() {
            module
                .audit(&mut dbtx.with_module_prefix(module_instance_id), &mut audit)
                .await
        }
        audit
    }
}

impl FundingVerifier {
    pub fn add_input(&mut self, input_amount: TransactionItemAmount) {
        self.input_amount += input_amount.amount;
        self.fee_amount += input_amount.fee;
    }

    pub fn add_output(&mut self, output_amount: TransactionItemAmount) {
        self.output_amount += output_amount.amount;
        self.fee_amount += output_amount.fee;
    }

    pub fn verify_funding(self) -> Result<(), TransactionError> {
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

#[derive(Debug, Error)]
pub enum TransactionSubmissionError {
    #[error("High level transaction error: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("Module input or output error in tx {0}: {1}")]
    ModuleError(TransactionId, ModuleError),
    #[error("Transaction channel was closed")]
    TxChannelError,
    #[error("Transaction was already successfully processed: {0}")]
    TransactionReplayError(TransactionId),
}
