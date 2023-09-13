#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod server;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

use anyhow::bail;
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::epoch::*;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ServerModuleRegistry};
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::server::DynVerificationCache;
use fedimint_core::{timing, Amount, NumPeers, OutPoint, PeerId, TransactionId};
use fedimint_logging::LOG_CONSENSUS;
use futures::future::select_all;
use futures::StreamExt;
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use tracing::{debug, instrument, warn};

use crate::config::ServerConfig;
use crate::db::{
    AcceptedTransactionKey, ClientConfigSignatureKey, ClientConfigSignatureShareKey,
    ClientConfigSignatureSharePrefix, ConsensusUpgradeKey, EpochHistoryKey, LastEpochKey,
};
use crate::net::api::ConsensusApi;
use crate::transaction::{Transaction, TransactionError};

pub type HbbftSerdeConsensusOutcome = Batch<Vec<SerdeConsensusItem>, PeerId>;
pub type HbbftConsensusOutcome = Batch<Vec<ConsensusItem>, PeerId>;
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
            contributions: BTreeMap::from_iter(history.items),
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
    ForceProcessOutcome(EpochOutcome),
}

// TODO: we should make other fields private and get rid of this
#[non_exhaustive]
pub struct FedimintConsensus {
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig,
    /// Modules config gen information
    pub module_inits: ServerModuleInitRegistry,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Database storing the result of processing consensus outcomes
    pub db: Database,
    /// API for accessing state
    pub api: ConsensusApi,
    /// Cache of `ApiEvent` to include in a proposal
    pub api_event_cache: HashSet<ApiEvent>,
}

#[derive(Debug)]
pub struct VerificationCaches {
    pub caches: HashMap<ModuleInstanceId, DynVerificationCache>,
}

pub struct FundingVerifier {
    input_amount: Amount,
    output_amount: Amount,
    fee_amount: Amount,
}

impl VerificationCaches {
    pub(crate) fn get_cache(&self, module_key: ModuleInstanceId) -> &DynVerificationCache {
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
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_outcome");

        let mut rejected_txs = BTreeSet::new();
        // Since multiple peers can submit the same tx within epoch, track them
        // and handle only once.
        let mut processed_txes = BTreeSet::new();

        let items = consensus_outcome
            .clone()
            .contributions
            .into_iter()
            .flat_map(|(peer_id, items)| items.into_iter().map(move |item| (peer_id, item)));

        let mut dbtx = self.db.begin_transaction().await;

        for (peer_id, consensus_item) in items {
            dbtx.set_tx_savepoint()
                .await
                .expect("Setting transaction savepoint failed");

            if let ConsensusItem::Transaction(ref transaction) = consensus_item {
                if !processed_txes.insert(transaction.tx_hash()) {
                    continue;
                }
            }

            match self
                .process_consensus_item(&mut dbtx, consensus_item.clone(), peer_id)
                .await
            {
                Ok(()) => {
                    debug!(
                        target: LOG_CONSENSUS,
                        "Accept consensus item from {peer_id}"
                    );
                }
                Err(error) => {
                    debug!(
                        target: LOG_CONSENSUS,
                        "Discard consensus item from {peer_id}: {error}"
                    );

                    dbtx.rollback_tx_to_savepoint()
                        .await
                        .expect("Rolling back transaction to savepoint failed");

                    if let ConsensusItem::Transaction(transaction) = consensus_item {
                        rejected_txs.insert(transaction.tx_hash());
                    }
                }
            }
        }

        if let Some(reference_rejected_txs) = reference_rejected_txs.as_ref() {
            // Result of the consensus are supposed to be deterministic.
            // If our result is not the same as what the (honest) majority of the federation
            // signed over, it's a catastrophic bug/mismatch of Federation's fedimintd
            // implementations.
            assert_eq!(
                reference_rejected_txs, &rejected_txs,
                "rejected_txs mismatch: reference = {reference_rejected_txs:?} != {rejected_txs:?}"
            );
        }

        let epoch_history = self
            .save_epoch_history(consensus_outcome, &mut dbtx, &mut vec![], rejected_txs)
            .await;

        dbtx.commit_tx_result()
            .await
            .expect("Committing consensus epoch failed");

        let audit = self.audit().await;

        if audit.net_assets().milli_sat < 0 {
            panic!("Balance sheet of the fed has gone negative, this should never happen! {audit}")
        }

        epoch_history
    }

    async fn process_consensus_item(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        consensus_item: ConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // We rely on decoding rejecting any unknown module instance ids to avoid
        // peer-triggered panic here
        self.decoders().assert_reject_mode();

        match consensus_item {
            ConsensusItem::Module(module_item) => {
                let moduletx = &mut dbtx.with_module_prefix(module_item.module_instance_id());

                self.modules
                    .get_expect(module_item.module_instance_id())
                    .process_consensus_item(moduletx, module_item, peer_id)
                    .await
            }
            ConsensusItem::Transaction(transaction) => {
                if dbtx
                    .get_value(&AcceptedTransactionKey(transaction.tx_hash()))
                    .await
                    .is_some()
                {
                    bail!("The transaction is already accepted");
                }

                let txid = transaction.tx_hash();
                let caches = self.build_verification_caches(transaction.clone());

                let mut funding_verifier = FundingVerifier::default();
                let mut public_keys = Vec::new();

                for input in transaction.inputs.iter() {
                    let meta = self
                        .modules
                        .get_expect(input.module_instance_id())
                        .process_input(
                            &mut dbtx.with_module_prefix(input.module_instance_id()),
                            input,
                            caches.get_cache(input.module_instance_id()),
                        )
                        .await?;

                    funding_verifier.add_input(meta.amount);
                    public_keys.push(meta.pub_keys);
                }

                transaction.validate_signature(public_keys.into_iter().flatten())?;

                for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
                    let amount = self
                        .modules
                        .get_expect(output.module_instance_id())
                        .process_output(
                            &mut dbtx.with_module_prefix(output.module_instance_id()),
                            output,
                            OutPoint { txid, out_idx },
                        )
                        .await?;

                    funding_verifier.add_output(amount);
                }

                funding_verifier.verify_funding()?;

                let modules_ids = transaction
                    .outputs
                    .iter()
                    .map(|output| output.module_instance_id())
                    .collect::<Vec<_>>();

                dbtx.insert_entry(&AcceptedTransactionKey(txid), &modules_ids)
                    .await;

                Ok(())
            }
            ConsensusItem::ClientConfigSignatureShare(signature_share) => {
                if dbtx
                    .get_isolated()
                    .get_value(&ClientConfigSignatureKey)
                    .await
                    .is_some()
                {
                    bail!("Client config is already signed");
                }

                if dbtx
                    .get_value(&ClientConfigSignatureShareKey(peer_id))
                    .await
                    .is_some()
                {
                    bail!("Already received a valid signature share for this peer");
                }

                let pks = self.cfg.consensus.auth_pk_set.clone();

                if !pks
                    .public_key_share(peer_id.to_usize())
                    .verify(&signature_share.0, self.api.client_cfg.consensus_hash())
                {
                    bail!("Client config signature share is invalid");
                }

                // we have received the first valid signature share for this peer
                dbtx.insert_new_entry(&ClientConfigSignatureShareKey(peer_id), &signature_share)
                    .await;

                // collect all valid signature shares received previously
                let signature_shares = dbtx
                    .find_by_prefix(&ClientConfigSignatureSharePrefix)
                    .await
                    .map(|(key, share)| (key.0.to_usize(), share.0))
                    .collect::<Vec<_>>()
                    .await;

                if signature_shares.len() <= pks.threshold() {
                    return Ok(());
                }

                let threshold_signature = pks
                    .combine_signatures(signature_shares.iter().map(|(peer, share)| (peer, share)))
                    .expect("All signature shares are valid");

                dbtx.remove_by_prefix(&ClientConfigSignatureSharePrefix)
                    .await;

                dbtx.insert_entry(
                    &ClientConfigSignatureKey,
                    &SerdeSignature(threshold_signature),
                )
                .await;

                Ok(())
            }
            ConsensusItem::ConsensusUpgrade(..) => {
                let mut peers = dbtx
                    .get_value(&ConsensusUpgradeKey)
                    .await
                    .unwrap_or_default();

                if !peers.insert(peer_id) {
                    bail!("Already received an upgrade signal by this peer")
                }

                dbtx.insert_entry(&ConsensusUpgradeKey, &peers).await;

                Ok(())
            }
            // these items are handled in save_epoch_history
            ConsensusItem::EpochOutcomeSignatureShare(..) => Ok(()),
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
            .map(|(module_instance_id, _kind, module)| {
                Box::pin(async move {
                    let mut dbtx = self.db.begin_transaction().await;
                    let mut module_dbtx = dbtx.with_module_prefix(module_instance_id);
                    module.await_consensus_proposal(&mut module_dbtx).await
                })
            })
            .collect::<Vec<_>>();

        if !proposal_futures.is_empty() {
            select_all(proposal_futures).await;
        } else {
            std::future::pending().await
        }
    }

    pub async fn get_consensus_proposal(&self) -> ConsensusProposal {
        let mut dbtx = self.db.begin_transaction().await;

        let mut items: Vec<ConsensusItem> = self
            .api_event_cache
            .iter()
            .cloned()
            .filter_map(|event| match event {
                ApiEvent::Transaction(tx) => Some(ConsensusItem::Transaction(tx)),
                ApiEvent::UpgradeSignal => Some(ConsensusItem::ConsensusUpgrade(ConsensusUpgrade)),
                ApiEvent::ForceProcessOutcome(_) => None,
            })
            .collect();
        let mut force_new_epoch = false;

        for (instance_id, _, module) in self.modules.iter_modules() {
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

            let timing = timing::TimeReporter::new("sign last epoch key");
            let sig = self.cfg.private.epoch_sks.0.sign(last_epoch.hash);
            drop(timing);
            let item = ConsensusItem::EpochOutcomeSignatureShare(SerdeSignatureShare(sig));
            items.push(item);
        };

        // Add a signature share for the client config hash if we don't have it signed
        // yet
        let sig = dbtx
            .get_isolated()
            .get_value(&ClientConfigSignatureKey)
            .await;
        if sig.is_none() {
            let hash = self.api.client_cfg.consensus_hash();
            let timing = timing::TimeReporter::new("sign client config");
            let share = self.cfg.private.auth_sks.0.sign(hash);
            drop(timing);
            let item = ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(share));
            items.push(item);
        }

        let drop_peers = vec![];

        ConsensusProposal {
            items,
            drop_peers,
            force_new_epoch,
        }
    }

    fn build_verification_caches(&self, transaction: Transaction) -> VerificationCaches {
        let _timing /* logs on drop */ = timing::TimeReporter::new("build_verification_caches");
        let module_inputs = transaction
            .inputs
            .into_iter()
            .into_group_map_by(|input| input.module_instance_id());

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
        let _timing /* logs on drop */ = timing::TimeReporter::new("audit");
        let mut dbtx = self.db.begin_transaction().await;
        let mut audit = Audit::default();
        for (module_instance_id, _, module) in self.modules.iter_modules() {
            module
                .audit(
                    &mut dbtx.with_module_prefix(module_instance_id),
                    &mut audit,
                    module_instance_id,
                )
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
