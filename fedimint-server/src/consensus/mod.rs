#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod server;

use std::sync::Arc;

use anyhow::bail;
use bitcoin_hashes::sha256;
use fedimint_core::block::{AcceptedItem, Block, SignedBlock};
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::epoch::*;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ServerModuleRegistry};
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::{timing, Amount, OutPoint, PeerId};
use futures::StreamExt;
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::ServerConfig;
use crate::consensus::server::LatestContributionByPeer;
use crate::db::{
    AcceptedItemKey, AcceptedItemPrefix, AcceptedTransactionKey, AlephUnitsPrefix,
    ClientConfigSignatureKey, ClientConfigSignatureShareKey, ClientConfigSignatureSharePrefix,
    SignedBlockKey, SignedBlockPrefix,
};
use crate::transaction::TransactionError;

// TODO: we should make other fields private and get rid of this
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FedimintConsensus {
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig,
    /// Modules registered with the federation
    pub modules: ServerModuleRegistry,
    /// Database storing the result of processing consensus outcomes
    pub db: Database,
    /// API for accessing state
    pub client_cfg_hash: sha256::Hash,
    /// track the latest contribution by peer
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    /// The index of the current consensus session
    pub session_index: u64,
    /// The index of the next consensus item
    pub item_index: u64,
}

impl FedimintConsensus {
    pub fn decoders(&self) -> ModuleDecoderRegistry {
        self.modules.decoder_registry()
    }

    pub async fn load_current_session(
        cfg: ServerConfig,
        modules: ServerModuleRegistry,
        db: Database,
        client_cfg_hash: sha256::Hash,
        latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    ) -> Self {
        let session_index = db
            .begin_transaction()
            .await
            .find_by_prefix(&SignedBlockPrefix)
            .await
            .count()
            .await as u64;

        FedimintConsensus {
            cfg,
            modules,
            db,
            client_cfg_hash,
            latest_contribution_by_peer,
            session_index,
            item_index: 0,
        }
    }

    pub async fn build_block(&self) -> Block {
        Block {
            items: self
                .db
                .begin_transaction()
                .await
                .find_by_prefix(&AcceptedItemPrefix)
                .await
                .map(|entry| entry.1)
                .collect()
                .await,
        }
    }

    pub async fn complete_session(&self, signed_block: SignedBlock) {
        let mut dbtx = self.db.begin_transaction().await;

        dbtx.remove_by_prefix(&AlephUnitsPrefix).await;

        dbtx.remove_by_prefix(&AcceptedItemPrefix).await;

        if dbtx
            .insert_entry(&SignedBlockKey(self.session_index), &signed_block)
            .await
            .is_some()
        {
            panic!("We tried to overwrite a signed block");
        }

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");
    }

    pub async fn process_consensus_item(
        &mut self,
        item: ConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_item");

        debug!("Peer {peer}: {}", debug::item_message(&item));

        self.latest_contribution_by_peer
            .write()
            .await
            .insert(peer, self.session_index);

        let mut dbtx = self.db.begin_transaction().await;

        if let Some(accepted_item) = dbtx.get_value(&AcceptedItemKey(self.item_index)).await {
            if accepted_item.item == item && accepted_item.peer == peer {
                self.item_index += 1;
                return Ok(());
            }

            bail!("Consensus item was discarded before recovery");
        }

        self.process_consensus_item_with_db_transaction(&mut dbtx, item.clone(), peer)
            .await?;

        dbtx.insert_entry(
            &AcceptedItemKey(self.item_index),
            &AcceptedItem { item, peer },
        )
        .await;

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

        if audit.net_assets().milli_sat < 0 {
            panic!("Balance sheet of the fed has gone negative, this should never happen! {audit}")
        }

        dbtx.commit_tx_result()
            .await
            .expect("Committing consensus epoch failed");

        self.item_index += 1;

        Ok(())
    }

    async fn process_consensus_item_with_db_transaction(
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

                let mut funding_verifier = FundingVerifier::default();
                let mut public_keys = Vec::new();

                for input in transaction.inputs.iter() {
                    let meta = self
                        .modules
                        .get_expect(input.module_instance_id())
                        .process_input(
                            &mut dbtx.with_module_prefix(input.module_instance_id()),
                            input,
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
                    .verify(&signature_share.0, self.client_cfg_hash)
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
        }
    }
}

pub struct FundingVerifier {
    input_amount: Amount,
    output_amount: Amount,
    fee_amount: Amount,
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
