#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod server;

use std::collections::HashMap;

use anyhow::bail;
use bitcoin_hashes::sha256;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::encoding::Decodable;
use fedimint_core::epoch::*;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ServerModuleRegistry};
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::server::DynVerificationCache;
use fedimint_core::{timing, Amount, OutPoint, PeerId};
use futures::StreamExt;
use itertools::Itertools;
use tracing::debug;

use crate::config::ServerConfig;
use crate::db::{
    AcceptedTransactionKey, ClientConfigSignatureKey, ClientConfigSignatureShareKey,
    ClientConfigSignatureSharePrefix,
};
use crate::transaction::{Transaction, TransactionError};

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
}

#[derive(Debug)]
pub struct VerificationCaches {
    pub caches: HashMap<ModuleInstanceId, DynVerificationCache>,
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

    pub async fn process_consensus_item(
        &self,
        item: Vec<u8>,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_item");

        let mut reader = std::io::Cursor::new(item);
        let consensus_item = ConsensusItem::consensus_decode(&mut reader, &self.decoders())?;

        let item_debug = debug::item_message(&consensus_item);
        debug!("\n  Peer {peer_id}: {item_debug}");

        let mut dbtx = self.db.begin_transaction().await;

        self.process_consensus_item_with_db_transaction(&mut dbtx, consensus_item, peer_id)
            .await?;

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

    pub async fn get_consensus_proposal(&self) -> Vec<ConsensusItem> {
        let mut dbtx = self.db.begin_transaction().await;

        // We ignore any writes
        dbtx.ignore_uncommitted();

        let mut consensus_items = Vec::new();

        for (instance_id, _, module) in self.modules.iter_modules() {
            let items = module
                .consensus_proposal(&mut dbtx.with_module_prefix(instance_id), instance_id)
                .await
                .into_iter()
                .map(ConsensusItem::Module);

            consensus_items.extend(items);
        }

        // Add a signature share for the client config hash
        let sig = dbtx
            .get_isolated()
            .get_value(&ClientConfigSignatureKey)
            .await;

        if sig.is_none() {
            let timing = timing::TimeReporter::new("sign client config");
            let share = self.cfg.private.auth_sks.0.sign(self.client_cfg_hash);
            drop(timing);
            let item = ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(share));
            consensus_items.push(item);
        }

        consensus_items
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
