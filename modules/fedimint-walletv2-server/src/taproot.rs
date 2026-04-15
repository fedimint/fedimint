use std::collections::BTreeMap;

use anyhow::{Context, bail, ensure};
use bitcoin::hashes::sha256;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use bitcoin::{ScriptBuf, TapLeafHash, TxOut};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::{BitcoinHash, NumPeersExt, PeerId};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::{descriptor_tr, tweak_xonly_public_key};
use futures::StreamExt;
use secp256k1::{Keypair, PublicKey, Scalar, XOnlyPublicKey, schnorr};
use tracing::debug;

use crate::db::{
    SchnorrSignaturesKey, SchnorrSignaturesTxidPrefix, UnconfirmedTxKey, UnsignedTxKey,
};
use crate::{FederationTx, Wallet};

impl Wallet {
    pub(crate) fn script_pubkey_for(&self, tweak: &sha256::Hash) -> ScriptBuf {
        match self.cfg.consensus.descriptor {
            WalletDescriptor::Wsh => self.descriptor(tweak).script_pubkey(),
            WalletDescriptor::Tr => {
                descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak).script_pubkey()
            }
        }
    }

    pub(crate) async fn process_signatures_schnorr(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: bitcoin::Txid,
        signatures: Vec<schnorr::Signature>,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let mut unsigned = dbtx
            .get_value(&UnsignedTxKey(txid))
            .await
            .context("Unsigned transaction does not exist")?;

        let pk = self
            .cfg
            .consensus
            .bitcoin_pks
            .get(&peer)
            .expect("Failed to get public key of peer from config");

        self.verify_signatures_schnorr(&unsigned, &signatures, *pk)?;

        if dbtx
            .insert_entry(&SchnorrSignaturesKey(txid, peer), &signatures)
            .await
            .is_some()
        {
            bail!("Already received valid signatures from this peer")
        }

        let signatures = dbtx
            .find_by_prefix(&SchnorrSignaturesTxidPrefix(txid))
            .await
            .map(|(key, signatures)| (key.1, signatures))
            .collect::<BTreeMap<PeerId, Vec<schnorr::Signature>>>()
            .await;

        if signatures.len() == self.cfg.consensus.bitcoin_pks.to_num_peers().threshold() {
            dbtx.remove_entry(&UnsignedTxKey(txid)).await;

            dbtx.remove_by_prefix(&SchnorrSignaturesTxidPrefix(txid))
                .await;

            self.finalize_tx_schnorr(&mut unsigned, &signatures);

            dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
                .await;
            if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
                debug!(target: LOG_MODULE_WALLETV2, err = %err.fmt_compact_anyhow(), "Error broadcasting finalized transaction");
            }
        }
        Ok(())
    }

    fn tap_leaf_hash(&self, tweak: &sha256::Hash) -> TapLeafHash {
        let tr = descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak);
        let (_, ms) = tr
            .iter_scripts()
            .next()
            .expect("Taproot descriptor always has exactly one script leaf");
        TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript)
    }

    fn build_prevouts(&self, unsigned_tx: &FederationTx) -> Vec<TxOut> {
        unsigned_tx
            .spent_tx_outs
            .iter()
            .map(|utxo| TxOut {
                value: utxo.value,
                script_pubkey: self.script_pubkey_for(&utxo.tweak),
            })
            .collect()
    }

    pub(crate) fn sign_tx_schnorr(&self, unsigned_tx: &FederationTx) -> Vec<schnorr::Signature> {
        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .map(|(index, utxo)| {
                let leaf_hash = self.tap_leaf_hash(&utxo.tweak);
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        leaf_hash,
                        bitcoin::TapSighashType::Default,
                    )
                    .expect("Failed to compute taproot script spend sighash");

                let scalar = &Scalar::from_be_bytes(utxo.tweak.to_byte_array())
                    .expect("Hash is within field order");

                let keypair =
                    Keypair::from_secret_key(secp256k1::SECP256K1, &self.cfg.private.bitcoin_sk);
                let tweaked_keypair = keypair
                    .add_xonly_tweak(secp256k1::SECP256K1, scalar)
                    .expect("Failed to tweak bitcoin keypair");
                secp256k1::SECP256K1
                    .sign_schnorr(&secp256k1::Message::from(sighash), &tweaked_keypair)
            })
            .collect()
    }

    pub(crate) fn verify_signatures_schnorr(
        &self,
        unsigned_tx: &FederationTx,
        signatures: &[schnorr::Signature],
        pk: PublicKey,
    ) -> anyhow::Result<()> {
        ensure!(
            unsigned_tx.spent_tx_outs.len() == signatures.len(),
            "Incorrect number of signatures"
        );

        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        let xonly = pk.x_only_public_key().0;

        for ((index, utxo), signature) in unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .zip(signatures.iter())
        {
            let leaf_hash = self.tap_leaf_hash(&utxo.tweak);

            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    bitcoin::TapSighashType::Default,
                )
                .expect("Failed to compute taproot script spend sighash");

            let pk = tweak_xonly_public_key(&xonly, &utxo.tweak);

            secp256k1::SECP256K1.verify_schnorr(
                signature,
                &secp256k1::Message::from(sighash),
                &pk,
            )?;
        }

        Ok(())
    }

    fn finalize_tx_schnorr(
        &self,
        federation_tx: &mut FederationTx,
        signatures: &BTreeMap<PeerId, Vec<schnorr::Signature>>,
    ) {
        assert_eq!(
            federation_tx.spent_tx_outs.len(),
            federation_tx.tx.input.len()
        );

        for (index, utxo) in federation_tx.spent_tx_outs.iter().enumerate() {
            let leaf_hash = self.tap_leaf_hash(&utxo.tweak);

            let satisfier: BTreeMap<(XOnlyPublicKey, TapLeafHash), bitcoin::taproot::Signature> =
                signatures
                    .iter()
                    .map(|(peer, sigs)| {
                        assert_eq!(sigs.len(), federation_tx.tx.input.len());

                        let pk = self
                            .cfg
                            .consensus
                            .bitcoin_pks
                            .get(peer)
                            .expect("Failed to get public key of peer from config")
                            .x_only_public_key()
                            .0;

                        let pk = tweak_xonly_public_key(&pk, &utxo.tweak);

                        (
                            (pk, leaf_hash),
                            bitcoin::taproot::Signature {
                                signature: sigs[index],
                                sighash_type: bitcoin::TapSighashType::Default,
                            },
                        )
                    })
                    .collect();

            miniscript::Descriptor::Tr(descriptor_tr(&self.cfg.consensus.bitcoin_pks, &utxo.tweak))
                .satisfy(&mut federation_tx.tx.input[index], satisfier)
                .expect("Failed to satisfy descriptor");
        }
    }
}
