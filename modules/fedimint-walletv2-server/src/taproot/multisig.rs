use std::collections::BTreeMap;

use anyhow::{Context, bail, ensure};
use bitcoin::TapLeafHash;
use bitcoin::sighash::{Prevouts, SighashCache};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::{BitcoinHash, NumPeersExt, PeerId};
use fedimint_walletv2_common::taproot::{descriptor_tr, nums_point, tweak_xonly_public_key};
use futures::StreamExt;
use secp256k1::{Keypair, PublicKey, Scalar, XOnlyPublicKey, schnorr};

use crate::db::{SchnorrSignaturesKey, SchnorrSignaturesTxidPrefix, UnsignedTxKey};
use crate::{FederationTx, Wallet};

impl Wallet {
    /// Handle a `SchnorrSignatures` consensus item under the
    /// `WalletDescriptor::Tr` descriptor (NUMS internal key + k-of-n
    /// `multi_a` script-path). Looks up `peer`'s bitcoin pubkey,
    /// verifies the signatures against the script-spend sighash, stores
    /// them under `(txid, peer)`, and once `threshold` peers have
    /// contributed assembles the witness via miniscript's `satisfy`
    /// and broadcasts the finalized transaction.
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
            dbtx.remove_by_prefix(&SchnorrSignaturesTxidPrefix(txid))
                .await;

            self.finalize_tx_schnorr(&mut unsigned, &signatures);

            self.finalize_and_broadcast(dbtx, txid, unsigned).await;
        }
        Ok(())
    }

    /// Produce one Schnorr signature per input for the script-path
    /// spend of `unsigned_tx`. Each signature is over the
    /// `taproot_script_spend_signature_hash` for that input's
    /// `tap_leaf_hash` (the `multi_a` leaf). The signing key is the
    /// guardian's `bitcoin_sk` tweaked by the per-UTXO fedimint tweak —
    /// matching `descriptor_tr`'s tweaked-key entries — so the
    /// signature verifies against that peer's tweaked entry inside
    /// the `multi_a`.
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

    /// Verify that `signatures` (one per input of `unsigned_tx`) are
    /// valid script-path signatures from `pk`. For each input we
    /// reconstruct the same script-spend sighash as `sign_tx_schnorr`
    /// and verify against `tweak_xonly_public_key(pk_xonly,
    /// utxo.tweak)` — the peer's tweaked entry inside the `multi_a`
    /// script. Returns an error on the first failed verification or
    /// signature-count mismatch.
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

    /// Assemble the script-path witness for every input of
    /// `federation_tx` once the `threshold` set of peer signatures
    /// has been collected. For each input we hand miniscript a
    /// `(tweaked_xonly_pk, leaf_hash) -> Signature` map and let
    /// `Descriptor::Tr(...).satisfy()` produce the witness — the
    /// `multi_a` script consumes `threshold` of those signatures and
    /// pushes the script + control block. The transaction is mutated
    /// in place; the caller broadcasts it afterwards.
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

            miniscript::Descriptor::Tr(descriptor_tr(
                &self.cfg.consensus.bitcoin_pks,
                &utxo.tweak,
                nums_point(),
            ))
            .satisfy(&mut federation_tx.tx.input[index], satisfier)
            .expect("Failed to satisfy descriptor");
        }
    }
}
