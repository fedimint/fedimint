use anyhow::{Context, bail, ensure};
use bitcoin::key::TapTweak;
use bitcoin::sighash::{Prevouts, SighashCache};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::{BitcoinHash, PeerId};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::tweak_xonly_public_key;
use secp256k1::{Keypair, Scalar, schnorr};
use tracing::debug;

use crate::db::{SchnorrSignaturesKey, UnconfirmedTxKey, UnsignedTxKey};
use crate::{FederationTx, Wallet};

impl Wallet {
    /// Handle a `SchnorrSignatures` consensus item under the
    /// `WalletDescriptor::SinglePeer` descriptor. Verifies the signatures
    /// against the lone peer's tweaked output key, persists them, builds
    /// the key-path witness, and broadcasts the finalized transaction to
    /// the bitcoin node. The threshold is trivially 1, so finalization
    /// happens on the first valid `SchnorrSignatures` item.
    pub(crate) async fn process_signatures_single_peer(
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

        self.verify_signatures_single_peer(&unsigned, &signatures)?;

        if dbtx
            .insert_entry(&SchnorrSignaturesKey(txid, peer), &signatures)
            .await
            .is_some()
        {
            bail!("Already received valid signatures from this peer")
        }

        dbtx.remove_entry(&UnsignedTxKey(txid)).await;

        Self::finalize_tx_single_peer(&mut unsigned, &signatures);

        dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
            .await;
        if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
            debug!(target: LOG_MODULE_WALLETV2, err = %err.fmt_compact_anyhow(), "Error broadcasting finalized transaction");
        }

        Ok(())
    }

    /// Produce a BIP-341 key-path Schnorr signature for each input of
    /// `unsigned_tx` using the lone peer's bitcoin secret key. For every
    /// input the key is tweaked twice: first by the per-UTXO fedimint
    /// tweak (mirroring `descriptor_tr_single_peer`'s public-side
    /// tweak), then by the BIP-341 taproot tweak with no merkle root —
    /// because there is no script tree. The resulting signature
    /// validates against the descriptor's output key.
    pub(crate) fn sign_tx_single_peer(
        &self,
        unsigned_tx: &FederationTx,
    ) -> Vec<schnorr::Signature> {
        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .map(|(index, utxo)| {
                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        bitcoin::TapSighashType::Default,
                    )
                    .expect("Failed to compute taproot key spend sighash");

                let scalar = &Scalar::from_be_bytes(utxo.tweak.to_byte_array())
                    .expect("Hash is within field order");

                let keypair =
                    Keypair::from_secret_key(secp256k1::SECP256K1, &self.cfg.private.bitcoin_sk);
                let utxo_tweaked = keypair
                    .add_xonly_tweak(secp256k1::SECP256K1, scalar)
                    .expect("Failed to tweak bitcoin keypair");
                // BIP-341 key-spend with no merkle root (no taptree).
                let output_keypair = utxo_tweaked
                    .tap_tweak(secp256k1::SECP256K1, None)
                    .to_keypair();
                secp256k1::SECP256K1
                    .sign_schnorr(&secp256k1::Message::from(sighash), &output_keypair)
            })
            .collect()
    }

    /// Verify a vector of key-path Schnorr signatures (one per input)
    /// against the descriptor's output key for each input. Reconstructs
    /// the same key-spend sighash as `sign_tx_single_peer` and applies
    /// the same two-step tweak chain on the public side: per-UTXO
    /// fedimint tweak, then BIP-341 tap tweak with no merkle root.
    /// Returns an error if a signature fails to verify or if the count
    /// doesn't match the number of inputs.
    pub(crate) fn verify_signatures_single_peer(
        &self,
        unsigned_tx: &FederationTx,
        signatures: &[schnorr::Signature],
    ) -> anyhow::Result<()> {
        ensure!(
            unsigned_tx.spent_tx_outs.len() == signatures.len(),
            "Incorrect number of signatures"
        );

        let WalletDescriptor::SinglePeer(internal_key) = self.cfg.consensus.descriptor else {
            bail!("verify_signatures_single_peer called on non-SinglePeer descriptor");
        };

        let prevouts = self.build_prevouts(unsigned_tx);
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        for ((index, utxo), signature) in unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .zip(signatures.iter())
        {
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    bitcoin::TapSighashType::Default,
                )
                .expect("Failed to compute taproot key spend sighash");

            let utxo_tweaked = tweak_xonly_public_key(&internal_key, &utxo.tweak);
            let (output_key, _parity) = utxo_tweaked.tap_tweak(secp256k1::SECP256K1, None);

            secp256k1::SECP256K1.verify_schnorr(
                signature,
                &secp256k1::Message::from(sighash),
                &output_key.to_x_only_public_key(),
            )?;
        }

        Ok(())
    }

    /// Attach the key-path witness to each input of `federation_tx`
    /// in-place. For BIP-341 key-path spends the witness is just the
    /// 64-byte Schnorr signature (`SIGHASH_DEFAULT` keeps it 64 bytes;
    /// any other sighash type would append a single byte). No script,
    /// no control block — that's the whole point of collapsing to
    /// `SinglePeer` instead of using the script-path multisig path.
    fn finalize_tx_single_peer(
        federation_tx: &mut FederationTx,
        signatures: &[schnorr::Signature],
    ) {
        assert_eq!(
            federation_tx.spent_tx_outs.len(),
            federation_tx.tx.input.len()
        );
        assert_eq!(federation_tx.spent_tx_outs.len(), signatures.len());

        for (index, sig) in signatures.iter().enumerate() {
            // BIP-341 key-path witness: just the schnorr signature bytes.
            // `SIGHASH_DEFAULT` keeps the witness at 64 bytes (no trailing
            // sighash byte).
            let bitcoin_sig = bitcoin::taproot::Signature {
                signature: *sig,
                sighash_type: bitcoin::TapSighashType::Default,
            };
            let mut witness = bitcoin::Witness::new();
            witness.push(bitcoin_sig.to_vec());
            federation_tx.tx.input[index].witness = witness;
        }
    }
}
