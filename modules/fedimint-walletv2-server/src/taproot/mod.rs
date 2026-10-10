pub mod frost;
mod multisig;
mod single_peer;

use bitcoin::hashes::sha256;
use bitcoin::taproot::LeafVersion;
use bitcoin::{ScriptBuf, TapLeafHash, TxOut};
use fedimint_walletv2_common::taproot::{descriptor_tr, nums_point, script_pubkey_for_descriptor};

use crate::{FederationTx, Wallet};

impl Wallet {
    /// The federation `script_pubkey` for the UTXO identified by
    /// `tweak`, per the configured descriptor. Used both to derive
    /// deposit addresses and to reconstruct prevouts when computing
    /// sighashes.
    pub(crate) fn script_pubkey_for(&self, tweak: &sha256::Hash) -> ScriptBuf {
        script_pubkey_for_descriptor(
            &self.cfg.consensus.descriptor,
            &self.cfg.consensus.bitcoin_pks,
            tweak,
        )
    }

    /// The `TapLeafHash` of the single `multi_a` script leaf for the
    /// UTXO identified by `tweak`. Both the `Tr` and `Frost`
    /// descriptors build a Tr with this same script tree (only the
    /// internal key differs: NUMS for `Tr`, the FROST aggregated key
    /// for `Frost`), so the leaf hash is well-defined for both.
    ///
    /// Used by:
    /// - `multisig::{sign,verify,finalize}_tx_schnorr` for the `Tr`
    ///   script-spend sighash and the satisfier map.
    /// - The `Frost` aggregation paths in `frost.rs` and `lib.rs` as the
    ///   BIP-341 merkle root passed to `frost::round2::sign_with_tweak` and to
    ///   FROST verification — because the key-path output key commits to the
    ///   script tree even when we sign via key-path.
    ///
    /// Not used for `Wsh` (no Taproot) or `SinglePeer` (key-path only,
    /// no script tree, merkle root is `None`).
    pub(crate) fn tap_leaf_hash(&self, tweak: &sha256::Hash) -> TapLeafHash {
        let tr = descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, nums_point());
        let (_, ms) = tr
            .iter_scripts()
            .next()
            .expect("Taproot descriptor always has exactly one script leaf");
        TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript)
    }

    /// Reconstruct the `prevouts` vector (one `TxOut` per input)
    /// needed for BIP-341 sighash computation. Each prevout's
    /// `script_pubkey` is re-derived from the per-UTXO `tweak` stored
    /// on the `FederationTx` rather than fetched — so all signers
    /// agree on the prevouts deterministically without needing to
    /// look up the original funding tx. Used by every signing /
    /// verification helper in this module tree.
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
}

/// Attach a BIP-341 key-path witness to every input of `federation_tx`:
/// each witness is exactly the serialized Schnorr signature — with
/// `SIGHASH_DEFAULT` that is 64 bytes and no sighash-type byte is
/// appended. No script, no control block. Shared by the `SinglePeer` and
/// `Frost` descriptors, which both spend via the key path only.
pub(crate) fn attach_key_path_witnesses(
    federation_tx: &mut crate::FederationTx,
    signatures: impl ExactSizeIterator<Item = Vec<u8>>,
) {
    assert_eq!(
        federation_tx.spent_tx_outs.len(),
        federation_tx.tx.input.len()
    );
    assert_eq!(signatures.len(), federation_tx.tx.input.len());

    for (input, signature) in federation_tx.tx.input.iter_mut().zip(signatures) {
        let mut witness = bitcoin::Witness::new();
        witness.push(&signature);
        input.witness = witness;
    }
}
