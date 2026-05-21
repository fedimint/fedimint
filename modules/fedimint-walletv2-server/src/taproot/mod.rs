pub mod frost;
mod multisig;
mod single_peer;

use bitcoin::hashes::sha256;
use bitcoin::taproot::LeafVersion;
use bitcoin::{ScriptBuf, TapLeafHash, TxOut};
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::{descriptor_tr, descriptor_tr_single_peer, nums_point};

use crate::{FederationTx, Wallet};

impl Wallet {
    /// The federation `script_pubkey` for the UTXO identified by
    /// `tweak`. Branches on the configured descriptor: P2WSH for `Wsh`,
    /// P2TR with NUMS internal key + script-path multisig for `Tr`,
    /// P2TR key-path with the lone peer's xonly for `SinglePeer`, or
    /// P2TR key-path with the FROST aggregated key for `Frost`. Used
    /// both to derive deposit addresses and to reconstruct prevouts
    /// when computing sighashes.
    pub(crate) fn script_pubkey_for(&self, tweak: &sha256::Hash) -> ScriptBuf {
        match self.cfg.consensus.descriptor {
            WalletDescriptor::Wsh => self.descriptor(tweak).script_pubkey(),
            WalletDescriptor::Tr => {
                descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, nums_point()).script_pubkey()
            }
            WalletDescriptor::SinglePeer(peer_xonly) => {
                descriptor_tr_single_peer(peer_xonly, tweak).script_pubkey()
            }
            WalletDescriptor::Frost(internal_key) => {
                descriptor_tr(&self.cfg.consensus.bitcoin_pks, tweak, internal_key).script_pubkey()
            }
        }
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
