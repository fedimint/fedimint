use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Network, XOnlyPublicKey};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::setup_code::WalletDescriptorKind;
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config, weight_to_vbytes};
use frost_secp256k1_tr::keys::KeyPackage;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::taproot::frost::FrostPublicKeyPackage;
use crate::taproot::{descriptor_tr, descriptor_tr_single_peer, nums_point};
use crate::{WalletCommonInit, descriptor};

plugin_types_trait_impl_config!(
    WalletCommonInit,
    WalletConfig,
    WalletConfigPrivate,
    WalletConfigConsensus,
    WalletClientConfig
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub private: WalletConfigPrivate,
    pub consensus: WalletConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfigPrivate {
    pub bitcoin_sk: SecretKey,
    #[serde(default)]
    pub frost_key_package: Option<KeyPackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletConfigConsensus {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
    /// The kind of descriptor the federation uses for the multisig.
    pub descriptor: WalletDescriptor,
    /// Total vbytes of a pegout bitcoin transaction
    pub send_tx_vbytes: u64,
    /// Total vbytes of a pegin bitcoin transaction
    pub receive_tx_vbytes: u64,
    /// The minimum feerate doubles for each pending transaction in the stack,
    /// protecting against catastrophic feerate estimation errors
    pub feerate_base: u64,
    /// The minimum amount a user can send on chain
    pub dust_limit: bitcoin::Amount,
    /// Fees taken by the guardians to process wallet inputs and outputs
    pub fee_consensus: FeeConsensus,
    /// Bitcoin network (e.g. testnet, bitcoin)
    pub network: Network,
    /// FROST public key package from DKG. Contains the group verifying key and
    /// each participant's verifying share — needed at aggregation time for
    /// cheater detection. Only populated for FROST federations; `None` for
    /// pre-existing `Wsh` / `Tr` federations.
    #[serde(default)]
    pub frost_pubkey_package: Option<FrostPublicKeyPackage>,
}

impl WalletConfigConsensus {
    /// The constructor will derive the following number of vbytes for a send
    /// and receive transaction with respect to the number of guardians:
    ///
    /// | Guardians | Send | Receive |
    /// |-----------|------|---------|
    /// | 1         | 166  | 192     |
    /// | 4         | 228  | 316     |
    /// | 5         | 255  | 369     |
    /// | 6         | 281  | 423     |
    /// | 7         | 290  | 440     |
    /// | 8         | 317  | 494     |
    /// | 9         | 344  | 548     |
    /// | 10        | 352  | 565     |
    /// | 11        | 379  | 618     |
    /// | 12        | 406  | 672     |
    /// | 13        | 414  | 689     |
    /// | 14        | 441  | 742     |
    /// | 15        | 468  | 796     |
    /// | 16        | 476  | 813     |
    /// | 17        | 503  | 867     |
    /// | 18        | 530  | 920     |
    /// | 19        | 539  | 937     |
    /// | 20        | 565  | 991     |
    /// `frost_internal_key` is only used when `descriptor_kind` is
    /// [`WalletDescriptorKind::Frost`] — it's the FROST aggregated public
    /// key, used as the BIP-341 internal key so the federation can spend
    /// via the key path. For [`WalletDescriptorKind::Tr`] we use a NUMS
    /// point as the internal key instead, which makes the key path
    /// provably unspendable and forces all spends through the script-path
    /// multisig. For [`WalletDescriptorKind::Wsh`] there's no internal key
    /// at all (P2WSH multisig).
    pub fn new(
        bitcoin_pks: BTreeMap<PeerId, PublicKey>,
        fee_consensus: FeeConsensus,
        network: Network,
        descriptor_kind: WalletDescriptorKind,
        frost_internal_key: Option<XOnlyPublicKey>,
        frost_pubkey_package: Option<FrostPublicKeyPackage>,
    ) -> Self {
        let tx_overhead_weight = 4 * 4 // nVersion
            + 1 // SegWit marker
            + 1 // SegWit flag
            + 4 // up to 2 inputs
            + 4 // up to 2 outputs
            + 4 * 4; // nLockTime

        // For Tr/Frost with N=1, multisig and FROST both degenerate to a
        // single signature — collapse both into a SinglePeer descriptor
        // that uses the lone peer's xonly bitcoin pubkey as the internal
        // key (no NUMS, no script-path, no FROST protocol).
        let single_peer_xonly = match (descriptor_kind, bitcoin_pks.len() == 1) {
            (WalletDescriptorKind::Tr | WalletDescriptorKind::Frost, true) => Some(
                bitcoin_pks
                    .values()
                    .next()
                    .expect("bitcoin_pks.len() == 1")
                    .x_only_public_key()
                    .0,
            ),
            _ => None,
        };

        let change_witness_weight = match (descriptor_kind, single_peer_xonly) {
            (WalletDescriptorKind::Wsh, _) => descriptor(&bitcoin_pks, &sha256::Hash::all_zeros())
                .max_weight_to_satisfy()
                .expect("Cannot satisfy the change descriptor.")
                .to_wu(),
            (_, Some(xonly)) => descriptor_tr_single_peer(xonly, &sha256::Hash::all_zeros())
                .max_weight_to_satisfy()
                .expect("Cannot satisfy the single-peer taproot descriptor.")
                .to_wu(),
            (WalletDescriptorKind::Tr, None) => {
                descriptor_tr(&bitcoin_pks, &sha256::Hash::all_zeros(), nums_point())
                    .max_weight_to_satisfy()
                    .expect("Cannot satisfy the taproot change descriptor.")
                    .to_wu()
            }
            (WalletDescriptorKind::Frost, None) => {
                // FROST always spends via key-path (single 64-byte
                // Schnorr signature). The on-chain `script_pubkey` for
                // a FROST utxo is built by `descriptor_tr` with the
                // `multi_a` script tree present as a fallback, but we
                // never actually script-spend — sizing here off the
                // script-path would over-estimate witness weight by
                // an order of magnitude. Use the key-path-only shape
                // for accurate sizing.
                descriptor_tr_single_peer(
                    frost_internal_key.expect("Frost descriptor requires a FROST internal key"),
                    &sha256::Hash::all_zeros(),
                )
                .max_weight_to_satisfy()
                .expect("Cannot satisfy the FROST keypath descriptor.")
                .to_wu()
            }
        };

        let descriptor = match (descriptor_kind, single_peer_xonly) {
            (WalletDescriptorKind::Wsh, _) => WalletDescriptor::Wsh,
            (_, Some(xonly)) => WalletDescriptor::SinglePeer(xonly),
            (WalletDescriptorKind::Tr, None) => WalletDescriptor::Tr,
            (WalletDescriptorKind::Frost, None) => WalletDescriptor::Frost(
                frost_internal_key.expect("Frost descriptor requires a FROST internal key"),
            ),
        };

        let change_input_weight = 32 * 4 // txid
            + 4 * 4 // vout
            + 4 // Script length
            + 4 * 4 // nSequence
            + change_witness_weight;

        let change_output_weight = 8 * 4 // nValue
            + 4 // scriptPubKey length
            + 34 * 4; // scriptPubKey

        let destination_output_weight = 8 * 4 // nValue
            + 4 // scriptPubKey length
            + 34 * 4; // scriptPubKey

        Self {
            bitcoin_pks,
            descriptor,
            send_tx_vbytes: weight_to_vbytes(
                tx_overhead_weight
                    + change_input_weight
                    + change_output_weight
                    + destination_output_weight,
            ),
            receive_tx_vbytes: weight_to_vbytes(
                tx_overhead_weight
                    + change_input_weight
                    + change_input_weight
                    + change_output_weight,
            ),
            // This is intentionally lower than the 1 sat/vB minimum feerate
            // vote floor. This allows for at least three pending transactions
            // which only pay the consensus feerate before the exponential
            // doubling kicks in.
            feerate_base: 250,
            dust_limit: bitcoin::Amount::from_sat(10_000),
            fee_consensus,
            network,
            frost_pubkey_package,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl FeeConsensus {
    /// The wallet module will charge a non-configurable base fee of one hundred
    /// satoshis per transaction input and output to account for the costs
    /// incurred by the federation for processing the transaction. On top of
    /// that the federation may charge an additional relative fee per input and
    /// output of up to ten thousand parts per million which equals one
    /// percent.
    ///
    /// # Errors
    /// - This constructor returns an error if the relative fee is in excess of
    ///   ten thousand parts per million.
    pub fn new(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 10_000,
            "Relative fee over ten thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_sats(100),
            parts_per_million,
        })
    }

    pub fn fee(&self, amount: Amount) -> Amount {
        Amount::from_msats(self.fee_msats(amount.msats))
    }

    fn fee_msats(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .checked_add(self.base.msats)
            .expect("The division creates sufficient headroom to add the base fee")
    }
}

#[test]
fn test_fee_consensus() {
    let fee_consensus = FeeConsensus::new(10_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus.fee(Amount::from_msats(99)),
        Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1)),
        Amount::from_msats(10) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1000)),
        Amount::from_sats(10) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(1_000_000) + Amount::from_sats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(10_000)),
        Amount::from_bitcoins(100) + Amount::from_sats(100)
    );
}

/// Which kind of bitcoin descriptor the federation uses.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum WalletDescriptor {
    /// `SegWit` v0 (`P2WSH`) k-of-n ECDSA multisig.
    Wsh,
    /// Taproot (P2TR) with NUMS internal key + k-of-n Schnorr multisig
    /// in the script path. Used when the federation has more than one
    /// peer and the leader picked Tr.
    Tr,
    /// Taproot (P2TR) key-path with the FROST aggregated public key as
    /// internal key. The federation produces a single threshold Schnorr
    /// signature via FROST.
    Frost(XOnlyPublicKey),
    /// Single-peer federation: taproot key-path spend with the lone
    /// peer's bitcoin xonly pubkey as internal key. Collapses both Tr and
    /// Frost when `bitcoin_pks.len() == 1` — no NUMS, no script-path,
    /// no FROST protocol; signing is a direct schnorr signature with the
    /// peer's bitcoin secret key.
    SinglePeer(XOnlyPublicKey),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletClientConfig {
    /// The public keys for the bitcoin multisig
    pub bitcoin_pks: BTreeMap<PeerId, PublicKey>,
    /// The kind of descriptor the federation uses for the multisig.
    pub descriptor: WalletDescriptor,
    /// Total vbytes of a pegout bitcoin transaction
    pub send_tx_vbytes: u64,
    /// Total vbytes of a pegin bitcoin transaction
    pub receive_tx_vbytes: u64,
    /// The minimum feerate doubles for each pending transaction in the stack,
    /// protecting against catastrophic feerate estimation errors
    pub feerate_base: u64,
    /// The minimum amount a user can send on chain
    pub dust_limit: bitcoin::Amount,
    /// Fees taken by the guardians to process wallet inputs and outputs
    pub fee_consensus: FeeConsensus,
    /// Bitcoin network (e.g. testnet, bitcoin)
    pub network: Network,
}

impl std::fmt::Display for WalletClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletClientConfig {self:?}")
    }
}
