use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashSet};

use bitcoin_hashes::sha256::Hash as Sha256;
use fedimint_api::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_api::encoding::{Decodable, DecodeError, Encodable, UnzipConsensus};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::module::SerdeModuleEncoding;
use fedimint_api::{PeerId, TransactionId};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKey, PublicKeySet, Signature, SignatureShare};

use crate::transaction::Transaction;

#[derive(Debug, Clone, Eq, PartialEq, Hash, UnzipConsensus, Encodable, Decodable)]
pub enum ConsensusItem {
    EpochOutcomeSignatureShare(EpochOutcomeSignatureShare),
    Transaction(Transaction),
    Module(ModuleConsensusItem),
}

pub type SerdeConsensusItem = SerdeModuleEncoding<ConsensusItem>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochOutcomeSignatureShare(pub SignatureShare);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochOutcomeSignature(pub Signature);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SignedEpochOutcome {
    pub outcome: EpochOutcome,
    pub hash: Sha256,
    pub signature: Option<EpochOutcomeSignature>,
}

pub type SerdeEpochHistory = SerdeModuleEncoding<SignedEpochOutcome>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct EpochOutcome {
    pub epoch: u64,
    pub last_hash: Option<Sha256>,
    /// All the consensus items along with the `PeerId` of the
    /// peer that contributed them.
    /// Some of the consensus items here might be invalid,
    /// (eg. transaction double-spending) but they were still
    /// submitted and considered as accepted.
    // TODO: It would be better to encode this as `Vec<(ConsensusItem, Vec<PeerId>)>`
    // to avoid duplicates (and make iterating over it nicer too in a lot of uses).
    pub items: Vec<(PeerId, Vec<ConsensusItem>)>,

    /// Transactions from `items` that turned out to be invalid.
    pub rejected_txs: BTreeSet<TransactionId>,
}

impl SignedEpochOutcome {
    pub fn new(
        epoch: u64,
        contributions: BTreeMap<PeerId, Vec<ConsensusItem>>,
        rejected_txs: BTreeSet<TransactionId>,
        prev_epoch: Option<&SignedEpochOutcome>,
    ) -> Self {
        let items = contributions
            .into_iter()
            .sorted_by_key(|(peer, _)| *peer)
            .collect();
        let outcome = EpochOutcome {
            last_hash: prev_epoch.map(|epoch| epoch.hash),
            items,
            epoch,
            rejected_txs,
        };

        SignedEpochOutcome {
            hash: outcome.consensus_hash().expect("Hashes"),
            outcome,
            signature: None,
        }
    }

    pub fn add_sig_to_prev(
        &self,
        pks: &PublicKeySet,
        mut prev_epoch: SignedEpochOutcome,
    ) -> Result<SignedEpochOutcome, EpochVerifyError> {
        let mut contributing_peers = HashSet::new();

        let sigs: BTreeMap<_, _> = self
            .outcome
            .items
            .iter()
            .flat_map(|(peer, items)| items.iter().map(|i| (*peer, i)))
            .filter_map(|(peer, item)| match item {
                ConsensusItem::EpochOutcomeSignatureShare(EpochOutcomeSignatureShare(sig)) => {
                    Some((peer, sig))
                }
                _ => None,
            })
            .filter(|(peer, sig)| {
                let pub_key = pks.public_key_share(peer.to_usize());
                pub_key.verify(sig, prev_epoch.hash)
            })
            .map(|(peer, sig)| {
                contributing_peers.insert(peer);
                (peer.to_usize(), sig)
            })
            .collect();

        if let Ok(final_sig) = pks.combine_signatures(sigs) {
            assert!(pks.public_key().verify(&final_sig, prev_epoch.hash));

            prev_epoch.signature = Some(EpochOutcomeSignature(final_sig));
            Ok(prev_epoch)
        } else {
            Err(EpochVerifyError::NotEnoughValidSigShares(
                contributing_peers,
            ))
        }
    }

    pub fn verify_sig(&self, pk: &PublicKey) -> Result<(), EpochVerifyError> {
        if let Some(sig) = &self.signature {
            if !pk.verify(&sig.0, self.hash) {
                return Err(EpochVerifyError::InvalidSignature);
            }
        } else {
            return Err(EpochVerifyError::MissingSignature);
        }

        Ok(())
    }

    pub fn verify_hash(
        &self,
        prev_epoch: &Option<SignedEpochOutcome>,
    ) -> Result<(), EpochVerifyError> {
        if self.outcome.epoch > 0 {
            match prev_epoch {
                None => return Err(EpochVerifyError::MissingPreviousEpoch),
                Some(prev_epoch) => {
                    if prev_epoch.outcome.consensus_hash().ok() != self.outcome.last_hash {
                        return Err(EpochVerifyError::InvalidPreviousEpochHash);
                    }
                }
            }
        }

        if Some(self.hash) == self.outcome.consensus_hash().ok() {
            Ok(())
        } else {
            Err(EpochVerifyError::InvalidEpochHash)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EpochVerifyError {
    MissingSignature,
    InvalidSignature,
    MissingPreviousEpoch,
    InvalidEpochHash,
    InvalidPreviousEpochHash,
    NotEnoughValidSigShares(HashSet<PeerId>),
}

impl Encodable for EpochOutcomeSignature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for EpochOutcomeSignature {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochOutcomeSignature(Signature::from_bytes(bytes).unwrap()))
    }
}

impl Encodable for EpochOutcomeSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for EpochOutcomeSignatureShare {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochOutcomeSignatureShare(
            SignatureShare::from_bytes(bytes).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};

    use bitcoin::hashes::Hash;
    use fedimint_api::encoding::Encodable;
    use fedimint_api::PeerId;
    use rand::rngs::OsRng;
    use threshold_crypto::{SecretKey, SecretKeySet};

    use crate::epoch::{ConsensusItem, EpochOutcomeSignatureShare, Sha256};
    use crate::epoch::{EpochOutcome, EpochOutcomeSignature, EpochVerifyError, SignedEpochOutcome};

    fn signed_history(
        epoch: u16,
        prev_epoch: &Option<SignedEpochOutcome>,
        sk: &SecretKey,
    ) -> SignedEpochOutcome {
        let missing_sig = history(epoch, prev_epoch, None);
        let signature = sk.sign(missing_sig.outcome.consensus_hash().expect("Hashes"));
        history(epoch, prev_epoch, Some(EpochOutcomeSignature(signature)))
    }

    fn history(
        epoch: u16,
        prev_epoch: &Option<SignedEpochOutcome>,
        signature: Option<EpochOutcomeSignature>,
    ) -> SignedEpochOutcome {
        let items = vec![(PeerId::from(epoch), vec![])];
        let outcome = EpochOutcome {
            last_hash: prev_epoch.clone().map(|epoch| epoch.hash),
            items,
            epoch: epoch as u64,
            // seems like in these tests we don't care about this one
            rejected_txs: BTreeSet::default(),
        };

        SignedEpochOutcome {
            hash: outcome.consensus_hash().expect("Hashes"),
            outcome,
            signature,
        }
    }

    #[test]
    fn adds_sig_to_prev_epoch() {
        let mut rng = OsRng;
        let sk_set = SecretKeySet::random(2, &mut rng);
        let pk_set = sk_set.public_keys();

        let epoch0 = history(0, &None, None);
        let mut epoch1 = history(1, &Some(epoch0.clone()), None);

        let peers = [PeerId::from(0), PeerId::from(1), PeerId::from(2)];
        let sigs: Vec<(PeerId, Vec<ConsensusItem>)> = peers
            .iter()
            .map(|&peer| {
                let sig = sk_set.secret_key_share(peer.to_usize()).sign(epoch0.hash);
                (
                    peer,
                    vec![ConsensusItem::EpochOutcomeSignatureShare(
                        EpochOutcomeSignatureShare(sig),
                    )],
                )
            })
            .collect();

        epoch1.outcome = EpochOutcome {
            epoch: 1,
            last_hash: None,
            items: sigs[0..1].to_vec(),
            rejected_txs: BTreeSet::default(),
        };
        let contributing = HashSet::from([PeerId::from(0)]);
        let result = epoch1.add_sig_to_prev(&pk_set, epoch0.clone()).unwrap_err();
        assert_eq!(
            result,
            EpochVerifyError::NotEnoughValidSigShares(contributing)
        );

        epoch1.outcome = EpochOutcome {
            epoch: 1,
            last_hash: None,
            items: sigs,
            rejected_txs: BTreeSet::default(),
        };
        let epoch0 = epoch1.add_sig_to_prev(&pk_set, epoch0).unwrap();
        assert_eq!(epoch0.verify_sig(&pk_set.public_key()), Ok(()));
    }

    #[test]
    fn verifies_hash() {
        let sk: SecretKey = SecretKey::random();
        let _pk = sk.public_key();
        let wrong_hash: Sha256 = Hash::hash(b"wrong");
        let sig = EpochOutcomeSignature(sk.sign(wrong_hash));

        let epoch0 = history(0, &None, Some(sig));
        let epoch = SignedEpochOutcome {
            outcome: epoch0.outcome,
            hash: wrong_hash,
            signature: epoch0.signature,
        };

        assert_eq!(
            epoch.verify_hash(&None),
            Err(EpochVerifyError::InvalidEpochHash)
        );
    }

    #[test]
    fn verifies_merkle_tree() {
        let sk: SecretKey = SecretKey::random();
        let _pk = sk.public_key();

        let epoch0 = signed_history(0, &None, &sk);
        let epoch1 = signed_history(1, &Some(epoch0.clone()), &sk);
        let epoch2 = signed_history(2, &Some(epoch1.clone()), &sk);

        assert_eq!(epoch0.verify_hash(&None), Ok(()));
        assert_eq!(epoch1.verify_hash(&Some(epoch0)), Ok(()));
        assert_eq!(epoch2.verify_hash(&Some(epoch1.clone())), Ok(()));

        assert_eq!(
            epoch1.verify_hash(&None),
            Err(EpochVerifyError::MissingPreviousEpoch)
        );
        assert_eq!(
            epoch1.verify_hash(&Some(epoch2)),
            Err(EpochVerifyError::InvalidPreviousEpochHash)
        );
    }

    #[test]
    fn verifies_sigs() {
        let sk: SecretKey = SecretKey::random();
        let pk = sk.public_key();

        let epoch0 = signed_history(0, &None, &sk);
        let epoch1 = signed_history(1, &Some(epoch0.clone()), &sk);

        assert_eq!(epoch0.verify_sig(&pk), Ok(()));
        assert_eq!(epoch1.verify_sig(&pk), Ok(()));

        let epoch0_wrong = history(0, &None, epoch1.signature);
        let epoch1_wrong = history(1, &Some(epoch0.clone()), epoch0.signature);

        assert_eq!(
            epoch0_wrong.verify_sig(&pk),
            Err(EpochVerifyError::InvalidSignature)
        );
        assert_eq!(
            epoch1_wrong.verify_sig(&pk),
            Err(EpochVerifyError::InvalidSignature)
        );
    }
}
