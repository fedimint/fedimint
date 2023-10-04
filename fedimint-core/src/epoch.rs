use std::collections::{BTreeMap, BTreeSet};

use bitcoin_hashes::sha256::Hash as Sha256;
use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable, UnzipConsensus};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::{PeerId, TransactionId};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKey, PublicKeySet, Signature, SignatureShare};

use crate::transaction::Transaction;
use crate::{serde_as_encodable_hex, timing};

/// All the items that may be produced during a consensus epoch
#[derive(Debug, Clone, Eq, PartialEq, Hash, UnzipConsensus, Encodable, Decodable)]
pub enum ConsensusItem {
    /// Threshold sign the configs for verification via the API
    ClientConfigSignatureShare(SerdeSignatureShare),
    /// Threshold sign the epoch history for verification via the API
    Transaction(Transaction),
    /// Any data that modules require consensus on
    Module(ModuleConsensusItem),
}

/// May eventually contains consensus info about the upgrade
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct ConsensusUpgrade;

pub type SerdeConsensusItem = SerdeModuleEncoding<ConsensusItem>;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SerdeSignatureShare(pub SignatureShare);

serde_as_encodable_hex!(SerdeSignatureShare);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SerdeSignature(pub Signature);

serde_as_encodable_hex!(SerdeSignature);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SignedEpochOutcome {
    pub outcome: EpochOutcome,
    pub hash: Sha256,
    pub signature: Option<SerdeSignature>,
}

pub type SerdeEpochHistory = SerdeModuleEncoding<SignedEpochOutcome>;

/// Combines signature shares from peers, ignoring bad signatures to avoid a DoS
/// attack.  If not enough valid shares, returns the peers that were valid.
pub fn combine_sigs<M: AsRef<[u8]>>(
    pks: &PublicKeySet,
    shares: &BTreeMap<PeerId, SerdeSignatureShare>,
    msg: &M,
) -> Result<SerdeSignature, BTreeSet<PeerId>> {
    // Remove bad sigs
    let mut valid_peers = BTreeSet::new();
    let valid_shares = shares.iter().filter_map(|(peer, share)| {
        if pks.public_key_share(peer.to_usize()).verify(&share.0, msg) {
            valid_peers.insert(*peer);
            Some((peer.to_usize(), &share.0))
        } else {
            None
        }
    });

    match pks.combine_signatures(valid_shares) {
        Ok(sig) => Ok(SerdeSignature(sig)),
        Err(_) => Err(valid_peers),
    }
}

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
            hash: outcome.consensus_hash(),
            outcome,
            signature: None,
        }
    }

    pub fn verify_sig(&self, pk: &PublicKey) -> Result<(), EpochVerifyError> {
        if let Some(sig) = &self.signature {
            let _timing /* logs on drop */ = timing::TimeReporter::new("verify epoch outcome signature");
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
        let _timing /* logs on drop */ = timing::TimeReporter::new("verify epoch outcome hash");
        if self.outcome.epoch > 0 {
            match prev_epoch {
                None => return Err(EpochVerifyError::MissingPreviousEpoch),
                Some(prev_epoch) => {
                    if Some(prev_epoch.outcome.consensus_hash()) != self.outcome.last_hash {
                        return Err(EpochVerifyError::InvalidPreviousEpochHash);
                    }
                }
            }
        }

        if self.hash == self.outcome.consensus_hash() {
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
    NotEnoughValidSigShares(BTreeSet<PeerId>),
}

impl From<BTreeSet<PeerId>> for EpochVerifyError {
    fn from(valid_peers: BTreeSet<PeerId>) -> Self {
        EpochVerifyError::NotEnoughValidSigShares(valid_peers)
    }
}

impl Encodable for SerdeSignature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for SerdeSignature {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(SerdeSignature(Signature::from_bytes(bytes).unwrap()))
    }
}

impl Encodable for SerdeSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for SerdeSignatureShare {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(SerdeSignatureShare(
            SignatureShare::from_bytes(bytes).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use bitcoin::hashes::Hash;
    use bitcoin_hashes::sha256;
    use fedimint_core::encoding::Encodable;
    use fedimint_core::epoch::combine_sigs;
    use fedimint_core::PeerId;
    use rand::rngs::OsRng;
    use threshold_crypto::{SecretKey, SecretKeySet};

    use crate::epoch::{
        EpochOutcome, EpochVerifyError, SerdeSignature, SerdeSignatureShare, Sha256,
        SignedEpochOutcome,
    };

    fn signed_history(
        epoch: u16,
        prev_epoch: &Option<SignedEpochOutcome>,
        sk: &SecretKey,
    ) -> SignedEpochOutcome {
        let missing_sig = history(epoch, prev_epoch, None);
        let signature = sk.sign(missing_sig.outcome.consensus_hash::<sha256::Hash>());
        history(epoch, prev_epoch, Some(SerdeSignature(signature)))
    }

    fn history(
        epoch: u16,
        prev_epoch: &Option<SignedEpochOutcome>,
        signature: Option<SerdeSignature>,
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
            hash: outcome.consensus_hash(),
            outcome,
            signature,
        }
    }

    #[test]
    fn combines_single_share() {
        let mut rng = OsRng;
        let sk_set = SecretKeySet::random(0, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = "test message";

        let shares = BTreeMap::from([(
            PeerId::from(0),
            SerdeSignatureShare(sk_set.secret_key_share(0).sign(msg)),
        )]);

        assert!(combine_sigs(&pk_set, &shares, &msg.to_string()).is_ok());
    }

    #[test]
    fn combines_shares() {
        let mut rng = OsRng;
        let sk_set = SecretKeySet::random(1, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = "test message";

        let mut shares = BTreeMap::from([
            (
                PeerId::from(0),
                SerdeSignatureShare(sk_set.secret_key_share(0).sign(msg)),
            ),
            (
                PeerId::from(1),
                SerdeSignatureShare(sk_set.secret_key_share(1).sign(msg)),
            ),
        ]);

        assert!(combine_sigs(&pk_set, &shares, &msg.to_string()).is_ok());

        shares.remove(&PeerId::from(0));
        assert_eq!(
            combine_sigs(&pk_set, &shares, &msg.to_string()),
            Err(BTreeSet::from([PeerId::from(1)]))
        );
    }

    #[test]
    fn verifies_hash() {
        let sk: SecretKey = SecretKey::random();
        let _pk = sk.public_key();
        let wrong_hash: Sha256 = Hash::hash(b"wrong");
        let sig = SerdeSignature(sk.sign(wrong_hash));

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
