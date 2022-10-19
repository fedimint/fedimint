use std::collections::{BTreeMap, HashSet};

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256::HashEngine;
use fedimint_api::encoding::{Decodable, DecodeError, Encodable, ModuleRegistry, UnzipConsensus};
use fedimint_api::{BitcoinHash, FederationModule, PeerId};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKey, PublicKeySet, Signature, SignatureShare};

use crate::transaction::Transaction;

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, UnzipConsensus, Encodable, Decodable,
)]
pub enum ConsensusItem {
    EpochInfo(EpochSignatureShare),
    Transaction(Transaction),
    Mint(<fedimint_mint::Mint as FederationModule>::ConsensusItem),
    Wallet(<fedimint_wallet::Wallet as FederationModule>::ConsensusItem),
    LN(<fedimint_ln::LightningModule as FederationModule>::ConsensusItem),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochSignatureShare(pub SignatureShare);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochSignature(pub Signature);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EpochHistory {
    pub outcome: OutcomeHistory,
    pub hash: Sha256,
    pub signature: Option<EpochSignature>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct OutcomeHistory {
    pub epoch: u64,
    pub last_hash: Option<Sha256>,
    pub items: Vec<(PeerId, Vec<ConsensusItem>)>,
}

impl OutcomeHistory {
    pub fn hash(&self) -> Sha256 {
        let mut engine = HashEngine::default();
        self.consensus_encode(&mut engine).unwrap();
        Sha256::from_engine(engine)
    }
}

impl EpochHistory {
    pub fn new(
        epoch: u64,
        contributions: BTreeMap<PeerId, Vec<ConsensusItem>>,
        prev_epoch: &Option<EpochHistory>,
    ) -> Self {
        let items = contributions
            .into_iter()
            .sorted_by_key(|(peer, _)| *peer)
            .collect();
        let outcome = OutcomeHistory {
            last_hash: prev_epoch.clone().map(|epoch| epoch.hash),
            items,
            epoch,
        };

        EpochHistory {
            hash: outcome.hash(),
            outcome,
            signature: None,
        }
    }

    pub fn add_sig_to_prev(
        &self,
        pks: &PublicKeySet,
        mut prev_epoch: EpochHistory,
    ) -> Result<EpochHistory, EpochVerifyError> {
        let mut contributing_peers = HashSet::new();

        let sigs: BTreeMap<_, _> = self
            .outcome
            .items
            .iter()
            .flat_map(|(peer, items)| items.iter().map(|i| (*peer, i)))
            .filter_map(|(peer, item)| match item {
                ConsensusItem::EpochInfo(EpochSignatureShare(sig)) => Some((peer, sig)),
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

            prev_epoch.signature = Some(EpochSignature(final_sig));
            Ok(prev_epoch)
        } else {
            Err(EpochVerifyError::NotEnoughValidSigShares(
                contributing_peers,
            ))
        }
    }

    pub fn verify_sig(&self, pks: &PublicKey) -> Result<(), EpochVerifyError> {
        if let Some(sig) = &self.signature {
            if !pks.verify(&sig.0, self.hash) {
                return Err(EpochVerifyError::InvalidSignature);
            }
        } else {
            return Err(EpochVerifyError::MissingSignature);
        }

        Ok(())
    }

    pub fn verify_hash(&self, prev_epoch: &Option<EpochHistory>) -> Result<(), EpochVerifyError> {
        if self.outcome.epoch > 0 {
            match prev_epoch {
                None => return Err(EpochVerifyError::MissingPreviousEpoch),
                Some(epoch) if Some(epoch.outcome.hash()) != self.outcome.last_hash => {
                    return Err(EpochVerifyError::InvalidPreviousEpochHash)
                }
                _ => {}
            }
        }

        if self.hash == self.outcome.hash() {
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

impl Encodable for EpochSignature {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl<M> Decodable<M> for EpochSignature {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochSignature(Signature::from_bytes(&bytes).unwrap()))
    }
}

impl Encodable for EpochSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl<M> Decodable<M> for EpochSignatureShare {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochSignatureShare(
            SignatureShare::from_bytes(&bytes).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bitcoin::hashes::Hash;
    use fedimint_api::PeerId;
    use rand::rngs::OsRng;
    use threshold_crypto::{SecretKey, SecretKeySet};

    use crate::epoch::{ConsensusItem, EpochSignatureShare, Sha256};
    use crate::epoch::{EpochHistory, EpochSignature, EpochVerifyError, OutcomeHistory};

    fn signed_history(
        epoch: u16,
        prev_epoch: &Option<EpochHistory>,
        sk: &SecretKey,
    ) -> EpochHistory {
        let missing_sig = history(epoch, prev_epoch, None);
        let signature = sk.sign(missing_sig.outcome.hash());
        history(epoch, prev_epoch, Some(EpochSignature(signature)))
    }

    fn history(
        epoch: u16,
        prev_epoch: &Option<EpochHistory>,
        signature: Option<EpochSignature>,
    ) -> EpochHistory {
        let items = vec![(PeerId::from(epoch), vec![])];
        let outcome = OutcomeHistory {
            last_hash: prev_epoch.clone().map(|epoch| epoch.hash),
            items,
            epoch: epoch as u64,
        };

        EpochHistory {
            hash: outcome.hash(),
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
                let sig = sk_set.secret_key_share(peer.to_usize()).sign(&epoch0.hash);
                (
                    peer,
                    vec![ConsensusItem::EpochInfo(EpochSignatureShare(sig))],
                )
            })
            .collect();

        epoch1.outcome = OutcomeHistory {
            epoch: 1,
            last_hash: None,
            items: sigs[0..1].to_vec(),
        };
        let contributing = HashSet::from([PeerId::from(0)]);
        let result = epoch1.add_sig_to_prev(&pk_set, epoch0.clone()).unwrap_err();
        assert_eq!(
            result,
            EpochVerifyError::NotEnoughValidSigShares(contributing)
        );

        epoch1.outcome = OutcomeHistory {
            epoch: 1,
            last_hash: None,
            items: sigs,
        };
        let epoch0 = epoch1.add_sig_to_prev(&pk_set, epoch0).unwrap();
        assert_eq!(epoch0.verify_sig(&pk_set.public_key()), Ok(()));
    }

    #[test]
    fn verifies_hash() {
        let sk: SecretKey = SecretKey::random();
        let _pk = sk.public_key();
        let wrong_hash: Sha256 = Hash::hash(b"wrong");
        let sig = EpochSignature(sk.sign(&wrong_hash));

        let epoch0 = history(0, &None, Some(sig));
        let epoch = EpochHistory {
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
