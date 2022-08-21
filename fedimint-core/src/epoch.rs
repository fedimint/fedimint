use crate::transaction::Transaction;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256::HashEngine;
use fedimint_api::encoding::{Decodable, DecodeError, Encodable};
use fedimint_api::{BitcoinHash, FederationModule, PeerId};
use fedimint_derive::UnzipConsensus;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use threshold_crypto::{PublicKey, Signature, SignatureShare};

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

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct EpochHistory {
    pub outcome: OutcomeHistory,
    pub hash: Sha256,
    pub signature: Option<EpochSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
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

    /// verifies the sig, the hash, and the merkle tree
    pub fn verify(
        &self,
        pks: &PublicKey,
        prev_epoch: Option<&EpochHistory>,
    ) -> Result<(), EpochVerifyError> {
        if let Some(sig) = &self.signature {
            if !pks.verify(&sig.0, self.hash) {
                return Err(EpochVerifyError::InvalidSignature);
            }
        } else {
            return Err(EpochVerifyError::MissingSignature);
        }

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
}

impl Encodable for EpochSignature {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for EpochSignature {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochSignature(Signature::from_bytes(&bytes).unwrap()))
    }
}

impl Encodable for EpochSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: W) -> Result<usize, std::io::Error> {
        self.0.to_bytes().consensus_encode(writer)
    }
}

impl Decodable for EpochSignatureShare {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 96];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(EpochSignatureShare(
            SignatureShare::from_bytes(&bytes).unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::epoch::Sha256;
    use crate::epoch::{EpochHistory, EpochSignature, EpochVerifyError, OutcomeHistory};
    use fedimint_api::PeerId;
    use threshold_crypto::SecretKey;

    fn signed_history(
        epoch: u16,
        prev_epoch: Option<&EpochHistory>,
        sk: &SecretKey,
    ) -> EpochHistory {
        let missing_sig = history(epoch, prev_epoch, None);
        let signature = sk.sign(missing_sig.outcome.hash());
        history(epoch, prev_epoch, Some(EpochSignature(signature)))
    }

    fn history(
        epoch: u16,
        prev_epoch: Option<&EpochHistory>,
        signature: Option<EpochSignature>,
    ) -> EpochHistory {
        let items = vec![(PeerId::from(epoch), vec![])];
        let outcome = OutcomeHistory {
            last_hash: prev_epoch.map(|epoch| epoch.hash),
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
    fn verifies_hash() {
        let sk: SecretKey = SecretKey::random();
        let pk = sk.public_key();
        let wrong_hash: Sha256 = Default::default();
        let sig = EpochSignature(sk.sign(&wrong_hash));

        let epoch0 = history(0, None, Some(sig));
        let epoch = EpochHistory {
            outcome: epoch0.outcome,
            hash: wrong_hash,
            signature: epoch0.signature,
        };

        assert_eq!(
            epoch.verify(&pk, None),
            Err(EpochVerifyError::InvalidEpochHash)
        );
    }

    #[test]
    fn verifies_merkle_tree() {
        let sk: SecretKey = SecretKey::random();
        let pk = sk.public_key();

        let epoch0 = signed_history(0, None, &sk);
        let epoch1 = signed_history(1, Some(&epoch0), &sk);
        let epoch2 = signed_history(2, Some(&epoch1), &sk);

        assert_eq!(epoch0.verify(&pk, None), Ok(()));
        assert_eq!(epoch1.verify(&pk, Some(&epoch0)), Ok(()));
        assert_eq!(epoch2.verify(&pk, Some(&epoch1)), Ok(()));

        assert_eq!(
            epoch1.verify(&pk, None),
            Err(EpochVerifyError::MissingPreviousEpoch)
        );
        assert_eq!(
            epoch1.verify(&pk, Some(&epoch2)),
            Err(EpochVerifyError::InvalidPreviousEpochHash)
        );
    }

    #[test]
    fn verifies_sigs() {
        let sk: SecretKey = SecretKey::random();
        let pk = sk.public_key();

        let epoch0 = signed_history(0, None, &sk);
        let epoch1 = signed_history(1, Some(&epoch0), &sk);

        assert_eq!(epoch0.verify(&pk, None), Ok(()));
        assert_eq!(epoch1.verify(&pk, Some(&epoch0)), Ok(()));

        let epoch0_wrong = history(0, None, epoch1.signature);
        let epoch1_wrong = history(1, Some(&epoch0), epoch0.signature.clone());

        assert_eq!(
            epoch0_wrong.verify(&pk, None),
            Err(EpochVerifyError::InvalidSignature)
        );
        assert_eq!(
            epoch1_wrong.verify(&pk, Some(&epoch0)),
            Err(EpochVerifyError::InvalidSignature)
        );
    }
}
