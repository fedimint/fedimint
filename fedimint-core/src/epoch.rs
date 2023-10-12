use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable, UnzipConsensus};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKeySet, Signature, SignatureShare};

use crate::serde_as_encodable_hex;
use crate::transaction::Transaction;

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

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SerdeSignatureShare(pub SignatureShare);

serde_as_encodable_hex!(SerdeSignatureShare);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SerdeSignature(pub Signature);

serde_as_encodable_hex!(SerdeSignature);

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

    use fedimint_core::epoch::combine_sigs;
    use fedimint_core::PeerId;
    use rand::rngs::OsRng;
    use threshold_crypto::SecretKeySet;

    use crate::epoch::SerdeSignatureShare;

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
}
