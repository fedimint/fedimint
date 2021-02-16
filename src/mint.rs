use crate::musig;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use tbs::{
    combine_valid_shares, min_shares, sign_blinded_msg, verify, verify_blind_share, Aggregatable,
    AggregatePublicKey, BlindedMessage, BlindedSignature, BlindedSignatureShare, Message,
    PublicKeyShare, SecretKeyShare, Signature,
};
use tracing::{debug, warn};

/// Federated mint member mint
#[derive(Debug)]
pub struct Mint {
    key_idx: usize,
    sec_key: SecretKeyShare,
    pub_key_shares: Vec<PublicKeyShare>,
    pub_key: AggregatePublicKey,
    threshold: usize,
    spendbook: HashSet<CoinNonce>,
}

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SignRequest(pub Vec<BlindedMessage>);

/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PartialSigResponse(Vec<(BlindedMessage, BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SigResponse(pub u64, pub Vec<BlindedSignature>);

/// A cryptographic coin consisting of a token and a threshold signature by the federated mint
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coin(pub CoinNonce, pub Signature);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct CoinNonce(pub musig::PubKey);

impl Mint {
    /// Constructs a new ming
    ///
    /// # Panics
    /// If the pub key belonging to the secret key share is not in the pub key list.
    pub fn new(sec_key: SecretKeyShare, pub_keys: Vec<PublicKeyShare>, threshold: usize) -> Mint {
        let pub_key = pub_keys.aggregate(threshold);
        Mint {
            key_idx: pub_keys
                .iter()
                .position(|pk| pk == &sec_key.to_pub_key_share())
                .expect("Own key not found among pub keys."),
            sec_key,
            pub_key_shares: pub_keys,
            pub_key,
            threshold,
            spendbook: HashSet::new(),
        }
    }

    /// Generate our signature share for a `SignRequest`
    pub fn sign(&self, req: SignRequest) -> PartialSigResponse {
        PartialSigResponse(
            req.0
                .into_iter()
                .map(|msg| {
                    let bsig = sign_blinded_msg(msg, self.sec_key);
                    (msg, bsig)
                })
                .collect(),
        )
    }

    /// Try to combine signature shares to a complete signature, filtering out invalid contributions
    /// and reporting peer misbehaviour.
    pub fn combine(
        &self,
        partial_sigs: Vec<(usize, PartialSigResponse)>,
    ) -> (Result<SigResponse, CombineError>, MintShareErrors) {
        // FIXME: decide on right boundary place for this invariant
        // Filter out duplicate contributions, they make share combinations fail
        let peer_contrib_counts = partial_sigs
            .iter()
            .map(|(idx, _)| *idx)
            .collect::<counter::Counter<_>>();
        if let Some((peer, _)) = peer_contrib_counts.into_iter().find(|(_, cnt)| **cnt > 1) {
            return (
                Err(CombineError::MultiplePeerContributions(*peer)),
                MintShareErrors(vec![]),
            );
        }

        // Determine the reference response to check against
        let our_contribution = match &partial_sigs.iter().find(|(peer, _)| *peer == self.key_idx) {
            Some((_, psigs)) => psigs,
            None => {
                return (
                    Err(CombineError::NoOwnContribution),
                    MintShareErrors(vec![]),
                )
            }
        };

        let reference_msgs = our_contribution.0.iter().map(|(msg, _)| msg);
        let request_id = our_contribution.id();

        let mut peer_errors = vec![];

        let reference_len = our_contribution.0.len();
        let partial_sigs = partial_sigs
            .iter()
            .filter(|(peer, sigs)| {
                if sigs.0.len() != reference_len {
                    warn!(
                        "Peer {} proposed a sig share of wrong length (expected={}; actual={})",
                        peer,
                        reference_len,
                        sigs.0.len()
                    );
                    peer_errors.push((*peer, MintErrorType::DifferentLengthAnswer));
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();
        debug!(
            "After length filtering {} sig shares are left.",
            partial_sigs.len()
        );
        let bsigs = PartialSigZip::new(partial_sigs.as_ref(), reference_len)
            .zip(reference_msgs)
            .map(|(row, ref_msg)| {
                // Filter out invalid peer contributions
                let valid_sigs = row
                    .filter_map(|(peer, msg, sig)| {
                        if msg != ref_msg {
                            peer_errors.push((*peer, MintErrorType::DifferentNonce));
                            None
                        } else if !verify_blind_share(*msg, *sig, self.pub_key_shares[*peer]) {
                            peer_errors.push((*peer, MintErrorType::InvalidSignature));
                            None
                        } else {
                            Some((*peer, *sig))
                        }
                    })
                    .collect::<Vec<_>>();

                // Check that there are still sufficient
                if valid_sigs.len() < min_shares(self.pub_key_shares.len(), self.threshold) {
                    return Err(CombineError::TooFewValidShares);
                }

                Ok(combine_valid_shares(
                    valid_sigs,
                    self.pub_key_shares.len(),
                    self.threshold,
                ))
            })
            .collect::<Result<Vec<_>, CombineError>>();

        let bsigs = match bsigs {
            Ok(bs) => bs,
            Err(e) => return (Err(e), MintShareErrors(peer_errors)),
        };

        (
            Ok(SigResponse(request_id, bsigs)),
            MintShareErrors(peer_errors),
        )
    }

    /// Adds coins to the spendbook. Returns `true` if all coins were previously unspent and valid,
    /// false otherwise.
    pub fn spend(&mut self, coins: Vec<Coin>) -> bool {
        coins.into_iter().all(|c| {
            let unspent = self.spendbook.insert(c.0.clone());
            let valid = verify(
                Message::from_bytes(&bincode::serialize(&c.0).unwrap()), // FIXME: use digest, don't allocate
                c.1,
                self.pub_key,
            );
            unspent && valid
        })
    }

    /// Spend `coins` and generate a signature share for `new_tokens` if the amount of coins sent
    /// was greater or equal to the ones to be issued and they were all unspent and valid.
    pub fn reissue(
        &mut self,
        coins: Vec<Coin>,
        new_tokens: SignRequest,
    ) -> Option<PartialSigResponse> {
        if coins.len() >= new_tokens.0.len() && self.spend(coins) {
            Some(self.sign(new_tokens))
        } else {
            None
        }
    }
}

impl Coin {
    pub fn verify(&self, pk: AggregatePublicKey) -> bool {
        verify(
            Message::from_bytes(&bincode::serialize(&self.0).unwrap()),
            self.1,
            pk,
        )
    }

    pub fn spend_key(&self) -> &musig::PubKey {
        &self.0 .0
    }
}

impl CoinNonce {
    pub fn to_message(&self) -> Message {
        let mut hasher = Sha3_256::default();
        bincode::serialize_into(&mut hasher, &self.0).unwrap();
        Message::from_hash(hasher)
    }
}

pub trait RequestId {
    fn id(&self) -> u64;
}

impl RequestId for SignRequest {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for PartialSigResponse {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0
            .iter()
            .map(|(msg, _)| msg)
            .collect::<Vec<_>>()
            .hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for SigResponse {
    fn id(&self) -> u64 {
        self.0
    }
}

struct PartialSigZip<'a> {
    psigs: &'a [&'a (usize, PartialSigResponse)],
    idx: usize,
    len: usize,
}

struct PartialSigZipIter<'a> {
    psigs: &'a [&'a (usize, PartialSigResponse)],
    row: usize,
    col: usize,
}

impl<'a> PartialSigZip<'a> {
    fn new(psigs: &'a [&'a (usize, PartialSigResponse)], len: usize) -> Self {
        PartialSigZip { psigs, idx: 0, len }
    }
}

impl<'a> Iterator for PartialSigZip<'a> {
    type Item = PartialSigZipIter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < self.len {
            let res_iter = PartialSigZipIter {
                psigs: self.psigs,
                row: self.idx,
                col: 0,
            };
            self.idx += 1;
            Some(res_iter)
        } else {
            None
        }
    }
}

impl<'a> Iterator for PartialSigZipIter<'a>
where
    Self: 'a,
{
    type Item = (&'a usize, &'a BlindedMessage, &'a BlindedSignatureShare);

    fn next(&mut self) -> Option<Self::Item> {
        if self.col < self.psigs.len() {
            let (peer_id, row) = &self.psigs[self.col];
            let (msg, sig) = &row.0[self.row];
            self.col += 1;
            Some((peer_id, msg, sig))
        } else {
            None
        }
    }
}

/// Represents an array of mint indexes that delivered faulty shares
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct MintShareErrors(pub Vec<(usize, MintErrorType)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum MintErrorType {
    InvalidSignature,
    DifferentLengthAnswer,
    DifferentNonce,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum CombineError {
    TooFewValidShares,
    NoOwnContribution,
    MultiplePeerContributions(usize),
}
