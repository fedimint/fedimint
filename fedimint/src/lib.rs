mod util;

use crate::util::PartialSigZip;
use database::{Database, DatabaseKey, DatabaseKeyPrefix, DecodingError};
use mint_api::{Coin, CoinNonce, PartialSigResponse, RequestId, SigResponse, SignRequest};
use std::hash::Hash;
use tbs::{
    combine_valid_shares, min_shares, sign_blinded_msg, verify_blind_share, Aggregatable,
    AggregatePublicKey, PublicKeyShare, SecretKeyShare,
};
use thiserror::Error;
use tracing::{debug, warn};

/// Federated mint member mint
#[derive(Debug)]
pub struct Mint {
    key_idx: usize,
    sec_key: SecretKeyShare,
    pub_key_shares: Vec<PublicKeyShare>,
    pub_key: AggregatePublicKey,
    threshold: usize,
}

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
    ///
    /// # Panics:
    /// * if a supplied peer id is unknown
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
        if let Some((peer, count)) = peer_contrib_counts.into_iter().find(|(_, cnt)| **cnt > 1) {
            return (
                Err(CombineError::MultiplePeerContributions(*peer, *count)),
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
                let min_shares = min_shares(self.pub_key_shares.len(), self.threshold);
                if valid_sigs.len() < min_shares {
                    return Err(CombineError::TooFewValidShares(
                        valid_sigs.len(),
                        partial_sigs.len(),
                        min_shares,
                    ));
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
    pub fn spend<T: Database>(&self, transaction: &T, coins: Vec<Coin>) -> bool {
        coins.into_iter().all(|coin| {
            let valid = coin.verify(self.pub_key);
            let unspent = transaction
                .insert_entry(&NonceKey(coin.0), &())
                .expect("DB error")
                .is_none();
            unspent && valid
        })
    }

    /// Checks if coins are unspent and signed
    pub fn validate<T: Database>(&self, transaction: &T, coins: &[Coin]) -> bool {
        coins.into_iter().all(|coin| {
            let valid = coin.verify(self.pub_key);
            let unspent = transaction
                .get_value::<_, ()>(&NonceKey(coin.0.clone()))
                .expect("DB error")
                .is_none();
            unspent && valid
        })
    }

    /// Spend `coins` and generate a signature share for `new_tokens` if the amount of coins sent
    /// was greater or equal to the ones to be issued and they were all unspent and valid.
    pub fn reissue<T: Database>(
        &self,
        transaction: &T,
        coins: Vec<Coin>,
        new_tokens: SignRequest,
    ) -> Option<PartialSigResponse> {
        if coins.len() >= new_tokens.0.len() && self.spend(transaction, coins) {
            Some(self.sign(new_tokens))
        } else {
            None
        }
    }
}

const DB_PREFIX_COIN_NONCE: u8 = 10;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct NonceKey(CoinNonce);

impl DatabaseKeyPrefix for NonceKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_COIN_NONCE];
        bytes.extend_from_slice(&self.0.to_bytes());
        bytes
    }
}

impl DatabaseKey for NonceKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() == 0 || data[0] != DB_PREFIX_COIN_NONCE {
            return Err(DecodingError("Wrong prefix".into()));
        }

        Ok(NonceKey(CoinNonce::from_bytes(data)))
    }
}

/// Represents an array of mint indexes that delivered faulty shares
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MintShareErrors(pub Vec<(usize, MintErrorType)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum MintErrorType {
    InvalidSignature,
    DifferentLengthAnswer,
    DifferentNonce,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum CombineError {
    #[error(
        "Too few valid shares, only {0} of {1} (required minimum {2}) provided shares were valid"
    )]
    TooFewValidShares(usize, usize, usize),
    #[error("We could not find our own contribution in the provided shares, so we have no validation reference")]
    NoOwnContribution,
    #[error("Peer {0} contributed {1} shares, 1 expected")]
    MultiplePeerContributions(usize, usize),
}

#[cfg(test)]
mod test {
    use crate::{CombineError, Mint, MintErrorType};
    use mint_api::{RequestId, SignRequest};
    use tbs::{blind_message, unblind_signature, verify, AggregatePublicKey, Message};

    const THRESHOLD: usize = 1;
    const MINTS: usize = 5;

    fn build_mints() -> (AggregatePublicKey, Vec<Mint>) {
        let (pk, pks, sks) = tbs::dealer_keygen(THRESHOLD, MINTS);

        let mints = sks
            .into_iter()
            .map(|sk| Mint::new(sk, pks.clone(), THRESHOLD))
            .collect::<Vec<_>>();

        (pk, mints)
    }

    #[test]
    fn test_issuance() {
        let (pk, mut mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (bkey, bmsg) = blind_message(nonce);
        let req = SignRequest(vec![bmsg, bmsg]);

        let req_id = req.id();

        let psigs = mints
            .iter()
            .map(move |m| m.sign(req.clone()))
            .enumerate()
            .collect::<Vec<_>>();

        let mint = &mut mints[0];

        // Test happy path
        let (bsig_res, errors) = mint.combine(psigs.clone());
        assert!(errors.0.is_empty());

        let bsig = bsig_res.unwrap();
        assert_eq!(bsig.0, req_id);
        assert_eq!(bsig.1.len(), 2);

        bsig.1.iter().for_each(|bs| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test threshold sig shares
        let (bsig_res, errors) = mint.combine(psigs[..(MINTS - THRESHOLD)].to_vec());
        assert!(bsig_res.is_ok());
        assert!(errors.0.is_empty());

        bsig_res.unwrap().1.iter().for_each(|bs| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test too few sig shares
        let (bsig_res, errors) = mint.combine(psigs[..(MINTS - THRESHOLD - 1)].to_vec());
        assert_eq!(bsig_res, Err(CombineError::TooFewValidShares(3, 3, 4)));
        assert!(errors.0.is_empty());

        // Test no own share
        let (bsig_res, errors) = mint.combine(psigs[1..].to_vec());
        assert_eq!(bsig_res, Err(CombineError::NoOwnContribution));
        assert!(errors.0.is_empty());

        // Test multiple peer contributions
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .chain(std::iter::once(psigs[0].clone()))
                .collect(),
        );
        assert_eq!(bsig_res, Err(CombineError::MultiplePeerContributions(0, 2)));
        assert!(errors.0.is_empty());

        // Test wrong length response
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psigs)| {
                    if peer == 1 {
                        psigs.0.pop();
                    }
                    (peer, psigs)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(1, MintErrorType::DifferentLengthAnswer)));

        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == 2 {
                        psig.0[0].1 = psigs[0].1 .0[0].1;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors.0.contains(&(2, MintErrorType::InvalidSignature)));

        let (_bk, bmsg) = blind_message(Message::from_bytes(b"test"));
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == 3 {
                        psig.0[0].0 = bmsg;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors.0.contains(&(3, MintErrorType::DifferentNonce)));
    }

    #[test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (_pk, pks, sks) = tbs::dealer_keygen(THRESHOLD, MINTS);

        Mint::new(sks[0], pks[1..].to_vec(), THRESHOLD);
    }

    // FIXME: possibly make this an error
    #[test]
    #[should_panic(expected = "index out of bounds: the len is 5 but the index is 42")]
    fn test_combine_panic_with_unknown_mint_id() {
        let (_pk, mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (_bkey, bmsg) = blind_message(nonce);
        let req = SignRequest(vec![bmsg]);

        let psigs = mints
            .iter()
            .map(move |m| m.sign(req.clone()))
            .enumerate()
            .map(
                |(mint, sig)| {
                    if mint == 2 {
                        (42, sig)
                    } else {
                        (mint, sig)
                    }
                },
            )
            .collect::<Vec<_>>();
        let _ = mints[0].combine(psigs);
    }
}
