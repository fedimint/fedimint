pub mod config;
mod db;

use crate::config::MintConfig;
use crate::db::{
    NonceKey, OutputOutcomeKey, ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix,
    ReceivedPartialSignatureKey, ReceivedPartialSignatureKeyOutputPrefix,
    ReceivedPartialSignaturesKeyPrefix,
};
use async_trait::async_trait;
use itertools::Itertools;
use minimint_api::db::batch::{BatchItem, BatchTx, DbBatch};
use minimint_api::db::{Database, RawDatabase};
use minimint_api::transaction::{BlindToken, OutPoint};
use minimint_api::util::TieredMultiZip;
use minimint_api::{
    Amount, Coin, Coins, FederationModule, InvalidAmountTierError, Keys, PartialSigResponse,
    PeerId, SigResponse,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Arc;
use tbs::{
    combine_valid_shares, sign_blinded_msg, verify_blind_share, Aggregatable, AggregatePublicKey,
    PublicKeyShare, SecretKeyShare,
};
use thiserror::Error;
use tracing::{debug, error, warn};

/// Federated mint member mint
pub struct Mint {
    key_id: PeerId,
    sec_key: Keys<SecretKeyShare>,
    pub_key_shares: BTreeMap<PeerId, Keys<PublicKeyShare>>,
    pub_key: HashMap<Amount, AggregatePublicKey>,
    threshold: usize, // TODO: move to cfg
    db: Arc<dyn RawDatabase>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartiallySignedRequest {
    out_point: OutPoint,
    partial_signature: minimint_api::PartialSigResponse,
}

#[async_trait(?Send)]
impl FederationModule for Mint {
    type Error = MintError;
    type TxInput = Coins<Coin>;
    type TxOutput = Coins<BlindToken>;
    type TxOutputOutcome = Option<SigResponse>;
    type ConsensusItem = PartiallySignedRequest;

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        self.db
            .find_by_prefix::<_, ProposedPartialSignatureKey, PartialSigResponse>(
                &ProposedPartialSignaturesKeyPrefix,
            )
            .map(|res| {
                let (key, partial_signature) = res.expect("DB error");
                PartiallySignedRequest {
                    out_point: key.request_id,
                    partial_signature,
                }
            })
            .collect()
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        for (peer, partial_sig) in consensus_items {
            self.process_partial_signature(
                batch.subtransaction(),
                peer,
                partial_sig.out_point,
                partial_sig.partial_signature,
            )
        }
        batch.commit();
    }

    fn validate_input(&self, input: &Self::TxInput) -> Result<Amount, Self::Error> {
        input
            .iter()
            .map(|(amount, coin)| {
                if !coin.verify(
                    *self
                        .pub_key
                        .get(&amount)
                        .ok_or(MintError::InvalidAmountTier(amount))?,
                ) {
                    return Err(MintError::InvalidSignature);
                }

                if self
                    .db
                    .get_value::<_, ()>(&NonceKey(coin.0.clone()))
                    .expect("DB error")
                    .is_some()
                {
                    return Err(MintError::SpentCoin);
                }

                Ok(())
            })
            .collect::<Result<(), MintError>>()?;
        Ok(input.amount())
    }

    fn apply_input<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        input: &'a Self::TxInput,
    ) -> Result<Amount, Self::Error> {
        let amount = self.validate_input(input)?;

        batch.append_from_iter(
            input
                .iter()
                .map(|(_, coin)| BatchItem::insert_new(NonceKey(coin.0.clone()), ())),
        );
        batch.commit();

        Ok(amount)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        if let Some(amount) = output.iter().find_map(|(amount, _)| {
            if self.pub_key.get(&amount).is_none() {
                Some(amount)
            } else {
                None
            }
        }) {
            Err(MintError::InvalidAmountTier(amount))
        } else {
            Ok(output.amount())
        }
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        // TODO: move actual signing to worker thread
        // TODO: get rid of clone
        let partial_sig = output
            .clone()
            .map(|amt, msg| -> Result<_, InvalidAmountTierError> {
                let sec_key = self.sec_key.tier(&amt)?;
                let blind_signature = sign_blinded_msg(msg.0, *sec_key);
                Ok((msg.0, blind_signature))
            })?;

        batch.append_insert_new(
            ProposedPartialSignatureKey {
                request_id: out_point,
            },
            PartialSigResponse(partial_sig),
        );

        batch.commit();
        Ok(output.amount())
    }

    async fn end_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        // Finalize partial signatures for which we now have enough shares
        let req_psigs = self
            .db
            .find_by_prefix::<_, ReceivedPartialSignatureKey, PartialSigResponse>(
                &ReceivedPartialSignaturesKeyPrefix,
            )
            .map(|entry_res| {
                let (key, partial_sig) = entry_res.expect("DB error");
                (key.request_id, (key.peer_id, partial_sig))
            })
            .into_group_map();

        // TODO: use own par iter impl that allows efficient use of accumulators or just decouple it entirely (doesn't need consensus)
        let par_batches = req_psigs
            .into_par_iter()
            .filter_map(|(issuance_id, shares)| {
                let mut batch = DbBatch::new();
                let mut batch_tx = batch.transaction();

                if shares.len() > self.threshold {
                    debug!(
                        "Trying to combine sig shares for issuance request {}",
                        issuance_id
                    );
                    let (bsig, errors) = self.combine(shares.clone());
                    // FIXME: validate shares before writing to DB to make combine infallible
                    if !errors.0.is_empty() {
                        warn!("Peer sent faulty share: {:?}", errors);
                    }

                    match bsig {
                        Ok(blind_signature) => {
                            debug!(
                                "Successfully combined signature shares for issuance request {}",
                                issuance_id
                            );

                            batch_tx.append_from_iter(shares.into_iter().map(|(peer, _)| {
                                BatchItem::delete(ReceivedPartialSignatureKey {
                                    request_id: issuance_id,
                                    peer_id: peer,
                                })
                            }));

                            batch_tx.append_insert(OutputOutcomeKey(issuance_id), blind_signature);
                            batch_tx.commit();
                            Some(batch)
                        }
                        Err(e) => {
                            error!("Could not combine shares: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        batch.append_from_accumulators(par_batches.into_iter());
        batch.commit();
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        let we_proposed = self
            .db
            .get_value::<_, PartialSigResponse>(&ProposedPartialSignatureKey {
                request_id: out_point,
            })
            .expect("DB error")
            .is_some();
        let was_consensus_outcome = self
            .db
            .find_by_prefix::<_, ReceivedPartialSignatureKey, PartialSigResponse>(
                &ReceivedPartialSignatureKeyOutputPrefix {
                    request_id: out_point,
                },
            )
            .any(|res| res.is_ok());

        let final_sig = self
            .db
            .get_value(&OutputOutcomeKey(out_point))
            .expect("DB error");

        if final_sig.is_some() {
            Some(final_sig)
        } else if we_proposed || was_consensus_outcome {
            Some(None)
        } else {
            None
        }
    }
}

impl Mint {
    /// Constructs a new ming
    ///
    /// # Panics
    /// * If there are no amount tiers
    /// * If the amount tiers for secret and public keys are inconsistent
    /// * If the pub key belonging to the secret key share is not in the pub key list.
    pub fn new(cfg: MintConfig, threshold: usize, db: Arc<dyn RawDatabase>) -> Mint {
        assert!(cfg.tbs_sks.tiers().count() > 0);

        // The amount tiers are implicitly provided by the key sets, make sure they are internally
        // consistent.
        assert!(cfg
            .peer_tbs_pks
            .values()
            .all(|pk| pk.structural_eq(&cfg.tbs_sks)));

        let ref_pub_key = cfg.tbs_sks.to_public();

        // Find our key index and make sure we know the private key for all our public key shares
        let our_id = cfg // FIXME: make sure we use id instead of idx everywhere
            .peer_tbs_pks
            .iter()
            .find_map(|(&id, pk)| if pk == &ref_pub_key { Some(id) } else { None })
            .expect("Own key not found among pub keys.");

        assert_eq!(
            cfg.peer_tbs_pks[&our_id],
            cfg.tbs_sks
                .iter()
                .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
                .collect()
        );

        let aggregate_pub_keys = TieredMultiZip::new(
            cfg.peer_tbs_pks
                .iter()
                .map(|(_, keys)| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(threshold))
        })
        .collect();

        Mint {
            key_id: our_id,
            sec_key: cfg.tbs_sks,
            pub_key_shares: cfg.peer_tbs_pks,
            pub_key: aggregate_pub_keys,
            threshold,
            db,
        }
    }
}

impl Mint {
    fn combine(
        &self,
        partial_sigs: Vec<(PeerId, PartialSigResponse)>,
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
        let our_contribution = match &partial_sigs.iter().find(|(peer, _)| *peer == self.key_id) {
            Some((_, psigs)) => psigs,
            None => {
                return (
                    Err(CombineError::NoOwnContribution),
                    MintShareErrors(vec![]),
                )
            }
        };

        let reference_msgs = our_contribution.0.iter().map(|(_amt, (msg, _sig))| msg);

        let mut peer_errors = vec![];

        let partial_sigs = partial_sigs
            .iter()
            .filter(|(peer, sigs)| {
                if !sigs.0.structural_eq(&our_contribution.0) {
                    warn!(
                        "Peer {} proposed a sig share of wrong structure (different than ours)",
                        peer,
                    );
                    peer_errors.push((*peer, PeerErrorType::DifferentStructureSigShare));
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

        let bsigs = TieredMultiZip::new(
            partial_sigs
                .iter()
                .map(|(_peer, sig_share)| sig_share.0.iter())
                .collect(),
        )
        .zip(reference_msgs)
        .map(|((amt, sig_shares), ref_msg)| {
            let peer_ids = partial_sigs.iter().map(|(peer, _)| *peer);

            // Filter out invalid peer contributions
            let valid_sigs = sig_shares
                .into_iter()
                .zip(peer_ids)
                .filter_map(|((msg, sig), peer)| {
                    let amount_key = match self.pub_key_shares[&peer].tier(&amt) {
                        Ok(key) => key,
                        Err(_) => {
                            peer_errors.push((peer, PeerErrorType::InvalidAmountTier));
                            return None;
                        }
                    };

                    if msg != ref_msg {
                        peer_errors.push((peer, PeerErrorType::DifferentNonce));
                        None
                    } else if !verify_blind_share(*msg, *sig, *amount_key) {
                        peer_errors.push((peer, PeerErrorType::InvalidSignature));
                        None
                    } else {
                        Some((peer, *sig))
                    }
                })
                .collect::<Vec<_>>();

            // Check that there are still sufficient
            if valid_sigs.len() < self.threshold {
                return Err(CombineError::TooFewValidShares(
                    valid_sigs.len(),
                    partial_sigs.len(),
                    self.threshold,
                ));
            }

            let sig = combine_valid_shares(
                valid_sigs
                    .into_iter()
                    .map(|(peer, share)| (peer.to_usize(), share)),
                self.threshold,
            );

            Ok((amt, sig))
        })
        .collect::<Result<Coins<_>, CombineError>>();

        let bsigs = match bsigs {
            Ok(bs) => bs,
            Err(e) => return (Err(e), MintShareErrors(peer_errors)),
        };

        (Ok(SigResponse(bsigs)), MintShareErrors(peer_errors))
    }

    fn process_partial_signature(
        &self,
        mut batch: BatchTx,
        peer: PeerId,
        output_id: OutPoint,
        partial_sig: PartialSigResponse,
    ) {
        match self
            .db
            .get_value::<_, SigResponse>(&OutputOutcomeKey(output_id))
            .expect("DB error")
        {
            Some(_) => {
                debug!(
                    "Received sig share for finalized issuance {}, ignoring",
                    output_id
                );
                return;
            }
            None => {}
        };

        debug!(
            "Received sig share from peer {} for issuance {}",
            peer, output_id
        );
        batch.append_insert_new(
            ReceivedPartialSignatureKey {
                request_id: output_id,
                peer_id: peer,
            },
            partial_sig,
        );

        // FIXME: add own id to cfg
        if peer == self.key_id {
            batch.append_delete(ProposedPartialSignatureKey {
                request_id: output_id,
            });
        }

        batch.commit();
    }
}

/// Represents an array of mint indexes that delivered faulty shares
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MintShareErrors(pub Vec<(PeerId, PeerErrorType)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PeerErrorType {
    InvalidSignature,
    DifferentStructureSigShare,
    DifferentNonce,
    InvalidAmountTier,
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
    MultiplePeerContributions(PeerId, usize),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum MintError {
    #[error("One of the supplied coins had an invalid mint signature")]
    InvalidCoin,
    #[error("Insufficient coin value: reissuing {0} but only got {1} in coins")]
    TooFewCoins(Amount, Amount),
    #[error("One of the supplied coins was already spent previously")]
    SpentCoin,
    #[error("One of the coins had an invalid amount not issued by the mint: {0:?}")]
    InvalidAmountTier(Amount),
    #[error("One of the coins had an invalid signature")]
    InvalidSignature,
}

impl From<InvalidAmountTierError> for MintError {
    fn from(e: InvalidAmountTierError) -> Self {
        MintError::InvalidAmountTier(e.0)
    }
}

#[cfg(test)]
mod test {
    // TODO: reactivate
    /*
    use crate::{CombineError, Mint, MintError, MintShareErrors, PeerErrorType};
    use ::database::mem_impl::MemDatabase;
    use minimint_api::{Amount, Coin, Coins, Keys, PartialSigResponse, SigResponse, SignRequest};
    use std::sync::Arc;
    use tbs::{blind_message, unblind_signature, verify, AggregatePublicKey, Message};

    const THRESHOLD: usize = 1;
    const MINTS: usize = 5;

    fn build_mints() -> (AggregatePublicKey, Vec<Mint>) {
        let (pk, pks, sks) = tbs::dealer_keygen(THRESHOLD, MINTS);

        let mints = sks
            .into_iter()
            .map(|sk| {
                Mint::new(
                    [(Amount::from_sat(1), sk)].iter().cloned().collect(),
                    pks.iter()
                        .map(|pk| Keys {
                            keys: vec![(Amount::from_sat(1), *pk)].into_iter().collect(),
                        })
                        .collect(),
                    THRESHOLD,
                    Arc::new(MemDatabase::new()),
                )
            })
            .collect::<Vec<_>>();

        (pk, mints)
    }

    #[test]
    fn test_issuance() {
        let (pk, mut mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (bkey, bmsg) = blind_message(nonce);
        let req = SignRequest(Coins {
            coins: vec![(Amount::from_sat(1), vec![bmsg, bmsg])]
                .into_iter()
                .collect(),
        });

        let psigs = mints
            .iter()
            .map(move |m| m.issue(req.clone()).unwrap())
            .enumerate()
            .collect::<Vec<_>>();

        let mint = &mut mints[0];

        // Test happy path
        let (bsig_res, errors) = mint.combine(psigs.clone());
        assert!(errors.0.is_empty());

        let bsig = bsig_res.unwrap();
        assert_eq!(bsig.0.amount(), Amount::from_sat(2));

        bsig.0.iter().for_each(|(_, bs)| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test threshold sig shares
        let (bsig_res, errors) = mint.combine(psigs[..(MINTS - THRESHOLD)].to_vec());
        assert!(bsig_res.is_ok());
        assert!(errors.0.is_empty());

        bsig_res.unwrap().0.iter().for_each(|(_, bs)| {
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
                        psigs.0.coins.get_mut(&Amount::from_sat(1)).unwrap().pop();
                    }
                    (peer, psigs)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(1, PeerErrorType::DifferentStructureSigShare)));

        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == 2 {
                        psig.0.coins.get_mut(&Amount::from_sat(1)).unwrap()[0].1 =
                            psigs[0].1 .0.coins[&Amount::from_sat(1)][0].1;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors.0.contains(&(2, PeerErrorType::InvalidSignature)));

        let (_bk, bmsg) = blind_message(Message::from_bytes(b"test"));
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == 3 {
                        psig.0.coins.get_mut(&Amount::from_sat(1)).unwrap()[0].0 = bmsg;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors.0.contains(&(3, PeerErrorType::DifferentNonce)));
    }

    #[test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (_pk, pks, sks) = tbs::dealer_keygen(THRESHOLD, MINTS);
        let db = MemDatabase::new();

        Mint::new(
            vec![(Amount::from_sat(1), sks[0])].into_iter().collect(),
            pks[1..]
                .iter()
                .map(|pk| Keys {
                    keys: vec![(Amount::from_sat(1), *pk)].into_iter().collect(),
                })
                .collect(),
            THRESHOLD,
            Arc::new(db),
        );
    }


    // FIXME: possibly make this an error
    #[test]
    #[should_panic(expected = "index out of bounds: the len is 5 but the index is 42")]
    fn test_combine_panic_with_unknown_mint_id() {
        let (_pk, mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (_bkey, bmsg) = blind_message(nonce);
        let req = SignRequest(vec![(Amount::from_sat(1), bmsg)].into_iter().collect());

        let psigs = mints
            .iter()
            .map(move |m| m.issue(req.clone()).unwrap())
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
     */
}
