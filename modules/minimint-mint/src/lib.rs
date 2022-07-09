use crate::config::MintConfig;
use crate::db::{
    MintAuditItemKey, MintAuditItemKeyPrefix, NonceKey, OutputOutcomeKey,
    ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix, ReceivedPartialSignatureKey,
    ReceivedPartialSignatureKeyOutputPrefix, ReceivedPartialSignaturesKeyPrefix,
};
use async_trait::async_trait;
use itertools::Itertools;
use minimint_api::db::batch::{BatchItem, BatchTx, DbBatch};
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::audit::Audit;
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::ApiEndpoint;
use minimint_api::{Amount, FederationModule, InputMeta, OutPoint, PeerId};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use secp256k1_zkp::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::Sub;
use std::sync::Arc;
use tbs::{
    combine_valid_shares, sign_blinded_msg, verify_blind_share, Aggregatable, AggregatePublicKey,
    PublicKeyShare, SecretKeyShare,
};
use thiserror::Error;
use tiered::coins::Coins;
use tiered::coins::TieredMultiZip;
pub use tiered::keys::Keys;
use tracing::{debug, error, warn};

pub mod config;

mod db;
/// Data structures taking into account different amount tiers
pub mod tiered;

/// Federated mint member mint
pub struct Mint {
    key_id: PeerId,
    sec_key: Keys<SecretKeyShare>,
    pub_key_shares: BTreeMap<PeerId, Keys<PublicKeyShare>>,
    pub_key: HashMap<Amount, AggregatePublicKey>,
    threshold: usize, // TODO: move to cfg
    db: Arc<dyn Database>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartiallySignedRequest {
    pub out_point: OutPoint,
    pub partial_signature: PartialSigResponse,
}

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SignRequest(pub Coins<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PartialSigResponse(pub Coins<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SigResponse(pub Coins<tbs::BlindedSignature>);

/// A cryptographic coin consisting of a token and a threshold signature by the federated mint. In
/// this form it can oly be validated, not spent since for that the corresponding secret spend key
/// is required.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Coin(pub CoinNonce, pub tbs::Signature);

/// A unique coin nonce which is also a MuSig pub key so that transactions can be signed by the
/// spent coin's spending keys to avoid mint frontrunning.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinNonce(pub XOnlyPublicKey);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct BlindToken(pub tbs::BlindedMessage);

#[derive(Debug)]
pub struct VerificationCache {
    valid_coins: HashMap<Coin, Amount>,
}

#[async_trait(?Send)]
impl FederationModule for Mint {
    type Error = MintError;
    type TxInput = Coins<Coin>;
    type TxOutput = Coins<BlindToken>;
    type TxOutputOutcome = Option<SigResponse>; // TODO: make newtype
    type ConsensusItem = PartiallySignedRequest;
    type VerificationCache = VerificationCache;

    async fn await_consensus_proposal<'a>(&'a self, rng: impl RngCore + CryptoRng + 'a) {
        if self.consensus_proposal(rng).await.is_empty() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        self.db
            .find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
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

    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a Self::TxInput> + Send,
    ) -> Self::VerificationCache {
        // We build a lookup table for checking the validity of all coins for certain amounts. This
        // calculation can happen massively in parallel since verification is a pure function and
        // thus has no side effects.
        let valid_coins = inputs
            .flat_map(|inputs| inputs.iter())
            .par_bridge()
            .filter_map(|(amount, coin)| {
                let amount_key = self.pub_key.get(&amount)?;
                if coin.verify(*amount_key) {
                    Some((coin.clone(), amount))
                } else {
                    None
                }
            })
            .collect();

        VerificationCache { valid_coins }
    }

    fn validate_input<'a>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        input.iter().try_for_each(|(amount, coin)| {
            let coin_valid = cache
                .valid_coins
                .get(coin) // We validated the coin
                .map(|coint_amount| *coint_amount == amount) // It has the right amount tier
                .unwrap_or(false); // If we didn't validate the coin return false

            if !coin_valid {
                return Err(MintError::InvalidSignature);
            }

            if self
                .db
                .get_value(&NonceKey(coin.0.clone()))
                .expect("DB error")
                .is_some()
            {
                return Err(MintError::SpentCoin);
            }

            Ok(())
        })?;

        Ok(InputMeta {
            amount: input.amount(),
            puk_keys: Box::new(input.iter().map(|(_, coin)| *coin.spend_key())),
        })
    }

    fn apply_input<'a, 'b>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        mut batch: BatchTx<'a>,
        input: &'b Self::TxInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error> {
        let meta = self.validate_input(interconnect, cache, input)?;

        batch.append_from_iter(input.iter().flat_map(|(amount, coin)| {
            let key = NonceKey(coin.0.clone());
            vec![
                BatchItem::insert_new(key.clone(), ()),
                BatchItem::insert_new(MintAuditItemKey::Redemption(key), amount),
            ]
        }));
        batch.commit();

        Ok(meta)
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
        let partial_sig = self.blind_sign(output.clone())?;

        batch.append_insert_new(
            ProposedPartialSignatureKey {
                request_id: out_point,
            },
            partial_sig,
        );
        batch.append_insert_new(MintAuditItemKey::Issuance(out_point), output.amount());
        batch.commit();
        Ok(output.amount())
    }

    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // Finalize partial signatures for which we now have enough shares
        let req_psigs = self
            .db
            .find_by_prefix(&ReceivedPartialSignaturesKeyPrefix)
            .map(|entry_res| {
                let (key, partial_sig) = entry_res.expect("DB error");
                (key.request_id, (key.peer_id, partial_sig))
            })
            .into_group_map();

        // TODO: use own par iter impl that allows efficient use of accumulators or just decouple it entirely (doesn't need consensus)
        let par_batches = req_psigs
            .into_par_iter()
            .map(|(issuance_id, shares)| {
                let mut drop_peers = Vec::<PeerId>::new();
                let mut batch = DbBatch::new();
                let mut batch_tx = batch.transaction();
                let (bsig, errors) = self.combine(shares.clone());

                // FIXME: validate shares before writing to DB to make combine infallible
                errors.0.iter().for_each(|(peer, error)| {
                    error!("Dropping {:?} for {:?}", peer, error);
                    drop_peers.push(*peer);
                });

                match bsig {
                    Ok(blind_signature) => {
                        debug!(
                            %issuance_id,
                            "Successfully combined signature shares",
                        );

                        batch_tx.append_from_iter(shares.into_iter().map(|(peer, _)| {
                            BatchItem::delete(ReceivedPartialSignatureKey {
                                request_id: issuance_id,
                                peer_id: peer,
                            })
                        }));

                        batch_tx.append_insert(OutputOutcomeKey(issuance_id), blind_signature);
                    }
                    Err(CombineError::TooFewShares(got, _)) => {
                        for peer in consensus_peers.sub(&HashSet::from_iter(got)) {
                            error!("Dropping {:?} for not contributing shares", peer);
                            drop_peers.push(peer);
                        }
                    }
                    Err(error) => {
                        warn!(%error, "Could not combine shares");
                    }
                }
                batch_tx.commit();
                (batch, drop_peers)
            })
            .collect::<Vec<_>>();

        let dropped_peers = par_batches
            .iter()
            .flat_map(|(_, peers)| peers)
            .copied()
            .collect();

        let mut redemptions = Amount::from_sat(0);
        let mut issuances = Amount::from_sat(0);
        self.db
            .find_by_prefix(&MintAuditItemKeyPrefix)
            .for_each(|res| {
                let (key, amount) = res.expect("DB error");
                match key {
                    MintAuditItemKey::Issuance(_) => issuances += amount,
                    MintAuditItemKey::IssuanceTotal => issuances += amount,
                    MintAuditItemKey::Redemption(_) => redemptions += amount,
                    MintAuditItemKey::RedemptionTotal => redemptions += amount,
                }
                batch.append_delete(key);
            });
        batch.append_insert(MintAuditItemKey::IssuanceTotal, issuances);
        batch.append_insert(MintAuditItemKey::RedemptionTotal, redemptions);

        batch.append_from_accumulators(par_batches.into_iter().map(|(batch, _)| batch));
        batch.commit();

        dropped_peers
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        let we_proposed = self
            .db
            .get_value(&ProposedPartialSignatureKey {
                request_id: out_point,
            })
            .expect("DB error")
            .is_some();
        let was_consensus_outcome = self
            .db
            .find_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix {
                request_id: out_point,
            })
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

    fn audit(&self, audit: &mut Audit) {
        audit.add_items(&self.db, &MintAuditItemKeyPrefix, |k, v| match k {
            MintAuditItemKey::Issuance(_) => -(v.milli_sat as i64),
            MintAuditItemKey::IssuanceTotal => -(v.milli_sat as i64),
            MintAuditItemKey::Redemption(_) => v.milli_sat as i64,
            MintAuditItemKey::RedemptionTotal => v.milli_sat as i64,
        });
    }

    fn api_base_name(&self) -> &'static str {
        "mint"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[]
    }
}

impl Mint {
    /// Constructs a new mint
    ///
    /// # Panics
    /// * If there are no amount tiers
    /// * If the amount tiers for secret and public keys are inconsistent
    /// * If the pub key belonging to the secret key share is not in the pub key list.
    pub fn new(cfg: MintConfig, threshold: usize, db: Arc<dyn Database>) -> Mint {
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

    fn blind_sign(&self, output: Coins<BlindToken>) -> Result<PartialSigResponse, MintError> {
        Ok(PartialSigResponse(output.map(
            |amt, msg| -> Result<_, InvalidAmountTierError> {
                let sec_key = self.sec_key.tier(&amt)?;
                let blind_signature = sign_blinded_msg(msg.0, *sec_key);
                Ok((msg.0, blind_signature))
            },
        )?))
    }

    fn combine(
        &self,
        partial_sigs: Vec<(PeerId, PartialSigResponse)>,
    ) -> (Result<SigResponse, CombineError>, MintShareErrors) {
        // Terminate early if there are not enough shares
        if partial_sigs.len() < self.threshold {
            return (
                Err(CombineError::TooFewShares(
                    partial_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                    self.threshold,
                )),
                MintShareErrors(vec![]),
            );
        }

        // FIXME: decide on right boundary place for this invariant
        // Filter out duplicate contributions, they make share combinations fail
        let peer_contrib_counts = partial_sigs
            .iter()
            .map(|(idx, _)| *idx)
            .collect::<counter::Counter<_>>();
        if let Some((peer, count)) = peer_contrib_counts.into_iter().find(|(_, cnt)| *cnt > 1) {
            return (
                Err(CombineError::MultiplePeerContributions(peer, count)),
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
                        %peer,
                        "Peer proposed a sig share of wrong structure (different than ours)",
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
        if self
            .db
            .get_value(&OutputOutcomeKey(output_id))
            .expect("DB error")
            .is_some()
        {
            debug!(
                issuance = %output_id,
                "Received sig share for finalized issuance, ignoring",
            );
            return;
        }

        debug!(
            %peer,
            issuance = %output_id,
            "Received sig share"
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

impl Coin {
    /// Verify the coin's validity under a mit key `pk`
    pub fn verify(&self, pk: tbs::AggregatePublicKey) -> bool {
        tbs::verify(self.0.to_message(), self.1, pk)
    }

    /// Access the nonce as the public key to the spend key
    pub fn spend_key(&self) -> &XOnlyPublicKey {
        &self.0 .0
    }
}

impl CoinNonce {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bincode::serialize_into(&mut bytes, &self.0).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // FIXME: handle errors or the client can be crashed
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_message(&self) -> tbs::Message {
        tbs::Message::from_bytes(&self.0.serialize()[..])
    }
}

impl From<SignRequest> for Coins<BlindToken> {
    fn from(sig_req: SignRequest) -> Self {
        sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, crate::BlindToken(token)))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct InvalidAmountTierError(pub Amount);

impl std::fmt::Display for InvalidAmountTierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Amount tier unknown to mint: {}", self.0)
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
    #[error("Too few shares to begin the combination: got {0:?} need {1}")]
    TooFewShares(Vec<PeerId>, usize),
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
    use crate::config::MintClientConfig;
    use crate::{BlindToken, Coins, CombineError, Mint, MintConfig, PeerErrorType};
    use minimint_api::config::GenerateConfig;
    use minimint_api::db::mem_impl::MemDatabase;
    use minimint_api::{Amount, PeerId};
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tbs::{blind_message, unblind_signature, verify, AggregatePublicKey, Message};

    const THRESHOLD: usize = 1;
    const MINTS: usize = 5;

    fn build_configs() -> (Vec<MintConfig>, MintClientConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let (mint_cfg, client_cfg) = MintConfig::trusted_dealer_gen(
            &peers,
            THRESHOLD,
            &[Amount::from_sat(1)],
            OsRng::new().unwrap(),
        );

        (mint_cfg.into_iter().map(|(_, c)| c).collect(), client_cfg)
    }

    fn build_mints() -> (AggregatePublicKey, Vec<Mint>) {
        let (mint_cfg, client_cfg) = build_configs();
        let mints = mint_cfg
            .into_iter()
            .map(|config| Mint::new(config, MINTS - THRESHOLD, Arc::new(MemDatabase::new())))
            .collect::<Vec<_>>();

        let agg_pk = *client_cfg.tbs_pks.keys.get(&Amount::from_sat(1)).unwrap();

        (agg_pk, mints)
    }

    #[test_log::test]
    fn test_issuance() {
        let (pk, mut mints) = build_mints();

        let nonce = Message::from_bytes(&b"test coin"[..]);
        let (bkey, bmsg) = blind_message(nonce);
        let blind_tokens = Coins {
            coins: vec![(
                Amount::from_sat(1),
                vec![BlindToken(bmsg), BlindToken(bmsg)],
            )]
            .into_iter()
            .collect(),
        };

        let psigs = mints
            .iter()
            .map(move |m| (m.key_id, m.blind_sign(blind_tokens.clone()).unwrap()))
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
        let few_sigs = psigs[..(MINTS - THRESHOLD - 1)].to_vec();
        let (bsig_res, errors) = mint.combine(few_sigs.clone());
        assert_eq!(
            bsig_res,
            Err(CombineError::TooFewShares(
                few_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                MINTS - THRESHOLD
            ))
        );
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
        assert_eq!(
            bsig_res,
            Err(CombineError::MultiplePeerContributions(PeerId::from(0), 2))
        );
        assert!(errors.0.is_empty());

        // Test wrong length response
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psigs)| {
                    if peer == PeerId::from(1) {
                        psigs.0.coins.get_mut(&Amount::from_sat(1)).unwrap().pop();
                    }
                    (peer, psigs)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(1), PeerErrorType::DifferentStructureSigShare)));

        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(2) {
                        psig.0.coins.get_mut(&Amount::from_sat(1)).unwrap()[0].1 =
                            psigs[0].1 .0.coins[&Amount::from_sat(1)][0].1;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(2), PeerErrorType::InvalidSignature)));

        let (_bk, bmsg) = blind_message(Message::from_bytes(b"test"));
        let (bsig_res, errors) = mint.combine(
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(3) {
                        psig.0.coins.get_mut(&Amount::from_sat(1)).unwrap()[0].0 = bmsg;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(3), PeerErrorType::DifferentNonce)));
    }

    #[test_log::test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (mint_server_cfg1, _) = build_configs();
        let (mint_server_cfg2, _) = build_configs();

        Mint::new(
            MintConfig {
                tbs_sks: mint_server_cfg1[0].tbs_sks.clone(),
                peer_tbs_pks: mint_server_cfg2[0].peer_tbs_pks.clone(),
            },
            THRESHOLD,
            Arc::new(MemDatabase::new()),
        );
    }
}
