use crate::database::{
    AllConsensusItemsKeyPrefix, AllPartialSignaturesKey, ConsensusItemKeyPrefix, DummyValue,
    FinalizedSignatureKey, PartialSignatureKey,
};
use crate::net::api::ClientRequest;
use crate::rng::RngGenerator;
use config::ServerConfig;
use counter::Counter;
use database::batch::{Batch as DbBatch, BatchItem, Element};
use database::{BatchDb, BincodeSerialized, Database, DatabaseError, PrefixSearchable};
use fedimint::{FediMint, MintError};
use fediwallet::{Wallet, WalletConsensusItem};
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use mint_api::{
    Amount, BitcoinHash, InvalidAmountTierError, PartialSigResponse, PegInRequest,
    ReissuanceRequest, TransactionId, TxId,
};
use musig;
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ConsensusItem {
    ClientRequest(ClientRequest),
    PartiallySignedRequest(TransactionId, mint_api::PartialSigResponse),
    Wallet(WalletConsensusItem),
}

pub type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;

pub struct FediMintConsensus<R, D, M>
where
    R: RngCore + CryptoRng,
    D: Database + PrefixSearchable + Sync,
    M: FediMint + Sync,
{
    /// Cryptographic random number generator used for everything
    pub rng_gen: Box<dyn RngGenerator<Rng = R>>,
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig, // TODO: make custom config

    /// Our local mint
    pub mint: M, //TODO: box dyn trait
    pub wallet: Wallet<D>,

    /// KV Database into which all state is persisted to recover from in case of a crash
    pub db: D,
}

impl<R, D, M> FediMintConsensus<R, D, M>
where
    R: RngCore + CryptoRng,
    D: Database + PrefixSearchable + BatchDb + Sync + Send + Clone + 'static,
    M: FediMint + Sync,
{
    pub fn submit_client_request(&self, cr: ClientRequest) -> Result<(), ClientRequestError> {
        debug!("Received client request of type {}", cr.dbg_type_name());
        match cr {
            ClientRequest::Reissuance(ref reissuance_req) => {
                let pub_keys = reissuance_req
                    .coins
                    .iter()
                    .map(|(_, coin)| coin.spend_key())
                    .collect::<Vec<_>>();

                if !musig::verify(
                    reissuance_req.id().into_inner(),
                    reissuance_req.sig.clone(),
                    &pub_keys,
                ) {
                    return Err(ClientRequestError::InvalidTransactionSignature);
                }

                reissuance_req.coins.check_tiers(&self.cfg.tbs_sks)?;
                reissuance_req
                    .blind_tokens
                    .0
                    .check_tiers(&self.cfg.tbs_sks)?;

                self.mint.validate(&self.db, &reissuance_req.coins)?;
            }
            // FIXME: validate peg in/out proofs
            ClientRequest::PegIn(ref peg_in) => {
                self.wallet
                    .verify_pigin(&peg_in.proof)
                    .ok_or(ClientRequestError::InvalidPegIn)?;

                secp256k1::global::SECP256K1
                    .verify(
                        &peg_in.id().as_hash().into(),
                        &peg_in.sig,
                        peg_in.proof.tweak_contract_key(),
                    )
                    .map_err(|_| ClientRequestError::InvalidPegIn)?;

                peg_in.blind_tokens.0.check_tiers(&self.cfg.tbs_sks)?;
            }
            ClientRequest::PegOut(ref peg_out) => {
                peg_out.coins.check_tiers(&self.cfg.tbs_sks)?;
            }
        }

        let new = self
            .db
            .insert_entry(&ConsensusItem::ClientRequest(cr), &())
            .expect("DB error");

        if new.is_some() {
            warn!("Added consensus item was already in consensus queue");
        }

        Ok(())
    }

    pub async fn process_consensus_outcome(&self, batch: Batch<Vec<ConsensusItem>, u16>) {
        info!("Processing output of epoch {}", batch.epoch);

        let wallet_consensus = batch
            .contributions
            .values()
            .flatten()
            .filter_map(|ci| match ci {
                ConsensusItem::ClientRequest(_) => None,
                ConsensusItem::PartiallySignedRequest(_, _) => None,
                ConsensusItem::Wallet(wci) => Some(wci.clone()),
            })
            .collect::<Vec<_>>();
        self.wallet
            .process_consensus_proposals(wallet_consensus)
            .await
            .expect("wallet error");

        // Since the changes to the database will happen all at once we won't be able to handle
        // conflicts between consensus items in one batch there. Thus we need to make sure that
        // all items in a batch are consistent/deterministically filter out inconsistent ones.
        // There are two item tyoes that need checking:
        //  * peg-ins that each peg-in tx is only used to issue coins once
        //  * coin spends to avoid double spends in one batch

        // TODO: check if spent coins are the only thing needing a sanity cross tx check
        // Make sure every coin appears only in one request
        let spent_coins = batch
            .contributions
            .iter()
            .flat_map(|(_, cis)| cis.iter())
            .unique()
            .filter_map(|ci| match ci {
                ConsensusItem::ClientRequest(ClientRequest::Reissuance(req)) => {
                    Some(req.coins.iter().map(|(_, coin)| coin.clone())) // TODO: get rid of clone once MuSig2 lands
                }
                ConsensusItem::ClientRequest(ClientRequest::PegOut(_)) => {
                    unimplemented!()
                }
                _ => None,
            })
            .flatten()
            .collect::<Counter<_>>();

        let used_peg_in_proofs = batch
            .contributions
            .iter()
            .flat_map(|(_, cis)| cis.iter())
            .unique()
            .filter_map(|ci| match ci {
                ConsensusItem::ClientRequest(ClientRequest::PegIn(req)) => {
                    Some(req.proof.identity())
                }
                _ => None,
            })
            .collect::<Counter<_>>();

        // Filter batch for consistency
        let batch = batch
            .contributions
            .into_iter()
            .flat_map(|(peer, cis)| {
                debug!("Peer {} contributed {} items", peer, cis.len());

                // TODO: possibly clean DB afterwards/burn coins
                // Filter out any double spends
                cis.into_iter()
                    .filter(|ci| match ci {
                        ConsensusItem::ClientRequest(ClientRequest::Reissuance(req)) => req
                            .coins
                            .iter()
                            .all(|(_, coin)| *spent_coins.get(&coin).unwrap() == 1),
                        ConsensusItem::ClientRequest(ClientRequest::PegOut(req)) => req
                            .coins
                            .iter()
                            .all(|(_, coin)| *spent_coins.get(&coin).unwrap() == 1),
                        ConsensusItem::ClientRequest(ClientRequest::PegIn(req)) => {
                            *used_peg_in_proofs.get(&req.proof.identity()).unwrap() == 1
                        }
                        _ => true,
                    })
                    .map(move |ci| (peer, ci))
            })
            .unique_by(|(_, contribution)| contribution.clone())
            .collect::<Vec<_>>();

        let (process_items_batches, remove_ci_batch) = batch
            .into_par_iter()
            .map(|(peer, ci)| {
                trace!("Processing consensus item {:?} from peer {}", ci, peer);
                let remove_ci = BatchItem::MaybeDeleteElement(Box::new(ci.clone()));

                let batch = match ci {
                    ConsensusItem::ClientRequest(client_request) => {
                        self.process_client_request(peer, client_request)
                    }
                    ConsensusItem::PartiallySignedRequest(id, psig) => {
                        self.process_partial_signature(peer, id, psig)
                    }
                    ConsensusItem::Wallet(_) => vec![],
                };

                (batch, remove_ci)
            })
            .unzip::<_, _, Vec<DbBatch>, DbBatch>();

        // Apply all consensus-critical changes atomically to the DB
        self.db
            .apply_batch(
                process_items_batches
                    .iter()
                    .flatten()
                    .chain(remove_ci_batch.iter()),
            )
            .expect("DB error");

        // Now that we have updated the DB with the epoch results also try to combine signatures
        let combine_sigs_batches = self.finalize_signatures();
        self.db
            .apply_batch(combine_sigs_batches.iter().flatten())
            .expect("DB error");
    }

    pub async fn get_consensus_proposal(&self) -> Vec<ConsensusItem> {
        let wallet_consensus = self
            .wallet
            .consensus_proposal()
            .await
            .expect("wallet error");
        debug!("Wallet proposal: {:?}", wallet_consensus);

        self.db
            .find_by_prefix(&AllConsensusItemsKeyPrefix)
            .map(|res| res.map(|(ci, ())| ci))
            .chain(std::iter::once(Ok(ConsensusItem::Wallet(wallet_consensus))))
            .collect::<Result<_, DatabaseError>>()
            .expect("DB error")
    }

    fn process_client_request(&self, peer: u16, cr: ClientRequest) -> DbBatch {
        match cr {
            ClientRequest::PegIn(peg_in) => self.process_peg_in_request(peg_in),
            ClientRequest::Reissuance(reissuance) => {
                self.process_reissuance_request(peer, reissuance)
            }
            ClientRequest::PegOut(_req) => {
                unimplemented!()
            }
        }
    }

    fn process_peg_in_request(&self, peg_in: PegInRequest) -> DbBatch {
        // TODO: maybe deduplicate verification logic
        let (mut batch, peg_in_amount) = match self.wallet.claim_pegin(&peg_in.proof) {
            Some(res) => res,
            None => {
                warn!("Received invalid peg-in request from consensus: invalid proof");
                return vec![];
            }
        };

        if secp256k1::global::SECP256K1
            .verify(
                &peg_in.id().as_hash().into(),
                &peg_in.sig,
                peg_in.proof.tweak_contract_key(),
            )
            .is_err()
        {
            warn!("Received invalid peg-in request from consensus: invalid signature");
            return vec![];
        }

        if peg_in_amount != peg_in.blind_tokens.0.amount() {
            // TODO: improve abort communication
            warn!("Received invalid peg-in request from consensus: mismatching amount");
            return vec![];
        }

        let peg_in_id = peg_in.id();
        debug!("Signing peg-in request {}", peg_in_id);
        let signed_req = match self.mint.sign(peg_in.blind_tokens) {
            Ok(signed_req) => signed_req,
            Err(e) => {
                warn!(
                    "Error signing a proposed peg-in, proposing peer might be faulty: {}",
                    e
                );
                return vec![];
            }
        };

        let db_sig_request = BatchItem::InsertNewElement(Element::new(
            ConsensusItem::PartiallySignedRequest(peg_in_id, signed_req.clone()),
            (),
        ));
        let db_own_sig_element = BatchItem::InsertNewElement(Element::new(
            PartialSignatureKey {
                request_id: peg_in_id,
                peer_id: self.cfg.identity,
            },
            BincodeSerialized::owned(signed_req),
        ));
        batch.push(db_sig_request);
        batch.push(db_own_sig_element);

        batch
    }

    fn process_reissuance_request(&self, peer: u16, reissuance: ReissuanceRequest) -> DbBatch {
        let reissuance_id = reissuance.id();

        let (signed_request, mut batch) = match self.mint.reissue(
            &self.db,
            reissuance.coins.clone(),
            reissuance.blind_tokens.clone(),
        ) {
            Ok((sr, batch)) => (sr, batch),
            Err(e) => {
                warn!(
                    "Rejected reissuance request proposed by peer {}, reason: {}",
                    peer, e
                );
                return vec![];
            }
        };
        debug!("Signed reissuance request {}", reissuance_id);

        batch.push(BatchItem::InsertNewElement(Element::new(
            ConsensusItem::PartiallySignedRequest(reissuance_id, signed_request.clone()),
            (),
        )));

        let our_sig_key = PartialSignatureKey {
            request_id: reissuance_id,
            peer_id: self.cfg.identity,
        };
        let our_sig = BincodeSerialized::owned(signed_request);
        batch.push(BatchItem::InsertNewElement(Element::new(
            our_sig_key,
            our_sig,
        )));

        batch
    }

    fn process_partial_signature(
        &self,
        peer: u16,
        req_id: TransactionId,
        partial_sig: PartialSigResponse,
    ) -> DbBatch {
        let is_finalized = self
            .db
            .get_value::<_, DummyValue>(&FinalizedSignatureKey {
                issuance_id: req_id,
            })
            .expect("DB error")
            .is_some();

        if peer == self.cfg.identity {
            trace!("Received own sig share for issuance {}, ignoring", req_id);
            vec![]
        } else if is_finalized {
            trace!(
                "Received sig share for finalized issuance {}, ignoring",
                req_id
            );
            vec![]
        } else {
            debug!(
                "Received sig share from peer {} for issuance {}",
                peer, req_id
            );
            let psig = BatchItem::InsertNewElement(Element::new(
                PartialSignatureKey {
                    request_id: req_id,
                    peer_id: peer,
                },
                BincodeSerialized::owned(partial_sig),
            ));

            vec![psig]
        }
    }

    fn finalize_signatures(&self) -> Vec<DbBatch> {
        let req_psigs = self
            .db
            .find_by_prefix::<_, PartialSignatureKey, BincodeSerialized<PartialSigResponse>>(
                &AllPartialSignaturesKey,
            )
            .map(|entry_res| {
                let (key, value) = entry_res.expect("DB error");
                (key.request_id, (key.peer_id as usize, value.into_owned()))
            })
            .into_group_map();

        req_psigs
            .into_par_iter()
            .filter_map(|(issuance_id, shares)| {
                if shares.len() > self.tbs_threshold() {
                    debug!(
                        "Trying to combine sig shares for issuance request {}",
                        issuance_id
                    );
                    let (bsig, errors) = self.mint.combine(shares.clone());
                    if !errors.0.is_empty() {
                        warn!("Peer sent faulty share: {:?}", errors);
                    }

                    match bsig {
                        Ok(bsig) => {
                            debug!(
                                "Successfully combined signature shares for issuance request {}",
                                issuance_id
                            );

                            let outdated_consensus_items = self
                                .db
                                .find_by_prefix::<_, ConsensusItem, ()>(&ConsensusItemKeyPrefix(
                                    issuance_id,
                                ))
                                .map(|res| {
                                    let key = res.expect("DB error").0;
                                    BatchItem::DeleteElement(Box::new(key))
                                });

                            let outdated_sig_shares = shares.into_iter().map(|(peer, _)| {
                                BatchItem::DeleteElement(Box::new(PartialSignatureKey {
                                    request_id: issuance_id,
                                    peer_id: peer as u16,
                                }))
                            });

                            let sig_key = FinalizedSignatureKey { issuance_id };
                            let sig_value = BincodeSerialized::owned(bsig);
                            let sig_insert = BatchItem::InsertNewElement(Element {
                                key: Box::new(sig_key),
                                value: Box::new(sig_value),
                            });

                            let batch = outdated_consensus_items
                                .chain(outdated_sig_shares)
                                .chain(std::iter::once(sig_insert))
                                .collect::<Vec<_>>();

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
            .collect()
    }

    fn tbs_threshold(&self) -> usize {
        self.cfg.peers.len() - self.cfg.max_faulty() - 1
    }
}

#[derive(Debug, Error)]
pub enum ClientRequestError {
    #[error("Client Reuqest was not authorized with a valid signature")]
    InvalidTransactionSignature,
    #[error("Client request was denied by mint: {0}")]
    DeniedByMint(MintError),
    #[error("Invalid peg-in")]
    InvalidPegIn,
    #[error("Client request uses invalid amount tier: {0}")]
    InvalidAmountTier(Amount),
}

impl From<MintError> for ClientRequestError {
    fn from(e: MintError) -> Self {
        ClientRequestError::DeniedByMint(e)
    }
}

impl From<InvalidAmountTierError> for ClientRequestError {
    fn from(e: InvalidAmountTierError) -> Self {
        ClientRequestError::InvalidAmountTier(e.0)
    }
}
