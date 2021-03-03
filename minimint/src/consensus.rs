use crate::database::{
    AllPartialSignaturesKey, BincodeSerialized, ConsensusItemKeyPrefix, PartialSignatureKey,
};
use crate::net::api::ClientRequest;
use crate::rng::RngGenerator;
use config::ServerConfig;
use counter::Counter;
use database::batch::{Batch as DbBatch, BatchItem, Element};
use database::{BatchDb, Database, DatabaseError, PrefixSearchable, Transactional};
use fedimint::Mint;
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use mint_api::{Coin, PartialSigResponse, PegInRequest, ReissuanceRequest, RequestId, SigResponse};
use musig;
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ConsensusItem {
    ClientRequest(ClientRequest),
    PartiallySignedRequest(mint_api::PartialSigResponse),
}

pub type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;

pub struct FediMintConsensus<R, D>
where
    R: RngCore + CryptoRng,
    D: Database + PrefixSearchable + Transactional + Sync,
{
    /// Cryptographic random number generator used for everything
    pub rng_gen: Box<dyn RngGenerator<Rng = R>>,
    /// Configuration describing the federation and containing our secrets
    pub cfg: ServerConfig, // TODO: make custom config

    /// Our local mint
    pub mint: Mint, //TODO: box dyn trait for testability

    /// KV Database into which all state is persisted to recover from in case of a crash
    pub db: D,
}

impl<R, D> FediMintConsensus<R, D>
where
    R: RngCore + CryptoRng,
    D: Database + PrefixSearchable + Transactional + BatchDb + Sync,
{
    pub fn submit_client_request(&self, cr: ClientRequest) -> Result<(), ClientRequestError> {
        debug!("Received client request of type {}", cr.dbg_type_name());
        match cr {
            ClientRequest::Reissuance(ref reissuance_req) => {
                let pub_keys = reissuance_req
                    .coins
                    .iter()
                    .map(Coin::spend_key)
                    .collect::<Vec<_>>();

                if !musig::verify(
                    reissuance_req.digest(),
                    reissuance_req.sig.clone(),
                    &pub_keys,
                ) {
                    warn!("Rejecting invalid reissuance request: invalid tx sig");
                    return Err(ClientRequestError::InvalidTransactionSignature);
                }

                if !self.mint.validate(&self.db, &reissuance_req.coins) {
                    warn!("Rejecting invalid reissuance request: spent or invalid mint sig");
                    return Err(ClientRequestError::DeniedByMint);
                }
            }
            _ => {
                // FIXME: validate other request types or move validation elsewhere
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

    pub fn process_consensus_outcome(
        &self,
        batch: Batch<Vec<ConsensusItem>, u16>,
    ) -> Vec<SigResponse> {
        info!("Processing output of epoch {}", batch.epoch);

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
                    Some(req.coins.iter().cloned()) // TODO: get rid of clone once MuSig2 lands
                }
                ConsensusItem::ClientRequest(ClientRequest::PegOut(_)) => {
                    unimplemented!()
                }
                _ => None,
            })
            .flatten()
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
                            .all(|coin| *spent_coins.get(&coin).unwrap() == 1),
                        ConsensusItem::ClientRequest(ClientRequest::PegOut(_)) => {
                            unimplemented!()
                        }
                        _ => true,
                    })
                    .map(move |ci| (peer, ci))
            })
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
                    ConsensusItem::PartiallySignedRequest(psig) => {
                        self.process_partial_signature(peer, psig)
                    }
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
        let (combine_sigs_batches, sigs) = self.finalize_signatures();
        self.db
            .apply_batch(combine_sigs_batches.iter().flatten())
            .expect("DB error");

        sigs
    }

    pub fn get_consensus_proposal(&self) -> Vec<ConsensusItem> {
        self.db
            .find_by_prefix(&ConsensusItemKeyPrefix)
            .map(|res| res.map(|(ci, ())| ci))
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
        // FIXME: check pegin proof and mark as used (ATOMICITY!!!)
        let issuance_req = peg_in.blind_tokens;
        debug!("Signing issuance request {}", issuance_req.id());
        let signed_req = self.mint.sign(issuance_req);

        let db_sig_request = BatchItem::InsertNewElement(Element::new(
            ConsensusItem::PartiallySignedRequest(signed_req.clone()),
            (),
        ));
        let db_own_sig_element = BatchItem::InsertNewElement(Element::new(
            PartialSignatureKey {
                request_id: signed_req.id(),
                peer_id: self.cfg.identity,
            },
            BincodeSerialized::owned(signed_req),
        ));

        vec![db_sig_request, db_own_sig_element]
    }

    fn process_reissuance_request(&self, peer: u16, reissuance: ReissuanceRequest) -> DbBatch {
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
        debug!("Signed reissuance request {}", signed_request.id());

        batch.push(BatchItem::InsertNewElement(Element::new(
            ConsensusItem::PartiallySignedRequest(signed_request.clone()),
            (),
        )));

        let our_sig_key = PartialSignatureKey {
            request_id: signed_request.id(),
            peer_id: self.cfg.identity,
        };
        let our_sig = BincodeSerialized::owned(signed_request);
        batch.push(BatchItem::InsertNewElement(Element::new(
            our_sig_key,
            our_sig,
        )));

        batch
    }

    fn process_partial_signature(&self, peer: u16, partial_sig: PartialSigResponse) -> DbBatch {
        let req_id = partial_sig.id();

        if peer != self.cfg.identity {
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
        } else {
            trace!("Received own sig share for issuance {}, ignoring", req_id);
            vec![]
        }
    }

    fn finalize_signatures(&self) -> (Vec<DbBatch>, Vec<SigResponse>) {
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

                            // TODO: don't allow shares into the DB after this, e.g. by matching against finalized issuances
                            let batch = shares
                                .into_iter()
                                .map(|(peer, _)| {
                                    BatchItem::DeleteElement(Box::new(PartialSignatureKey {
                                        request_id: issuance_id,
                                        peer_id: peer as u16,
                                    }))
                                })
                                .collect::<Vec<_>>();

                            Some((batch, bsig))
                        }
                        Err(e) => {
                            error!("Warn: could not combine shares: {:?}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .unzip()
    }

    fn tbs_threshold(&self) -> usize {
        self.cfg.peers.len() - self.cfg.max_faulty() - 1
    }
}

#[derive(Debug, Error)]
pub enum ClientRequestError {
    #[error("Client Reuqest was not authorized with a valid signature")]
    InvalidTransactionSignature,
    #[error("Client request was denied by mint (double spend or invalid mint signature)")]
    DeniedByMint,
}
