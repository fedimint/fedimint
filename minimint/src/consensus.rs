use crate::net;
use crate::net::api::ClientRequest;
use crate::net::connect::Connections;
use crate::net::framed::Framed;
use crate::net::PeerConnections;
use config::ServerConfig;
use fedimint::Mint;
use hbbft::honey_badger::{Batch, HoneyBadger};
use hbbft::NetworkInfo;
use mint_api::{Coin, PartialSigResponse, PegInRequest, ReissuanceRequest, RequestId, SigResponse};
use musig;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{interval, sleep, Duration};
use tokio_util::compat::Compat;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
enum ConsensusItem {
    ClientRequest(ClientRequest),
    PartiallySignedRequest(u16, mint_api::PartialSigResponse),
}

pub type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;
pub type Connection = Framed<Compat<TcpStream>, HoneyBadgerMessage>;

pub struct FediMint {
    /// Cryptographic random number generator used for everything
    rng: Box<dyn RngCore>,
    /// Configuration describing the federation and containing our secrets
    cfg: ServerConfig,

    /// Sink for completed issuances being given back to clients through the API
    sig_response_sender: Sender<SigResponse>,
    /// Stream of client request from API
    client_req_receiver: Receiver<ClientRequest>,
}

impl FediMint {
    pub async fn init(rng: impl RngCore + 'static, cfg: ServerConfig) -> Self {
        // Start API server
        let (bsig_sender, bsig_receiver) = channel(4);
        let (consensus_sender, consensus_receiver) = channel(4);
        spawn(net::api::run_server(
            cfg.clone(),
            consensus_sender,
            bsig_receiver,
        ));

        FediMint {
            rng: Box::new(rng),
            cfg,
            sig_response_sender: bsig_sender,
            client_req_receiver: consensus_receiver,
        }
    }

    pub async fn run(mut self) {
        let mut connections = Connections::connect_to_all(&self.cfg).await;

        let mint = fedimint::Mint::new(
            self.cfg.tbs_sks.clone(),
            self.cfg
                .peers
                .values()
                .map(|peer| peer.tbs_pks.clone())
                .collect(),
            self.cfg.peers.len() - self.cfg.max_faulty() - 1, //FIXME
        );

        let mut mint_consensus = FediMintConsensus {
            rng: Box::new(rand::rngs::OsRng::new().unwrap()), //FIXME
            cfg: self.cfg.clone(),
            mint,
            outstanding_consensus_items: Default::default(),
            partial_blind_signatures: Default::default(),
        };

        let net_info = NetworkInfo::new(
            self.cfg.identity,
            self.cfg.hbbft_sks.inner().clone(),
            self.cfg.hbbft_pk_set.clone(),
            self.cfg.hbbft_sk.inner().clone(),
            self.cfg
                .peers
                .iter()
                .map(|(id, peer)| (*id, peer.hbbft_pk.clone()))
                .collect(),
        );

        let mut hb: HoneyBadger<Vec<ConsensusItem>, _> =
            HoneyBadger::builder(Arc::new(net_info)).build();
        info!("Created Honey Badger instance");

        // Wait for other instances to become ready, not strictly necessary
        sleep(Duration::from_millis(2000)).await;

        let mut wake_up = interval(Duration::from_millis(5_000));

        loop {
            let step = select! {
                _ = wake_up.tick(), if !hb.has_input() => {
                    let proposal = mint_consensus.get_consensus_proposal();
                    debug!("Proposing a contribution with {} consensus items for the next epoch", proposal.len());
                    hb.propose(&proposal, &mut self.rng)
                },
                (peer, peer_msg) = connections.receive() => {
                    hb.handle_message(&peer, peer_msg)
                },
                Some(cr) = self.client_req_receiver.recv() => {
                    let _ = mint_consensus.submit_client_request(cr); // TODO: decide where to log
                    continue;
                },
            }
            .expect("Failed to process HBBFT input");

            for msg in step.messages {
                connections.send(msg.target, msg.message).await;
            }

            for batch in step.output {
                for sig in mint_consensus.process_consensus_outcome(batch) {
                    self.sig_response_sender
                        .send(sig)
                        .await
                        .expect("API server died"); // TODO: send entire vecs
                }
            }

            if !step.fault_log.is_empty() {
                warn!("Faults: {:?}", step.fault_log);
            }
        }
    }
}

struct FediMintConsensus {
    /// Cryptographic random number generator used for everything
    rng: Box<dyn RngCore>,
    /// Configuration describing the federation and containing our secrets
    cfg: ServerConfig,

    /// Our local mint
    mint: Mint, //TODO: box dyn trait for testability
    /// Consensus items that still need to be agreed on, either because they are new or because
    /// they weren't accepted in previous rounds
    outstanding_consensus_items: HashSet<ConsensusItem>,
    /// Partial signatures for (re)issuance requests that haven't reached the threshold for
    /// combination yet
    partial_blind_signatures: HashMap<u64, Vec<(usize, PartialSigResponse)>>,
}

impl FediMintConsensus {
    pub fn submit_client_request(&mut self, cr: ClientRequest) -> Result<(), ClientRequestError> {
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

                if !self.mint.validate(&reissuance_req.coins) {
                    warn!("Rejecting invalid reissuance request: spent or invalid mint sig");
                    return Err(ClientRequestError::DeniedByMint);
                }
            }
            _ => {
                // FIXME: validate other request types or move validation elsewhere
            }
        }

        let new = self
            .outstanding_consensus_items
            .insert(ConsensusItem::ClientRequest(cr));
        if !new {
            warn!("Added consensus item was already in consensus queue");
        }

        Ok(())
    }

    pub fn process_consensus_outcome(
        &mut self,
        batch: Batch<Vec<ConsensusItem>, u16>,
    ) -> Vec<SigResponse> {
        info!("Processing output of epoch {}", batch.epoch);

        let mut signaturre_responses = Vec::new();

        for (peer, ci) in batch.contributions.into_iter().flat_map(|(peer, cis)| {
            debug!("Peer {} contributed {} items", peer, cis.len());
            cis.into_iter().map(move |ci| (peer, ci))
        }) {
            trace!("Processing consensus item {:?} from peer {}", ci, peer);
            self.outstanding_consensus_items.remove(&ci);
            match ci {
                ConsensusItem::ClientRequest(client_request) => {
                    self.process_client_request(peer, client_request)
                }
                ConsensusItem::PartiallySignedRequest(peer, psig) => {
                    if let Some(signature_response) = self.process_partial_signature(peer, psig) {
                        signaturre_responses.push(signature_response);
                    }
                }
            };
        }

        signaturre_responses
    }

    pub fn get_consensus_proposal(&mut self) -> Vec<ConsensusItem> {
        self.outstanding_consensus_items.iter().cloned().collect()
    }

    fn process_client_request(&mut self, peer: u16, cr: ClientRequest) {
        match cr {
            ClientRequest::PegIn(peg_in) => self.process_peg_in_request(peg_in),
            ClientRequest::Reissuance(reissuance) => {
                self.process_reissuance_request(peer, reissuance)
            }
            ClientRequest::PegOut(_req) => {
                unimplemented!()
            }
        };
    }

    fn process_peg_in_request(&mut self, peg_in: PegInRequest) {
        // FIXME: check pegin proof and mark as used (ATOMICITY!!!)
        let issuance_req = peg_in.blind_tokens;
        debug!("Signing issuance request {}", issuance_req.id());
        let signed_req = self.mint.sign(issuance_req);
        self.outstanding_consensus_items
            .insert(ConsensusItem::PartiallySignedRequest(
                self.cfg.identity,
                signed_req.clone(),
            ));
        self.partial_blind_signatures
            .entry(signed_req.id())
            .or_default()
            .push((self.cfg.identity as usize, signed_req));
    }

    fn process_reissuance_request(&mut self, peer: u16, reissuance: ReissuanceRequest) {
        let signed_request = match self.mint.reissue(reissuance.coins, reissuance.blind_tokens) {
            Some(sr) => sr,
            None => {
                warn!("Rejected reissuance request proposed by peer {}", peer);
                return;
            }
        };
        debug!("Signed reissuance request {}", signed_request.id());
        self.outstanding_consensus_items
            .insert(ConsensusItem::PartiallySignedRequest(
                self.cfg.identity,
                signed_request.clone(),
            ));
        self.partial_blind_signatures
            .entry(signed_request.id())
            .or_default()
            .push((self.cfg.identity as usize, signed_request));
    }

    fn process_partial_signature(
        &mut self,
        peer: u16,
        partial_sig: PartialSigResponse,
    ) -> Option<SigResponse> {
        let req_id = partial_sig.id();
        let tbs_thresh = self.tbs_threshold();
        debug!(
            "Received sig share from peer {} for issuance {}",
            peer, req_id
        );
        let req_psigs = self.partial_blind_signatures.entry(req_id).or_default();

        // Add sig share if we don't already have it
        if req_psigs
            .iter()
            .find(|(ref p, _)| *p == peer as usize)
            .is_none()
        {
            // FIXME: check if shares are actually duplicates, ring alarm otherwise
            req_psigs.push((peer as usize, partial_sig));
        }
        if req_psigs.len() > tbs_thresh {
            debug!(
                "Trying to combine sig shares for issuance request {}",
                req_id
            );
            let (bsig, errors) = self.mint.combine(req_psigs.clone());
            if !errors.0.is_empty() {
                warn!("Peer sent faulty share: {:?}", errors);
            }

            match bsig {
                Ok(bsig) => {
                    debug!(
                        "Successfully combined signature shares for issuance request {}",
                        req_id
                    );
                    self.partial_blind_signatures.remove(&req_id);
                    return Some(bsig);
                }
                Err(e) => {
                    error!("Warn: could not combine shares: {:?}", e);
                }
            }
        }

        None
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
