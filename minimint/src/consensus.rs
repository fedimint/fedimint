use crate::net;
use crate::net::api::ClientRequest;
use crate::net::connect::Connections;
use crate::net::framed::Framed;
use config::ServerConfig;
use fedimint::Mint;
use hbbft::honey_badger::{Batch, HoneyBadger};
use hbbft::NetworkInfo;
use mint_api::{Coin, PartialSigResponse, RequestId, SigResponse};
use musig;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
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

    /// Our local mint
    mint: Mint,
    /// Consensus items that still need to be agreed on, either because they are new or because
    /// they weren't accepted in previous rounds
    outstanding_consensus_items: HashSet<ConsensusItem>,
    /// Partial signatures for (re)issuance requests that haven't reached the threshold for
    /// combination yet
    partial_blind_signatures: HashMap<u64, Vec<(usize, PartialSigResponse)>>,
    /// Sink for completed issuances being given back to clients through the API
    sig_response_sender: Sender<SigResponse>,
    /// Stream of client request from API
    client_req_receiver: Receiver<ClientRequest>,
}

impl FediMint {
    pub async fn init(rng: impl RngCore + 'static, cfg: ServerConfig) -> Self {
        let mint = fedimint::Mint::new(
            cfg.tbs_sks.clone(),
            cfg.peers
                .values()
                .map(|peer| peer.tbs_pks.clone())
                .collect(),
            cfg.peers.len() - cfg.max_faulty() - 1,
        );

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
            mint,
            outstanding_consensus_items: Default::default(),
            partial_blind_signatures: Default::default(),
            sig_response_sender: bsig_sender,
            client_req_receiver: consensus_receiver,
        }
    }

    pub async fn run(&mut self) {
        let mut connections = Connections::connect_to_all(&self.cfg).await;

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

        let mut wake_up = interval(Duration::from_millis(15_000));

        loop {
            let step = select! {
                _ = wake_up.tick() => {
                    let proposal = self.outstanding_consensus_items.iter().cloned().collect::<Vec<_>>();
                    debug!("Proposing a contribution with {} consensus items for the next epoch", proposal.len());
                    hb.propose(&proposal, &mut self.rng)
                },
                (peer, peer_msg) = connections.receive() => {
                    hb.handle_message(&peer, peer_msg)
                },
                Some(cr) = self.client_req_receiver.recv() => {
                    self.handle_client_request(cr);
                    continue;
                },
            }
            .expect("Failed to process HBBFT input");

            for msg in step.messages {
                connections.send(&msg.message, &msg.target).await;
            }

            for batch in step.output {
                self.process_batch(batch).await;
            }

            if !step.fault_log.is_empty() {
                warn!("Faults: {:?}", step.fault_log);
            }
        }
    }

    async fn process_batch(&mut self, batch: Batch<Vec<ConsensusItem>, u16>) {
        info!("Processing output of epoch {}", batch.epoch);

        for (peer, ci) in batch.contributions.into_iter().flat_map(|(peer, cis)| {
            debug!("Peer {} contributed {} items", peer, cis.len());
            cis.into_iter().map(move |ci| (peer, ci))
        }) {
            trace!("Processing consensus item {:?} from peer {}", ci, peer);
            self.outstanding_consensus_items.remove(&ci);
            match ci {
                ConsensusItem::ClientRequest(ClientRequest::PegIn(req)) => {
                    // FIXME: check pegin proof
                    let issuance_req = req.blind_tokens;
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
                ConsensusItem::ClientRequest(ClientRequest::Reissuance(req)) => {
                    let signed_request = match self.mint.reissue(req.coins, req.blind_tokens) {
                        Some(sr) => sr,
                        None => {
                            warn!("Rejected reissuance request proposed by peer {}", peer);
                            continue;
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
                ConsensusItem::ClientRequest(ClientRequest::PegOut(_req)) => {
                    unimplemented!()
                }
                ConsensusItem::PartiallySignedRequest(peer, psig) => {
                    let req_id = psig.id();
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
                        req_psigs.push((peer as usize, psig));
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
                                debug!("Successfully combined signature shares for issuance request {}", req_id);
                                self.sig_response_sender
                                    .send(bsig)
                                    .await
                                    .expect("Could not send blind sig to API");
                                self.partial_blind_signatures.remove(&req_id);
                            }
                            Err(e) => {
                                error!("Warn: could not combine shares: {:?}", e);
                            }
                        }
                    }
                }
            };
        }
    }

    fn tbs_threshold(&self) -> usize {
        self.cfg.peers.len() - self.cfg.max_faulty() - 1
    }

    fn handle_client_request(&mut self, cr: ClientRequest) {
        debug!("Received request from API: {}", cr.dbg_type_name());
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
                    return;
                }

                if !self.mint.validate(&reissuance_req.coins) {
                    warn!("Rejecting invalid reissuance request: spent or invalid mint sig");
                    return;
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
    }
}
