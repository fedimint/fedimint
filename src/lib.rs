#![feature(async_closure)]

use crate::mint::{Coin, PartialSigResponse, RequestId, SigResponse, SignRequest};
use crate::net::framed::Framed;
use futures::future::select_all;
use futures::{FutureExt, SinkExt, StreamExt};
use hbbft::honey_badger::HoneyBadger;
use hbbft::{NetworkInfo, Target};
use rand::{thread_rng, Rng};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tbs::{blind_message, unblind_signature, Message};
use tokio::net::TcpStream;
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::channel;
use tokio::time::{interval, sleep};
use tokio_util::compat::Compat;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::EnvFilter;

pub mod config;
mod connect;
// Distributed keygen is deactivated for now since we lack an implementation for our TBS protocol
// and it slows down testing. Eventually it will be extracted into a distributed config generator.
// mod keygen;
mod mint;
mod net;

type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
enum ConsensusItem {
    IssuanceRequest(mint::SignRequest),
    PartiallySignedRequest(u16, mint::PartialSigResponse),
}

pub async fn server() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: config::ServerOpts = StructOpt::from_args();
    let cfg: config::ServerConfig = config::load_from_file(&opts.cfg_path);

    let tbs_threshold = cfg.peers.len() - cfg.max_faulty() - 1;

    let mut rng = rand::rngs::OsRng::new().expect("Failed to get RNG");

    let mut connections = connect::connect_to_all(&cfg).await;

    let net_info = NetworkInfo::new(
        cfg.identity,
        cfg.hbbft_sks.inner().clone(),
        cfg.hbbft_pk_set.clone(),
        cfg.hbbft_sk.inner().clone(),
        cfg.peers
            .iter()
            .map(|(id, peer)| (*id, peer.hbbft_pk.clone()))
            .collect(),
    );

    let mut hb: HoneyBadger<Vec<ConsensusItem>, _> =
        HoneyBadger::builder(Arc::new(net_info)).build();
    info!("Created Honey Badger instance");

    sleep(Duration::from_millis(2000)).await;

    let mint = mint::Mint::new(
        cfg.tbs_sks.clone(),
        cfg.peers
            .values()
            .map(|peer| peer.tbs_pks.clone())
            .collect(),
        tbs_threshold,
    );
    let mut outstanding_consensus_items = HashSet::new();
    let mut psigs = HashMap::<u64, Vec<(usize, PartialSigResponse)>>::new();
    let mut wake_up = interval(Duration::from_millis(15_000));

    let (bsig_sender, bsig_receiver) = channel(4);
    let (consensus_sender, mut consensus_receiver) = channel(4);
    spawn(net::api::run_server(
        cfg.clone(),
        consensus_sender,
        bsig_receiver,
    ));

    loop {
        let receive_msg = select_all(
            connections
                .iter_mut()
                .map(|(id, peer)| receive_from_peer(*id, peer).boxed()),
        );

        let step = select! {
            _ = wake_up.tick() => {
                let proposal = outstanding_consensus_items.iter().cloned().collect::<Vec<_>>();
                debug!("Proposing a contribution with {} consensus items for the next epoch", proposal.len());
                hb.propose(&proposal, &mut rng)
            },
            ((peer, peer_msg), _, _) = receive_msg => {
                hb.handle_message(&peer, peer_msg)
            },
            ci = consensus_receiver.recv() => {
                outstanding_consensus_items.insert(ConsensusItem::IssuanceRequest(ci.unwrap()));
                continue;
            },
        }
        .expect("Failed to process HBBFT input");

        for msg in step.messages {
            trace!("Sending message to {:?}", msg.target);
            match msg.target {
                Target::All => {
                    for peer in connections.values_mut() {
                        peer.send(&msg.message)
                            .await
                            .expect("Failed to send message to peer");
                    }
                }
                Target::Node(peer_id) => {
                    let peer = connections.get_mut(&peer_id).expect("Unknown peer");
                    peer.send(&msg.message)
                        .await
                        .expect("Failed to send message to peer");
                }
            }
        }

        for batch in step.output {
            info!("Processing output of epoch {}", batch.epoch);

            for (peer, ci) in batch.contributions.into_iter().flat_map(|(peer, cis)| {
                debug!("Peer {} contributed {} items", peer, cis.len());
                cis.into_iter().map(move |ci| (peer, ci))
            }) {
                trace!("Processing consensus item {:?} from peer {}", ci, peer);
                outstanding_consensus_items.remove(&ci);
                match ci {
                    ConsensusItem::IssuanceRequest(req) => {
                        debug!("Signing issuance request {}", req.id());
                        let signed_req = mint.sign(req);
                        outstanding_consensus_items.insert(ConsensusItem::PartiallySignedRequest(
                            cfg.identity,
                            signed_req.clone(),
                        ));
                        psigs
                            .entry(signed_req.id())
                            .or_default()
                            .push((cfg.identity as usize, signed_req));
                    }
                    ConsensusItem::PartiallySignedRequest(peer, psig) => {
                        let req_id = psig.id();
                        debug!(
                            "Received sig share from peer {} for issuance {}",
                            peer, req_id
                        );
                        let req_psigs = psigs.entry(req_id).or_default();

                        // Add sig share if we don't already have it
                        if req_psigs
                            .iter()
                            .find(|(ref p, _)| *p == peer as usize)
                            .is_none()
                        {
                            // FIXME: check if shares are actually duplicates, ring alarm otherwise
                            req_psigs.push((peer as usize, psig));
                        }
                        if req_psigs.len() > tbs_threshold {
                            debug!(
                                "Trying to combine sig shares for issuance request {}",
                                req_id
                            );
                            let (bsig, errors) = mint.combine(req_psigs.clone());
                            if !errors.0.is_empty() {
                                warn!("Peer sent faulty share: {:?}", errors);
                            }

                            match bsig {
                                Ok(bsig) => {
                                    debug!("Successfully combined signature shares for issuance request {}", req_id);
                                    bsig_sender
                                        .send(bsig)
                                        .await
                                        .expect("Could not send blind sig to API");
                                    psigs.remove(&req_id);
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

        if !step.fault_log.is_empty() {
            warn!("Faults: {:?}", step.fault_log);
        }
    }
}

async fn receive_from_peer(
    id: u16,
    peer: &mut Framed<Compat<TcpStream>, HoneyBadgerMessage>,
) -> (u16, HoneyBadgerMessage) {
    let msg = peer
        .next()
        .await
        .expect("Stream closed unexpectedly")
        .expect("Error receiving peer message");

    trace!("Received msg from peer {}", id);

    (id, msg)
}

pub async fn client() {
    let opts: config::ClientOpts = StructOpt::from_args();
    let cfg: config::ClientConfig = config::load_from_file(&opts.cfg_path);

    let (nonces, bmsgs): (Vec<_>, _) = (0..opts.issue_amt)
        .map(|_| {
            let nonce: [u8; 32] = thread_rng().gen();
            let (bkey, bmsg) = blind_message(Message::from_bytes(&nonce));
            ((nonce, bkey), bmsg)
        })
        .unzip();

    let req = SignRequest(bmsgs);
    let client = reqwest::Client::new();
    client
        .put(&format!("{}/issuance", cfg.url))
        .json(&req)
        .send()
        .await
        .expect("API error");

    let resp: SigResponse = loop {
        let url = format!("{}/issuance/{}", cfg.url, req.id());

        println!("looking for coins: {}", url);

        let api_resp = client.get(&url).send().await;
        match api_resp {
            Ok(r) => {
                if r.status() == StatusCode::OK {
                    break r.json().await.expect("invalid reply");
                } else {
                    println!("Status: {:?}", r.status());
                }
            }
            Err(e) => {
                if e.status() != Some(StatusCode::NOT_FOUND) {
                    panic!("Error: {:?}", e);
                }
            }
        };
        tokio::time::sleep(Duration::from_millis(1500)).await;
    };

    let coins: Vec<Coin> = resp
        .1
        .into_iter()
        .zip(nonces)
        .map(|(sig, (nonce, bkey))| {
            let sig = unblind_signature(bkey, sig);
            Coin(nonce, sig)
        })
        .collect();

    assert!(coins.iter().all(|c| c.verify(cfg.mint_pk)));
}
