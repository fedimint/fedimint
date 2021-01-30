#![feature(async_closure)]

use crate::mint::{Coin, PartialSigResponse, RequestId, SigResponse, SignRequest};
use crate::peer::Peer;
use futures::future::select_all;
use futures::{FutureExt, SinkExt, StreamExt};
use hbbft::honey_badger::{Batch, EncryptionSchedule, HoneyBadger, SubsetHandlingStrategy};
use hbbft::{NetworkInfo, Target};
use rand::{thread_rng, Rng};
use reqwest::{Error, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::iter::once;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tbs::{blind_message, unblind_signature, Aggregatable, Message};
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::{interval, sleep};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::Level;
use tracing::{debug, error, info, warn};

mod config;
mod connect;
mod keygen;
mod mint;
mod net;
mod peer;

const TBS_THRESHOLD: usize = 3;

type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
enum ConsensusItem {
    IssuanceRequest(mint::SignRequest),
    PartiallySignedRequest(u16, mint::PartialSigResponse),
}

pub async fn server() {
    let cfg: config::ServerConfig = StructOpt::from_args();
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let mut rng = rand::rngs::OsRng::new().expect("Failed to get RNG");

    let connections = connect::connect_to_all(&cfg).await;
    let (peers, pub_key_set, sec_key, sec_key_share, tbs_pks, tbs_sk) =
        keygen::generate_keys(&cfg, &mut rng, connections).await;

    let mut peers = peers
        .into_iter()
        .map(|(id, conn, hbbft_pub_key)| {
            (
                id,
                Peer {
                    id,
                    conn: net::framed::Framed::new(conn.compat()),
                    hbbft_pub_key,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    let net_info = NetworkInfo::new(
        cfg.identity,
        sec_key_share,
        pub_key_set,
        sec_key.clone(),
        peers
            .values()
            .map(|peer| (peer.id, peer.hbbft_pub_key.clone()))
            .chain(once((cfg.identity, sec_key.public_key())))
            .collect(),
    );

    let mut hb: HoneyBadger<Vec<ConsensusItem>, _> = HoneyBadger::builder(Arc::new(net_info))
        //.encryption_schedule(EncryptionSchedule::Always)
        //.max_future_epochs(2)
        //.subset_handling_strategy(SubsetHandlingStrategy::Incremental)
        .build();
    info!("Created Honey Badger instance");

    sleep(Duration::from_millis(2000));

    let mut mint = mint::Mint::new(tbs_sk, tbs_pks, TBS_THRESHOLD);
    let mut outstanding_consensus_items = HashSet::new();
    let mut psigs = HashMap::<u64, Vec<(u16, PartialSigResponse)>>::new();
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
            peers
                .values_mut()
                .map(|peer| receive_from_peer(peer).boxed()),
        );

        let step = select! {
            _ = wake_up.tick() => {
                let proposal = outstanding_consensus_items.iter().cloned().collect();
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
            debug!("Sending message to {:?}", msg.target);
            match msg.target {
                Target::All => {
                    for peer in peers.values_mut() {
                        peer.conn
                            .send(&msg.message)
                            .await
                            .expect("Failed to send message to peer");
                    }
                }
                Target::Node(peer_id) => {
                    let peer = peers.get_mut(&peer_id).expect("Unknown peer");
                    peer.conn
                        .send(&msg.message)
                        .await
                        .expect("Failed to send message to peer");
                }
            }
        }

        if !step.output.is_empty() {}

        for batch in step.output {
            info!("Processing output of epoch {}", batch.epoch);

            for (peer, ci) in batch
                .contributions
                .into_iter()
                .flat_map(|(peer, cis)| cis.into_iter().map(move |ci| (peer, ci)))
            {
                outstanding_consensus_items.remove(&ci);
                match ci {
                    ConsensusItem::IssuanceRequest(req) => {
                        outstanding_consensus_items.insert(ConsensusItem::PartiallySignedRequest(
                            cfg.identity,
                            mint.sign(req),
                        ));
                    }
                    ConsensusItem::PartiallySignedRequest(peer, psig) => {
                        let req_id = psig.id();
                        let req_psigs = psigs.entry(req_id).or_default();
                        req_psigs.push((peer, psig));
                        if req_psigs.len() > TBS_THRESHOLD {
                            // FIXME: handle error case, report, retain psigs and retry
                            let bsig = mint.combine(&req_psigs).expect("Some mint is faulty");
                            bsig_sender
                                .send(bsig)
                                .await
                                .expect("Could not send blind sig to API");
                            psigs.remove(&req_id);
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

async fn receive_from_peer(peer: &mut Peer) -> (u16, HoneyBadgerMessage) {
    let msg = peer
        .conn
        .next()
        .await
        .expect("Stream closed unexpectedly")
        .expect("Error receiving peer message");

    debug!("Received msg from peer {}", peer.id);

    (peer.id, msg)
}

pub async fn client() {
    let pk = keygen::fake_pub_keys().aggregate(TBS_THRESHOLD);
    let cfg: config::ClientConfig = StructOpt::from_args();
    let (nonces, bmsgs): (Vec<_>, _) = (0..cfg.amount)
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
        .0
        .into_iter()
        .zip(nonces)
        .map(|((_, sig), (nonce, bkey))| {
            let sig = unblind_signature(bkey, sig);
            Coin(nonce, sig)
        })
        .collect();

    assert!(coins.iter().all(|c| c.verify(pk)));
}
