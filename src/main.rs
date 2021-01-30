#![feature(async_closure)]

use crate::mint::{PartialSigResponse, RequestId};
use crate::peer::Peer;
use futures::future::select_all;
use futures::{FutureExt, SinkExt, StreamExt};
use hbbft::honey_badger::{Batch, EncryptionSchedule, HoneyBadger, SubsetHandlingStrategy};
use hbbft::{NetworkInfo, Target};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::iter::once;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
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

#[tokio::main]
async fn main() {
    let cfg: config::Config = StructOpt::from_args();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
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
    let mut bsigs = HashMap::new();

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
            }
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

        if !step.output.is_empty() {
            info!("Processing output {:?} ", step.output);
        }

        for batch in step.output {
            let batch: Batch<Vec<ConsensusItem>, u16> = batch;

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
                            bsigs.insert(req_id, bsig);
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
