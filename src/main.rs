#![feature(async_closure)]

use crate::peer::Peer;
use futures::future::select_all;
use futures::{FutureExt, SinkExt, StreamExt};
use hbbft::honey_badger::{EncryptionSchedule, HoneyBadger, SubsetHandlingStrategy};
use hbbft::{NetworkInfo, Target};
use std::collections::HashMap;
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

type Transaction = u64;
type HoneyBadgerMessage = hbbft::honey_badger::Message<u16>;

#[tokio::main]
async fn main() {
    let cfg: config::Config = StructOpt::from_args();
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let mut rng = rand::rngs::OsRng::new().expect("Failed to get RNG");

    let connections = connect::connect_to_all(&cfg).await;
    let (peers, pub_key_set, sec_key, sec_key_share) =
        keygen::generate_keys(&cfg, &mut rng, connections).await;

    let mut peers = peers
        .into_iter()
        .map(|(id, conn, hbbft_pub_key, mint_pub_key)| {
            (
                id,
                Peer {
                    id,
                    conn: net::framed::Framed::new(conn.compat()),
                    hbbft_pub_key,
                    mint_pub_key,
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

    let mut hb: HoneyBadger<Vec<Transaction>, _> = HoneyBadger::builder(Arc::new(net_info))
        //.encryption_schedule(EncryptionSchedule::Always)
        //.max_future_epochs(2)
        //.subset_handling_strategy(SubsetHandlingStrategy::Incremental)
        .build();
    info!("Created Honey Badger instance");

    sleep(Duration::from_millis(2000));

    let (send_prop, mut receive_prop) = channel(1);
    spawn(proposal_source((cfg.identity as u64) * 1000, send_prop));

    loop {
        let receive_msg = select_all(
            peers
                .values_mut()
                .map(|peer| receive_from_peer(peer).boxed()),
        );

        let step = select! {
            proposal = receive_prop.recv(), if !hb.has_input() => {
                let proposal = proposal.unwrap();
                debug!("Sending proposal {}", proposal);
                hb.propose(&vec![proposal], &mut rng)
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
            info!("Round result: {:?}", step.output);
        }

        if !step.fault_log.is_empty() {
            warn!("Faults: {:?}", step.fault_log);
        }
    }
}

async fn proposal_source(mut base: u64, sender: Sender<u64>) {
    let mut proposal_source = interval(Duration::from_secs(10));
    while let _ = proposal_source.tick().await {
        sender.send(base).await;
        base += 1;
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
