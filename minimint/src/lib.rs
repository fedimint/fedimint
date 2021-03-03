#![feature(async_closure)]
#![feature(iterator_fold_self)]

use crate::consensus::{ConsensusItem, FediMintConsensus};
use crate::net::connect::Connections;
use crate::net::PeerConnections;
use crate::rng::RngGenerator;
use config::ServerConfig;
use futures::future::FusedFuture;
use futures::future::OptionFuture;
use futures::FutureExt;
use hbbft::honey_badger::{HoneyBadger, Step};
use hbbft::NetworkInfo;
use rand::{CryptoRng, RngCore};
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::sync::mpsc::channel;
use tokio::task::spawn;
use tokio::time::{interval, Duration};
use tracing::{debug, info, trace, warn};

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod database;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Some abstractions to handle randomness
mod rng;

/// Start all the components of the mintan d plug them together
pub async fn run_minimint(
    mut rng: impl RngCore + CryptoRng + Clone + Send + 'static,
    cfg: ServerConfig,
) {
    let (sig_response_sender, sig_response_receiver) = channel(4);
    let (client_req_sender, mut client_req_receiver) = channel(4);
    spawn(net::api::run_server(
        cfg.clone(),
        client_req_sender,
        sig_response_receiver,
    ));

    let mut connections = Connections::connect_to_all(&cfg).await;

    let mint = fedimint::Mint::new(
        cfg.tbs_sks.clone(),
        cfg.peers
            .values()
            .map(|peer| peer.tbs_pks.clone())
            .collect(),
        cfg.peers.len() - cfg.max_faulty() - 1, //FIXME
    );

    let mint_consensus = Arc::new(FediMintConsensus {
        rng_gen: Box::new(CloneRngGen(Mutex::new(rng.clone()))), //FIXME
        cfg: cfg.clone(),
        mint,
        db: sled::open(&cfg.db_path).unwrap().open_tree("mint").unwrap(),
    });

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

    let mut wake_up = interval(Duration::from_millis(5_000));
    let mut batch_process = OptionFuture::from(None);

    loop {
        let step = select! {
            _ = wake_up.tick(), if !hb.has_input() && batch_process.is_terminated() => {
                let proposal = mint_consensus.get_consensus_proposal();
                debug!("Proposing a contribution with {} consensus items for the next epoch", proposal.len());
                trace!("Proposal: {:?}", proposal);
                hb.propose(&proposal, &mut rng)
            },
            (peer, peer_msg) = connections.receive() => {
                hb.handle_message(&peer, peer_msg)
            },
            Some(cr) = client_req_receiver.recv() => {
                let _ = mint_consensus.submit_client_request(cr); // TODO: decide where to log
                continue;
            },
            _ = &mut batch_process, if !batch_process.is_terminated() => {
                batch_process = None.into(); // Not necessary due to fusing, but here for clarity
                continue;
            }
        }
            .expect("Failed to process HBBFT input");

        let Step {
            output,
            fault_log,
            messages,
        } = step;

        for msg in messages {
            connections.send(msg.target, msg.message).await;
        }

        wake_up = if output
            .iter()
            .all(|batch| batch.contributions.contains_key(&cfg.identity))
        {
            interval(Duration::from_millis(5_000))
        } else {
            // Don't wait around if we are supposedly lacking behind
            interval(Duration::from_millis(500))
        };
        wake_up.tick().await; // consume first tick immediately

        let batch_mint_consensus = mint_consensus.clone();
        let batch_sig_response_sender = sig_response_sender.clone();
        batch_process = Some(
            spawn(async move {
                for batch in output {
                    let sigs = batch_mint_consensus.process_consensus_outcome(batch);
                    if !sigs.is_empty() {
                        batch_sig_response_sender
                            .send(sigs)
                            .await
                            .expect("API server died");
                    }
                }
            })
            .fuse(),
        )
        .into();

        if !fault_log.is_empty() {
            warn!("Faults: {:?}", fault_log);
        }
    }
}

struct CloneRngGen<T: RngCore + CryptoRng + Clone + Send>(Mutex<T>);

impl<T: RngCore + CryptoRng + Clone + Send> RngGenerator for CloneRngGen<T> {
    type Rng = T;

    fn get_rng(&self) -> Self::Rng {
        self.0.lock().unwrap().clone()
    }
}
