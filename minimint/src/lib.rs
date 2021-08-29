#![feature(async_closure)]

extern crate mint_api;

use crate::consensus::{ConsensusItem, FediMintConsensus};
use crate::net::connect::Connections;
use crate::net::PeerConnections;
use crate::rng::RngGenerator;
use ::database::RawDatabase;
use config::ServerConfig;
use consensus::ConsensusOutcome;
use hbbft::honey_badger::{HoneyBadger, Step};
use hbbft::{Epoched, NetworkInfo};
use rand::{CryptoRng, RngCore};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::{spawn, JoinHandle};
use tracing::{debug, info, trace, warn};

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod db;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Some abstractions to handle randomness
mod rng;

/// Start all the components of the mintan d plug them together
pub async fn run_minimint(cfg: ServerConfig) {
    assert_eq!(
        cfg.peers.keys().max().copied(),
        Some((cfg.peers.len() as u16) - 1)
    );
    assert_eq!(cfg.peers.keys().min().copied(), Some(0));

    let database: Arc<dyn RawDatabase> =
        Arc::new(sled::open(&cfg.db_path).unwrap().open_tree("mint").unwrap());

    let pub_key_shares = cfg
        .peers
        .values()
        .map(|peer| peer.tbs_pks.clone())
        .collect();

    let mint = fedimint::Mint::new(
        cfg.tbs_sks.clone(),
        pub_key_shares,
        cfg.peers.len() - cfg.max_faulty() - 1, //FIXME
        database.clone(),
    );

    let wallet = fediwallet::Wallet::new(cfg.wallet.clone(), database.clone())
        .await
        .expect("Couldn't create wallet");

    let mint_consensus = Arc::new(FediMintConsensus {
        rng_gen: Box::new(CloneRngGen(Mutex::new(rand::rngs::OsRng::new().unwrap()))), //FIXME
        cfg: cfg.clone(),
        mint,
        wallet,
        db: database,
    });

    spawn(net::api::run_server(cfg.clone(), mint_consensus.clone()));

    let (output_sender, mut output_receiver) = channel::<ConsensusOutcome>(1);
    let (proposal_sender, proposal_receiver) = channel::<Vec<ConsensusItem>>(1);

    info!("Spawning consensus with first proposal");
    spawn_hbbft(
        output_sender,
        proposal_receiver,
        cfg.clone(),
        mint_consensus.get_consensus_proposal().await,
        rand::rngs::OsRng::new().unwrap(),
    )
    .await;

    // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
    debug!("Generating second proposal");
    let mut proposal = Some(mint_consensus.get_consensus_proposal().await);
    loop {
        debug!("Ready to exchange proposal for consensus outcome");

        // We filter out the already agreed on consensus items from our proposal to avoid proposing
        // duplicates. Yet we can not remove them from the database entirely because we might crash
        // while processing the outcome.
        let outcome = {
            let outcome = output_receiver.recv().await.expect("other thread died");
            let outcome_filter_set = outcome
                .contributions
                .values()
                .flatten()
                .filter(|ci| match ci {
                    ConsensusItem::Wallet(_) => false,
                    _ => true,
                })
                .collect::<HashSet<_>>();

            let full_proposal = proposal.take().expect("Is always refilled");
            let filtered_proposal = full_proposal
                .into_iter()
                .filter(|ci| !outcome_filter_set.contains(ci))
                .collect::<Vec<ConsensusItem>>();
            proposal_sender
                .send(filtered_proposal)
                .await
                .expect("other thread died");

            outcome
        };

        let we_contributed = outcome.contributions.contains_key(&cfg.identity);

        debug!(
            "Processing consensus outcome from epoch {} with {} items",
            outcome.epoch,
            outcome.contributions.values().flatten().count()
        );
        mint_consensus.process_consensus_outcome(outcome).await;

        if we_contributed {
            // TODO: define latency target for consensus rounds and monitor it
            // give others a chance to catch up
            tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
        }

        proposal = Some(mint_consensus.get_consensus_proposal().await);
    }
}

async fn spawn_hbbft(
    outcome_sender: Sender<ConsensusOutcome>,
    mut proposal_receiver: Receiver<Vec<ConsensusItem>>,
    cfg: ServerConfig,
    initial_cis: Vec<ConsensusItem>,
    mut rng: impl RngCore + CryptoRng + Clone + Send + 'static,
) -> JoinHandle<()> {
    spawn(async move {
        let mut connections = Connections::connect_to_all(&cfg).await;

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

        let mut next_consensus_items = Some(initial_cis);
        loop {
            let contribution = next_consensus_items
                .take()
                .expect("This is always refilled");

            debug!(
                "Proposing a contribution with {} consensus items for epoch {}",
                contribution.len(),
                hb.epoch()
            );
            trace!("Contribution: {:?}", contribution);
            let mut initial_step = Some(
                hb.propose(&contribution, &mut rng)
                    .expect("Failed to process HBBFT input"),
            );

            let outcome = 'inner: loop {
                // We either want to handle the initial step or generate a new one by receiving a
                // message from a peer
                let Step {
                    output,
                    fault_log,
                    messages,
                } = match initial_step.take() {
                    Some(step) => step,
                    None => {
                        let (peer, peer_msg) = connections.receive().await;
                        trace!("Received message from {}", peer);
                        hb.handle_message(&peer, peer_msg)
                            .expect("Failed to process HBBFT input")
                    }
                };

                for msg in messages {
                    trace!("sending message to {:?}", msg.target);
                    connections.send(msg.target, msg.message).await;
                }

                if !fault_log.is_empty() {
                    warn!("Faults: {:?}", fault_log);
                }

                if !output.is_empty() {
                    trace!("Processed step had an output, handing it off");
                    break 'inner output;
                }
            };

            for batch in outcome {
                debug!("Exchanging consensus outcome of epoch {}", batch.epoch);
                // Old consensus contributions are overwritten on case of multiple batches arriving
                // at once. The new contribution should be used to avoid redundantly included items.
                outcome_sender.send(batch).await.expect("other thread died");
                next_consensus_items =
                    Some(proposal_receiver.recv().await.expect("other thread died"));
            }
        }
    })
}

struct CloneRngGen<T: RngCore + CryptoRng + Clone + Send>(Mutex<T>);

impl<T: RngCore + CryptoRng + Clone + Send> RngGenerator for CloneRngGen<T> {
    type Rng = T;

    fn get_rng(&self) -> Self::Rng {
        self.0.lock().unwrap().clone()
    }
}
