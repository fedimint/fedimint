extern crate minimint_api;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use hbbft::honey_badger::{HoneyBadger, Step};
use hbbft::{Epoched, NetworkInfo};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::spawn;
use tracing::{debug, info, instrument, trace, warn};

use config::ServerConfig;
use consensus::ConsensusOutcome;
use minimint_api::db::Database;
use minimint_api::PeerId;
use minimint_ln::LightningModule;
use minimint_wallet::bitcoind::BitcoindRpc;
use minimint_wallet::{bitcoincore_rpc, Wallet};

pub use minimint_core::*;

use crate::consensus::{ConsensusItem, ConsensusProposal, MinimintConsensus};
use crate::net::connect::Connections;
use crate::net::PeerConnections;
use crate::rng::RngGenerator;

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod db;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// MiniMint toplevel config
pub mod config;

/// Some abstractions to handle randomness
mod rng;

pub mod modules {
    pub use minimint_ln as ln;
    pub use minimint_mint as mint;
    pub use minimint_wallet as wallet;
}

pub struct MinimintServer {
    pub outcome_sender: Sender<ConsensusOutcome>,
    pub proposal_receiver: Receiver<ConsensusProposal>,
    pub outcome_receiver: Receiver<ConsensusOutcome>,
    pub proposal_sender: Sender<ConsensusProposal>,
    pub mint_consensus: Arc<MinimintConsensus<OsRng>>,
    pub cfg: ServerConfig,
}

/// Start all the components of the mint and plug them together
pub async fn run_minimint(cfg: ServerConfig) {
    let MinimintServer {
        outcome_sender,
        proposal_receiver,
        outcome_receiver,
        proposal_sender,
        mint_consensus,
        cfg,
    } = minimint_server(cfg).await;
    let initial_cis = mint_consensus.get_consensus_proposal().await;

    spawn(net::api::run_server(cfg.clone(), mint_consensus.clone()));
    spawn(hbbft(
        outcome_sender,
        proposal_receiver,
        cfg.clone(),
        initial_cis,
        OsRng::new().unwrap(),
    ));
    run_consensus(&mint_consensus, outcome_receiver, proposal_sender, cfg).await;
}

pub async fn minimint_server(cfg: ServerConfig) -> MinimintServer {
    minimint_server_with(
        cfg.clone(),
        Arc::new(sled::open(&cfg.db_path).unwrap().open_tree("mint").unwrap()),
        bitcoincore_rpc::bitcoind_gen(cfg.wallet.clone()),
    )
    .await
}

pub async fn minimint_server_with(
    cfg: ServerConfig,
    database: Arc<dyn Database>,
    bitcoind: impl Fn() -> Box<dyn BitcoindRpc>,
) -> MinimintServer {
    assert_eq!(
        cfg.peers.keys().max().copied().map(|id| id.to_usize()),
        Some(cfg.peers.len() - 1)
    );
    assert_eq!(cfg.peers.keys().min().copied(), Some(PeerId::from(0)));

    let threshold = cfg.peers.len() - cfg.max_faulty();

    let mint = minimint_mint::Mint::new(cfg.mint.clone(), threshold, database.clone());

    let wallet = Wallet::new_with_bitcoind(cfg.wallet.clone(), database.clone(), bitcoind)
        .await
        .expect("Couldn't create wallet");

    let ln = LightningModule::new(cfg.ln.clone(), database.clone());

    let mint_consensus = Arc::new(MinimintConsensus {
        rng_gen: Box::new(CloneRngGen(Mutex::new(OsRng::new().unwrap()))), //FIXME
        cfg: cfg.clone(),
        mint,
        wallet,
        ln,
        db: database,
    });

    let (outcome_sender, outcome_receiver) = channel::<ConsensusOutcome>(1);
    let (proposal_sender, proposal_receiver) = channel::<ConsensusProposal>(1);

    MinimintServer {
        outcome_sender,
        proposal_receiver,
        outcome_receiver,
        proposal_sender,
        mint_consensus,
        cfg: cfg.clone(),
    }
}

pub async fn run_consensus(
    mint_consensus: &Arc<MinimintConsensus<OsRng>>,
    mut outcome_receiver: Receiver<ConsensusOutcome>,
    proposal_sender: Sender<ConsensusProposal>,
    cfg: ServerConfig,
) {
    // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
    debug!("Generating second proposal");
    loop {
        let outcome = outcome_receiver.recv().await.expect("other thread died");
        let proposal = mint_consensus.get_consensus_proposal().await;

        run_consensus_epoch(proposal, &outcome, &proposal_sender).await;

        let we_contributed = outcome.contributions.contains_key(&cfg.identity);

        debug!(
            epoch = outcome.epoch,
            items_count = outcome.contributions.values().flatten().count(),
            "Processing consensus outcome",
        );
        mint_consensus.process_consensus_outcome(outcome).await;

        if we_contributed {
            // TODO: define latency target for consensus rounds and monitor it
            // give others a chance to catch up
            minimint_api::task::sleep(std::time::Duration::from_millis(2000)).await;
        }
    }
}

/// Creates new proposal, filters out items from the previous outcome
pub async fn run_consensus_epoch(
    mut proposal: ConsensusProposal,
    outcome: &ConsensusOutcome,
    proposal_sender: &Sender<ConsensusProposal>,
) {
    // We filter out the already agreed on consensus items from our proposal to avoid proposing
    // duplicates. Yet we can not remove them from the database entirely because we might crash
    // while processing the outcome.
    let outcome_filter_set = outcome
        .contributions
        .values()
        .flatten()
        .filter(|ci| !matches!(ci, ConsensusItem::Wallet(_)))
        .collect::<HashSet<_>>();

    let filtered_proposal = proposal
        .items
        .into_iter()
        .filter(|ci| !outcome_filter_set.contains(ci))
        .collect::<Vec<ConsensusItem>>();

    proposal.items = filtered_proposal;
    proposal_sender
        .send(proposal)
        .await
        .expect("other thread died");
}

#[instrument(skip_all)]
pub async fn hbbft(
    outcome_sender: Sender<ConsensusOutcome>,
    mut proposal_receiver: Receiver<ConsensusProposal>,
    cfg: ServerConfig,
    initial_cis: ConsensusProposal,
    mut rng: impl RngCore + CryptoRng + Clone + Send + 'static,
) {
    let mut connections = Connections::connect_to_all(&cfg).await;

    let net_info = NetworkInfo::new(
        cfg.identity,
        cfg.hbbft_sks.inner().clone(),
        cfg.hbbft_pk_set.clone(),
        cfg.hbbft_sk.inner().clone(),
        cfg.peers
            .iter()
            .map(|(id, peer)| (*id, peer.hbbft_pk))
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

        for peer in contribution.drop_peers.iter() {
            connections.drop_peer(peer);
        }

        debug!(
            consesus_items_len = contribution.items.len(),
            epoch = hb.epoch(),
            "Proposing a contribution",
        );
        trace!(?contribution);
        let mut initial_step = Some(
            hb.propose(&contribution.items, &mut rng)
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
                    trace!(%peer, "Received message");
                    hb.handle_message(&peer, peer_msg)
                        .expect("Failed to process HBBFT input")
                }
            };

            for msg in messages {
                trace!(target = ?msg.target, "sending message");
                connections.send(msg.target, msg.message).await;
            }

            if !fault_log.is_empty() {
                warn!(?fault_log);
            }

            if !output.is_empty() {
                trace!("Processed step had an output, handing it off");
                break 'inner output;
            }
        };

        for batch in outcome {
            debug!(epoch = batch.epoch, "Exchanging consensus outcome");
            // Old consensus contributions are overwritten on case of multiple batches arriving
            // at once. The new contribution should be used to avoid redundantly included items.
            outcome_sender.send(batch).await.expect("other thread died");
            next_consensus_items = Some(proposal_receiver.recv().await.expect("other thread died"));
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
