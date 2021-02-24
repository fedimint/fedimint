#![feature(async_closure)]
#![feature(iterator_fold_self)]

use crate::consensus::{ConsensusItem, FediMintConsensus};
use crate::net::connect::Connections;
use crate::net::PeerConnections;
use crate::rng::RngGenerator;
use config::ServerConfig;
use hbbft::honey_badger::HoneyBadger;
use hbbft::NetworkInfo;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::channel;
use tokio::task::spawn;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod database;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Some abstractions to handle randomness
mod rng;

/// Start all the components of the mintan d plug them together
pub async fn run_minimint(mut rng: impl RngCore + CryptoRng + Clone + 'static, cfg: ServerConfig) {
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

    let mut mint_consensus = FediMintConsensus {
        rng_gen: Box::new(CloneRngGen(rng.clone())), //FIXME
        cfg: cfg.clone(),
        mint,
        outstanding_consensus_items: Default::default(),
        partial_blind_signatures: Default::default(),
    };

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

    loop {
        let step = select! {
            _ = wake_up.tick(), if !hb.has_input() => {
                let proposal = mint_consensus.get_consensus_proposal();
                debug!("Proposing a contribution with {} consensus items for the next epoch", proposal.len());
                hb.propose(&proposal, &mut rng)
            },
            (peer, peer_msg) = connections.receive() => {
                hb.handle_message(&peer, peer_msg)
            },
            Some(cr) = client_req_receiver.recv() => {
                let _ = mint_consensus.submit_client_request(cr); // TODO: decide where to log
                continue;
            },
        }
            .expect("Failed to process HBBFT input");

        for msg in step.messages {
            connections.send(msg.target, msg.message).await;
        }

        for batch in step.output {
            let sigs = mint_consensus.process_consensus_outcome(batch);
            if !sigs.is_empty() {
                sig_response_sender
                    .send(sigs)
                    .await
                    .expect("API server died");
            }
        }

        if !step.fault_log.is_empty() {
            warn!("Faults: {:?}", step.fault_log);
        }
    }
}

struct CloneRngGen<T: RngCore + CryptoRng + Clone>(T);

impl<T: RngCore + CryptoRng + Clone> RngGenerator for CloneRngGen<T> {
    type Rng = T;

    fn get_rng(&self) -> Self::Rng {
        self.0.clone()
    }
}
