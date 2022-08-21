extern crate fedimint_api;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_api::rand::Rand07Compat;
use hbbft::honey_badger::{HoneyBadger, Message};
use hbbft::NetworkInfo;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use tokio::sync::Notify;
use tokio::task::spawn;
use tracing::warn;

use config::ServerConfig;
use fedimint_api::db::Database;
use fedimint_api::PeerId;
use fedimint_core::modules::ln::LightningModule;
use fedimint_core::modules::wallet::bitcoind::BitcoindRpc;
use fedimint_core::modules::wallet::{bitcoincore_rpc, Wallet};

use fedimint_core::epoch::ConsensusItem;
pub use fedimint_core::*;

use crate::consensus::{ConsensusOutcome, ConsensusProposal, FedimintConsensus};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{
    AnyPeerConnections, PeerConnections, PeerConnector, ReconnectPeerConnections,
};
use crate::rng::RngGenerator;

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod db;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// Some abstractions to handle randomness
mod rng;

type PeerMessage = (PeerId, Message<PeerId>);

pub struct FedimintServer {
    pub consensus: Arc<FedimintConsensus<OsRng>>,
    pub connections: AnyPeerConnections<Message<PeerId>>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<ConsensusItem>, PeerId>,
}

/// Start all the components of the mint and plug them together
pub async fn run_fedimint(cfg: ServerConfig, db_path: PathBuf) {
    let server = FedimintServer::new(cfg.clone(), db_path.clone()).await;
    spawn(net::api::run_server(cfg, server.consensus.clone()));
    server.run_consensus().await;
}

impl FedimintServer {
    pub async fn new(cfg: ServerConfig, db_path: PathBuf) -> Self {
        let connector: PeerConnector<Message<PeerId>> =
            TlsTcpConnector::new(cfg.tls_config()).to_any();

        Self::new_with(
            cfg.clone(),
            Arc::new(rocksdb::OptimisticTransactionDB::open_default(&db_path).unwrap()),
            bitcoincore_rpc::bitcoind_gen(cfg.wallet.clone()),
            connector,
        )
        .await
    }

    pub async fn new_with(
        cfg: ServerConfig,
        database: Arc<dyn Database>,
        bitcoind: impl Fn() -> Box<dyn BitcoindRpc>,
        connector: PeerConnector<Message<PeerId>>,
    ) -> Self {
        assert_eq!(
            cfg.peers.keys().max().copied().map(|id| id.to_usize()),
            Some(cfg.peers.len() - 1)
        );
        assert_eq!(cfg.peers.keys().min().copied(), Some(PeerId::from(0)));

        let mint = fedimint_core::modules::mint::Mint::new(cfg.mint.clone(), database.clone());

        let wallet = Wallet::new_with_bitcoind(cfg.wallet.clone(), database.clone(), bitcoind)
            .await
            .expect("Couldn't create wallet");

        let ln = LightningModule::new(cfg.ln.clone(), database.clone());

        let consensus = Arc::new(FedimintConsensus {
            rng_gen: Box::new(OsRngGen),
            cfg: cfg.clone(),
            mint,
            wallet,
            ln,
            db: database,
            transaction_notify: Arc::new(Notify::new()),
        });

        let connections = ReconnectPeerConnections::new(cfg.network_config(), connector)
            .await
            .to_any();

        let net_info = NetworkInfo::new(
            cfg.identity,
            cfg.hbbft_sks.inner().clone(),
            cfg.hbbft_pk_set.clone(),
            cfg.peers.iter().map(|(id, _)| *id),
        );

        let hbbft: HoneyBadger<Vec<ConsensusItem>, _> =
            HoneyBadger::builder(Arc::new(net_info)).build();

        FedimintServer {
            connections,
            hbbft,
            consensus,
            cfg: cfg.clone(),
        }
    }

    /// Loop `run_conensus_epoch` forever
    async fn run_consensus(mut self) {
        // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
        let mut rng = OsRng::new().unwrap();
        let consensus = self.consensus.clone();

        loop {
            let outcomes = self
                .run_consensus_epoch(consensus.get_consensus_proposal(), &mut rng)
                .await;

            for outcome in outcomes {
                self.consensus.process_consensus_outcome(outcome).await;
            }
        }
    }

    /// The main consensus function:
    /// 1. Await a new proposal event or receiving a proposal from peers
    /// 2. Send the `ConsensusProposal` to peers
    /// 3. Run HBBFT until a `ConsensusOutcome` can be returned
    pub async fn run_consensus_epoch(
        &mut self,
        proposal: impl Future<Output = ConsensusProposal>,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> Vec<ConsensusOutcome> {
        // for testing federations with one peer
        if self.cfg.peers.len() == 1 {
            tokio::select! {
              () = self.consensus.transaction_notify.notified() => (),
              () = self.consensus.await_consensus_proposal() => (),
            }
            let proposal = proposal.await;
            let epoch = self.hbbft.next_epoch() + 1;
            self.hbbft.skip_to_epoch(epoch);
            return vec![ConsensusOutcome {
                epoch,
                contributions: BTreeMap::from([(self.cfg.identity, proposal.items)]),
            }];
        }

        // process messages until new epoch or we have a proposal
        let mut outcomes: Vec<ConsensusOutcome> = loop {
            match self.await_proposal_or_peer_message().await {
                Some(msg) if self.hbbft.next_epoch() == msg.1.epoch() => {
                    break self.handle_message(msg).await
                }
                Some(msg) => self.handle_message(msg).await,
                None => break vec![],
            };
        };

        let proposal = proposal.await;
        for peer in proposal.drop_peers.iter() {
            self.connections.ban_peer(*peer).await;
        }

        let step = self
            .hbbft
            .propose(&proposal.items, &mut Rand07Compat(rng))
            .expect("HBBFT propose failed");

        for msg in step.messages {
            self.connections.send(msg.target, msg.message).await;
        }

        while outcomes.is_empty() {
            let msg = self.connections.receive().await;
            outcomes = self.handle_message(msg).await;
        }
        outcomes
    }

    async fn await_proposal_or_peer_message(&mut self) -> Option<PeerMessage> {
        tokio::select! {
            () = self.consensus.transaction_notify.notified() => None,
            () = self.consensus.await_consensus_proposal() => None,
            msg = self.connections.receive() => Some(msg)
        }
    }

    /// Runs a single HBBFT consensus step
    async fn handle_message(&mut self, msg: PeerMessage) -> Vec<ConsensusOutcome> {
        let (peer, peer_msg) = msg;

        let step = self
            .hbbft
            .handle_message(&peer, peer_msg)
            .expect("HBBFT handle message failed");

        if !step.fault_log.is_empty() {
            warn!(?step.fault_log);
        }

        for msg in step.messages {
            self.connections.send(msg.target, msg.message).await;
        }

        step.output
    }
}

struct OsRngGen;
impl RngGenerator for OsRngGen {
    type Rng = OsRng;

    fn get_rng(&self) -> Self::Rng {
        OsRng::new().unwrap()
    }
}
