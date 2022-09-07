extern crate fedimint_api;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_api::rand::Rand07Compat;
use hbbft::honey_badger::{HoneyBadger, Message};
use hbbft::{Epoched, NetworkInfo, Target};
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

use fedimint_api::config::GenerateConfig;
use fedimint_core::epoch::{ConsensusItem, EpochHistory, EpochVerifyError};
pub use fedimint_core::*;
use mint_client::api::{FederationApi, WsFederationApi};
use serde::{Deserialize, Serialize};

use crate::consensus::{
    ConsensusOutcome, ConsensusOutcomeConversion, ConsensusProposal, FedimintConsensus,
};
use crate::db::{EpochHistoryKey, LastEpochKey};
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

type PeerMessage = (PeerId, EpochMessage);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EpochMessage {
    Continue(Message<PeerId>),
    RejoinRequest,
    Rejoin(Option<EpochHistory>, u64),
}

pub struct FedimintServer {
    pub consensus: Arc<FedimintConsensus<OsRng>>,
    pub connections: AnyPeerConnections<EpochMessage>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<ConsensusItem>, PeerId>,
    pub api: Arc<dyn FederationApi>,
}

/// Start all the components of the mint and plug them together
pub async fn run_fedimint(cfg: ServerConfig, db_path: PathBuf) {
    let server = FedimintServer::new(cfg.clone(), db_path.clone()).await;
    spawn(net::api::run_server(cfg, server.consensus.clone()));
    server.run_consensus().await;
}

impl FedimintServer {
    pub async fn new(cfg: ServerConfig, db_path: PathBuf) -> Self {
        let connector: PeerConnector<EpochMessage> =
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
        connector: PeerConnector<EpochMessage>,
    ) -> Self {
        cfg.validate_config(&cfg.identity);

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

        let api_endpoints = cfg
            .peers
            .clone()
            .into_iter()
            .map(|(id, peer)| (id, peer.connection.api_addr));
        let api = Arc::new(WsFederationApi::new(
            cfg.max_faulty(),
            api_endpoints.collect(),
        ));

        FedimintServer {
            connections,
            hbbft,
            consensus,
            cfg: cfg.clone(),
            api,
        }
    }

    /// Loop `run_conensus_epoch` forever
    async fn run_consensus(mut self) {
        // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
        let mut rng = OsRng::new().unwrap();
        let consensus = self.consensus.clone();

        // Rejoin consensus and catch up to the most recent epoch
        // TODO: be able to handle all peers restarting
        if let Ok(Some(_)) = self.consensus.db.get_value(&LastEpochKey) {
            tracing::info!("Rejoining consensus");
            self.rejoin_consensus().await;
        }

        loop {
            let outcomes = self
                .run_consensus_epoch(consensus.get_consensus_proposal(), &mut rng)
                .await;

            for outcome in outcomes {
                self.consensus.process_consensus_outcome(outcome).await;
            }
        }
    }

    // Build a `ConsensusOutcome` then use the API to validate and process missed epochs
    pub async fn rejoin_consensus(&mut self) {
        let mut msg_buffer = vec![];
        let next_epoch_num = self.determine_rejoin_epoch(&mut msg_buffer).await;
        tracing::info!("Rejoining consensus: at epoch {}", next_epoch_num);
        self.hbbft.skip_to_epoch(next_epoch_num);

        let mut outcomes: Vec<ConsensusOutcome> = vec![];
        for msg in msg_buffer {
            outcomes.append(&mut self.handle_message(msg).await);
        }
        while outcomes.is_empty() {
            let msg = self.connections.receive().await;
            outcomes = self.handle_message(msg).await;
        }
        tracing::info!("Rejoining consensus: created outcome");
        // FIXME: Should handle failing and querying other peers
        self.download_history(outcomes[0].clone()).await.unwrap();
    }

    /// Requests, verifies and processes history from peers
    async fn download_history(
        &mut self,
        last_outcome: ConsensusOutcome,
    ) -> Result<(), EpochVerifyError> {
        let mut epochs: Vec<EpochHistory> = vec![];
        let saved_epoch_key = self.consensus.db.get_value(&LastEpochKey).unwrap();

        let download_epoch_num = saved_epoch_key.map(|e| e.0 + 1).unwrap_or(0);
        let mut prev_epoch = saved_epoch_key.and_then(|e| self.consensus.db.get_value(&e).unwrap());

        for epoch_num in download_epoch_num..=last_outcome.epoch {
            let current_epoch = if epoch_num == last_outcome.epoch {
                let contributions = last_outcome.contributions.clone();
                EpochHistory::new(last_outcome.epoch, contributions, &prev_epoch)
            } else {
                let result = self.api.fetch_epoch_history(epoch_num).await;
                result.map_err(|_| EpochVerifyError::MissingPreviousEpoch)?
            };

            current_epoch.verify_hash(&prev_epoch)?;
            epochs.push(current_epoch.clone());

            let pk = self.cfg.epoch_pk_set.public_key();
            if current_epoch.verify_sig(&pk).is_ok() || epoch_num == last_outcome.epoch {
                for epoch in &epochs {
                    tracing::info!("Downloaded and processed epoch {}", epoch.outcome.epoch);
                    let outcome = ConsensusOutcomeConversion::from(epoch.outcome.clone()).0;
                    self.consensus.process_consensus_outcome(outcome).await;
                }
                epochs.clear();
            }

            prev_epoch = Some(current_epoch);
        }

        Ok(())
    }

    /// Sends a rejoin request and returns the max(valid_epoch) received from a threshold of peers
    async fn determine_rejoin_epoch(&mut self, msg_buffer: &mut Vec<PeerMessage>) -> u64 {
        self.connections
            .send(
                Target::AllExcept(BTreeSet::new()),
                EpochMessage::RejoinRequest,
            )
            .await;

        let mut consensus_peers = BTreeMap::<PeerId, u64>::new();
        let pks = self.cfg.epoch_pk_set.public_key();
        // last signed epoch is at most 3 epochs before the next epoch + faulty nodes because
        // faulty nodes can withhold sigs for an epoch before getting banned
        let max_age: u64 = self.cfg.max_faulty() as u64 + 3;

        loop {
            // a threshold of peers sent verified epochs, so target the next epoch
            if consensus_peers.len() > self.cfg.max_faulty() * 2 {
                return *consensus_peers.values().max().unwrap();
            }

            match self.connections.receive().await {
                (peer, EpochMessage::Rejoin(Some(history), epoch)) => {
                    let is_recent = epoch <= history.outcome.epoch + max_age;
                    if history.verify_sig(&pks).is_ok() && is_recent {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                (peer, EpochMessage::Rejoin(None, epoch)) => {
                    if epoch <= max_age {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                msg => msg_buffer.push(msg),
            };
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
                Some(msg) if self.start_next_epoch(&msg) => break self.handle_message(msg).await,
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
            self.connections
                .send(msg.target, EpochMessage::Continue(msg.message))
                .await;
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

    fn start_next_epoch(&self, msg: &PeerMessage) -> bool {
        match msg {
            (_, EpochMessage::Continue(peer_msg)) => self.hbbft.next_epoch() == peer_msg.epoch(),
            (_, EpochMessage::RejoinRequest) => true,
            _ => false,
        }
    }

    /// Runs a single HBBFT consensus step
    async fn handle_message(&mut self, msg: PeerMessage) -> Vec<ConsensusOutcome> {
        match msg {
            (_, EpochMessage::Rejoin(_, _)) => vec![],
            (peer, EpochMessage::RejoinRequest) => {
                let target = Target::Nodes(BTreeSet::from([peer]));
                let mut epoch = self.hbbft.epoch() - 1;

                let signed_history = loop {
                    let query = self.consensus.db.get_value(&EpochHistoryKey(epoch));
                    match query.expect("DB error") {
                        Some(result) if result.signature.is_some() => break Some(result),
                        _ if epoch == 0 => break None,
                        _ => {}
                    }
                    epoch -= 1;
                };

                self.connections
                    .send(
                        target,
                        EpochMessage::Rejoin(signed_history, self.hbbft.next_epoch()),
                    )
                    .await;
                vec![]
            }
            (peer, EpochMessage::Continue(peer_msg)) => {
                let step = self
                    .hbbft
                    .handle_message(&peer, peer_msg)
                    .expect("HBBFT handle message failed");

                if !step.fault_log.is_empty() {
                    warn!(?step.fault_log);
                }

                for msg in step.messages {
                    self.connections
                        .send(msg.target, EpochMessage::Continue(msg.message))
                        .await;
                }

                step.output
            }
        }
    }
}

struct OsRngGen;
impl RngGenerator for OsRngGen {
    type Rng = OsRng;

    fn get_rng(&self) -> Self::Rng {
        OsRng::new().unwrap()
    }
}
