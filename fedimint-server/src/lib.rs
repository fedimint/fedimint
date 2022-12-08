extern crate fedimint_api;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;

use config::ServerConfig;
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::core::ModuleDecode;
use fedimint_api::encoding::DecodeError;
use fedimint_api::net::peers::PeerConnections;
use fedimint_api::task::{TaskGroup, TaskHandle};
use fedimint_api::{NumPeers, PeerId};
use fedimint_core::epoch::{ConsensusItem, EpochHistory, EpochVerifyError, SerdeConsensusItem};
pub use fedimint_core::*;
use hbbft::honey_badger::{Batch, HoneyBadger, Message};
use hbbft::{Epoched, NetworkInfo, Target};
use mint_client::api::{IFederationApi, WsFederationApi};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::consensus::{
    ConsensusOutcome, ConsensusOutcomeConversion, ConsensusProposal, FedimintConsensus,
    SerdeConsensusOutcome,
};
use crate::db::LastEpochKey;
use crate::fedimint_api::net::peers::IPeerConnections;
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::PeerSlice;
use crate::net::peers::{PeerConnector, ReconnectPeerConnections};
use crate::rng::RngGenerator;

/// The actual implementation of the federated mint
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod db;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// Implementation of multiplexed peer connections
pub mod multiplexed;

/// Some abstractions to handle randomness
mod rng;

type PeerMessage = (PeerId, EpochMessage);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EpochMessage {
    Continue(Message<PeerId>),
    RejoinRequest,
}

pub struct FedimintServer {
    pub consensus: Arc<FedimintConsensus>,
    pub connections: PeerConnections<EpochMessage>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<SerdeConsensusItem>, PeerId>,
    pub api: Arc<dyn IFederationApi>,
    pub peers: BTreeSet<PeerId>,
    pub epochs: HashMap<u64, HashSet<PeerId>>,
    pub last_processed_epoch: Option<EpochHistory>,
}

impl FedimintServer {
    /// Start all the components of the mint and plug them together
    pub async fn run(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<()> {
        let server = FedimintServer::new(cfg.clone(), consensus, task_group).await;
        let server_consensus = server.consensus.clone();
        task_group
            .spawn("api-server", |handle| {
                net::api::run_server(cfg, server_consensus, handle)
            })
            .await;
        task_group
            .spawn_local("consensus", move |handle| server.run_consensus(handle))
            .await;
        Ok(())
    }

    pub async fn new(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        task_group: &mut TaskGroup,
    ) -> Self {
        let connector: PeerConnector<EpochMessage> =
            TlsTcpConnector::new(cfg.tls_config()).into_dyn();

        Self::new_with(cfg.clone(), consensus, connector, task_group).await
    }

    pub async fn new_with(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        connector: PeerConnector<EpochMessage>,
        task_group: &mut TaskGroup,
    ) -> Self {
        cfg.validate_config(&cfg.identity).expect("invalid config");

        let connections =
            ReconnectPeerConnections::new(cfg.network_config(), connector, task_group)
                .await
                .into_dyn();

        let net_info = NetworkInfo::new(
            cfg.identity,
            cfg.hbbft_sks.inner().clone(),
            cfg.hbbft_pk_set.clone(),
            cfg.peers.iter().map(|(id, _)| *id),
        );

        let hbbft: HoneyBadger<Vec<SerdeConsensusItem>, _> =
            HoneyBadger::builder(Arc::new(net_info)).build();

        let api_endpoints = cfg
            .peers
            .clone()
            .into_iter()
            .map(|(id, peer)| (id, peer.api_addr));
        let api = Arc::new(WsFederationApi::new(api_endpoints.collect()));

        FedimintServer {
            connections,
            hbbft,
            consensus: Arc::new(consensus),
            cfg: cfg.clone(),
            api,
            peers: cfg.peers.keys().cloned().collect(),
            epochs: Default::default(),
            last_processed_epoch: None,
        }
    }

    /// Loop `run_conensus_epoch` until shut down
    async fn run_consensus(mut self, task_handle: TaskHandle) {
        // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
        let mut rng = OsRng;
        let consensus = self.consensus.clone();
        self.start_consensus().await;

        while !task_handle.is_shutting_down() {
            let outcomes = if let Ok(v) = self
                .run_consensus_epoch(consensus.get_consensus_proposal(), &mut rng)
                .await
            {
                v
            } else {
                // `None` is supposed to mean the proccess is shutting down
                debug_assert!(task_handle.is_shutting_down());
                break;
            };

            for outcome in outcomes {
                info!("{}", consensus::debug::epoch_message(&outcome));
                self.process_outcome(outcome)
                    .await
                    .expect("failed to process epoch");
            }
        }

        info!("Consensus task shut down");
    }

    /// Starts consensus by advancing to the last saved epoch and triggering a new epoch
    pub async fn start_consensus(&mut self) {
        let mut tx = self
            .consensus
            .db
            .begin_transaction(self.consensus.decoders())
            .await;

        if let Some(key) = tx.get_value(&LastEpochKey).await.expect("DB error") {
            self.last_processed_epoch = tx.get_value(&key).await.expect("DB error");
        }

        info!(
            "Starting consensus at epoch {}",
            self.next_epoch_to_process()
        );
        self.hbbft.skip_to_epoch(self.next_epoch_to_process());
        self.connections
            .send(
                &Target::all().peers(&self.peers),
                EpochMessage::RejoinRequest,
            )
            .await
            .expect("Failed to send rejoin requests");
    }

    /// Returns the next epoch that we need to process, based on our saved history
    fn next_epoch_to_process(&self) -> u64 {
        self.last_processed_epoch
            .as_ref()
            .map(|e| 1 + e.outcome.epoch)
            .unwrap_or(0)
    }

    /// Requests, verifies and processes history from peers
    pub async fn process_outcome(
        &mut self,
        last_outcome: ConsensusOutcome,
    ) -> Result<(), EpochVerifyError> {
        let mut epochs: Vec<EpochHistory> = vec![];

        for epoch_num in self.next_epoch_to_process()..=last_outcome.epoch {
            let current_epoch = if epoch_num == last_outcome.epoch {
                let contributions = last_outcome.contributions.clone();
                EpochHistory::new(
                    last_outcome.epoch,
                    contributions,
                    &self.last_processed_epoch,
                )
            } else {
                info!("Downloading missing epoch {}", epoch_num);
                let epoch_pk = self.cfg.epoch_pk_set.public_key();
                self.api
                    .fetch_epoch_history(epoch_num, epoch_pk)
                    .await
                    .expect("fetches history")
            };

            current_epoch.verify_hash(&self.last_processed_epoch)?;
            epochs.push(current_epoch.clone());

            let pk = self.cfg.epoch_pk_set.public_key();
            if epoch_num == last_outcome.epoch || current_epoch.verify_sig(&pk).is_ok() {
                for epoch in epochs.drain(..) {
                    let outcome = ConsensusOutcomeConversion::from(epoch.outcome.clone()).0;
                    self.consensus.process_consensus_outcome(outcome).await;
                    self.last_processed_epoch = Some(epoch);
                }
                epochs.clear();
            }
        }

        Ok(())
    }

    /// The main consensus function:
    /// 1. Await a new proposal event or receiving a proposal from peers
    /// 2. Send the `ConsensusProposal` to peers
    /// 3. Run HBBFT until a `ConsensusOutcome` can be returned
    pub async fn run_consensus_epoch(
        &mut self,
        proposal: impl Future<Output = ConsensusProposal>,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> Cancellable<Vec<ConsensusOutcome>> {
        // for testing federations with one peer
        if self.cfg.peers.len() == 1 {
            tokio::select! {
              () = self.consensus.transaction_notify.notified() => (),
              () = self.consensus.await_consensus_proposal() => (),
            }
            let proposal = proposal.await;
            let epoch = self.hbbft.epoch();
            self.hbbft.skip_to_epoch(epoch + 1);
            return Ok(vec![ConsensusOutcome {
                epoch,
                contributions: BTreeMap::from([(self.cfg.identity, proposal.items)]),
            }]);
        }

        // process messages until new epoch or we have a proposal
        let mut outcomes: Vec<ConsensusOutcome> = loop {
            match self.await_proposal_or_peer_message().await? {
                Some(msg) if self.start_next_epoch(&msg) => break self.handle_message(msg).await?,
                Some(msg) => self.handle_message(msg).await?,
                None => break vec![],
            };
        };

        let proposal = proposal.await;
        for peer in proposal.drop_peers.iter() {
            self.connections.ban_peer(*peer).await;
        }
        outcomes.append(&mut self.propose_epoch(proposal, rng).await?);

        while outcomes.is_empty() {
            let msg = self.connections.receive().await?;
            outcomes = self.handle_message(msg).await?;
        }
        Ok(outcomes)
    }

    async fn propose_epoch(
        &mut self,
        proposal: ConsensusProposal,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> Cancellable<Vec<ConsensusOutcome>> {
        let step = self
            .hbbft
            .propose(
                &proposal.items.into_iter().map(|ci| (&ci).into()).collect(),
                rng,
            )
            .expect("HBBFT propose failed");

        for msg in step.messages {
            self.connections
                .send(
                    &msg.target.peers(&self.peers),
                    EpochMessage::Continue(msg.message),
                )
                .await?;
        }

        Ok(step
            .output
            .into_iter()
            .map(|outcome| {
                // FIXME: deal with faulty messages
                let (outcome, _ban_peers) =
                    module_parse_outcome(outcome, &self.consensus.modules.decoders());
                outcome
            })
            .collect())
    }

    async fn await_proposal_or_peer_message(&mut self) -> Cancellable<Option<PeerMessage>> {
        tokio::select! {
            () = self.consensus.transaction_notify.notified() => Ok(None),
            () = self.consensus.await_consensus_proposal() => Ok(None),
            msg = self.connections.receive() => msg.map(Some)
        }
    }

    fn start_next_epoch(&self, msg: &PeerMessage) -> bool {
        match msg {
            (_, EpochMessage::Continue(peer_msg)) => self.hbbft.next_epoch() <= peer_msg.epoch(),
            (_, EpochMessage::RejoinRequest) => true,
        }
    }

    /// Runs a single HBBFT consensus step
    async fn handle_message(&mut self, msg: PeerMessage) -> Cancellable<Vec<ConsensusOutcome>> {
        match msg {
            (peer, EpochMessage::Continue(peer_msg)) => {
                self.advance_to_consensus_epoch(peer_msg.epoch(), peer);

                let step = self
                    .hbbft
                    .handle_message(&peer, peer_msg)
                    .expect("HBBFT handle message failed");

                if !step.fault_log.is_empty() {
                    warn!(?step.fault_log);
                }

                for msg in step.messages {
                    self.connections
                        .send(
                            &msg.target.peers(&self.peers),
                            EpochMessage::Continue(msg.message),
                        )
                        .await?;
                }

                Ok(step
                    .output
                    .into_iter()
                    .map(|outcome| {
                        // FIXME: deal with faulty messages
                        let (outcome, _ban_peers) =
                            module_parse_outcome(outcome, &self.consensus.modules.decoders());
                        outcome
                    })
                    .collect())
            }
            (_, EpochMessage::RejoinRequest) => Ok(vec![]),
        }
    }

    /// Advances our epoch if we received a threshold of messages from a future epoch so we can
    /// sync up to our peers
    fn advance_to_consensus_epoch(&mut self, epoch: u64, peer: PeerId) {
        let peers = self.epochs.entry(epoch).or_default();
        peers.insert(peer);

        if peers.len() >= self.peers.threshold() {
            for epoch in self.hbbft.epoch()..=epoch {
                self.epochs.remove_entry(&epoch);
            }

            if self.hbbft.epoch() < epoch {
                info!("Skipping to epoch {}", epoch);
                self.hbbft.skip_to_epoch(epoch);
            }
        }
    }
}

pub struct OsRngGen;
impl RngGenerator for OsRngGen {
    type Rng = OsRng;

    fn get_rng(&self) -> Self::Rng {
        OsRng
    }
}

fn module_parse_outcome(
    outcome: SerdeConsensusOutcome,
    module_registry: &ModuleDecoderRegistry,
) -> (ConsensusOutcome, Vec<PeerId>) {
    let mut ban_peers = vec![];
    let contributions = outcome
        .contributions
        .into_iter()
        .filter_map(|(peer, cis)| {
            let decoded_cis = cis
                .into_iter()
                .map(|ci| ci.try_into_inner(module_registry))
                .collect::<Result<Vec<ConsensusItem>, DecodeError>>();

            match decoded_cis {
                Ok(cis) => Some((peer, cis)),
                Err(e) => {
                    warn!("Received invalid message from peer {}: {}", peer, e);
                    ban_peers.push(peer);
                    None
                }
            }
        })
        .collect::<BTreeMap<PeerId, Vec<ConsensusItem>>>();

    let outcome = Batch {
        epoch: outcome.epoch,
        contributions,
    };

    (outcome, ban_peers)
}
