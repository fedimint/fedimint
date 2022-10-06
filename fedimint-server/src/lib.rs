extern crate fedimint_api;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use config::ServerConfig;
use fedimint_api::config::GenerateConfig;
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::{NumPeers, PeerId};
use fedimint_core::epoch::{ConsensusItem, EpochHistory, EpochVerifyError};
pub use fedimint_core::*;
use hbbft::honey_badger::{HoneyBadger, Message};
use hbbft::{Epoched, NetworkInfo, Target};
use mint_client::api::{IFederationApi, WsFederationApi};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::task::spawn;
use tracing::{info, warn};

use crate::consensus::{
    ConsensusOutcome, ConsensusOutcomeConversion, ConsensusProposal, FedimintConsensus,
};
use crate::db::{EpochHistoryKey, LastEpochKey};
use crate::fedimint_api::net::peers::PeerConnections;
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

/// Admin UI
pub mod ui;

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
    pub consensus: Arc<FedimintConsensus>,
    pub connections: AnyPeerConnections<EpochMessage>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<ConsensusItem>, PeerId>,
    pub api: Arc<dyn IFederationApi>,
    pub peers: BTreeSet<PeerId>,
}

impl FedimintServer {
    /// Start all the components of the mint and plug them together
    pub async fn run(cfg: ServerConfig, consensus: FedimintConsensus) {
        let server = FedimintServer::new(cfg.clone(), consensus).await;
        spawn(net::api::run_server(cfg, server.consensus.clone()));
        server.run_consensus().await;
    }
    pub async fn new(cfg: ServerConfig, consensus: FedimintConsensus) -> Self {
        let connector: PeerConnector<EpochMessage> =
            TlsTcpConnector::new(cfg.tls_config()).into_dyn();

        Self::new_with(cfg.clone(), consensus, connector).await
    }

    pub async fn new_with(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        connector: PeerConnector<EpochMessage>,
    ) -> Self {
        cfg.validate_config(&cfg.identity);

        let connections = ReconnectPeerConnections::new(cfg.network_config(), connector)
            .await
            .into_dyn();

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
            .map(|(id, peer)| (id, peer.api_addr));
        let api = Arc::new(WsFederationApi::new(api_endpoints.collect()));

        FedimintServer {
            connections,
            hbbft,
            consensus: Arc::new(consensus),
            cfg: cfg.clone(),
            api,
            peers: cfg.peers.keys().cloned().collect(),
        }
    }

    /// Loop `run_conensus_epoch` forever
    async fn run_consensus(mut self) {
        // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
        let mut rng = OsRng;
        let consensus = self.consensus.clone();

        // Rejoin consensus and catch up to the most recent epoch
        tracing::info!("Rejoining consensus");
        self.rejoin_consensus(Duration::from_secs(60), &mut rng)
            .await;

        loop {
            let outcomes = self
                .run_consensus_epoch(consensus.get_consensus_proposal(), &mut rng)
                .await;

            for outcome in outcomes {
                self.consensus.process_consensus_outcome(outcome).await;
            }
        }
    }

    /// Builds a `ConsensusOutcome` then use the API to validate and process missed epochs
    ///
    /// * `timeout` gives all peers an opportunity to respond with the next epoch, without being
    /// blocked by any evil peers.  If a threshold `2f+1` respond with the same epoch choose that
    /// one, otherwise take the max of the responses within a reasonable bounds.
    pub async fn rejoin_consensus(
        &mut self,
        timeout: Duration,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) {
        let (msg_buffer, next_epoch_num) = self.determine_rejoin_epoch(timeout).await;
        info!("Rejoining consensus: at epoch {}", next_epoch_num);
        self.hbbft.skip_to_epoch(next_epoch_num);

        let last_saved_response = self
            .consensus
            .db
            .get_value(&LastEpochKey)
            .expect("DB error");
        let last_saved_epoch = last_saved_response.map(|e| e.0);

        let mut outcomes: Vec<ConsensusOutcome> = vec![];
        if next_epoch_num == 0 || last_saved_epoch == Some(next_epoch_num - 1) {
            info!("Rejoining consensus: proposing epoch {}", next_epoch_num);
            let proposal = self.consensus.get_consensus_proposal().await;
            outcomes = self.propose_epoch(proposal, rng).await
        }

        for msg in msg_buffer {
            outcomes.append(&mut self.handle_message(msg).await);
        }
        while outcomes.is_empty() {
            let msg = self.connections.receive().await;
            outcomes = self.handle_message(msg).await;
        }
        info!("Rejoining consensus: created outcome");

        self.download_history(outcomes[0].clone())
            .await
            .expect("Download error");
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
                let epoch_pk = self.cfg.epoch_pk_set.public_key();
                let result = self.api.fetch_epoch_history(epoch_num, epoch_pk).await;
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
    /// Also returns any messages that need to be processed by hbbft
    async fn determine_rejoin_epoch(&mut self, timeout: Duration) -> (Vec<PeerMessage>, u64) {
        let mut msg_buffer: Vec<PeerMessage> = vec![];

        self.connections
            .send(
                &Target::AllExcept(BTreeSet::new()).peers(&self.peers),
                EpochMessage::RejoinRequest,
            )
            .await;

        let mut consensus_peers = BTreeMap::<PeerId, u64>::new();
        let pks = self.cfg.epoch_pk_set.public_key();
        // last signed epoch is at most 3 epochs before the next epoch + faulty nodes because
        // faulty nodes can withhold sigs for an epoch before getting banned
        let max_age: u64 = self.cfg.peers.max_evil() as u64 + 3;
        let threshold = self.cfg.peers.threshold();

        // include our expected next_epoch as well in case we can contribute to the next consensus
        let last_saved = self.consensus.db.get_value(&LastEpochKey);
        let next_epoch = last_saved.expect("DB error").map(|e| e.0 + 1).unwrap_or(0);
        consensus_peers.insert(self.cfg.identity, next_epoch);

        loop {
            // if a threshold of peers agree on an epoch, go with that
            for epoch in consensus_peers.values() {
                if consensus_peers.values().filter(|e| *e == epoch).count() >= threshold {
                    return (msg_buffer, *epoch);
                }
            }

            // if all responded return the max of next_epoch
            if consensus_peers.len() == self.cfg.peers.len() {
                info!("All peers responded with no consensus epoch");
                let epoch = *consensus_peers.values().max().expect("len > 0");
                return (msg_buffer, epoch);
            }

            match tokio::time::timeout(timeout, self.connections.receive()).await {
                Ok((peer, EpochMessage::Rejoin(Some(history), epoch))) => {
                    let is_recent = epoch <= history.outcome.epoch + max_age;
                    if history.verify_sig(&pks).is_ok() && is_recent {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                Ok((peer, EpochMessage::Rejoin(None, epoch))) => {
                    if epoch <= max_age {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                Ok((peer, EpochMessage::RejoinRequest)) => {
                    let msg = EpochMessage::Rejoin(self.last_signed_epoch(next_epoch), next_epoch);
                    self.connections.send(&[peer], msg).await;
                }
                Ok(msg) => msg_buffer.push(msg),
                // if peers had an opportunity to reply take max(next_epoch) from a peer threshold
                Err(_) => {
                    if consensus_peers.len() >= threshold {
                        warn!("Timed-out waiting for all peers, going with max threshold");
                        let epoch = *consensus_peers.values().max().expect("len > 0");
                        return (msg_buffer, epoch);
                    }
                }
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
        outcomes.append(&mut self.propose_epoch(proposal, rng).await);

        while outcomes.is_empty() {
            let msg = self.connections.receive().await;
            outcomes = self.handle_message(msg).await;
        }
        outcomes
    }

    async fn propose_epoch(
        &mut self,
        proposal: ConsensusProposal,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> Vec<ConsensusOutcome> {
        let step = self
            .hbbft
            .propose(&proposal.items, rng)
            .expect("HBBFT propose failed");

        for msg in step.messages {
            self.connections
                .send(
                    &msg.target.peers(&self.peers),
                    EpochMessage::Continue(msg.message),
                )
                .await;
        }

        step.output
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
                let last_signed = self.last_signed_epoch(self.hbbft.epoch());

                let msg = EpochMessage::Rejoin(last_signed, self.hbbft.next_epoch());
                self.connections.send(&[peer], msg).await;
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
                        .send(
                            &msg.target.peers(&self.peers),
                            EpochMessage::Continue(msg.message),
                        )
                        .await;
                }

                step.output
            }
        }
    }

    /// Searches back in saved epoch history for the last signed epoch
    fn last_signed_epoch(&self, mut epoch: u64) -> Option<EpochHistory> {
        loop {
            let query = self.consensus.db.get_value(&EpochHistoryKey(epoch));
            match query.expect("DB error") {
                Some(result) if result.signature.is_some() => break Some(result),
                _ if epoch == 0 => break None,
                _ => {}
            }
            epoch -= 1;
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
