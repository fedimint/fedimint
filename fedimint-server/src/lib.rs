extern crate fedimint_api;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use config::ServerConfig;
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::core::ModuleDecode;
use fedimint_api::encoding::{DecodeError, ModuleRegistry};
use fedimint_api::net::peers::PeerConnections;
use fedimint_api::task::{TaskGroup, TaskHandle};
use fedimint_api::{NumPeers, PeerId};
use fedimint_core::epoch::{
    ConsensusItem, EpochHistory, EpochVerifyError, SerdeConsensusItem, SerdeEpochHistory,
};
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
use crate::db::{EpochHistoryKey, LastEpochKey};
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
    Rejoin(Option<SerdeEpochHistory>, u64),
}

pub struct FedimintServer {
    pub consensus: Arc<FedimintConsensus>,
    pub connections: PeerConnections<EpochMessage>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<SerdeConsensusItem>, PeerId>,
    pub api: Arc<dyn IFederationApi>,
    pub peers: BTreeSet<PeerId>,
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
        }
    }

    /// Loop `run_conensus_epoch` until shut down
    async fn run_consensus(mut self, task_handle: TaskHandle) {
        // FIXME: reusing the wallet CI leads to duplicate randomness beacons, not a problem for change, but maybe later for other use cases
        let mut rng = OsRng;
        let consensus = self.consensus.clone();

        // Rejoin consensus and catch up to the most recent epoch
        tracing::info!("Rejoining consensus");
        if let Err(Cancelled) = self
            .rejoin_consensus(Duration::from_secs(60), &mut rng)
            .await
        {
            info!("Consensus task shut down while rejoining");
        }

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
                self.consensus.process_consensus_outcome(outcome).await;
            }
        }

        info!("Consensus task shut down");
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
    ) -> Cancellable<()> {
        let (msg_buffer, next_epoch_num) = self.determine_rejoin_epoch(timeout).await?;

        info!("Rejoining consensus: at epoch {}", next_epoch_num);
        self.hbbft.skip_to_epoch(next_epoch_num);

        let last_saved_response = self
            .consensus
            .db
            .begin_transaction(self.consensus.decoders())
            .get_value(&LastEpochKey)
            .expect("DB error");
        let last_saved_epoch = last_saved_response.map(|e| e.0);

        let mut outcomes: Vec<ConsensusOutcome> = vec![];
        if next_epoch_num == 0 || last_saved_epoch == Some(next_epoch_num - 1) {
            info!("Rejoining consensus: proposing epoch {}", next_epoch_num);
            let proposal = self.consensus.get_consensus_proposal().await;
            outcomes = self.propose_epoch(proposal, rng).await?;
        }

        for msg in msg_buffer {
            outcomes.append(&mut self.handle_message(msg).await?);
        }
        while outcomes.is_empty() {
            let msg = self.connections.receive().await?;
            outcomes = self.handle_message(msg).await?;
        }
        info!("Rejoining consensus: created outcome");

        self.download_history(outcomes[0].clone())
            .await
            .expect("Download error");

        Ok(())
    }

    /// Requests, verifies and processes history from peers
    async fn download_history(
        &mut self,
        last_outcome: ConsensusOutcome,
    ) -> Result<(), EpochVerifyError> {
        let mut epochs: Vec<EpochHistory> = vec![];
        let saved_epoch_key = self
            .consensus
            .db
            .begin_transaction(self.consensus.decoders())
            .get_value(&LastEpochKey)
            .unwrap();

        let download_epoch_num = saved_epoch_key.map(|e| e.0 + 1).unwrap_or(0);
        let mut prev_epoch = saved_epoch_key.and_then(|e| {
            self.consensus
                .db
                .begin_transaction(self.consensus.decoders())
                .get_value(&e)
                .unwrap()
        });

        for epoch_num in download_epoch_num..=last_outcome.epoch {
            let current_epoch = if epoch_num == last_outcome.epoch {
                let contributions = last_outcome.contributions.clone();
                EpochHistory::new(last_outcome.epoch, contributions, &prev_epoch)
            } else {
                let epoch_pk = self.cfg.epoch_pk_set.public_key();
                self.api
                    .fetch_epoch_history(epoch_num, epoch_pk)
                    .await
                    .expect("fetches history")
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
    ///
    /// Returns `None` if process is shutting down.
    async fn determine_rejoin_epoch(
        &mut self,
        timeout: Duration,
    ) -> Cancellable<(Vec<PeerMessage>, u64)> {
        let mut msg_buffer: Vec<PeerMessage> = vec![];

        let mut consensus_peers = BTreeMap::<PeerId, u64>::new();
        let pks = self.cfg.epoch_pk_set.public_key();
        // last signed epoch is at most 3 epochs before the next epoch + faulty nodes because
        // faulty nodes can withhold sigs for an epoch before getting banned
        let max_age: u64 = self.cfg.peers.max_evil() as u64 + 3;
        let threshold = self.cfg.peers.threshold();

        // include our expected next_epoch as well in case we can contribute to the next consensus
        let last_saved = self
            .consensus
            .db
            .begin_transaction(self.consensus.decoders())
            .get_value(&LastEpochKey);
        let next_epoch = last_saved.expect("DB error").map(|e| e.0 + 1).unwrap_or(0);
        consensus_peers.insert(self.cfg.identity, next_epoch);

        loop {
            self.connections
                .send(
                    &Target::AllExcept(consensus_peers.keys().cloned().collect())
                        .peers(&self.peers),
                    EpochMessage::RejoinRequest,
                )
                .await?;
            // if a threshold of peers agree on an epoch, go with that
            for epoch in consensus_peers.values() {
                if consensus_peers.values().filter(|e| *e == epoch).count() >= threshold {
                    return Ok((msg_buffer, *epoch));
                }
            }

            // if all responded return the max of next_epoch
            if consensus_peers.len() == self.cfg.peers.len() {
                info!("All peers responded with no consensus epoch");
                let epoch = *consensus_peers.values().max().expect("len > 0");
                return Ok((msg_buffer, epoch));
            }

            match tokio::time::timeout(timeout, self.connections.receive()).await {
                Ok(Err(Cancelled)) => {
                    return Err(Cancelled);
                }
                Ok(Ok((peer, EpochMessage::Rejoin(Some(history), epoch)))) => {
                    let history = match history.try_into_inner(&self.consensus.modules) {
                        Ok(history) => history,
                        Err(decode_err) => {
                            warn!("Peer {} sent malformed message: {}", peer, decode_err);
                            continue;
                        }
                    };

                    let is_recent = epoch <= history.outcome.epoch + max_age;
                    if history.verify_sig(&pks).is_ok() && is_recent {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                Ok(Ok((peer, EpochMessage::Rejoin(None, epoch)))) => {
                    if epoch <= max_age {
                        consensus_peers.insert(peer, epoch);
                    }
                }
                Ok(Ok((peer, EpochMessage::RejoinRequest))) => {
                    let msg = EpochMessage::Rejoin(
                        self.last_signed_epoch(next_epoch).map(|eh| (&eh).into()),
                        next_epoch,
                    );
                    self.connections.send(&[peer], msg).await?;
                }
                Ok(Ok(msg)) => msg_buffer.push(msg),
                // if peers had an opportunity to reply take max(next_epoch) from a peer threshold
                Err(_) => {
                    if consensus_peers.len() >= threshold {
                        warn!("Timed-out waiting for all peers, going with max threshold");
                        let epoch = *consensus_peers.values().max().expect("len > 0");
                        return Ok((msg_buffer, epoch));
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
    ) -> Cancellable<Vec<ConsensusOutcome>> {
        // for testing federations with one peer
        if self.cfg.peers.len() == 1 {
            tokio::select! {
              () = self.consensus.transaction_notify.notified() => (),
              () = self.consensus.await_consensus_proposal() => (),
            }
            let proposal = proposal.await;
            let epoch = self.hbbft.next_epoch() + 1;
            self.hbbft.skip_to_epoch(epoch);
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
                let (outcome, _ban_peers) = module_parse_outcome(outcome, &self.consensus.modules);
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
            (_, EpochMessage::Continue(peer_msg)) => self.hbbft.next_epoch() == peer_msg.epoch(),
            (_, EpochMessage::RejoinRequest) => true,
            _ => false,
        }
    }

    /// Runs a single HBBFT consensus step
    async fn handle_message(&mut self, msg: PeerMessage) -> Cancellable<Vec<ConsensusOutcome>> {
        match msg {
            (_, EpochMessage::Rejoin(_, _)) => Ok(vec![]),
            (peer, EpochMessage::RejoinRequest) => {
                let last_signed = self.last_signed_epoch(self.hbbft.epoch());

                let msg = EpochMessage::Rejoin(
                    last_signed.map(|eh| (&eh).into()),
                    self.hbbft.next_epoch(),
                );
                self.connections.send(&[peer], msg).await?;
                Ok(vec![])
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
                        .await?;
                }

                Ok(step
                    .output
                    .into_iter()
                    .map(|outcome| {
                        // FIXME: deal with faulty messages
                        let (outcome, _ban_peers) =
                            module_parse_outcome(outcome, &self.consensus.modules);
                        outcome
                    })
                    .collect())
            }
        }
    }

    /// Searches back in saved epoch history for the last signed epoch
    fn last_signed_epoch(&self, mut epoch: u64) -> Option<EpochHistory> {
        loop {
            let query = self
                .consensus
                .db
                .begin_transaction(self.consensus.decoders())
                .get_value(&EpochHistoryKey(epoch));
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

fn module_parse_outcome<M: ModuleDecode>(
    outcome: SerdeConsensusOutcome,
    module_registry: &ModuleRegistry<M>,
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
