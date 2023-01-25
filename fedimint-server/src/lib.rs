extern crate fedimint_api;

use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, format_err};
use config::ServerConfig;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::encoding::DecodeError;
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::net::peers::PeerConnections;
use fedimint_api::task::{sleep, TaskGroup, TaskHandle};
use fedimint_api::{NumPeers, PeerId};
use fedimint_core::epoch::{
    ConsensusItem, EpochVerifyError, SerdeConsensusItem, SignedEpochOutcome,
};
use fedimint_core::transaction::Transaction;
pub use fedimint_core::*;
use hbbft::honey_badger::{Batch, HoneyBadger, Message, Step};
use hbbft::{Epoched, NetworkInfo, Target};
use itertools::Itertools;
use mint_client::api::WsFederationApi;
use mint_client::api::{DynFederationApi, GlobalFederationApi};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tracing::{info, warn};

use crate::consensus::{
    ConsensusProposal, FedimintConsensus, HbbftConsensusOutcome, HbbftSerdeConsensusOutcome,
};
use crate::db::LastEpochKey;
use crate::fedimint_api::encoding::Encodable;
use crate::fedimint_api::net::peers::IPeerConnections;
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::PeerSlice;
use crate::net::peers::{PeerConnector, ReconnectPeerConnections};

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

type PeerMessage = (PeerId, EpochMessage);

/// how many epochs ahead of consensus to rejoin
const NUM_EPOCHS_REJOIN_AHEAD: u64 = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EpochMessage {
    Continue(Message<PeerId>),
    RejoinRequest(u64),
}

type EpochStep = Step<Vec<SerdeConsensusItem>, PeerId>;

enum EpochTriggerEvent {
    /// A user has sent us a new transaction
    NewTransaction(Option<Transaction>),
    /// A peer has sent us a consensus message
    NewMessage(PeerMessage),
    /// One of our modules triggered an event (e.g. new bitcoin block)
    ModuleProposalEvent,
    /// A rejoining peer wants us to run an empty epoch
    RunEpochRequest,
}

pub struct FedimintServer {
    pub consensus: Arc<FedimintConsensus>,
    pub tx_receiver: Receiver<Transaction>,
    pub connections: PeerConnections<EpochMessage>,
    pub cfg: ServerConfig,
    pub hbbft: HoneyBadger<Vec<SerdeConsensusItem>, PeerId>,
    pub api: DynFederationApi,
    pub peers: BTreeSet<PeerId>,
    pub rejoin_at_epoch: Option<HashMap<u64, HashSet<PeerId>>>,
    pub run_empty_epochs: u64,
    pub last_processed_epoch: Option<SignedEpochOutcome>,
    pub decoders: ModuleDecoderRegistry,
}

impl FedimintServer {
    /// Start all the components of the mint and plug them together
    pub async fn run(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        tx_receiver: Receiver<Transaction>,
        decoders: ModuleDecoderRegistry,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<()> {
        let server =
            FedimintServer::new(cfg.clone(), consensus, tx_receiver, decoders, task_group).await;
        let server_consensus = server.consensus.clone();
        let consensus = server
            .cfg
            .consensus
            .to_config_response(&server_consensus.module_inits);

        task_group
            .spawn("api-server", |handle| {
                net::api::run_server(cfg, server_consensus, handle)
            })
            .await;

        loop {
            info!("Waiting for peers to agree on a consensus config hash");
            match server.api.download_client_config().await {
                Ok(response) if response.consensus_hash == consensus.consensus_hash => break,
                Ok(_) => bail!("Our consensus config doesn't match peers!"),
                Err(e) => {
                    warn!("ERROR {:?}", e)
                }
            }
            sleep(Duration::from_millis(1000)).await;
        }

        task_group
            .spawn_local("consensus", move |handle| server.run_consensus(handle))
            .await;
        Ok(())
    }

    pub async fn new(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        tx_receiver: Receiver<Transaction>,
        decoders: ModuleDecoderRegistry,
        task_group: &mut TaskGroup,
    ) -> Self {
        let connector: PeerConnector<EpochMessage> =
            TlsTcpConnector::new(cfg.tls_config()).into_dyn();

        Self::new_with(
            cfg.clone(),
            consensus,
            tx_receiver,
            connector,
            decoders,
            task_group,
        )
        .await
    }

    pub async fn new_with(
        cfg: ServerConfig,
        consensus: FedimintConsensus,
        tx_receiver: Receiver<Transaction>,
        connector: PeerConnector<EpochMessage>,
        decoders: ModuleDecoderRegistry,
        task_group: &mut TaskGroup,
    ) -> Self {
        cfg.validate_config(&cfg.local.identity, &consensus.module_inits)
            .expect("invalid config");

        let connections =
            ReconnectPeerConnections::new(cfg.network_config(), connector, task_group)
                .await
                .into_dyn();

        let net_info = NetworkInfo::new(
            cfg.local.identity,
            cfg.private.hbbft_sks.inner().clone(),
            cfg.consensus.hbbft_pk_set.clone(),
            cfg.local.p2p.keys().copied(),
        );

        let hbbft: HoneyBadger<Vec<SerdeConsensusItem>, _> =
            HoneyBadger::builder(Arc::new(net_info)).build();

        let api_endpoints = cfg
            .consensus
            .api
            .clone()
            .into_iter()
            .map(|(id, node)| (id, node.url));
        let api = WsFederationApi::new(api_endpoints.collect());

        FedimintServer {
            connections,
            hbbft,
            consensus: Arc::new(consensus),
            tx_receiver,
            cfg: cfg.clone(),
            api: api.into(),
            peers: cfg.local.p2p.keys().cloned().collect(),
            rejoin_at_epoch: None,
            run_empty_epochs: 0,
            last_processed_epoch: None,
            decoders,
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

    /// Starts consensus by skipping to the last saved epoch history  and triggering a new epoch
    pub async fn start_consensus(&mut self) {
        let db = self.consensus.db.clone();
        let mut tx = db.begin_transaction().await;

        if let Some(key) = tx.get_value(&LastEpochKey).await.expect("DB error") {
            self.last_processed_epoch = tx.get_value(&key).await.expect("DB error");
        }

        let epoch = self.next_epoch_to_process();
        info!("Starting consensus at epoch {}", epoch);
        self.hbbft.skip_to_epoch(epoch);
        self.rejoin_at_epoch = Some(HashMap::new());
        self.request_rejoin(1).await;
    }

    /// Returns the next epoch that we need to process, based on our saved history
    fn next_epoch_to_process(&self) -> u64 {
        self.last_processed_epoch
            .as_ref()
            .map(|e| 1 + e.outcome.epoch)
            .unwrap_or(0)
    }

    /// Requests, verifies and processes history from peers
    ///
    /// `last_outcome` - The consensus outcome (unprocessed), we're trying to process.
    pub async fn process_outcome(
        &mut self,
        last_outcome: HbbftConsensusOutcome,
    ) -> Result<(), EpochVerifyError> {
        let mut epochs: Vec<_> = vec![];
        // for checking the hashes of the epoch history
        let mut prev_epoch: Option<SignedEpochOutcome> = self.last_processed_epoch.clone();
        // once we produce an outcome we no longer need to rejoin
        self.rejoin_at_epoch = None;

        for epoch_num in self.next_epoch_to_process()..=last_outcome.epoch {
            let (items, epoch, prev_epoch_hash, rejected_txs, at_know_trusted_checkpoint) =
                if epoch_num == last_outcome.epoch {
                    (
                        last_outcome
                            .contributions
                            .iter()
                            .sorted_by_key(|(peer, _)| *peer)
                            .map(|(peer, items)| (*peer, items.clone()))
                            .collect(),
                        last_outcome.epoch,
                        self.last_processed_epoch
                            .as_ref()
                            .and_then(|epoch| epoch.outcome.consensus_hash().ok()),
                        None,
                        true,
                    )
                } else {
                    info!("Downloading missing epoch {}", epoch_num);
                    let epoch_pk = self.cfg.consensus.epoch_pk_set.public_key();
                    let epoch = self
                        .api
                        .fetch_epoch_history(epoch_num, epoch_pk, &self.decoders)
                        .await
                        .expect("fetches history");

                    epoch.verify_hash(&prev_epoch)?;
                    prev_epoch = Some(epoch.clone());

                    let pk = self.cfg.consensus.epoch_pk_set.public_key();
                    let sig_valid = epoch.verify_sig(&pk).is_ok();
                    (
                        epoch.outcome.items,
                        epoch.outcome.epoch,
                        epoch.outcome.last_hash,
                        Some(epoch.outcome.rejected_txs),
                        sig_valid,
                    )
                };

            epochs.push((items, epoch, prev_epoch_hash, rejected_txs));

            if at_know_trusted_checkpoint {
                for (items, epoch, _prev_epoch_hash, rejected_txs) in epochs.drain(..) {
                    let epoch = self
                        .consensus
                        .process_consensus_outcome(
                            Batch {
                                epoch,
                                contributions: BTreeMap::from_iter(items.into_iter()),
                            },
                            rejected_txs.clone(),
                        )
                        .await;
                    self.last_processed_epoch = Some(epoch);
                }
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
    ) -> anyhow::Result<Vec<HbbftConsensusOutcome>> {
        // for testing federations with one peer
        if self.cfg.local.p2p.len() == 1 {
            tokio::select! {
              maybe_tx = self.tx_receiver.recv() => {
                    let tx = maybe_tx.ok_or_else(|| format_err!("Tx channel closed"))?;
                    self.consensus.save_transaction_to_db(tx).await;
                },
              () = self.consensus.await_consensus_proposal() => (),
            }
            let proposal = proposal.await;
            let epoch = self.hbbft.epoch();
            self.hbbft.skip_to_epoch(epoch + 1);
            return Ok(vec![HbbftConsensusOutcome {
                epoch,
                contributions: BTreeMap::from([(self.cfg.local.identity, proposal.items)]),
            }]);
        }

        // process messages until new epoch or we have a proposal
        let mut outcomes: Vec<HbbftConsensusOutcome> = loop {
            match self.await_next_epoch().await? {
                EpochTriggerEvent::NewMessage(msg) if self.start_next_epoch(&msg) => {
                    break self.handle_message(msg).await?
                }
                EpochTriggerEvent::NewMessage(msg) => self.handle_message(msg).await?,
                EpochTriggerEvent::NewTransaction(maybe_tx) => {
                    let tx = maybe_tx.ok_or_else(|| format_err!("Tx channel closed"))?;
                    self.consensus.save_transaction_to_db(tx).await;
                    break vec![];
                }
                _ => break vec![],
            };
        };

        // save any transactions we have in the channel
        while let Ok(tx) = self.tx_receiver.try_recv() {
            self.consensus.save_transaction_to_db(tx).await;
        }

        let proposal = proposal.await;
        for peer in proposal.drop_peers.iter() {
            self.connections.ban_peer(*peer).await;
        }
        let step = self.propose_epoch(proposal, rng).await?;
        outcomes.append(&mut self.handle_step(step).await?);

        while outcomes.is_empty() {
            let msg = self.connections.receive().await?;
            outcomes = self.handle_message(msg).await?;
        }
        Ok(outcomes)
    }

    /// Handles one step of the HBBFT algorithm, sending messages to peers and parsing any
    /// outcomes contained in the step
    async fn handle_step(&mut self, step: EpochStep) -> Cancellable<Vec<HbbftConsensusOutcome>> {
        for msg in step.messages {
            self.connections
                .send(
                    &msg.target.peers(&self.peers),
                    EpochMessage::Continue(msg.message),
                )
                .await?;
        }

        if !step.fault_log.is_empty() {
            warn!(?step.fault_log);
        }

        let mut outcomes: Vec<HbbftConsensusOutcome> = vec![];
        for outcome in step.output {
            let (outcome, ban_peers) =
                module_parse_outcome(outcome, &self.consensus.modules.decoder_registry());
            for peer in ban_peers {
                self.connections.ban_peer(peer).await;
            }
            outcomes.push(outcome);
        }

        Ok(outcomes)
    }

    async fn propose_epoch(
        &mut self,
        proposal: ConsensusProposal,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> Cancellable<EpochStep> {
        Ok(self
            .hbbft
            .propose(
                &proposal.items.into_iter().map(|ci| (&ci).into()).collect(),
                rng,
            )
            .expect("HBBFT propose failed"))
    }

    async fn await_next_epoch(&mut self) -> anyhow::Result<EpochTriggerEvent> {
        if self.run_empty_epochs > 0 {
            self.run_empty_epochs = self.run_empty_epochs.saturating_sub(1);
            return Ok(EpochTriggerEvent::RunEpochRequest);
        }

        tokio::select! {
            tx = self.tx_receiver.recv() => Ok(EpochTriggerEvent::NewTransaction(tx)),
            () = self.consensus.await_consensus_proposal() => Ok(EpochTriggerEvent::ModuleProposalEvent),
            msg = self.connections.receive() => Ok(EpochTriggerEvent::NewMessage(msg?))
        }
    }

    fn start_next_epoch(&self, msg: &PeerMessage) -> bool {
        match msg {
            (_, EpochMessage::Continue(peer_msg)) => self.hbbft.epoch() <= peer_msg.epoch(),
            (_, EpochMessage::RejoinRequest(_)) => false,
        }
    }

    /// Runs a single HBBFT consensus step
    async fn handle_message(
        &mut self,
        msg: PeerMessage,
    ) -> Cancellable<Vec<HbbftConsensusOutcome>> {
        match msg {
            (peer, EpochMessage::Continue(peer_msg)) => {
                self.rejoin_at_epoch(peer_msg.epoch(), peer).await;

                let step = self
                    .hbbft
                    .handle_message(&peer, peer_msg)
                    .expect("HBBFT handle message failed");

                Ok(self.handle_step(step).await?)
            }
            (_, EpochMessage::RejoinRequest(epoch)) => {
                info!("Requested to run {} epochs", epoch);
                self.run_empty_epochs = min(NUM_EPOCHS_REJOIN_AHEAD, epoch);
                Ok(vec![])
            }
        }
    }

    /// If we are rejoining and received a threshold of messages from the same epoch, then skip
    /// to that epoch.  Give ourselves a buffer of `NUM_EPOCHS_REJOIN_AHEAD` so we can ensure
    /// we receive enough HBBFT messages to produce an outcome.
    async fn rejoin_at_epoch(&mut self, epoch: u64, peer: PeerId) {
        if let Some(epochs) = self.rejoin_at_epoch.as_mut() {
            let peers = epochs.entry(epoch).or_default();
            peers.insert(peer);

            if peers.len() >= self.peers.threshold() && self.hbbft.epoch() < epoch {
                info!("Skipping to epoch {}", epoch + NUM_EPOCHS_REJOIN_AHEAD);
                self.hbbft.skip_to_epoch(epoch + NUM_EPOCHS_REJOIN_AHEAD);
                self.request_rejoin(NUM_EPOCHS_REJOIN_AHEAD).await;
            }
        }
    }

    /// Sends a rejoin request to all peers, indicating the number of epochs we want them to create
    async fn request_rejoin(&mut self, epochs_to_run: u64) {
        self.connections
            .send(
                &Target::all().peers(&self.peers),
                EpochMessage::RejoinRequest(epochs_to_run),
            )
            .await
            .expect("Failed to send rejoin requests");
    }
}

fn module_parse_outcome(
    outcome: HbbftSerdeConsensusOutcome,
    module_registry: &ModuleDecoderRegistry,
) -> (HbbftConsensusOutcome, Vec<PeerId>) {
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
