use std::cmp::{max, min};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use fedimint_core::api::{
    ConsensusContribution, DynGlobalApi, GlobalFederationApi, WsFederationApi,
};
use fedimint_core::cancellable::Cancellable;
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::db::{apply_migrations, Database};
use fedimint_core::encoding::DecodeError;
use fedimint_core::epoch::{
    ConsensusItem, EpochOutcome, EpochVerifyError, SerdeConsensusItem, SignedEpochOutcome,
};
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::net::peers::PeerConnections;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::{NumPeers, PeerId};
use futures::stream::Peekable;
use futures::{FutureExt, StreamExt};
use hbbft::honey_badger::{Batch, HoneyBadger, Message, Step};
use hbbft::{Epoched, NetworkInfo, Target};
use itertools::Itertools;
use jsonrpsee::core::Serialize;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::config::ServerConfig;
use crate::consensus::{
    ApiEvent, ConsensusOutcomeConversion, ConsensusProposal, FedimintConsensus,
    HbbftConsensusOutcome, HbbftSerdeConsensusOutcome,
};
use crate::db::{get_global_database_migrations, LastEpochKey, GLOBAL_DATABASE_VERSION};
use crate::fedimint_core::encoding::Encodable;
use crate::fedimint_core::net::peers::IPeerConnections;
use crate::net::api::{ConsensusApi, ExpiringCache};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{DelayCalculator, PeerConnector, PeerSlice, ReconnectPeerConnections};
use crate::{LOG_CONSENSUS, LOG_CORE};
type PeerMessage = (PeerId, EpochMessage);

/// how many epochs ahead of consensus to rejoin
const NUM_EPOCHS_REJOIN_AHEAD: u64 = 10;

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER_SIZE: usize = 1000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum EpochMessage {
    Continue(Message<PeerId>),
    RejoinRequest(u64),
}

type EpochStep = Step<Vec<SerdeConsensusItem>, PeerId>;

enum EpochTriggerEvent {
    /// A new event has been sent to us from the API
    ApiEvent,
    /// A peer has sent us a consensus message
    NewMessage(PeerMessage),
    /// One of our modules triggered an event (e.g. new bitcoin block)
    ModuleProposalEvent,
    /// A rejoining peer wants us to run an empty epoch
    RunEpochRequest,
}

pub(crate) type LatestContributionByPeer = HashMap<PeerId, ConsensusContribution>;

/// Runs the main server consensus loop
pub struct ConsensusServer {
    /// `TaskGroup` that is running the server
    pub task_group: TaskGroup,
    /// Delegate for processing consensus information
    pub consensus: FedimintConsensus,
    /// Receives event notifications from the API (triggers epochs)
    pub api_receiver: Peekable<ReceiverStream<ApiEvent>>,
    /// P2P connections for running consensus
    pub connections: PeerConnections<EpochMessage>,
    /// Our configuration
    pub cfg: ServerConfig,
    /// Runs the HBBFT consensus algorithm
    pub hbbft: HoneyBadger<Vec<SerdeConsensusItem>, PeerId>,
    /// Used to make API calls to our peers
    pub api: DynGlobalApi,
    /// The list of all other peers
    pub other_peers: BTreeSet<PeerId>,
    /// If `Some` then we restarted and look for the epoch to rejoin at
    pub rejoin_at_epoch: HashMap<u64, HashSet<PeerId>>,
    /// Under the HBBFT consensus algorithm, this will track the latest epoch
    /// message received by each peer and when it was received
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    /// Number of pending forced epochs (requested by peers to help join
    /// consensus faster)
    pub pending_forced_epochs: u64,
    /// Tracks the last epoch outcome from consensus
    pub last_processed_epoch: Option<SignedEpochOutcome>,
    /// Used for decoding module specific-values
    pub decoders: ModuleDecoderRegistry,
}

impl ConsensusServer {
    /// Creates a server with real network and no delays
    pub async fn new(
        cfg: ServerConfig,
        db: Database,
        module_inits: ServerModuleGenRegistry,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Self> {
        let connector: PeerConnector<EpochMessage> =
            TlsTcpConnector::new(cfg.tls_config(), cfg.local.identity).into_dyn();

        Self::new_with(
            cfg,
            db,
            module_inits,
            connector,
            DelayCalculator::PROD_DEFAULT,
            task_group,
        )
        .await
    }

    /// Creates a server that can simulate network and delays
    ///
    /// Initializes modules and runs any database migrations
    pub async fn new_with(
        cfg: ServerConfig,
        db: Database,
        module_inits: ServerModuleGenRegistry,
        connector: PeerConnector<EpochMessage>,
        delay_calculator: DelayCalculator,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Self> {
        // Apply database migrations and build `ServerModuleRegistry`
        let mut modules = BTreeMap::new();

        apply_migrations(
            &db,
            "Global".to_string(),
            GLOBAL_DATABASE_VERSION,
            get_global_database_migrations(),
        )
        .await?;

        for (module_id, module_cfg) in &cfg.consensus.modules {
            let kind = module_cfg.kind.clone();
            let Some(init) = module_inits.get(&kind) else {
                bail!("Detected configuration for unsupported module kind: {kind}")
            };
            info!(target: LOG_CORE,
                module_instance_id = *module_id, kind = %kind, "Init module");

            let isolated_db = db.new_isolated(*module_id);
            apply_migrations(
                &isolated_db,
                init.module_kind().to_string(),
                init.database_version(),
                init.get_database_migrations(),
            )
            .await?;

            let module = init
                .init(cfg.get_module_config(*module_id)?, isolated_db, task_group)
                .await?;
            modules.insert(*module_id, (kind, module));
        }

        // Check the configs are valid
        cfg.validate_config(&cfg.local.identity, &module_inits)?;

        // Build P2P connections for HBBFT consensus
        let (connections, peer_status_channels) = ReconnectPeerConnections::new(
            cfg.network_config(),
            delay_calculator,
            connector,
            task_group,
        )
        .await;
        let connections = connections.into_dyn();

        let net_info = NetworkInfo::new(
            cfg.local.identity,
            cfg.private.hbbft_sks.inner().clone(),
            cfg.consensus.hbbft_pk_set.clone(),
            cfg.local.p2p_endpoints.keys().copied(),
        );

        let hbbft: HoneyBadger<Vec<SerdeConsensusItem>, _> =
            HoneyBadger::builder(Arc::new(net_info)).build();

        let api_endpoints = cfg
            .consensus
            .api_endpoints
            .clone()
            .into_iter()
            .map(|(id, node)| (id, node.url));
        let api = WsFederationApi::new(api_endpoints.collect());
        let mut other_peers: BTreeSet<_> = cfg.local.p2p_endpoints.keys().cloned().collect();
        other_peers.remove(&cfg.local.identity);

        // Build API that can handle requests
        let (api_sender, api_receiver) = mpsc::channel(TRANSACTION_BUFFER_SIZE);
        let client_cfg = cfg.consensus.to_client_config(&module_inits)?;
        let modules = ModuleRegistry::from(modules);

        let latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>> = Default::default();
        let consensus_api = ConsensusApi {
            cfg: cfg.clone(),
            db: db.clone(),
            modules: modules.clone(),
            client_cfg,
            api_sender,
            supported_api_versions: ServerConfig::supported_api_versions_summary(&modules),
            latest_contribution_by_peer: Arc::clone(&latest_contribution_by_peer),
            peer_status_channels,
            // keep the status for a short time to protect the system against a denial-of-service
            // attack
            consensus_status_cache: ExpiringCache::new(Duration::from_millis(500)),
        };

        // Build consensus processor
        let consensus = FedimintConsensus {
            cfg: cfg.clone(),
            module_inits,
            modules: modules.clone(),
            db: db.clone(),
            api: consensus_api,
            api_event_cache: Default::default(),
        };

        Ok(ConsensusServer {
            task_group: task_group.clone(),
            connections,
            hbbft,
            consensus,
            api_receiver: ReceiverStream::new(api_receiver).peekable(),
            cfg: cfg.clone(),
            api: api.into(),
            other_peers,
            rejoin_at_epoch: Default::default(),
            latest_contribution_by_peer,
            pending_forced_epochs: 0,
            last_processed_epoch: None,
            decoders: modules.decoder_registry(),
        })
    }

    /// Loop `run_conensus_epoch` until shut down
    pub async fn run_consensus(mut self, task_handle: TaskHandle) -> anyhow::Result<()> {
        let our_hash = self.cfg.consensus.consensus_hash();

        // Confirm our hash matches with peers
        loop {
            info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");
            match self.api.consensus_config_hash().await {
                Ok(consensus_hash) if consensus_hash == our_hash => break,
                Ok(_) => bail!("Our consensus config doesn't match peers!"),
                Err(e) => {
                    warn!(target: LOG_CONSENSUS, "ERROR {:?}", e)
                }
            }
            sleep(Duration::from_millis(100)).await;
        }

        let mut rng = OsRng;
        self.start_consensus().await;

        while !task_handle.is_shutting_down() {
            let outcomes = if let Ok(v) = self.run_consensus_epoch(None, &mut rng).await {
                v
            } else {
                // `None` is supposed to mean the process is shutting down
                debug_assert!(task_handle.is_shutting_down());
                break;
            };

            for outcome in outcomes {
                info!(
                    target: LOG_CONSENSUS,
                    "{}",
                    crate::consensus::debug::epoch_message(&outcome)
                );
                self.process_outcome(outcome)
                    .await
                    .expect("failed to process epoch");
            }

            if self.consensus.is_at_upgrade_threshold().await {
                info!(
                    target: LOG_CONSENSUS,
                    "Received a threshold of upgrade signals, shutting down"
                );
                break;
            }
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");
        Ok(())
    }

    /// Starts consensus by skipping to the last saved epoch history  and
    /// triggering a new epoch
    pub async fn start_consensus(&mut self) {
        let db = self.consensus.db.clone();
        let mut tx = db.begin_transaction().await;

        if let Some(key) = tx.get_value(&LastEpochKey).await {
            self.last_processed_epoch = tx.get_value(&key).await;
        }

        let epoch = self.next_epoch_to_process();
        info!(
            target: LOG_CONSENSUS,
            "Starting consensus at epoch {}", epoch
        );
        self.hbbft.skip_to_epoch(epoch);
        self.rejoin_at_epoch.clear();
        self.latest_contribution_by_peer.write().await.clear();
        self.request_rejoin(1).await;
    }

    /// Returns the next epoch that we need to process, based on our saved
    /// history
    fn next_epoch_to_process(&self) -> u64 {
        self.last_processed_epoch
            .as_ref()
            .map(|e| 1 + e.outcome.epoch)
            .unwrap_or(0)
    }

    /// Requests, verifies and processes history from peers
    ///
    /// `last_outcome` - The consensus outcome (unprocessed), we're trying to
    /// process.
    pub async fn process_outcome(
        &mut self,
        last_outcome: HbbftConsensusOutcome,
    ) -> Result<(), EpochVerifyError> {
        let mut epochs: Vec<_> = vec![];
        // for checking the hashes of the epoch history
        let mut prev_epoch: Option<SignedEpochOutcome> = self.last_processed_epoch.clone();
        // we can remove tracking past epochs
        self.rejoin_at_epoch.retain(|k, _| k > &last_outcome.epoch);
        // ensure HBBFT is at the next epoch after we process this one
        self.hbbft.skip_to_epoch(last_outcome.epoch + 1);

        let next_epoch_to_process = self.next_epoch_to_process();
        for epoch_num in next_epoch_to_process..=last_outcome.epoch {
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
                            .map(|epoch| epoch.outcome.consensus_hash()),
                        None,
                        true,
                    )
                } else {
                    info!(
                        target: LOG_CONSENSUS,
                        "Downloading missing epoch {}", epoch_num
                    );
                    let epoch_pk = self.cfg.consensus.epoch_pk_set.public_key();
                    let epoch = self
                        .api
                        .fetch_epoch_history(epoch_num, epoch_pk, &self.decoders)
                        .await
                        .expect("fetches history");

                    info!(
                        target: LOG_CONSENSUS,
                        "Verifing missing epoch {}", epoch_num
                    );
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
                    info!(
                        target: LOG_CONSENSUS,
                        "Processing items from missing epoch {}", epoch
                    );
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
        override_proposal: Option<ConsensusProposal>,
        rng: &mut (impl RngCore + CryptoRng + Clone + 'static),
    ) -> anyhow::Result<Vec<HbbftConsensusOutcome>> {
        // for testing federations with one peer
        if self.cfg.local.p2p_endpoints.len() == 1 {
            if self.hbbft.next_epoch() > 0 {
                tokio::select! {
                    _ = Pin::new(&mut self.api_receiver).peek() => (),
                    () = self.consensus.await_consensus_proposal() => (),
                }
            }
            let proposal = self.process_events_then_propose(override_proposal).await;
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
                _ => break vec![],
            };
        };
        let proposal = self.process_events_then_propose(override_proposal).await;

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

    // save any API events we have in the channel then create a proposal
    async fn process_events_then_propose(
        &mut self,
        override_proposal: Option<ConsensusProposal>,
    ) -> ConsensusProposal {
        while let Some(Some(event)) = self.api_receiver.next().now_or_never() {
            match event {
                ApiEvent::ForceProcessOutcome(outcome) => self.force_process_epoch(outcome).await,
                event => {
                    self.consensus.api_event_cache.insert(event);
                }
            };
        }
        let consensus_proposal = self.consensus.get_consensus_proposal().await;
        self.consensus.api_event_cache.clear();
        override_proposal.unwrap_or(consensus_proposal)
    }

    async fn force_process_epoch(&mut self, outcome: EpochOutcome) {
        let convert = ConsensusOutcomeConversion::from(outcome).0;
        match self.process_outcome(convert).await {
            Ok(_) => {}
            Err(err) => warn!("Unable to force process epoch {:?}", err),
        }
    }

    /// Handles one step of the HBBFT algorithm, sending messages to peers and
    /// parsing any outcomes contained in the step
    async fn handle_step(&mut self, step: EpochStep) -> Cancellable<Vec<HbbftConsensusOutcome>> {
        for msg in step.messages {
            self.connections
                .send(
                    &msg.target.peers(&self.other_peers),
                    EpochMessage::Continue(msg.message),
                )
                .await?;
        }

        if !step.fault_log.is_empty() {
            warn!(target: LOG_CONSENSUS, fault_log = ?step.fault_log, "HBBFT step fault");
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
        if self.pending_forced_epochs > 0 {
            self.pending_forced_epochs = self.pending_forced_epochs.saturating_sub(1);
            return Ok(EpochTriggerEvent::RunEpochRequest);
        }

        tokio::select! {
            _peek = Pin::new(&mut self.api_receiver).peek() => Ok(EpochTriggerEvent::ApiEvent),
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
            (_, EpochMessage::RejoinRequest(epochs)) => {
                let requested_forced_epochs_capped = min(NUM_EPOCHS_REJOIN_AHEAD, epochs);
                self.pending_forced_epochs =
                    max(self.pending_forced_epochs, requested_forced_epochs_capped);
                info!(
                    target: LOG_CONSENSUS,
                    "Peer {} requested to run {} epochs. Set pending forced epochs to {}",
                    msg.0,
                    epochs,
                    self.pending_forced_epochs
                );
                Ok(vec![])
            }
        }
    }

    /// If we are rejoining and received a threshold of messages from the same
    /// epoch, then skip to that epoch.  Give ourselves a buffer of
    /// `NUM_EPOCHS_REJOIN_AHEAD` so we can ensure we receive enough HBBFT
    /// messages to produce an outcome.
    async fn rejoin_at_epoch(&mut self, epoch: u64, peer: PeerId) {
        let peers = self.rejoin_at_epoch.entry(epoch).or_default();
        peers.insert(peer);
        let contribution = ConsensusContribution {
            // this is equivalent to epoch count, so + 1 here as usual
            value: epoch + 1,
            time: fedimint_core::time::now(),
        };
        self.latest_contribution_by_peer
            .write()
            .await
            .entry(peer)
            .and_modify(|c| {
                // only update if epoch count is higher
                if contribution.value > c.value {
                    *c = contribution;
                }
            })
            .or_insert(contribution);
        let threshold = self.cfg.local.p2p_endpoints.threshold();

        if peers.len() >= threshold && self.hbbft.epoch() < epoch {
            info!(
                target: LOG_CONSENSUS,
                "Skipping to epoch {}",
                epoch + NUM_EPOCHS_REJOIN_AHEAD
            );
            self.hbbft.skip_to_epoch(epoch + NUM_EPOCHS_REJOIN_AHEAD);
            self.request_rejoin(NUM_EPOCHS_REJOIN_AHEAD).await;
        }
    }

    /// Sends a rejoin request to all peers, indicating the number of epochs we
    /// want them to create
    async fn request_rejoin(&mut self, epochs_to_run: u64) {
        self.connections
            .send(
                &Target::all().peers(&self.other_peers),
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
                    warn!(
                        target: LOG_CONSENSUS,
                        "Received invalid message from peer {}: {}", peer, e
                    );
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
