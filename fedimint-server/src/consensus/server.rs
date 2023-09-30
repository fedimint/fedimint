use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::{Receiver, Sender};
use fedimint_core::api::{DynGlobalApi, GlobalFederationApi, WsFederationApi};
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::{apply_migrations, Database};
use fedimint_core::encoding::Decodable;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::net::peers::PeerConnections;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::PeerId;
use futures::StreamExt;
use tokio::select;
use tracing::{debug, error, info, warn};

use crate::atomic_broadcast::{AtomicBroadcast, Decision, Keychain, Message, Recipient};
use crate::config::ServerConfig;
use crate::consensus::FedimintConsensus;
use crate::db::{
    get_global_database_migrations, AcceptedIndex, AcceptedIndexPrefix, SessionIndexKey,
    GLOBAL_DATABASE_VERSION,
};
use crate::fedimint_core::encoding::Encodable;
use crate::fedimint_core::net::peers::IPeerConnections;
use crate::net::api::{ConsensusApi, ExpiringCache, InvitationCodesTracker};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{DelayCalculator, PeerConnector, ReconnectPeerConnections};
use crate::{LOG_CONSENSUS, LOG_CORE};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

pub(crate) type LatestContributionByPeer = HashMap<PeerId, u64>;

/// Runs the main server consensus loop
pub struct ConsensusServer {
    /// `TaskGroup` that is running the server
    pub task_group: TaskGroup,
    /// Delegate for processing consensus information
    pub consensus: FedimintConsensus,
    pub consensus_api: ConsensusApi,
    /// Aleph BFT instance
    pub atomic_broadcast: AtomicBroadcast,
    /// Our configuration
    pub cfg: ServerConfig,
    /// Used to make API calls to our peers
    pub api: DynGlobalApi,
    /// The list of all other peers
    pub other_peers: Vec<PeerId>,
    /// Under the HBBFT consensus algorithm, this will track the latest epoch
    /// message received by each peer and when it was received
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
    /// Used for decoding module specific-values
    pub decoders: ModuleDecoderRegistry,
}

impl ConsensusServer {
    /// Creates a server with real network and no delays
    pub async fn new(
        cfg: ServerConfig,
        db: Database,
        module_inits: ServerModuleInitRegistry,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Self> {
        let connector: PeerConnector<Vec<u8>> =
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
        module_inits: ServerModuleInitRegistry,
        connector: PeerConnector<Vec<u8>>,
        delay_calculator: DelayCalculator,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Self> {
        assert!(cfg.consensus.api_endpoints.len() >= 4);

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
                bail!("Detected configuration for unsupported module id: {module_id}, kind: {kind}")
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

        let keychain = Keychain::new(
            cfg.local.identity,
            cfg.consensus.broadcast_public_keys.clone(),
            cfg.private.broadcast_secret_key,
        );

        let (submission_sender, submission_receiver) = async_channel::bounded(TRANSACTION_BUFFER);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(256);
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(256);

        let atomic_broadcast = AtomicBroadcast::new(
            keychain,
            db.clone(),
            submission_receiver,
            incoming_receiver,
            outgoing_sender,
        );

        let api_endpoints = cfg
            .consensus
            .api_endpoints
            .clone()
            .into_iter()
            .map(|(id, node)| (id, node.url));

        let api = WsFederationApi::new(api_endpoints.collect());

        let other_peers: Vec<PeerId> = cfg
            .local
            .p2p_endpoints
            .keys()
            .cloned()
            .filter(|peer| *peer != cfg.local.identity)
            .collect();

        // Build API that can handle requests
        let client_cfg = cfg.consensus.to_client_config(&module_inits)?;
        let modules = ModuleRegistry::from(modules);
        let latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>> = Default::default();
        let supported_api_versions =
            ServerConfig::supported_api_versions_summary(&cfg.consensus.modules, &module_inits);

        let consensus_api = ConsensusApi {
            cfg: cfg.clone(),
            invitation_codes_tracker: InvitationCodesTracker::new(db.clone(), task_group).await,
            db: db.clone(),
            modules: modules.clone(),
            client_cfg,
            submission_sender: submission_sender.clone(),
            supported_api_versions,
            latest_contribution_by_peer: Arc::clone(&latest_contribution_by_peer),
            peer_status_channels,
            // keep the status for a short time to protect the system against a denial-of-service
            // attack
            consensus_status_cache: ExpiringCache::new(Duration::from_millis(500)),
        };

        // Build consensus processor
        let consensus = FedimintConsensus {
            cfg: cfg.clone(),
            modules: modules.clone(),
            db: db.clone(),
            client_cfg_hash: consensus_api.client_cfg.consensus_hash(),
        };

        relay_messages(
            task_group,
            connections,
            outgoing_receiver,
            incoming_sender,
            other_peers.clone(),
            modules.decoder_registry().clone(),
        )
        .await;

        submit_module_consensus_items(task_group, consensus.clone(), submission_sender).await;

        Ok(ConsensusServer {
            task_group: task_group.clone(),
            atomic_broadcast,
            consensus,
            consensus_api,
            cfg: cfg.clone(),
            api: api.into(),
            other_peers,
            latest_contribution_by_peer,
            decoders: modules.decoder_registry(),
        })
    }

    async fn confirm_consensus_config_hash(&self) -> anyhow::Result<()> {
        let our_hash = self.cfg.consensus.consensus_hash();

        info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");

        loop {
            match self.api.consensus_config_hash().await {
                Ok(consensus_hash) => {
                    if consensus_hash != our_hash {
                        bail!("Our consensus config doesn't match peers!")
                    }

                    info!(target: LOG_CONSENSUS, "Confirmed peers config {our_hash}");

                    return Ok(());
                }
                Err(e) => {
                    warn!(target: LOG_CONSENSUS, "Could not check consensus config hash: {}", OptStacktrace(e))
                }
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn process_consensus_item(&self, item: Vec<u8>, index: u64, peer_id: PeerId) -> Decision {
        match self
            .consensus
            .process_consensus_item(item, index, peer_id)
            .await
        {
            Ok(()) => {
                debug!(
                    target: LOG_CONSENSUS,
                    "Accept consensus item from {peer_id}"
                );

                Decision::Accept
            }
            Err(error) => {
                debug!(
                    target: LOG_CONSENSUS,
                    "Discard consensus item from {peer_id}: {error}"
                );

                Decision::Discard
            }
        }
    }

    pub async fn run_consensus(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        self.confirm_consensus_config_hash().await?;

        while !task_handle.is_shutting_down() {
            let (session_index, accepted_indices) = self.consensus.open_session().await;
            let max_index = accepted_indices.iter().max();

            let mut ordered_item_receiver = self.atomic_broadcast.run_session(session_index).await;

            while !task_handle.is_shutting_down() {
                let ordered_item = ordered_item_receiver
                    .recv()
                    .await
                    .expect("Session was interrupted unexpectedly");

                match ordered_item {
                    Some((item, decision_sender)) => {
                        self.latest_contribution_by_peer
                            .write()
                            .await
                            .insert(item.peer_id, session_index);

                        // we process all items of higher index than last accepted item, which is
                        // the last item that changed our state - notice how
                        // we may call process_item on a ordered item
                        // a second time after a crash but only if it is discarded both times and
                        // therefore does not change our state
                        match max_index {
                            Some(max_index) if max_index >= &AcceptedIndex(item.index) => {
                                if accepted_indices.contains(&AcceptedIndex(item.index)) {
                                    decision_sender
                                        .send(Decision::Accept)
                                        .expect("This is the only sender");
                                } else {
                                    decision_sender
                                        .send(Decision::Discard)
                                        .expect("This is the only sender");
                                }
                            }
                            _ => {
                                let decision = self
                                    .process_consensus_item(item.item, item.index, item.peer_id)
                                    .await;

                                decision_sender
                                    .send(decision)
                                    .expect("This is the only sender");
                            }
                        }
                    }
                    None => break,
                };
            }

            self.consensus.complete_session().await;

            info!(target: LOG_CONSENSUS, "Session completed");
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }
}

async fn relay_messages(
    task_group: &mut TaskGroup,
    mut connections: PeerConnections<Vec<u8>>,
    outgoing_receiver: Receiver<(Message, Recipient)>,
    incoming_sender: Sender<(Message, PeerId)>,
    other_peers: Vec<PeerId>,
    decoders: ModuleDecoderRegistry,
) {
    task_group
        .spawn("relay_messages", |task_handle| async move {
            while !task_handle.is_shutting_down() {
                select! {
                        message = outgoing_receiver.recv() => {
                            match message{
                                Ok((message, recipient))=> {
                                    let message = message.consensus_encode_to_vec().expect("Infallible");
                                    match recipient {
                                        Recipient::Everyone => {
                                            connections.send(
                                                other_peers.as_slice(),
                                                message
                                            ).await.ok();
                                        }
                                        Recipient::Peer(peer_id) => {
                                            connections.send(&[peer_id], message).await.ok();
                                        }
                                    }
                                },
                                Err(..) => break
                            }

                        }
                        message = connections.receive() => {
                            match message {
                                Ok((peer_id, message)) => {
                                    let mut reader = std::io::Cursor::new(message);
                                    match Message::consensus_decode(&mut reader, &decoders){
                                        Ok(message) => {
                                            incoming_sender.send((message, peer_id)).await.ok();
                                        }
                                        Err(e) => {
                                            warn!(target: LOG_CONSENSUS, "Failed to decode message from peer {}: {}", peer_id, e);
                                        }
                                    }
                                }
                                Err(..) => break
                            }

                        }
                    }
            }
        }).await;
}

async fn submit_module_consensus_items(
    task_group: &mut TaskGroup,
    consensus: FedimintConsensus,
    submission_sender: Sender<Vec<u8>>,
) {
    task_group
        .spawn("submit_module_consensus_items", |task_handle| async move {
            while !task_handle.is_shutting_down() {
                for item in consensus.get_consensus_proposal().await {
                    if submission_sender
                        .send(item.consensus_encode_to_vec().expect("Infallible"))
                        .await
                        .is_err()
                    {
                        break;
                    };
                }

                sleep(Duration::from_secs(1)).await;
            }
        })
        .await;
}
