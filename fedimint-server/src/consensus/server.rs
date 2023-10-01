use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::{Receiver, Sender};
use bitcoin_hashes::sha256;
use fedimint_core::api::{GlobalFederationApi, WsFederationApi};
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::{apply_migrations, Database};
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::net::peers::PeerConnections;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::PeerId;
use tokio::select;
use tracing::{debug, info, warn};

use crate::atomic_broadcast::{AtomicBroadcast, Decision, Keychain, Message, Recipient};
use crate::config::ServerConfig;
use crate::consensus::FedimintConsensus;
use crate::db::{get_global_database_migrations, AcceptedIndex, GLOBAL_DATABASE_VERSION};
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
    /// Delegate for processing consensus information
    pub consensus: FedimintConsensus,
    /// Allows clients to access consensus state
    pub consensus_api: ConsensusApi,
    /// Aleph BFT instance
    pub atomic_broadcast: AtomicBroadcast,
    /// Our configuration
    pub cfg: ServerConfig,
    /// tracks the last session a message was received by peer
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
        let connector: PeerConnector<Message> =
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
        connector: PeerConnector<Message>,
        delay_calculator: DelayCalculator,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Self> {
        // We need four peers to run the atomic broadcast
        assert!(cfg.consensus.api_endpoints.len() >= 4);

        // Check the configs are valid
        cfg.validate_config(&cfg.local.identity, &module_inits)?;

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

        let modules = ModuleRegistry::from(modules);

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

        // Build P2P connections for the atomic broadcast
        let (connections, peer_status_channels) = ReconnectPeerConnections::new(
            cfg.network_config(),
            delay_calculator,
            connector,
            task_group,
        )
        .await;

        let connections = connections.into_dyn();

        let other_peers: Vec<PeerId> = cfg
            .local
            .p2p_endpoints
            .keys()
            .cloned()
            .filter(|peer| *peer != cfg.local.identity)
            .collect();

        relay_messages(
            task_group,
            connections,
            outgoing_receiver,
            incoming_sender,
            other_peers,
        )
        .await;

        // Build API that can handle requests
        let latest_contribution_by_peer = Default::default();

        let consensus_api = ConsensusApi {
            cfg: cfg.clone(),
            invitation_codes_tracker: InvitationCodesTracker::new(db.clone(), task_group).await,
            db: db.clone(),
            modules: modules.clone(),
            client_cfg: cfg.consensus.to_client_config(&module_inits)?,
            submission_sender: submission_sender.clone(),
            supported_api_versions: ServerConfig::supported_api_versions_summary(
                &cfg.consensus.modules,
                &module_inits,
            ),
            latest_contribution_by_peer: Arc::clone(&latest_contribution_by_peer),
            peer_status_channels,
            consensus_status_cache: ExpiringCache::new(Duration::from_millis(500)),
        };

        // Build consensus processor
        let consensus = FedimintConsensus {
            cfg: cfg.clone(),
            modules: modules.clone(),
            db: db.clone(),
            client_cfg_hash: consensus_api.client_cfg.consensus_hash(),
        };

        submit_module_consensus_items(task_group, consensus.clone(), submission_sender).await;

        Ok(ConsensusServer {
            atomic_broadcast,
            consensus,
            consensus_api,
            cfg: cfg.clone(),
            latest_contribution_by_peer,
            decoders: modules.decoder_registry(),
        })
    }

    pub async fn run_consensus(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        let api_endpoints: Vec<_> = self
            .cfg
            .consensus
            .api_endpoints
            .clone()
            .into_iter()
            .map(|(id, node)| (id, node.url))
            .collect();

        let federation_api = WsFederationApi::new(api_endpoints.clone());

        confirm_consensus_config_hash(&federation_api, self.cfg.consensus.consensus_hash()).await?;

        while !task_handle.is_shutting_down() {
            let (session_index, accepted_indices) = self.consensus.open_session().await;
            let max_index = accepted_indices.iter().max();

            let federation_api = WsFederationApi::new(api_endpoints.clone());

            let mut ordered_item_receiver = self
                .atomic_broadcast
                .run_session(session_index, federation_api)
                .await;

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
                                match self
                                    .consensus
                                    .process_consensus_item(item.item, item.index, item.peer_id)
                                    .await
                                {
                                    Ok(()) => {
                                        decision_sender
                                            .send(Decision::Accept)
                                            .expect("This is the only sender");
                                    }
                                    Err(error) => {
                                        debug!(
                                            target: LOG_CONSENSUS,
                                            "Discard consensus item: {error}"
                                        );

                                        decision_sender
                                            .send(Decision::Discard)
                                            .expect("This is the only sender");
                                    }
                                }
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

async fn confirm_consensus_config_hash(
    api: &WsFederationApi,
    our_hash: sha256::Hash,
) -> anyhow::Result<()> {
    info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");

    loop {
        match api.consensus_config_hash().await {
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

async fn relay_messages(
    task_group: &mut TaskGroup,
    mut connections: PeerConnections<Message>,
    outgoing_receiver: Receiver<(Message, Recipient)>,
    incoming_sender: Sender<Message>,
    other_peers: Vec<PeerId>,
) {
    task_group
        .spawn("relay_messages", |task_handle| async move {
            while !task_handle.is_shutting_down() {
                select! {
                    message = outgoing_receiver.recv() => {
                        match message{
                            Ok((message, recipient))=> {
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
                            Ok((.., message)) => {
                                incoming_sender.send(message).await.ok();
                            }
                            Err(..) => break
                        }

                    }
                }
            }
        })
        .await;
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
