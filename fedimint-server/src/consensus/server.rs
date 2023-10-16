use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::Sender;
use bitcoin_hashes::sha256;
use fedimint_core::api::{GlobalFederationApi, WsFederationApi};
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::{apply_migrations, Database};
use fedimint_core::epoch::{ConsensusItem, SerdeSignatureShare};
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::registry::{ModuleRegistry, ServerModuleRegistry};
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::{timing, PeerId};
use tracing::{info, warn};

use crate::atomic_broadcast::{AtomicBroadcast, Keychain, Message};
use crate::config::ServerConfig;
use crate::consensus::FedimintConsensus;
use crate::db::{
    get_global_database_migrations, ClientConfigSignatureKey, GLOBAL_DATABASE_VERSION,
};
use crate::fedimint_core::encoding::Encodable;
use crate::net::api::{ConsensusApi, ExpiringCache, InvitationCodesTracker};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{DelayCalculator, PeerConnector, ReconnectPeerConnections};
use crate::{LOG_CONSENSUS, LOG_CORE};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

pub(crate) type LatestContributionByPeer = HashMap<PeerId, u64>;

/// Runs the main server consensus loop
pub struct ConsensusServer {
    /// Allows clients to access consensus state
    pub db: Database,
    pub modules: ServerModuleRegistry,
    pub consensus_api: ConsensusApi,
    /// Aleph BFT instance
    pub atomic_broadcast: AtomicBroadcast,
    /// Our configuration
    pub cfg: ServerConfig,
    /// tracks the last session a message was received by peer
    pub latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
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
                .init(
                    cfg.get_module_config(*module_id)?,
                    isolated_db,
                    task_group,
                    cfg.local.identity,
                )
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

        // Build P2P connections for the atomic broadcast
        let (connections, peer_status_channels) = ReconnectPeerConnections::new(
            cfg.network_config(),
            delay_calculator,
            connector,
            task_group,
        )
        .await;

        let atomic_broadcast = AtomicBroadcast::new(
            keychain,
            db.clone(),
            connections.clone(),
            submission_receiver,
        );

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

        submit_module_consensus_items(
            task_group,
            db.clone(),
            modules.clone(),
            cfg.clone(),
            consensus_api.client_cfg.consensus_hash(),
            submission_sender,
        )
        .await;

        Ok(ConsensusServer {
            atomic_broadcast,
            db,
            consensus_api,
            cfg: cfg.clone(),
            latest_contribution_by_peer,
            modules,
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

        // TODO: latest contribution by peer
        while !task_handle.is_shutting_down() {
            let consensus = FedimintConsensus::load_current_session(
                self.cfg.clone(),
                self.modules.clone(),
                self.db.clone(),
                self.consensus_api.client_cfg.consensus_hash(),
                self.latest_contribution_by_peer.clone(),
            );

            let federation_api = WsFederationApi::new(api_endpoints.clone());

            self.atomic_broadcast
                .run_session(consensus.await, federation_api)
                .await?;

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

async fn submit_module_consensus_items(
    task_group: &mut TaskGroup,
    db: Database,
    modules: ServerModuleRegistry,
    cfg: ServerConfig,
    client_cfg_hash: sha256::Hash,
    submission_sender: Sender<ConsensusItem>,
) {
    task_group
        .spawn(
            "submit_module_consensus_items",
            move |task_handle| async move {
                while !task_handle.is_shutting_down() {
                    let mut dbtx = db.begin_transaction().await;

                    // We ignore any writes
                    dbtx.ignore_uncommitted();

                    let mut consensus_items = Vec::new();

                    for (instance_id, _, module) in modules.iter_modules() {
                        let items = module
                            .consensus_proposal(
                                &mut dbtx.with_module_prefix(instance_id),
                                instance_id,
                            )
                            .await
                            .into_iter()
                            .map(ConsensusItem::Module);

                        consensus_items.extend(items);
                    }

                    // Add a signature share for the client config hash
                    let sig = dbtx
                        .get_isolated()
                        .get_value(&ClientConfigSignatureKey)
                        .await;

                    if sig.is_none() {
                        let timing = timing::TimeReporter::new("sign client config");
                        let share = cfg.private.auth_sks.0.sign(client_cfg_hash);
                        drop(timing);
                        let item =
                            ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(share));
                        consensus_items.push(item);
                    }

                    for item in consensus_items {
                        submission_sender.send(item).await.ok();
                    }

                    sleep(Duration::from_secs(1)).await;
                }
            },
        )
        .await;
}
