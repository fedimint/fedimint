use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender};
use fedimint_core::api::{DynGlobalApi, FederationApiExt, WsFederationApi};
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::{
    apply_migrations, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Decodable;
use fedimint_core::endpoint_constants::AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{
    ModuleDecoderRegistry, ModuleRegistry, ServerModuleRegistry,
};
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::query::FilterMap;
use fedimint_core::session_outcome::{
    AcceptedItem, SchnorrSignature, SessionOutcome, SignedSessionOutcome,
};
use fedimint_core::task::{sleep, spawn, RwLock, TaskGroup, TaskHandle};
use fedimint_core::timing::TimeReporter;
use fedimint_core::util::SafeUrl;
use fedimint_core::{timing, PeerId};
use futures::StreamExt;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::atomic_broadcast::data_provider::{DataProvider, UnitData};
use crate::atomic_broadcast::finalization_handler::FinalizationHandler;
use crate::atomic_broadcast::network::Network;
use crate::atomic_broadcast::spawner::Spawner;
use crate::atomic_broadcast::{to_node_index, Keychain, Message};
use crate::config::ServerConfig;
use crate::consensus::process_transaction_with_dbtx;
use crate::db::{
    get_global_database_migrations, AcceptedItemKey, AcceptedItemPrefix, AcceptedTransactionKey,
    AlephUnitsPrefix, SignedSessionOutcomeCountKey, SignedSessionOutcomeKey,
    GLOBAL_DATABASE_VERSION,
};
use crate::fedimint_core::encoding::Encodable;
use crate::net::api::{ConsensusApi, ExpiringCache};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{DelayCalculator, PeerConnector, ReconnectPeerConnections};
use crate::{atomic_broadcast, LOG_CONSENSUS, LOG_CORE};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

pub(crate) type LatestContributionByPeer = HashMap<PeerId, u64>;

/// Runs the main server consensus loop
pub struct ConsensusServer {
    modules: ServerModuleRegistry,
    db: Database,
    connections: ReconnectPeerConnections<Message>,
    keychain: Keychain,
    api_endpoints: Vec<(PeerId, SafeUrl)>,
    cfg: ServerConfig,
    submission_receiver: Receiver<ConsensusItem>,
    latest_contribution_by_peer: Arc<RwLock<LatestContributionByPeer>>,
}

impl ConsensusServer {
    /// Creates a server with real network and no delays
    pub async fn new(
        cfg: ServerConfig,
        db: Database,
        module_inits: ServerModuleInitRegistry,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<(Self, ConsensusApi)> {
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
    ) -> anyhow::Result<(Self, ConsensusApi)> {
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

            let isolated_db = db.with_prefix_module_id(*module_id);

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

        // Build API that can handle requests
        let latest_contribution_by_peer = Default::default();

        let consensus_api = ConsensusApi {
            cfg: cfg.clone(),
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
            submission_sender.clone(),
        )
        .await;

        let api_endpoints: Vec<_> = cfg
            .consensus
            .api_endpoints
            .clone()
            .into_iter()
            .map(|(id, node)| (id, node.url))
            .collect();

        let consensus_server = ConsensusServer {
            connections,
            db,
            keychain,
            api_endpoints,
            cfg: cfg.clone(),
            submission_receiver,
            latest_contribution_by_peer,
            modules,
        };

        Ok((consensus_server, consensus_api))
    }

    pub async fn run(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        if self.cfg.consensus.broadcast_public_keys.len() == 1 {
            self.run_single_guardian(task_handle).await
        } else {
            self.run_consensus(task_handle).await
        }
    }

    pub async fn run_single_guardian(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        assert_eq!(self.cfg.consensus.broadcast_public_keys.len(), 1);

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            let mut item_index = self.pending_accepted_items().await.len() as u64;

            let session_start_time = std::time::Instant::now();

            while let Ok(item) = self.submission_receiver.recv().await {
                if self
                    .process_consensus_item(
                        session_index,
                        item_index,
                        item,
                        self.cfg.local.identity,
                    )
                    .await
                    .is_ok()
                {
                    item_index += 1;
                }

                // we rely on the module consensus items to notice the timeout
                if session_start_time.elapsed() > Duration::from_secs(60) {
                    break;
                }
            }

            let session_outcome = SessionOutcome {
                items: self.pending_accepted_items().await,
            };

            let header = session_outcome.header(session_index);
            let signature = self.keychain.sign(&header);
            let signatures = BTreeMap::from_iter([(self.cfg.local.identity, signature)]);

            self.complete_session(
                session_index,
                SignedSessionOutcome {
                    session_outcome,
                    signatures,
                },
            )
            .await;

            info!(target: LOG_CONSENSUS, "Session {session_index} completed");

            // if the submission channel is closed we are shutting down
            if self.submission_receiver.is_closed() {
                break;
            }
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }

    pub async fn run_consensus(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        // We need four peers to run the atomic broadcast
        assert!(self.cfg.consensus.broadcast_public_keys.len() >= 4);

        self.confirm_server_config_consensus_hash().await?;

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            self.run_session(session_index).await?;

            info!(target: LOG_CONSENSUS, "Session {session_index} completed");
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }

    async fn confirm_server_config_consensus_hash(&self) -> anyhow::Result<()> {
        let our_hash = self.cfg.consensus.consensus_hash();
        let federation_api = DynGlobalApi::from_endpoints(self.api_endpoints.clone());

        info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");

        loop {
            match federation_api.server_config_consensus_hash().await {
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

    pub async fn run_session(&self, session_index: u64) -> anyhow::Result<()> {
        // FIXME: see 4182, reduce session time
        // this constant needs to be 3000 or less to guarantee that the session
        // can never reach MAX_ROUNDs.
        let expected_rounds_per_session =
            3 * self.cfg.consensus.broadcast_expected_rounds_per_session as usize;
        let exponential_slowdown_offset: usize =
            3 * 3 * self.cfg.consensus.broadcast_expected_rounds_per_session as usize;
        let max_round = 3 * self.cfg.consensus.broadcast_max_rounds_per_session;
        let round_delay = self.cfg.local.broadcast_round_delay_ms as f64;
        const BASE: f64 = 1.005;

        // this is the minimum number of unit data that will be ordered before we reach
        // the EXPONENTIAL_SLOWDOWN_OFFSET even if f peers do not attach unit data
        let batches_per_session = expected_rounds_per_session * self.keychain.peer_count();

        // In order to bound a sessions RAM consumption we need to bound its number of
        // units and therefore its number of rounds. Since we use a session to
        // create a threshold signature for the corresponding session outcome we have to
        // guarantee that an attacker cannot exhaust our memory by preventing the
        // creation of a threshold signature, thereby keeping the session open
        // indefinitely. Hence we increase the delay between rounds exponentially
        // such that MAX_ROUND would only be reached after roughly 350 years.
        // In case of such an attack the broadcast stops ordering any items until the
        // attack subsides as not items are ordered while the signatures are collected.
        let mut delay_config = aleph_bft::default_delay_config();
        delay_config.unit_creation_delay = std::sync::Arc::new(move |round_index| {
            let delay = if round_index == 0 {
                0.0
            } else {
                round_delay
                    * BASE.powf(round_index.saturating_sub(exponential_slowdown_offset) as f64)
            };

            Duration::from_millis(delay.round() as u64)
        });

        let config = aleph_bft::create_config(
            self.keychain.peer_count().into(),
            self.keychain.peer_id().to_usize().into(),
            session_index,
            max_round,
            delay_config,
            Duration::from_secs(100 * 365 * 24 * 60 * 60),
        )
        .expect("Config is valid");

        // the number of units ordered in a single aleph session is bounded
        let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
        let (signature_sender, signature_receiver) = watch::channel(None);
        let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

        let (loader, saver) = atomic_broadcast::backup::load_session(self.db.clone()).await;

        let aleph_handle = spawn(
            "aleph run session",
            aleph_bft::run_session(
                config,
                aleph_bft::LocalIO::new(
                    DataProvider::new(self.submission_receiver.clone(), signature_receiver),
                    FinalizationHandler::new(unit_data_sender),
                    saver,
                    loader,
                ),
                Network::new(self.connections.clone()),
                self.keychain.clone(),
                Spawner::new(),
                aleph_bft_types::Terminator::create_root(terminator_receiver, "Terminator"),
            ),
        )
        .expect("some handle on non-wasm");

        let signed_session_outcome = self
            .complete_signed_session_outcome(
                session_index,
                batches_per_session,
                unit_data_receiver,
                signature_sender,
            )
            .await?;

        terminator_sender.send(()).ok();
        aleph_handle.await.ok();

        // Only call this after aleph bft has shutdown to avoid write-write conflicts
        // for the aleph bft units
        self.complete_session(session_index, signed_session_outcome)
            .await;

        Ok(())
    }

    pub async fn complete_signed_session_outcome(
        &self,
        session_index: u64,
        batches_per_session_outcome: usize,
        unit_data_receiver: Receiver<(UnitData, PeerId)>,
        signature_sender: watch::Sender<Option<SchnorrSignature>>,
    ) -> anyhow::Result<SignedSessionOutcome> {
        let mut num_batches = 0;
        let mut item_index = 0;

        // we build a session outcome out of the ordered batches until either we have
        // processed batches_per_session_outcome session outcomes or a signed session
        // outcome arrives from our peers
        while num_batches < batches_per_session_outcome {
            tokio::select! {
                unit_data = unit_data_receiver.recv() => {
                    let (unit, peer) = match unit_data {
                        Ok((unit, peer)) => (unit, peer),
                        Err(err) => {
                            warn!(target: LOG_CONSENSUS, item_index, "Unit receiving error");
                            return Err(err.into());
                        }
                    };
                    debug!(target: LOG_CONSENSUS, item_index, %peer, "Received data unit");
                    if let UnitData::Batch(bytes) = unit {
                        debug!(target: LOG_CONSENSUS, item_index, %peer, len = bytes.len(), "Received batch of bytes");
                        let decode_res = Vec::<ConsensusItem>::consensus_decode(&mut bytes.as_slice(), &self.decoders())
                            .map_err(|err| { warn!(target: LOG_CONSENSUS, %err, %peer, "Failed to decode a batch"); err }) ;
                        if let Ok(items) = decode_res  {
                            for item in items {
                                let process_res = self.process_consensus_item(
                                    session_index,
                                    item_index,
                                    item.clone(),
                                    peer
                                ).await.map_err(|err| {
                                    warn!(target: LOG_CONSENSUS, %err, item_index, %peer, "Failed to process consensus item from a batch");
                                    err
                                });
                                if process_res.is_ok() {
                                    debug!(target: LOG_CONSENSUS, item_index, %peer, "Processed an item from a batch");
                                    item_index += 1;
                                }
                            }
                        }
                        num_batches += 1;
                    }
                },
                signed_session_outcome = self.request_signed_session_outcome(session_index) => {
                    let pending_accepted_items = self.pending_accepted_items().await;

                    let (processed, unprocessed) = signed_session_outcome.session_outcome.items.split_at(pending_accepted_items.len());

                    assert!(processed.iter().eq(pending_accepted_items.iter()));

                    for accepted_item in unprocessed {
                        let result = self.process_consensus_item(
                            session_index,
                            item_index,
                            accepted_item.item.clone(),
                            accepted_item.peer
                        ).await;

                        assert!(result.is_ok());

                        item_index += 1;
                    }

                    return Ok(signed_session_outcome);
                }
            }
        }

        let session_outcome = SessionOutcome {
            items: self.pending_accepted_items().await,
        };

        let header = session_outcome.header(session_index);

        // we send our own signature to the data provider to be broadcasted
        signature_sender.send(Some(self.keychain.sign(&header)))?;

        let mut signatures = BTreeMap::new();

        // we collect the ordered signatures until we either obtain a threshold
        // signature or a signed session outcome arrives from our peers
        while signatures.len() < self.keychain.threshold() {
            tokio::select! {
                unit_data = unit_data_receiver.recv() => {
                    if let (UnitData::Signature(signature), peer) = unit_data? {
                        if self.keychain.verify(&header, &signature, to_node_index(peer)){
                            // since the signature is valid the node index can be converted to a peer id
                            signatures.insert(peer, signature);
                        } else {
                            warn!(target: LOG_CONSENSUS, "Received invalid signature from peer {peer}");
                        }
                    }
                }
                signed_session_outcome = self.request_signed_session_outcome(session_index) => {
                    // We check that the session outcome we have created agrees with the federations consensus
                    assert!(header == signed_session_outcome.session_outcome.header(session_index));

                    return Ok(signed_session_outcome);
                }
            }
        }

        Ok(SignedSessionOutcome {
            session_outcome,
            signatures,
        })
    }

    fn decoders(&self) -> ModuleDecoderRegistry {
        self.modules.decoder_registry()
    }

    pub async fn pending_accepted_items(&self) -> Vec<AcceptedItem> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&AcceptedItemPrefix)
            .await
            .map(|entry| entry.1)
            .collect()
            .await
    }

    pub async fn complete_session(
        &self,
        session_index: u64,
        signed_session_outcome: SignedSessionOutcome,
    ) {
        let mut dbtx = self.db.begin_transaction().await;

        dbtx.remove_by_prefix(&AlephUnitsPrefix).await;

        dbtx.remove_by_prefix(&AcceptedItemPrefix).await;

        if dbtx
            .insert_entry(
                &SignedSessionOutcomeKey(session_index),
                &signed_session_outcome,
            )
            .await
            .is_some()
        {
            panic!("We tried to overwrite a signed session outcome");
        }

        // Update cached session count
        let previous_session_count = self.get_finished_session_count().await;
        assert_eq!(
            previous_session_count, session_index,
            "Session count and session index diverged"
        );
        dbtx.insert_entry(&SignedSessionOutcomeCountKey, &(previous_session_count + 1))
            .await;

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");
    }

    pub async fn process_consensus_item(
        &self,
        session_index: u64,
        item_index: u64,
        item: ConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_item");

        debug!("Peer {peer}: {}", super::debug::item_message(&item));

        self.latest_contribution_by_peer
            .write()
            .await
            .insert(peer, session_index);

        let mut dbtx = self.db.begin_transaction().await;

        // we disable the warning for uncommitted writes in the database transaction
        // since we may return early because of a mid session crash or a rejected item
        dbtx.ignore_uncommitted();

        if let Some(accepted_item) = dbtx
            .get_value(&AcceptedItemKey(item_index.to_owned()))
            .await
        {
            // this branch is only taken if we crashed mid session
            if accepted_item.item == item && accepted_item.peer == peer {
                return Ok(());
            }

            bail!("Item was discarded before we recovered");
        }

        self.process_consensus_item_with_db_transaction(&mut dbtx.to_ref_nc(), item.clone(), peer)
            .await?;

        // after this point the we have to commit the database transaction
        dbtx.warn_uncommitted();

        dbtx.insert_entry(&AcceptedItemKey(item_index), &AcceptedItem { item, peer })
            .await;

        let mut audit = Audit::default();

        for (module_instance_id, _, module) in self.modules.iter_modules() {
            let _module_audit_timing =
                TimeReporter::new(format!("audit module {module_instance_id}"));
            module
                .audit(
                    &mut dbtx
                        .to_ref_with_prefix_module_id(module_instance_id)
                        .into_nc(),
                    &mut audit,
                    module_instance_id,
                )
                .await
        }

        if audit.net_assets().milli_sat < 0 {
            panic!("Balance sheet of the fed has gone negative, this should never happen! {audit}")
        }

        dbtx.commit_tx_result()
            .await
            .expect("Committing consensus epoch failed");

        Ok(())
    }

    async fn process_consensus_item_with_db_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        consensus_item: ConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // We rely on decoding rejecting any unknown module instance ids to avoid
        // peer-triggered panic here
        self.decoders().assert_reject_mode();

        match consensus_item {
            ConsensusItem::Module(module_item) => {
                let instance_id = module_item.module_instance_id();
                let module_dbtx = &mut dbtx.to_ref_with_prefix_module_id(instance_id);

                self.modules
                    .get_expect(instance_id)
                    .process_consensus_item(module_dbtx, module_item, peer_id)
                    .await
            }
            ConsensusItem::Transaction(transaction) => {
                if dbtx
                    .get_value(&AcceptedTransactionKey(transaction.tx_hash()))
                    .await
                    .is_some()
                {
                    bail!("Transaction is already accepted");
                }

                let txid = transaction.tx_hash();
                let modules_ids = transaction
                    .outputs
                    .iter()
                    .map(|output| output.module_instance_id())
                    .collect::<Vec<_>>();

                process_transaction_with_dbtx(self.modules.clone(), dbtx, transaction)
                    .await
                    .map_err(|error| anyhow!(error.to_string()))?;

                dbtx.insert_entry(&AcceptedTransactionKey(txid), &modules_ids)
                    .await;

                Ok(())
            }
            ConsensusItem::Default { variant, .. } => {
                warn!(
                    target: LOG_CONSENSUS,
                    "Minor consensus version mismatch: unexpected consensus item type: {variant}"
                );
                bail!("Unexpected consensus item type: {variant}")
            }
        }
    }

    async fn request_signed_session_outcome(&self, index: u64) -> SignedSessionOutcome {
        let keychain = self.keychain.clone();
        let total_peers = self.keychain.peer_count();
        let decoders = self.decoders();

        let filter_map = move |response: SerdeModuleEncoding<SignedSessionOutcome>| match response
            .try_into_inner(&decoders)
        {
            Ok(signed_session_outcome) => {
                match signed_session_outcome.signatures.len() == keychain.threshold()
                    && signed_session_outcome
                        .signatures
                        .iter()
                        .all(|(peer_id, sig)| {
                            keychain.verify(
                                &signed_session_outcome.session_outcome.header(index),
                                sig,
                                to_node_index(*peer_id),
                            )
                        }) {
                    true => Ok(signed_session_outcome),
                    false => Err(anyhow!("Invalid signatures")),
                }
            }
            Err(error) => Err(anyhow!(error.to_string())),
        };

        let federation_api = WsFederationApi::new(self.api_endpoints.clone());

        loop {
            // we wait until we have stalled
            info!(target: LOG_CONSENSUS, "### SLEEP START");
            sleep(Duration::from_secs(5)).await;
            info!(target: LOG_CONSENSUS, "### SLEEP END");

            let result = federation_api
                .request_with_strategy(
                    FilterMap::new(filter_map.clone(), total_peers),
                    AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT.to_string(),
                    ApiRequestErased::new(index),
                )
                .await;

            match result {
                Ok(signed_session_outcome) => return signed_session_outcome,
                Err(error) => {
                    tracing::error!("Error while requesting signed session outcome: {}", error)
                }
            }
        }
    }

    /// Returns the number of sessions already saved in the database. This count
    /// **does not** include the currently running session.
    async fn get_finished_session_count(&self) -> u64 {
        get_finished_session_count_static(&mut self.db.begin_transaction_nc().await).await
    }
}

pub(crate) async fn get_finished_session_count_static(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.get_value(&SignedSessionOutcomeCountKey)
        .await
        .unwrap_or(0)
}

async fn submit_module_consensus_items(
    task_group: &mut TaskGroup,
    db: Database,
    modules: ServerModuleRegistry,
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

                    for (instance_id, _, module) in modules.iter_modules() {
                        let module_consensus_items = module
                            .consensus_proposal(
                                &mut dbtx.to_ref_with_prefix_module_id(instance_id).into_nc(),
                                instance_id,
                            )
                            .await;

                        for item in module_consensus_items {
                            submission_sender
                                .send(ConsensusItem::Module(item))
                                .await
                                .ok();
                        }
                    }

                    sleep(Duration::from_secs(1)).await;
                }
            },
        )
        .await;
}
