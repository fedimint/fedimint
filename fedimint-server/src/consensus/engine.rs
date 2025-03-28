use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aleph_bft::Keychain as KeychainTrait;
use anyhow::{anyhow, bail};
use async_channel::Receiver;
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt, PeerError};
use fedimint_api_client::query::FilterMap;
use fedimint_core::config::P2PMessage;
use fedimint_core::core::{DynOutput, MODULE_INSTANCE_ID_GLOBAL};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Decodable;
use fedimint_core::endpoint_constants::AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::runtime::spawn;
use fedimint_core::session_outcome::{
    AcceptedItem, SchnorrSignature, SessionOutcome, SignedSessionOutcome,
};
use fedimint_core::task::{TaskGroup, TaskHandle, sleep};
use fedimint_core::timing::TimeReporter;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{NumPeers, NumPeersExt, PeerId, timing};
use fedimint_server_core::{ServerModuleRegistry, ServerModuleRegistryExt};
use futures::StreamExt;
use rand::Rng;
use tokio::sync::watch;
use tracing::{Level, debug, info, instrument, trace, warn};

use crate::LOG_CONSENSUS;
use crate::config::ServerConfig;
use crate::consensus::aleph_bft::backup::{BackupReader, BackupWriter};
use crate::consensus::aleph_bft::data_provider::{DataProvider, UnitData};
use crate::consensus::aleph_bft::finalization_handler::{FinalizationHandler, OrderedUnit};
use crate::consensus::aleph_bft::keychain::Keychain;
use crate::consensus::aleph_bft::network::Network;
use crate::consensus::aleph_bft::spawner::Spawner;
use crate::consensus::aleph_bft::to_node_index;
use crate::consensus::db::{
    AcceptedItemKey, AcceptedItemPrefix, AcceptedTransactionKey, AlephUnitsPrefix,
    SignedSessionOutcomeKey, SignedSessionOutcomePrefix,
};
use crate::consensus::debug::{DebugConsensusItem, DebugConsensusItemCompact};
use crate::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use crate::metrics::{
    CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS,
    CONSENSUS_ITEM_PROCESSING_MODULE_AUDIT_DURATION_SECONDS, CONSENSUS_ITEMS_PROCESSED_TOTAL,
    CONSENSUS_ORDERING_LATENCY_SECONDS, CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX,
    CONSENSUS_SESSION_COUNT,
};

// The name of the directory where the database checkpoints are stored.
const DB_CHECKPOINTS_DIR: &str = "db_checkpoints";

/// Runs the main server consensus loop
pub struct ConsensusEngine {
    pub modules: ServerModuleRegistry,
    pub db: Database,
    pub federation_api: DynGlobalApi,
    pub cfg: ServerConfig,
    pub submission_receiver: Receiver<ConsensusItem>,
    pub shutdown_receiver: watch::Receiver<Option<u64>>,
    pub connections: DynP2PConnections<P2PMessage>,
    pub ci_status_senders: BTreeMap<PeerId, watch::Sender<Option<u64>>>,
    pub ord_latency_sender: watch::Sender<Option<Duration>>,
    pub task_group: TaskGroup,
    pub data_dir: PathBuf,
    pub checkpoint_retention: u64,
}

impl ConsensusEngine {
    fn num_peers(&self) -> NumPeers {
        self.cfg.consensus.broadcast_public_keys.to_num_peers()
    }

    fn identity(&self) -> PeerId {
        self.cfg.local.identity
    }

    #[instrument(target = LOG_CONSENSUS, name = "run", skip_all, fields(id=%self.cfg.local.identity))]
    pub async fn run(self) -> anyhow::Result<()> {
        if self.num_peers().total() == 1 {
            self.run_single_guardian(self.task_group.make_handle())
                .await
        } else {
            self.run_consensus(self.task_group.make_handle()).await
        }
    }

    pub async fn run_single_guardian(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        assert_eq!(self.num_peers(), NumPeers::from(1));

        self.initialize_checkpoint_directory(self.get_finished_session_count().await)?;

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            CONSENSUS_SESSION_COUNT.set(session_index as i64);

            let mut item_index = self.pending_accepted_items().await.len() as u64;

            let session_start_time = std::time::Instant::now();

            while let Ok(item) = self.submission_receiver.recv().await {
                if self
                    .process_consensus_item(session_index, item_index, item, self.identity())
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
            let signature = Keychain::new(&self.cfg).sign(&header);
            let signatures = BTreeMap::from_iter([(self.identity(), signature)]);

            self.complete_session(
                session_index,
                SignedSessionOutcome {
                    session_outcome,
                    signatures,
                },
            )
            .await;

            self.checkpoint_database(session_index);

            info!(target: LOG_CONSENSUS, "Session {session_index} completed");

            if Some(session_index) == self.shutdown_receiver.borrow().to_owned() {
                break;
            }
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }

    pub async fn run_consensus(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        // We need four peers to run the atomic broadcast
        assert!(self.num_peers().total() >= 4);

        self.initialize_checkpoint_directory(self.get_finished_session_count().await)?;

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            CONSENSUS_SESSION_COUNT.set(session_index as i64);

            info!(target: LOG_CONSENSUS, session_index, "Starting consensus session");

            self.run_session(self.connections.clone(), session_index)
                .await?;

            info!(target: LOG_CONSENSUS, session_index, "Completed consensus session");

            if Some(session_index) == self.shutdown_receiver.borrow().to_owned() {
                info!(target: LOG_CONSENSUS, "Initiating shutdown, waiting for peers to complete the session...");

                sleep(Duration::from_secs(60)).await;

                break;
            }
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }

    pub async fn run_session(
        &self,
        connections: DynP2PConnections<P2PMessage>,
        session_index: u64,
    ) -> anyhow::Result<()> {
        // In order to bound a sessions RAM consumption we need to bound its number of
        // units and therefore its number of rounds. Since we use a session to
        // create a naive secp256k1 threshold signature for the header of session
        // outcome we have to guarantee that an attacker cannot exhaust our
        // memory by preventing the creation of a threshold signature, thereby
        // keeping the session open indefinitely. Hence, after a certain round
        // index, we increase the delay between rounds exponentially such that
        // the end of the aleph bft session would only be reached after a minimum
        // of 10 years. In case of such an attack the broadcast stops ordering any
        // items until the attack subsides as no items are ordered while the
        // signatures are collected. The maximum RAM consumption of the aleph bft
        // broadcast instance is therefore bound by:
        //
        // self.keychain.peer_count()
        //      * (broadcast_rounds_per_session + EXP_SLOWDOWN_ROUNDS)
        //      * ALEPH_BFT_UNIT_BYTE_LIMIT

        const EXP_SLOWDOWN_ROUNDS: u16 = 1000;
        const BASE: f64 = 1.02;

        let rounds_per_session = self.cfg.consensus.broadcast_rounds_per_session;
        let round_delay = f64::from(self.cfg.local.broadcast_round_delay_ms);

        let mut delay_config = aleph_bft::default_delay_config();

        delay_config.unit_creation_delay = Arc::new(move |round_index| {
            let delay = if round_index == 0 {
                0.0
            } else {
                round_delay
                    * BASE.powf(round_index.saturating_sub(rounds_per_session as usize) as f64)
                    * rand::thread_rng().gen_range(0.5..=1.5)
            };

            Duration::from_millis(delay.round() as u64)
        });

        let config = aleph_bft::create_config(
            self.num_peers().total().into(),
            self.identity().to_usize().into(),
            session_index,
            self.cfg
                .consensus
                .broadcast_rounds_per_session
                .checked_add(EXP_SLOWDOWN_ROUNDS)
                .expect("Rounds per session exceed maximum of u16::Max - EXP_SLOWDOWN_ROUNDS"),
            delay_config,
            Duration::from_secs(10 * 365 * 24 * 60 * 60),
        )
        .expect("The exponential slowdown exceeds 10 years");

        // we can use an unbounded channel here since the number and size of units
        // ordered in a single aleph session is bounded as described above
        let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
        let (signature_sender, signature_receiver) = watch::channel(None);
        let (timestamp_sender, timestamp_receiver) = async_channel::unbounded();
        let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

        let aleph_handle = spawn(
            "aleph run session",
            aleph_bft::run_session(
                config,
                aleph_bft::LocalIO::new(
                    DataProvider::new(
                        self.submission_receiver.clone(),
                        signature_receiver,
                        timestamp_sender,
                        self.is_recovery().await,
                    ),
                    FinalizationHandler::new(unit_data_sender),
                    BackupWriter::new(self.db.clone()).await,
                    BackupReader::new(self.db.clone()),
                ),
                Network::new(connections),
                Keychain::new(&self.cfg),
                Spawner::new(self.task_group.make_subgroup()),
                aleph_bft::Terminator::create_root(terminator_receiver, "Terminator"),
            ),
        );

        self.ord_latency_sender.send_replace(None);

        let signed_session_outcome = self
            .complete_signed_session_outcome(
                session_index,
                unit_data_receiver,
                signature_sender,
                timestamp_receiver,
            )
            .await?;

        // We can terminate the session instead of waiting for other peers to complete
        // it since they can always download the signed session outcome from us
        terminator_sender.send(()).ok();
        aleph_handle.await.ok();

        // This method removes the backup of the current session from the database
        // and therefore has to be called after we have waited for the session to
        // shut down, or we risk write-write conflicts with the UnitSaver
        self.complete_session(session_index, signed_session_outcome)
            .await;

        self.checkpoint_database(session_index);

        Ok(())
    }

    async fn is_recovery(&self) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&AlephUnitsPrefix)
            .await
            .next()
            .await
            .is_some()
    }

    pub async fn complete_signed_session_outcome(
        &self,
        session_index: u64,
        ordered_unit_receiver: Receiver<OrderedUnit>,
        signature_sender: watch::Sender<Option<SchnorrSignature>>,
        timestamp_receiver: Receiver<Instant>,
    ) -> anyhow::Result<SignedSessionOutcome> {
        // It is guaranteed that aleph bft will always replay all previously processed
        // items from the current session from index zero
        let mut item_index = 0;

        let mut request_signed_session_outcome = Box::pin(async {
            self.request_signed_session_outcome(&self.federation_api, session_index)
                .await
        });

        // We build a session outcome out of the ordered batches until either we have
        // processed broadcast_rounds_per_session rounds or a threshold signed
        // session outcome is obtained from our peers
        loop {
            tokio::select! {
                ordered_unit = ordered_unit_receiver.recv() => {
                    let ordered_unit = ordered_unit?;

                    if ordered_unit.round >= self.cfg.consensus.broadcast_rounds_per_session {
                        break;
                    }

                    if let Some(UnitData::Batch(bytes)) = ordered_unit.data {
                        if ordered_unit.creator == self.identity() {
                            match timestamp_receiver.try_recv() {
                                Ok(timestamp) => {
                                    let latency = match *self.ord_latency_sender.borrow() {
                                        Some(latency) => (9 * latency +  timestamp.elapsed()) / 10,
                                        None => timestamp.elapsed()
                                    };

                                    self.ord_latency_sender.send_replace(Some(latency));

                                    CONSENSUS_ORDERING_LATENCY_SECONDS.observe(timestamp.elapsed().as_secs_f64());
                                }
                                Err(err) => {
                                    debug!(target: LOG_CONSENSUS, err = %err.fmt_compact(), "Missing submission timestamp. This is normal in recovery");
                                }
                            }
                        }

                        if let Ok(items) = Vec::<ConsensusItem>::consensus_decode_whole(&bytes, &self.decoders()){
                            for item in items {
                                if self.process_consensus_item(
                                    session_index,
                                    item_index,
                                    item.clone(),
                                    ordered_unit.creator
                                ).await
                                .is_ok() {
                                    item_index += 1;
                                }
                            }
                        }
                    }
                },
                signed_session_outcome = &mut request_signed_session_outcome => {
                    let pending_accepted_items = self.pending_accepted_items().await;

                    // this panics if we have more accepted items than the signed session outcome
                    let (processed, unprocessed) = signed_session_outcome
                        .session_outcome
                        .items
                        .split_at(pending_accepted_items.len());

                    assert!(
                        processed.iter().eq(pending_accepted_items.iter()),
                        "Consensus Failure: pending accepted items disagree with federation consensus"
                    );

                    for (accepted_item, item_index) in unprocessed.iter().zip(processed.len()..) {
                        if let Err(err) = self.process_consensus_item(
                            session_index,
                            item_index as u64,
                            accepted_item.item.clone(),
                            accepted_item.peer
                        ).await {
                            panic!(
                                "Consensus Failure: rejected item accepted by federation consensus: {accepted_item:?}, items: {}+{}, session_idx: {session_index}, item_idx: {item_index}, err: {err}",
                                processed.len(),
                                unprocessed.len(),
                            );
                        }
                    }

                    return Ok(signed_session_outcome);
                }
            }
        }

        let items = self.pending_accepted_items().await;

        assert_eq!(item_index, items.len() as u64);

        let session_outcome = SessionOutcome { items };

        let header = session_outcome.header(session_index);

        let keychain = Keychain::new(&self.cfg);

        // We send our own signature to the data provider to be submitted to the atomic
        // broadcast and collected by our peers
        #[allow(clippy::disallowed_methods)]
        signature_sender.send(Some(keychain.sign(&header)))?;

        let mut signatures = BTreeMap::new();

        let items_dump = tokio::sync::OnceCell::new();

        // We collect the ordered signatures until we either obtain a threshold
        // signature or a signed session outcome arrives from our peers
        while signatures.len() < self.num_peers().threshold() {
            tokio::select! {
                ordered_unit = ordered_unit_receiver.recv() => {
                    let ordered_unit = ordered_unit?;

                    if let Some(UnitData::Signature(signature)) = ordered_unit.data {
                        if keychain.verify(&header, &signature, to_node_index(ordered_unit.creator)){
                            signatures.insert(ordered_unit.creator, signature);
                        } else {
                            warn!(target: LOG_CONSENSUS, "Consensus Failure: invalid header signature from {}", ordered_unit.creator);

                            items_dump.get_or_init(|| async {
                                for (idx, item) in session_outcome.items.iter().enumerate() {
                                    info!(target: LOG_CONSENSUS, idx, item = %DebugConsensusItemCompact(item), "Item");
                                }
                            }).await;
                        }
                    }
                }
                signed_session_outcome = &mut request_signed_session_outcome => {
                    assert_eq!(
                        header,
                        signed_session_outcome.session_outcome.header(session_index),
                        "Consensus Failure: header disagrees with federation consensus"
                    );

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

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");
    }

    /// Returns the full path where the database checkpoints are stored.
    fn db_checkpoints_dir(&self) -> PathBuf {
        self.data_dir.join(DB_CHECKPOINTS_DIR)
    }

    /// Creates the directory within the data directory for storing the database
    /// checkpoints or deletes checkpoints before `current_session` -
    /// `checkpoint_retention`.
    fn initialize_checkpoint_directory(&self, current_session: u64) -> anyhow::Result<()> {
        let checkpoint_dir = self.db_checkpoints_dir();

        if checkpoint_dir.exists() {
            debug!(
                target: LOG_CONSENSUS,
                ?current_session,
                "Removing database checkpoints up to `current_session`"
            );

            for checkpoint in fs::read_dir(checkpoint_dir)?.flatten() {
                // Validate that the directory is a session index
                if let Ok(file_name) = checkpoint.file_name().into_string() {
                    if let Ok(session) = file_name.parse::<u64>() {
                        if current_session >= self.checkpoint_retention
                            && session < current_session - self.checkpoint_retention
                        {
                            fs::remove_dir_all(checkpoint.path())?;
                        }
                    }
                }
            }
        } else {
            fs::create_dir_all(&checkpoint_dir)?;
        }

        Ok(())
    }

    /// Creates a backup of the database in the checkpoint directory. These
    /// checkpoints can be used to restore the database in case the
    /// federation falls out of consensus (recommended for experts only).
    fn checkpoint_database(&self, session_index: u64) {
        // If `checkpoint_retention` has been turned off, don't checkpoint the database
        // at all.
        if self.checkpoint_retention == 0 {
            return;
        }

        let checkpoint_dir = self.db_checkpoints_dir();
        let session_checkpoint_dir = checkpoint_dir.join(format!("{session_index}"));

        {
            let _timing /* logs on drop */ = timing::TimeReporter::new("database-checkpoint").level(Level::TRACE);
            match self.db.checkpoint(&session_checkpoint_dir) {
                Ok(()) => {
                    debug!(target: LOG_CONSENSUS, ?session_checkpoint_dir, ?session_index, "Created db checkpoint");
                }
                Err(e) => {
                    warn!(target: LOG_CONSENSUS, ?session_checkpoint_dir, ?session_index, ?e, "Could not create db checkpoint");
                }
            }
        }

        {
            // Check if any old checkpoint need to be cleaned up
            let _timing /* logs on drop */ = timing::TimeReporter::new("remove-database-checkpoint").level(Level::TRACE);
            if let Err(e) = self.delete_old_database_checkpoint(session_index, &checkpoint_dir) {
                warn!(target: LOG_CONSENSUS, ?e, "Could not delete old checkpoints");
            }
        }
    }

    /// Deletes the database checkpoint directory equal to `session_index` -
    /// `checkpoint_retention`
    fn delete_old_database_checkpoint(
        &self,
        session_index: u64,
        checkpoint_dir: &Path,
    ) -> anyhow::Result<()> {
        if self.checkpoint_retention > session_index {
            return Ok(());
        }

        let delete_session_index = session_index - self.checkpoint_retention;
        let checkpoint_to_delete = checkpoint_dir.join(delete_session_index.to_string());
        if checkpoint_to_delete.exists() {
            fs::remove_dir_all(checkpoint_to_delete)?;
        }

        Ok(())
    }

    #[instrument(target = LOG_CONSENSUS, skip(self, item), level = "info")]
    pub async fn process_consensus_item(
        &self,
        session_index: u64,
        item_index: u64,
        item: ConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_item").level(Level::TRACE);

        let timing_prom = CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS
            .with_label_values(&[&peer.to_usize().to_string()])
            .start_timer();

        trace!(
            target: LOG_CONSENSUS,
            %peer,
            item = ?DebugConsensusItem(&item),
            "Processing consensus item"
        );

        self.ci_status_senders
            .get(&peer)
            .expect("No ci status sender for peer {peer}")
            .send_replace(Some(session_index));

        CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX
            .with_label_values(&[
                &self.cfg.local.identity.to_usize().to_string(),
                &peer.to_usize().to_string(),
            ])
            .set(session_index as i64);

        let mut dbtx = self.db.begin_transaction().await;

        dbtx.ignore_uncommitted();

        // When we recover from a mid-session crash aleph bft will replay the units that
        // were already processed before the crash. We therefore skip all consensus
        // items until we have seen every previously accepted items again.
        if let Some(existing_item) = dbtx
            .get_value(&AcceptedItemKey(item_index.to_owned()))
            .await
        {
            if existing_item.item == item && existing_item.peer == peer {
                return Ok(());
            }

            bail!(
                "Item was discarded previously: existing: {existing_item:?} {}, current: {item:?}, {peer}",
                existing_item.peer
            );
        }

        self.process_consensus_item_with_db_transaction(&mut dbtx.to_ref_nc(), item.clone(), peer)
            .await?;

        // After this point we have to commit the database transaction since the
        // item has been fully processed without errors
        dbtx.warn_uncommitted();

        dbtx.insert_entry(
            &AcceptedItemKey(item_index),
            &AcceptedItem {
                item: item.clone(),
                peer,
            },
        )
        .await;

        debug!(
            target: LOG_CONSENSUS,
            %peer,
            item = ?DebugConsensusItem(&item),
            "Processed consensus item"
        );
        let mut audit = Audit::default();

        for (module_instance_id, kind, module) in self.modules.iter_modules() {
            let _module_audit_timing =
                TimeReporter::new(format!("audit module {module_instance_id}")).level(Level::TRACE);

            let timing_prom = CONSENSUS_ITEM_PROCESSING_MODULE_AUDIT_DURATION_SECONDS
                .with_label_values(&[&MODULE_INSTANCE_ID_GLOBAL.to_string(), kind.as_str()])
                .start_timer();

            module
                .audit(
                    &mut dbtx
                        .to_ref_with_prefix_module_id(module_instance_id)
                        .0
                        .into_nc(),
                    &mut audit,
                    module_instance_id,
                )
                .await;

            timing_prom.observe_duration();
        }

        assert!(
            audit
                .net_assets()
                .expect("Overflow while checking balance sheet")
                .milli_sat
                >= 0,
            "Balance sheet of the fed has gone negative, this should never happen! {audit}"
        );

        dbtx.commit_tx_result()
            .await
            .expect("Committing consensus epoch failed");

        CONSENSUS_ITEMS_PROCESSED_TOTAL
            .with_label_values(&[&peer.to_usize().to_string()])
            .inc();

        timing_prom.observe_duration();

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

                let module_dbtx = &mut dbtx.to_ref_with_prefix_module_id(instance_id).0;

                self.modules
                    .get_expect(instance_id)
                    .process_consensus_item(module_dbtx, &module_item, peer_id)
                    .await
            }
            ConsensusItem::Transaction(transaction) => {
                let txid = transaction.tx_hash();
                if dbtx
                    .get_value(&AcceptedTransactionKey(txid))
                    .await
                    .is_some()
                {
                    debug!(
                        target: LOG_CONSENSUS,
                        %txid,
                        "Transaction already accepted"
                    );
                    bail!("Transaction is already accepted");
                }

                let modules_ids = transaction
                    .outputs
                    .iter()
                    .map(DynOutput::module_instance_id)
                    .collect::<Vec<_>>();

                process_transaction_with_dbtx(
                    self.modules.clone(),
                    dbtx,
                    &transaction,
                    self.cfg.consensus.version,
                    TxProcessingMode::Consensus,
                )
                .await
                .map_err(|error| anyhow!(error.to_string()))?;

                debug!(target: LOG_CONSENSUS, %txid,  "Transaction accepted");
                dbtx.insert_entry(&AcceptedTransactionKey(txid), &modules_ids)
                    .await;

                Ok(())
            }
            ConsensusItem::Default { variant, .. } => {
                warn!(
                    target: LOG_CONSENSUS,
                    "Minor consensus version mismatch: unexpected consensus item type: {variant}"
                );

                panic!("Unexpected consensus item type: {variant}")
            }
        }
    }

    async fn request_signed_session_outcome(
        &self,
        federation_api: &DynGlobalApi,
        index: u64,
    ) -> SignedSessionOutcome {
        let decoders = self.decoders();
        let keychain = Keychain::new(&self.cfg);
        let threshold = self.num_peers().threshold();

        let filter_map = move |response: SerdeModuleEncoding<SignedSessionOutcome>| {
            let signed_session_outcome = response
                .try_into_inner(&decoders)
                .map_err(|x| PeerError::ResponseDeserialization(x.into()))?;
            let header = signed_session_outcome.session_outcome.header(index);
            if signed_session_outcome.signatures.len() == threshold
                && signed_session_outcome
                    .signatures
                    .iter()
                    .all(|(peer_id, sig)| keychain.verify(&header, sig, to_node_index(*peer_id)))
            {
                Ok(signed_session_outcome)
            } else {
                Err(PeerError::InvalidResponse(anyhow!("Invalid signatures")))
            }
        };

        loop {
            let result = federation_api
                .request_with_strategy(
                    FilterMap::new(filter_map.clone()),
                    AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT.to_string(),
                    ApiRequestErased::new(index),
                )
                .await;

            match result {
                Ok(signed_session_outcome) => return signed_session_outcome,
                Err(error) => {
                    error.report_if_unusual("Requesting Session Outcome");
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

pub async fn get_finished_session_count_static(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.find_by_prefix_sorted_descending(&SignedSessionOutcomePrefix)
        .await
        .next()
        .await
        .map_or(0, |entry| (entry.0.0) + 1)
}
