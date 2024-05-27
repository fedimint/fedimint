use std::collections::BTreeMap;
use std::default::Default;
use std::sync::Arc;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use anyhow::{anyhow, bail};
use async_channel::Receiver;
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt, PeerConnectionStatus};
use fedimint_api_client::query::FilterMap;
use fedimint_core::core::{DynOutput, MODULE_INSTANCE_ID_GLOBAL};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Decodable;
use fedimint_core::endpoint_constants::AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ServerModuleRegistry};
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::runtime::spawn;
use fedimint_core::session_outcome::{
    AcceptedItem, SchnorrSignature, SessionOutcome, SignedSessionOutcome,
};
use fedimint_core::task::{sleep, TaskGroup, TaskHandle};
use fedimint_core::timing::TimeReporter;
use fedimint_core::{timing, NumPeers, PeerId};
use futures::StreamExt;
use rand::Rng;
use tokio::sync::{watch, RwLock};
use tracing::{debug, info, instrument, warn, Level};

use crate::atomic_broadcast::backup::{BackupReader, BackupWriter};
use crate::atomic_broadcast::data_provider::{DataProvider, UnitData};
use crate::atomic_broadcast::finalization_handler::FinalizationHandler;
use crate::atomic_broadcast::network::Network;
use crate::atomic_broadcast::spawner::Spawner;
use crate::atomic_broadcast::{to_node_index, Keychain, Message};
use crate::config::ServerConfig;
use crate::consensus::db::{
    AcceptedItemKey, AcceptedItemPrefix, AcceptedTransactionKey, AlephUnitsPrefix,
    SignedSessionOutcomeKey, SignedSessionOutcomePrefix,
};
use crate::consensus::debug_fmt::FmtDbgConsensusItem;
use crate::consensus::transaction::process_transaction_with_dbtx;
use crate::fedimint_core::encoding::Encodable;
use crate::metrics::{
    CONSENSUS_ITEMS_PROCESSED_TOTAL, CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS,
    CONSENSUS_ITEM_PROCESSING_MODULE_AUDIT_DURATION_SECONDS,
    CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX, CONSENSUS_SESSION_COUNT,
};
use crate::net::connect::{Connector, TlsTcpConnector};
use crate::net::peers::{DelayCalculator, ReconnectPeerConnections};
use crate::LOG_CONSENSUS;

/// Runs the main server consensus loop
pub struct ConsensusEngine {
    pub modules: ServerModuleRegistry,
    pub db: Database,
    pub keychain: Keychain,
    pub federation_api: DynGlobalApi,
    pub cfg: ServerConfig,
    pub submission_receiver: Receiver<ConsensusItem>,
    pub shutdown_receiver: watch::Receiver<Option<u64>>,
    pub last_ci_by_peer: Arc<RwLock<BTreeMap<PeerId, u64>>>,
    /// Just a string version of `cfg.local.identity` for performance
    pub self_id_str: String,
    /// Just a string version of peer ids for performance
    pub peer_id_str: Vec<String>,
    pub connection_status_channels: Arc<RwLock<BTreeMap<PeerId, PeerConnectionStatus>>>,
    pub task_group: TaskGroup,
}

impl ConsensusEngine {
    #[instrument(name = "run", skip_all, fields(id=%self.cfg.local.identity))]
    pub async fn run(self) -> anyhow::Result<()> {
        if self.cfg.consensus.broadcast_public_keys.len() == 1 {
            self.run_single_guardian(self.task_group.make_handle())
                .await
        } else {
            self.run_consensus(self.task_group.make_handle()).await
        }
    }

    pub async fn run_single_guardian(&self, task_handle: TaskHandle) -> anyhow::Result<()> {
        assert_eq!(self.cfg.consensus.broadcast_public_keys.len(), 1);

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            CONSENSUS_SESSION_COUNT.set(session_index as i64);

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

            if Some(session_index) == self.shutdown_receiver.borrow().to_owned() {
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

        // Build P2P connections for the atomic broadcast
        let connections = ReconnectPeerConnections::new(
            self.cfg.network_config(),
            DelayCalculator::PROD_DEFAULT,
            TlsTcpConnector::new(self.cfg.tls_config(), self.cfg.local.identity).into_dyn(),
            &self.task_group,
            Arc::clone(&self.connection_status_channels),
        )
        .await;

        while !task_handle.is_shutting_down() {
            let session_index = self.get_finished_session_count().await;

            CONSENSUS_SESSION_COUNT.set(session_index as i64);

            self.run_session(connections.clone(), session_index).await?;

            info!(target: LOG_CONSENSUS, "Session {session_index} completed");

            if Some(session_index) == self.shutdown_receiver.borrow().to_owned() {
                info!(target: LOG_CONSENSUS, "Initiating shutdown, waiting for peers to complete the session...");

                sleep(Duration::from_secs(60)).await;

                break;
            }
        }

        info!(target: LOG_CONSENSUS, "Consensus task shut down");

        Ok(())
    }

    async fn confirm_server_config_consensus_hash(&self) -> anyhow::Result<()> {
        let our_hash = self.cfg.consensus.consensus_hash();

        info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");

        loop {
            match self.federation_api.server_config_consensus_hash().await {
                Ok(consensus_hash) => {
                    if consensus_hash != our_hash {
                        bail!("Our consensus config doesn't match peers!")
                    }

                    info!(target: LOG_CONSENSUS, "Confirmed peers config {our_hash}");

                    return Ok(());
                }
                Err(e) => {
                    warn!(target: LOG_CONSENSUS, "Could not check consensus config hash: {}", OptStacktrace(e));
                }
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn run_session(
        &self,
        connections: ReconnectPeerConnections<Message>,
        session_index: u64,
    ) -> anyhow::Result<()> {
        // In order to bound a sessions RAM consumption we need to bound its number of
        // units and therefore its number of rounds. Since we use a session to
        // create a naive secp256k1 threshold signature for the header of session
        // outcome we have to guarantee that an attacker cannot exhaust our
        // memory by preventing the creation of a threshold signature, thereby
        // keeping the session open indefinitely. Hence, after a certain round
        // index, we increase the delay between rounds exponentially such that
        // max_round would only be reached after a minimum of 100 years. In case
        // of such an attack the broadcast stops ordering any items until the
        // attack subsides as no items are ordered while the signatures are
        // collected. The maximum RAM consumption of a peer is bound by:
        //
        // self.keychain.peer_count() * max_round * ALEPH_BFT_UNIT_BYTE_LIMIT

        const BASE: f64 = 1.005;

        let expected_rounds = 3 * self.cfg.consensus.broadcast_expected_rounds_per_session as usize;
        let max_round = 3 * self.cfg.consensus.broadcast_max_rounds_per_session;
        let round_delay = f64::from(self.cfg.local.broadcast_round_delay_ms);

        let exp_slowdown_offset = 3 * expected_rounds;

        let mut delay_config = aleph_bft::default_delay_config();

        delay_config.unit_creation_delay = Arc::new(move |round_index| {
            let delay = if round_index == 0 {
                0.0
            } else {
                round_delay
                    * BASE.powf(round_index.saturating_sub(exp_slowdown_offset) as f64)
                    * rand::thread_rng().gen_range(0.5..=1.5)
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
        .expect("The exponential slowdown we defined exceeds 100 years");

        // we can use an unbounded channel here since the number and size of units
        // ordered in a single aleph session is bounded as described above
        let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
        let (signature_sender, signature_receiver) = watch::channel(None);
        let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

        let aleph_handle = spawn(
            "aleph run session",
            aleph_bft::run_session(
                config,
                aleph_bft::LocalIO::new(
                    DataProvider::new(self.submission_receiver.clone(), signature_receiver),
                    FinalizationHandler::new(unit_data_sender),
                    BackupWriter::new(self.db.clone()),
                    BackupReader::new(self.db.clone()),
                ),
                Network::new(connections),
                self.keychain.clone(),
                Spawner::new(self.task_group.make_subgroup()),
                aleph_bft_types::Terminator::create_root(terminator_receiver, "Terminator"),
            ),
        );

        // this is the minimum number of batches data that will be ordered before we
        // reach the exponential_slowdown_offset since at least f + 1 batches are
        // ordered every round
        let batches_per_session = expected_rounds * self.keychain.peer_count();

        let signed_session_outcome = self
            .complete_signed_session_outcome(
                session_index,
                batches_per_session,
                unit_data_receiver,
                signature_sender,
            )
            .await?;

        // We can terminate the session instead of waiting for other peers to complete
        // it since they can always download the signed session outcome from us
        terminator_sender.send(()).ok();
        aleph_handle.await.ok();

        // This method removes the backup of the current session from the database
        // and therefore has to be called after we have waited for the session to
        // shutdown or we risk write-write conflicts with the UnitSaver
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

        // We build a session outcome out of the ordered batches until either we have
        // processed batches_per_session_outcome of batches or a threshold signed
        // session outcome is obtained from our peers
        while num_batches < batches_per_session_outcome {
            tokio::select! {
                unit_data = unit_data_receiver.recv() => {
                    if let (UnitData::Batch(bytes), peer) = unit_data? {
                        if let Ok(items) = Vec::<ConsensusItem>::consensus_decode(&mut bytes.as_slice(), &self.decoders()){
                            for item in items {
                                if self.process_consensus_item(
                                    session_index,
                                    item_index,
                                    item.clone(),
                                    peer
                                ).await
                                .is_ok() {
                                    item_index += 1;
                                }
                            }
                        }
                        num_batches += 1;
                    }
                },
                signed_session_outcome = self.request_signed_session_outcome(&self.federation_api, session_index) => {
                    let pending_accepted_items = self.pending_accepted_items().await;

                    // this panics if we have more accepted items than the signed session outcome
                    let (processed, unprocessed) = signed_session_outcome
                        .session_outcome
                        .items
                        .split_at(pending_accepted_items.len());

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

        let items = self.pending_accepted_items().await;

        assert_eq!(item_index, items.len() as u64);

        let session_outcome = SessionOutcome { items };

        let header = session_outcome.header(session_index);

        // We send our own signature to the data provider to be submitted to the atomic
        // broadcast and collected by our peers
        signature_sender.send(Some(self.keychain.sign(&header)))?;

        let mut signatures = BTreeMap::new();

        // We collect the ordered signatures until we either obtain a threshold
        // signature or a signed session outcome arrives from our peers
        while signatures.len() < self.keychain.threshold() {
            tokio::select! {
                unit_data = unit_data_receiver.recv() => {
                    if let (UnitData::Signature(signature), peer) = unit_data? {
                        if self.keychain.verify(&header, &signature, to_node_index(peer)){
                            signatures.insert(peer, signature);
                        } else {
                            warn!(target: LOG_CONSENSUS, "Received invalid signature from peer {peer}");
                        }
                    }
                }
                signed_session_outcome = self.request_signed_session_outcome(&self.federation_api, session_index) => {
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

        dbtx.commit_tx_result()
            .await
            .expect("This is the only place where we write to this key");
    }

    #[instrument(target = "fm::consensus", skip(self, item), level = "info")]
    pub async fn process_consensus_item(
        &self,
        session_index: u64,
        item_index: u64,
        item: ConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let peer_id_str = &self.peer_id_str[peer.to_usize()];
        let _timing /* logs on drop */ = timing::TimeReporter::new("process_consensus_item").level(Level::TRACE);
        let timing_prom = CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS
            .with_label_values(&[peer_id_str])
            .start_timer();

        debug!(%peer, item = ?FmtDbgConsensusItem(&item), "Processing consensus item");

        self.last_ci_by_peer
            .write()
            .await
            .insert(peer, session_index);

        CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX
            .with_label_values(&[&self.self_id_str, peer_id_str])
            .set(session_index as i64);

        let mut dbtx = self.db.begin_transaction().await;

        dbtx.ignore_uncommitted();

        // When we recover from a mid session crash aleph bft will replay the units that
        // already were processed before the crash. We therefore skip all consensus
        // items until we have seen all previously accepted items again.
        if let Some(accepted_item) = dbtx
            .get_value(&AcceptedItemKey(item_index.to_owned()))
            .await
        {
            if accepted_item.item == item && accepted_item.peer == peer {
                return Ok(());
            }

            bail!("Item was discarded previously");
        }

        self.process_consensus_item_with_db_transaction(&mut dbtx.to_ref_nc(), item.clone(), peer)
            .await?;

        // After this point the we have to commit the database transaction since the
        // item has been fully processed without errors
        dbtx.warn_uncommitted();

        dbtx.insert_entry(&AcceptedItemKey(item_index), &AcceptedItem { item, peer })
            .await;

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
                        .into_nc(),
                    &mut audit,
                    module_instance_id,
                )
                .await;
            timing_prom.observe_duration();
        }

        assert!(
            audit.net_assets().milli_sat >= 0,
            "Balance sheet of the fed has gone negative, this should never happen! {audit}"
        );

        dbtx.commit_tx_result()
            .await
            .expect("Committing consensus epoch failed");

        CONSENSUS_ITEMS_PROCESSED_TOTAL
            .with_label_values(&[peer_id_str])
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
                let module_dbtx = &mut dbtx.to_ref_with_prefix_module_id(instance_id);

                self.modules
                    .get_expect(instance_id)
                    .process_consensus_item(module_dbtx, module_item, peer_id)
                    .await
            }
            ConsensusItem::Transaction(transaction) => {
                let txid = transaction.tx_hash();
                if dbtx
                    .get_value(&AcceptedTransactionKey(txid))
                    .await
                    .is_some()
                {
                    debug!(target: LOG_CONSENSUS, %txid, "Transaction already accepted");
                    bail!("Transaction is already accepted");
                }

                let modules_ids = transaction
                    .outputs
                    .iter()
                    .map(DynOutput::module_instance_id)
                    .collect::<Vec<_>>();

                process_transaction_with_dbtx(self.modules.clone(), dbtx, transaction)
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
                bail!("Unexpected consensus item type: {variant}")
            }
        }
    }

    async fn request_signed_session_outcome(
        &self,
        federation_api: &DynGlobalApi,
        index: u64,
    ) -> SignedSessionOutcome {
        let keychain = self.keychain.clone();
        let total_peers = self.keychain.peer_count();
        let decoders = self.decoders();

        let filter_map = move |response: SerdeModuleEncoding<SignedSessionOutcome>| match response
            .try_into_inner(&decoders)
        {
            Ok(signed_session_outcome) => {
                if signed_session_outcome.signatures.len() == keychain.threshold()
                    && signed_session_outcome
                        .signatures
                        .iter()
                        .all(|(peer_id, sig)| {
                            keychain.verify(
                                &signed_session_outcome.session_outcome.header(index),
                                sig,
                                to_node_index(*peer_id),
                            )
                        })
                {
                    Ok(signed_session_outcome)
                } else {
                    Err(anyhow!("Invalid signatures"))
                }
            }
            Err(error) => Err(anyhow!(error.to_string())),
        };

        loop {
            // We only want to initiate the request if we have not ordered a unit in a
            // while. This indicates that we have fallen behind and our peers
            // have already switched sessions without us
            sleep(Duration::from_secs(5)).await;

            let result = federation_api
                .request_with_strategy(
                    FilterMap::new(filter_map.clone(), NumPeers::from(total_peers)),
                    AWAIT_SIGNED_SESSION_OUTCOME_ENDPOINT.to_string(),
                    ApiRequestErased::new(index),
                )
                .await;

            match result {
                Ok(signed_session_outcome) => return signed_session_outcome,
                Err(error) => {
                    tracing::error!(target: LOG_CONSENSUS, "Error while requesting signed session outcome: {}", error);
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
        .map_or(0, |entry| (entry.0 .0) + 1)
}
