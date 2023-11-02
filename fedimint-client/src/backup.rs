use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use bitcoin::secp256k1;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::block::AcceptedItem;
use fedimint_core::core::backup::{BackupRequest, SignedBackupRequest};
use fedimint_core::core::{DynModuleConsensusItem, ModuleInstanceId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{sleep, spawn};
use fedimint_core::transaction::Transaction;
use fedimint_core::PeerId;
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_BACKUP, LOG_CLIENT_RECOVERY};
use futures::StreamExt;
use secp256k1_zkp::{KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, trace, warn};

use super::Client;
use crate::get_decoded_client_secret;
use crate::module::init::ClientModuleInitRegistry;
use crate::module::recovery::{DynModuleBackup, DynRecoveringModule};
use crate::secret::DeriveableSecretClientExt;

/// Backup metadata
///
/// A backup can have a blob of extra data encoded in it. We provide methods to
/// use json encoding, but clients are free to use their own encoding.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable, Clone)]
pub struct Metadata(Vec<u8>);

impl Metadata {
    /// Create empty metadata
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn from_raw(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.0
    }

    /// Is metadata empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Create metadata as json from typed `val`
    pub fn from_json_serialized<T: Serialize>(val: T) -> Self {
        Self(serde_json::to_vec(&val).expect("serializing to vec can't fail"))
    }

    /// Attempt to deserialize metadata as typed json
    pub fn to_json_deserialized<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.0)?)
    }

    /// Attempt to deserialize metadata as untyped json (`serde_json::Value`)
    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.0)?)
    }
}

/// Client state backup
#[derive(PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct ClientBackup {
    /// Epoch count taken right before taking the backup
    fedimint_block_count: u64,
    /// Application metadata
    metadata: Metadata,
    // TODO: remove redundant ModuleInstanceId
    /// Module specific-backup (if supported)
    modules: BTreeMap<ModuleInstanceId, DynModuleBackup>,
}

impl ClientBackup {
    /// Align an ecoded message size up for better privacy
    fn get_alignment_size(len: usize) -> usize {
        let padding_alignment = 16 * 1024;
        ((len.saturating_sub(1) / padding_alignment) + 1) * padding_alignment
    }

    /// Encode `self` to a padded (but still plaintext) message
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.consensus_encode_to_vec()?;

        let padding_size = Self::get_alignment_size(bytes.len()) - bytes.len();

        bytes.extend(std::iter::repeat(0u8).take(padding_size));

        Ok(bytes)
    }

    /// Decode from a plaintexet (possibly aligned) message
    fn decode(msg: &[u8]) -> Result<Self> {
        Ok(Decodable::consensus_decode(
            &mut &msg[..],
            &ModuleDecoderRegistry::default(),
        )?)
    }

    /// Encrypt with a key and turn into [`EncryptedClientBackup`]
    pub fn encrypt_to(&self, key: &fedimint_aead::LessSafeKey) -> Result<EncryptedClientBackup> {
        let encoded = self.encode()?;

        let encrypted = fedimint_aead::encrypt(encoded, key)?;
        Ok(EncryptedClientBackup(encrypted))
    }
}

/// Encrypted version of [`ClientBackup`].
pub struct EncryptedClientBackup(Vec<u8>);

impl EncryptedClientBackup {
    pub fn decrypt_with(mut self, key: &fedimint_aead::LessSafeKey) -> Result<ClientBackup> {
        let decrypted = fedimint_aead::decrypt(&mut self.0, key)?;
        ClientBackup::decode(decrypted)
    }

    pub fn into_backup_request(self, keypair: &KeyPair) -> Result<SignedBackupRequest> {
        let request = BackupRequest {
            id: keypair.x_only_public_key().0,
            timestamp: fedimint_core::time::now(),
            payload: self.0,
        };

        request.sign(keypair)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Client {
    /// Create a backup, include provided `metadata`
    pub async fn create_backup(&self, metadata: Metadata) -> anyhow::Result<ClientBackup> {
        let fedimint_block_count = self.inner.api.fetch_block_count().await?;
        let mut modules = BTreeMap::new();
        let mut dbtx = self.db().begin_transaction().await;
        for (id, kind, module) in self.inner.modules.iter_modules() {
            debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Preparing module backup");
            if module.supports_backup() {
                let backup = module
                    .backup(
                        &mut dbtx.with_module_prefix(id),
                        self.inner.executor.clone(),
                        self.inner.api.clone(),
                        id,
                    )
                    .await?;

                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Prepared module backup");
                modules.insert(id, backup);
            } else {
                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Module does not support backup");
            }
        }

        dbtx.commit_tx().await;

        Ok(ClientBackup {
            metadata,
            modules,
            fedimint_block_count,
        })
    }

    /// Create a backup, include provided `metadata`, and encrypt it with a
    /// (derived) client root key
    pub async fn create_encrypted_backup(
        &self,
        metadata: Metadata,
    ) -> Result<EncryptedClientBackup> {
        let plaintext = self.create_backup(metadata).await?;
        plaintext.encrypt_to(&self.get_derived_backup_encryption_key())
    }

    /// Prepare an encrypted backup and send it to federation for storing
    pub async fn backup_to_federation(&self, metadata: Metadata) -> Result<()> {
        let backup = self.create_encrypted_backup(metadata).await?;

        self.upload_backup(backup).await?;

        Ok(())
    }

    /// Wipe the client state (including module state)
    pub async fn wipe_state(&self) -> Result<()> {
        let mut dbtx = self.db().begin_transaction().await;
        info!(target: LOG_CLIENT, "Wiping client state");
        for (id, kind, module) in self.inner.modules.iter_modules() {
            if !module.supports_backup() {
                continue;
            }

            info!(
                target: LOG_CLIENT,
                module_kind = %kind,
                module_id = id,
                "Wiping module state"
            );
            module
                .wipe(
                    &mut dbtx.with_module_prefix(id),
                    id,
                    self.inner.executor.clone(),
                )
                .await?;
        }
        dbtx.commit_tx().await;

        debug!(target: LOG_CLIENT, "Wiping client state complete");

        Ok(())
    }

    /// Upload `backup` to federation
    pub async fn upload_backup(&self, backup: EncryptedClientBackup) -> Result<()> {
        let size = backup.len();
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploading backup to federation"
        );
        let backup_request = backup.into_backup_request(&self.get_derived_backup_signing_key())?;
        self.inner.api.upload_backup(&backup_request).await?;
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploaded backup to federation"
        );
        Ok(())
    }

    /// Restore client state from backup download from federation (if found) or
    /// from scratch
    ///
    /// This will restore (or initialize restoration process) in all sub-modules
    /// that support it.
    pub(crate) async fn restore_from_backup(&self) -> Result<Metadata> {
        info!(target: LOG_CLIENT_RECOVERY, "Restoring from backup");
        let backup = if let Some(backup) = self.download_backup_from_federation().await? {
            info!(
                target: LOG_CLIENT_RECOVERY,
                epoch = backup.fedimint_block_count,
                "Found backup"
            );
            Some(backup)
        } else {
            warn!(
                target: LOG_CLIENT_RECOVERY,
                id=%self.get_backup_id(),
                "Could not find any valid existing backup. Will attempt to restore from scratch. This might take a long time."
            );
            None
        };

        let metadata = backup
            .as_ref()
            .map(|b| b.metadata.clone())
            .unwrap_or_else(Metadata::empty);

        let mut dbtx = self.db().begin_transaction().await;
        for (id, kind, module) in self.inner.modules.iter_modules() {
            if !module.supports_backup() {
                continue;
            }
            let module_backup = backup.as_ref().and_then(|b| b.modules.get(&id)).cloned();

            info!(
                target: LOG_CLIENT_RECOVERY,
                module_kind = %kind,
                module_id = id,
                "Starting recovery from backup for module"
            );
            module
                .restore(
                    &mut dbtx,
                    id,
                    self.inner.executor.clone(),
                    self.inner.api.clone(),
                    module_backup,
                )
                .await?;
        }

        dbtx.commit_tx().await;
        Ok(metadata)
    }

    /// Download most recent valid backup found from the Federation
    pub async fn download_backup_from_federation(&self) -> Result<Option<ClientBackup>> {
        let mut responses: Vec<_> = self
            .inner
            .api
            .download_backup(&self.get_backup_id())
            .await?
            .into_iter()
            .filter_map(|backup| {
                match EncryptedClientBackup(backup.data)
                    .decrypt_with(&self.get_derived_backup_encryption_key())
                {
                    Ok(valid) => Some(valid),
                    Err(e) => {
                        warn!(
                            target: LOG_CLIENT_RECOVERY,
                            "Invalid backup returned by one of the peers: {e}"
                        );
                        None
                    }
                }
            })
            .collect();

        debug!(
            target: LOG_CLIENT_RECOVERY,
            "Received {} valid responses",
            responses.len()
        );
        // Use the newest (highest epoch)
        responses.sort_by_key(|backup| Reverse(backup.fedimint_block_count));

        Ok(responses.into_iter().next())
    }

    /// Backup id derived from the root secret key (public key used to self-sign
    /// backup requests)
    pub fn get_backup_id(&self) -> bitcoin::XOnlyPublicKey {
        self.get_derived_backup_signing_key().x_only_public_key().0
    }

    /// Static version of [`Self::get_derived_backup_encryption_key`] for
    /// testing without creating whole `MintClient`
    fn get_derived_backup_encryption_key_static(
        secret: &DerivableSecret,
    ) -> fedimint_aead::LessSafeKey {
        fedimint_aead::LessSafeKey::new(secret.derive_backup_secret().to_chacha20_poly1305_key())
    }

    /// Static version of [`Self::get_derived_backup_signing_key`] for testing
    /// without creating whole `MintClient`
    fn get_derived_backup_signing_key_static(secret: &DerivableSecret) -> secp256k1_zkp::KeyPair {
        secret
            .derive_backup_secret()
            .to_secp_key(&Secp256k1::<secp256k1::SignOnly>::gen_new())
    }

    fn get_derived_backup_encryption_key(&self) -> fedimint_aead::LessSafeKey {
        Self::get_derived_backup_encryption_key_static(&self.root_secret())
    }

    fn get_derived_backup_signing_key(&self) -> secp256k1::KeyPair {
        Self::get_derived_backup_signing_key_static(&self.root_secret())
    }

    pub async fn get_decoded_client_secret<T: Decodable>(&self) -> anyhow::Result<T> {
        get_decoded_client_secret::<T>(self.db()).await
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RecoveryProgress {
    pub recovery_start_epoch: u64,
    pub recovery_current_epoch: u64,
    pub recovery_target_epoch: u64,
}

pub struct RecoveringClient {
    progress: tokio::sync::watch::Receiver<Option<RecoveryProgress>>,
    cancel_recovery: CancellationToken,
    outcome_receiver: tokio::sync::oneshot::Receiver<anyhow::Result<Client>>,
}

#[derive(Debug, Clone, Encodable, Decodable)]
struct RecoverySnapshot {
    last_processed_epoch: u64,
    modules: RecoveringModules,
}

type RecoveringModules = BTreeMap<ModuleInstanceId, DynRecoveringModule>;

impl RecoveringClient {
    pub(crate) async fn new(
        stopped_client: Client,
        module_gens: ClientModuleInitRegistry,
    ) -> anyhow::Result<Self> {
        // FIXME: ensure that DB is empty except for possible partial recovery
        // TODO: check if a recovery is already in progress

        let (update_progress, progress) = tokio::sync::watch::channel(None);
        let (outcome_sender, outcome_receiver) = tokio::sync::oneshot::channel();
        let cancel_recovery = CancellationToken::new();

        let cfg = stopped_client.get_config();

        let mut modules = BTreeMap::new();
        for (&module_instance_id, module_config) in cfg.modules.iter() {
            if stopped_client
                .inner
                .modules
                .get(module_instance_id)
                .is_none()
            {
                // Module is not initialized in client, not attempting to recover
                continue;
            }

            let recovering_module = module_gens
                .get(module_config.kind())
                .expect("Unknown module kind")
                .init_recovering(
                    module_instance_id,
                    module_config,
                    stopped_client
                        .root_secret()
                        .derive_module_secret(module_instance_id),
                )
                .await?;
            modules.insert(module_instance_id, recovering_module);
        }

        let cancel_recovery_task = cancel_recovery.clone();
        spawn("recovery", async move {
            select! {
                client = Self::run_recovery(stopped_client, modules, update_progress) => {
                    let _ = outcome_sender.send(Ok(client));
                }
                _ = cancel_recovery_task.cancelled() => {
                    let _ = outcome_sender.send(Err(anyhow::anyhow!("Recovery cancelled")));
                }
            }
        });

        Ok(Self {
            progress,
            cancel_recovery,
            outcome_receiver,
        })
    }

    // TODO: Should this take &self so it can be selected over without having to
    // worry about recreating the future?
    // TODO: Should RecoveringClient be a future itself?
    /// Waits for the recovery process to finish and a fully initialized client
    /// to be returned
    ///
    /// # Errors
    /// If recovery is cancelled using [`RecoveringClient::cancel`].
    pub async fn wait_finished(self) -> anyhow::Result<Client> {
        self.outcome_receiver.await.expect("Recovery task panicked")
    }

    /// Returns a channel that will receive progress updates from the recovery
    /// task
    pub async fn progress(&self) -> tokio::sync::watch::Receiver<Option<RecoveryProgress>> {
        self.progress.clone()
    }

    /// Cancels the recovery process, stopping the recovery task and making
    /// [`RecoveringClient::wait_finished`] finish with an error shortly after.
    pub async fn cancel(&self) {
        self.cancel_recovery.cancel();
    }

    #[instrument(skip_all)]
    async fn run_recovery(
        stopped_client: Client,
        mut modules: RecoveringModules,
        progress: tokio::sync::watch::Sender<Option<RecoveryProgress>>,
    ) -> Client {
        const POLL_TIME: Duration = Duration::from_secs(1);
        const DOWNLOAD_PARALLELISM: usize = 16;

        let db = stopped_client.db().clone();
        let api = stopped_client.inner.api.clone();
        let decoders = stopped_client.decoders().clone();

        // TODO: fetch backup
        let last_backup_block = 0u64;
        let current_block = loop {
            match api.fetch_block_count().await {
                Ok(block) => break block,
                Err(e) => {
                    warn!("Could not fetch current epoch, retrying: {e:?}");
                    sleep(POLL_TIME).await;
                }
            }
        };

        let mut block_stream = futures::stream::iter(last_backup_block + 1..=current_block)
            .map(move |block_idx| {
                let api_inner = api.clone();
                let decoders = decoders.clone();
                async move {
                    loop {
                        match api_inner.await_block(block_idx, &decoders).await {
                            Ok(block) => break (block_idx, block.items),
                            Err(e) => {
                                warn!("Could not fetch block {block_idx}, retrying: {e:?}");
                                sleep(POLL_TIME).await;
                            }
                        }
                    }
                }
            })
            .buffered(DOWNLOAD_PARALLELISM);

        // Run recovery
        let mut dbtx = db.begin_transaction().await;
        while let Some((block_idx, items)) = block_stream.next().await {
            // TODO: persist progress every N epochs

            progress.send_replace(Some(RecoveryProgress {
                recovery_start_epoch: last_backup_block + 1,
                recovery_current_epoch: block_idx,
                recovery_target_epoch: current_block,
            }));

            for AcceptedItem { item, peer } in items {
                match item {
                    ConsensusItem::Transaction(tx) => {
                        Self::process_transaction(&mut dbtx, &mut modules, tx).await
                    }
                    ConsensusItem::Module(ci) => {
                        Self::process_module_ci(&mut dbtx, &mut modules, peer, ci).await
                    }
                    skipped => {
                        trace!("Skipping consensus item: {skipped:?}");
                    }
                }
            }
        }
        dbtx.commit_tx().await;

        // Finalize recovery
        let mut dbtx = db.begin_transaction().await;
        let mut states = Vec::new();
        for (module_instance_id, module) in modules {
            states.append(
                &mut module
                    .finalize(
                        &mut dbtx.with_module_prefix(module_instance_id),
                        module_instance_id,
                    )
                    .await,
            );
        }
        // I'm not aware of a concrete reason to start the executor later
        stopped_client.start_executor().await;
        stopped_client
            .add_state_machines(&mut dbtx, states)
            .await
            .expect("");
        dbtx.commit_tx().await;

        stopped_client
    }

    #[instrument(skip_all)]
    async fn process_transaction(
        dbtx: &mut DatabaseTransaction<'_>,
        modules: &mut RecoveringModules,
        tx: Transaction,
    ) {
        for input in tx.inputs {
            let module_instance_id = input.module_instance_id();
            let Some(module) = modules.get_mut(&module_instance_id) else {
                debug!("Skipping input for unknown module instance {module_instance_id}");
                continue;
            };
            module
                .process_input(&mut dbtx.with_module_prefix(module_instance_id), input)
                .await;
        }

        for output in tx.outputs {
            let module_instance_id = output.module_instance_id();
            let Some(module) = modules.get_mut(&module_instance_id) else {
                debug!("Skipping output for unknown module instance {module_instance_id}");
                continue;
            };
            module
                .process_output(&mut dbtx.with_module_prefix(module_instance_id), output)
                .await;
        }
    }

    #[instrument(skip_all)]
    async fn process_module_ci(
        dbtx: &mut DatabaseTransaction<'_>,
        modules: &mut RecoveringModules,
        contributor: PeerId,
        ci: DynModuleConsensusItem,
    ) {
        let module_instance_id = ci.module_instance_id();
        let Some(module) = modules.get_mut(&module_instance_id) else {
            debug!(
                "Skipping module consensus item for unknown module instance {module_instance_id}"
            );
            return;
        };
        module
            .process_ci(
                &mut dbtx.with_module_prefix(module_instance_id),
                contributor,
                ci,
            )
            .await;
    }
}

#[cfg(test)]
mod tests;
