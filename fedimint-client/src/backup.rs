use std::cmp::Reverse;
use std::collections::BTreeMap;

use anyhow::Result;
use bitcoin::secp256k1;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::backup::{BackupRequest, SignedBackupRequest};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_BACKUP, LOG_CLIENT_RECOVERY};
use secp256k1_zkp::{KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::Client;
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
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct ClientBackup {
    /// Epoch count taken right before taking the backup
    epoch_count: u64,
    /// Application metadata
    metadata: Metadata,
    /// Module specific-backup (if supported)
    modules: BTreeMap<ModuleInstanceId, Vec<u8>>,
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
        let epoch_count = self.inner.api.fetch_epoch_count().await?;
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

                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, size=backup.len(), "Prepared module backup");
                modules.insert(id, backup);
            } else {
                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Module does not support backup");
            }
        }

        {
            let module = &self.inner.primary_module;
            let id = self.inner.primary_module_instance;
            let kind = self.inner.primary_module_kind.clone();

            debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Preparing primary module backup");
            if module.supports_backup() {
                let backup = module
                    .backup(
                        &mut dbtx.with_module_prefix(id),
                        self.inner.executor.clone(),
                        self.inner.api.clone(),
                        id,
                    )
                    .await?;

                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, size=backup.len(), "Prepared primary module backup");
                modules.insert(id, backup);
            } else {
                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Primary module does not support backup");
            }
        }
        dbtx.commit_tx().await;

        Ok(ClientBackup {
            metadata,
            modules,
            epoch_count,
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

        {
            let module = &self.inner.primary_module;
            let id = self.inner.primary_module_instance;
            let kind = self.inner.primary_module_kind.clone();

            if module.supports_backup() {
                info!(
                    target: LOG_CLIENT,
                    module_kind = %kind,
                    module_id = id,
                    "Wiping primary module state"
                );
                module
                    .wipe(
                        &mut dbtx.with_module_prefix(id),
                        id,
                        self.inner.executor.clone(),
                    )
                    .await?;
            }
        }
        dbtx.commit_tx().await;
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
                epoch = backup.epoch_count,
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
            let module_backup = backup.as_ref().and_then(|b| b.modules.get(&id));

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
                    module_backup.map(Vec::as_slice),
                )
                .await?;
        }

        {
            let module = &self.inner.primary_module;
            let id = self.inner.primary_module_instance;
            let kind = self.inner.primary_module_kind.clone();

            if module.supports_backup() {
                let module_backup = backup.as_ref().and_then(|b| b.modules.get(&id));

                info!(
                    target: LOG_CLIENT_RECOVERY,
                    module_kind = %kind,
                    module_id = id,
                    "Starting recovery from backup for primary module"
                );
                module
                    .restore(
                        &mut dbtx,
                        id,
                        self.inner.executor.clone(),
                        self.inner.api.clone(),
                        module_backup.map(Vec::as_slice),
                    )
                    .await?;
            }
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
        responses.sort_by_key(|backup| Reverse(backup.epoch_count));

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
}
