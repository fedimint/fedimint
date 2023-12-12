use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::io::{Cursor, Error, Read, Write};

use anyhow::Result;
use bitcoin::secp256k1;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::backup::{BackupRequest, SignedBackupRequest};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_BACKUP, LOG_CLIENT_RECOVERY};
use secp256k1_zkp::{KeyPair, Secp256k1};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::Client;
use crate::get_decoded_client_secret;
use crate::module::recovery::DynModuleBackup;
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
#[derive(PartialEq, Eq, Debug)]
pub struct ClientBackup {
    /// Session count taken right before taking the backup
    session_count: u64,
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

    /// Encrypt with a key and turn into [`EncryptedClientBackup`]
    pub fn encrypt_to(&self, key: &fedimint_aead::LessSafeKey) -> Result<EncryptedClientBackup> {
        let encoded = Encodable::consensus_encode_to_vec(self);

        let encrypted = fedimint_aead::encrypt(encoded, key)?;
        Ok(EncryptedClientBackup(encrypted))
    }
}

impl Encodable for ClientBackup {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> std::result::Result<usize, Error> {
        let mut len = 0;
        len += self.session_count.consensus_encode(writer)?;
        len += self.metadata.consensus_encode(writer)?;
        len += self.modules.consensus_encode(writer)?;

        // FIXME: this still leaks some information about the backup size if the padding
        // is so short that its length is encoded as 1 byte instead of 3.
        let estimated_len = len + 3;

        // Hide small changes in backup size for privacy
        let alignment_size = Self::get_alignment_size(estimated_len); // +3 for most likely padding len len
        let padding = vec![0u8; alignment_size - estimated_len];
        len += padding.consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for ClientBackup {
    fn consensus_decode<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodeError> {
        let session_count = u64::consensus_decode(r, modules)?;
        let metadata = Metadata::consensus_decode(r, modules)?;
        let module_backups =
            BTreeMap::<ModuleInstanceId, DynModuleBackup>::consensus_decode(r, modules)?;
        let _padding = Vec::<u8>::consensus_decode(r, modules)?;

        Ok(Self {
            session_count,
            metadata,
            modules: module_backups,
        })
    }
}

/// Encrypted version of [`ClientBackup`].
pub struct EncryptedClientBackup(Vec<u8>);

impl EncryptedClientBackup {
    pub fn decrypt_with(
        mut self,
        key: &fedimint_aead::LessSafeKey,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientBackup> {
        let decrypted = fedimint_aead::decrypt(&mut self.0, key)?;
        Ok(ClientBackup::consensus_decode(
            &mut Cursor::new(decrypted),
            decoders,
        )?)
    }

    pub fn into_backup_request(self, keypair: &KeyPair) -> Result<SignedBackupRequest> {
        let request = BackupRequest {
            id: keypair.public_key(),
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
        let session_count = self.api.session_count().await?;
        let mut modules = BTreeMap::new();
        for (id, kind, module) in self.modules.iter_modules() {
            debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Preparing module backup");
            if module.supports_backup() {
                let backup = module.backup(id).await?;

                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Prepared module backup");
                modules.insert(id, backup);
            } else {
                info!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Module does not support backup");
            }
        }

        Ok(ClientBackup {
            metadata,
            modules,
            session_count,
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

    /// Upload `backup` to federation
    pub async fn upload_backup(&self, backup: EncryptedClientBackup) -> Result<()> {
        let size = backup.len();
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploading backup to federation"
        );
        let backup_request = backup.into_backup_request(&self.get_derived_backup_signing_key())?;
        self.api.upload_backup(&backup_request).await?;
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploaded backup to federation"
        );
        Ok(())
    }

    /// Restore client state from backup if provided or from scratch.
    ///
    /// This will restore (or initialize restoration process) in all sub-modules
    /// that support it.
    pub async fn restore_from_backup(&self, backup: Option<ClientBackup>) -> Result<Metadata> {
        info!(target: LOG_CLIENT_RECOVERY, "Restoring from backup");
        if backup.is_none() {
            warn!(
                target: LOG_CLIENT_RECOVERY,
                id=%self.get_backup_id(),
                "Existing backup not provided. Will attempt to restore from scratch. This might take a long time."
            );
        };

        let metadata = backup
            .as_ref()
            .map(|b| b.metadata.clone())
            .unwrap_or_else(Metadata::empty);

        for (id, kind, module) in self.modules.iter_modules() {
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
            module.restore(id, module_backup).await?;
        }

        Ok(metadata)
    }

    /// Download most recent valid backup found from the Federation
    pub async fn download_backup_from_federation(&self) -> Result<Option<ClientBackup>> {
        debug!(target: LOG_CLIENT, "Downloading backup from the federation");
        let mut responses: Vec<_> = self
            .api
            .download_backup(&self.get_backup_id())
            .await?
            .into_iter()
            .filter_map(|backup| {
                match EncryptedClientBackup(backup.data)
                    .decrypt_with(&self.get_derived_backup_encryption_key(), self.decoders())
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
        responses.sort_by_key(|backup| Reverse(backup.session_count));

        Ok(responses.into_iter().next())
    }

    /// Backup id derived from the root secret key (public key used to self-sign
    /// backup requests)
    pub fn get_backup_id(&self) -> secp256k1::PublicKey {
        self.get_derived_backup_signing_key().public_key()
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

#[cfg(test)]
mod tests;
