use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::io::{Cursor, Write};

use anyhow::{Context, Result, bail, ensure};
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SignOnly};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_client_module::module::recovery::DynModuleBackup;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::core::backup::{
    BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES, BackupRequest, SignedBackupRequest,
};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::serde_json;
use fedimint_derive_secret::DerivableSecret;
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_BACKUP, LOG_CLIENT_RECOVERY};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::Client;
use crate::db::LastBackupKey;
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
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ClientBackup {
    /// Session count taken right before taking the backup
    /// used to timestamp the backup file. Used for finding the
    /// most recent backup from all available ones.
    ///
    /// Warning: Each particular module backup for each instance
    /// in `Self::modules` could have been taken earlier than
    /// that (e.g. older one used due to size limits), so modules
    /// MUST maintain their own `session_count`s.
    pub session_count: u64,
    /// Application metadata
    pub metadata: Metadata,
    // TODO: remove redundant ModuleInstanceId
    /// Module specific-backup (if supported)
    pub modules: BTreeMap<ModuleInstanceId, DynModuleBackup>,
}

impl Encodable for ClientBackup {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> std::result::Result<(), io::Error> {
        self.session_count.consensus_encode(writer)?;
        self.metadata.consensus_encode(writer)?;
        self.modules.consensus_encode(writer)?;

        // Old-style padding.
        //
        // Older version of the client used a custom zero-filled vec to
        // pad `ClientBackup` to alignment-size here. This has a problem
        // that the size of encoding of the padding can have different sizes
        // (due to var-ints).
        //
        // Conceptually serialization is also a the wrong place to do padding
        // anyway, so we moved padding to encrypt/decryption. But for abundance of
        // caution, we'll keep the old padding around, and always fill it
        // with an empty Vec.
        Vec::<u8>::new().consensus_encode(writer)?;

        Ok(())
    }
}

impl Decodable for ClientBackup {
    fn consensus_decode_partial<R: io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> std::result::Result<Self, DecodeError> {
        let session_count = u64::consensus_decode_partial(r, modules).context("session_count")?;
        let metadata = Metadata::consensus_decode_partial(r, modules).context("metadata")?;
        let module_backups =
            BTreeMap::<ModuleInstanceId, DynModuleBackup>::consensus_decode_partial(r, modules)
                .context("module_backups")?;
        let _padding = Vec::<u8>::consensus_decode_partial(r, modules).context("padding")?;

        Ok(Self {
            session_count,
            metadata,
            modules: module_backups,
        })
    }
}

impl ClientBackup {
    pub const PADDING_ALIGNMENT: usize = 4 * 1024;

    /// "32kiB is enough for any module backup" --dpc
    ///
    /// Federation storage is scarce, and since we can take older versions of
    /// the backup, temporarily going over the limit is not a big problem.
    pub const PER_MODULE_SIZE_LIMIT_BYTES: usize = 32 * 1024;

    /// Align an ecoded message size up for better privacy
    fn get_alignment_size(len: usize) -> usize {
        let padding_alignment = Self::PADDING_ALIGNMENT;
        ((len.saturating_sub(1) / padding_alignment) + 1) * padding_alignment
    }

    /// Encrypt with a key and turn into [`EncryptedClientBackup`]
    pub fn encrypt_to(&self, key: &fedimint_aead::LessSafeKey) -> Result<EncryptedClientBackup> {
        let mut encoded = Encodable::consensus_encode_to_vec(self);

        let alignment_size = Self::get_alignment_size(encoded.len());
        let padding_size = alignment_size - encoded.len();
        encoded.write_all(&vec![0u8; padding_size])?;

        let encrypted = fedimint_aead::encrypt(encoded, key)?;
        Ok(EncryptedClientBackup(encrypted))
    }

    /// Validate and fallback invalid parts of the backup
    ///
    /// Given the size constraints and possible 3rd party modules,
    /// it seems to use older, but smaller versions of backups when
    /// current ones do not fit (either globally or in per-module limit).
    fn validate_and_fallback_module_backups(
        self,
        last_backup: Option<&ClientBackup>,
    ) -> ClientBackup {
        // take all module ids from both backup and add them together
        let all_ids: BTreeSet<_> = self
            .modules
            .keys()
            .chain(last_backup.iter().flat_map(|b| b.modules.keys()))
            .copied()
            .collect();

        let mut modules = BTreeMap::new();
        for module_id in all_ids {
            if let Some(module_backup) = self
                .modules
                .get(&module_id)
                .or_else(|| last_backup.and_then(|lb| lb.modules.get(&module_id)))
            {
                let size = module_backup.consensus_encode_to_len();
                let limit = Self::PER_MODULE_SIZE_LIMIT_BYTES;
                if size < u64::try_from(limit).expect("Can't fail") {
                    modules.insert(module_id, module_backup.clone());
                } else if let Some(last_module_backup) =
                    last_backup.and_then(|lb| lb.modules.get(&module_id))
                {
                    let size_previous = last_module_backup.consensus_encode_to_len();
                    warn!(
                        target: LOG_CLIENT_BACKUP,
                        size,
                        limit,
                        %module_id,
                        size_previous,
                        "Module backup too large, will use previous version"
                    );
                    modules.insert(module_id, last_module_backup.clone());
                } else {
                    warn!(
                        target: LOG_CLIENT_BACKUP,
                        size,
                        limit,
                        %module_id,
                        "Module backup too large, no previous version available to fall-back to"
                    );
                }
            }
        }
        ClientBackup {
            session_count: self.session_count,
            metadata: self.metadata,
            modules,
        }
    }
}

/// Encrypted version of [`ClientBackup`].
#[derive(Clone)]
pub struct EncryptedClientBackup(Vec<u8>);

impl EncryptedClientBackup {
    pub fn decrypt_with(
        mut self,
        key: &fedimint_aead::LessSafeKey,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientBackup> {
        let decrypted = fedimint_aead::decrypt(&mut self.0, key)?;
        let mut cursor = Cursor::new(decrypted);
        // We specifically want to ignore the padding in the backup here.
        let client_backup = ClientBackup::consensus_decode_partial(&mut cursor, decoders)?;
        debug!(
            target: LOG_CLIENT_BACKUP,
            len = decrypted.len(),
            padding = u64::try_from(decrypted.len()).expect("Can't fail") - cursor.position(),
            "Decrypted client backup"
        );
        Ok(client_backup)
    }

    pub fn into_backup_request(self, keypair: &Keypair) -> Result<SignedBackupRequest> {
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

#[derive(Serialize, Deserialize)]
pub struct EventBackupDone;

impl Event for EventBackupDone {
    const MODULE: Option<fedimint_core::core::ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("backup-done");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

impl Client {
    /// Create a backup, include provided `metadata`
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    pub async fn create_backup(&self, metadata: Metadata) -> anyhow::Result<ClientBackup> {
        let session_count = self.api.session_count().await?;
        let mut modules = BTreeMap::new();
        for (id, kind, module) in self.modules.iter_modules() {
            debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Preparing module backup");
            if module.supports_backup() {
                let backup = module.backup(id).await?;

                debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Prepared module backup");
                modules.insert(id, backup);
            } else {
                debug!(target: LOG_CLIENT_BACKUP, module_id=id, module_kind=%kind, "Module does not support backup");
            }
        }

        Ok(ClientBackup {
            session_count,
            metadata,
            modules,
        })
    }

    async fn load_previous_backup(&self) -> Option<ClientBackup> {
        let mut dbtx = self.db().begin_transaction_nc().await;
        dbtx.get_value(&LastBackupKey).await
    }

    async fn store_last_backup(&self, backup: &ClientBackup) {
        let mut dbtx = self.db().begin_transaction().await;
        dbtx.insert_entry(&LastBackupKey, backup).await;
        dbtx.commit_tx().await;
    }

    /// Prepare an encrypted backup and send it to federation for storing
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    #[allow(deprecated)]
    pub async fn backup_to_federation(&self, metadata: Metadata) -> Result<()> {
        ensure!(
            !self.has_pending_recoveries(),
            "Cannot backup while there are pending recoveries"
        );

        let last_backup = self.load_previous_backup().await;
        let new_backup = self.create_backup(metadata).await?;

        let new_backup = new_backup.validate_and_fallback_module_backups(last_backup.as_ref());

        let encrypted = new_backup.encrypt_to(&self.get_derived_backup_encryption_key())?;

        self.validate_backup(&encrypted)?;

        self.store_last_backup(&new_backup).await;

        self.upload_backup(&encrypted).await?;

        self.log_event(None, EventBackupDone).await;

        Ok(())
    }

    /// Validate backup before sending it to federation
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    pub fn validate_backup(&self, backup: &EncryptedClientBackup) -> Result<()> {
        if BACKUP_REQUEST_MAX_PAYLOAD_SIZE_BYTES < backup.len() {
            bail!("Backup payload too large");
        }
        Ok(())
    }

    /// Upload `backup` to federation
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    #[allow(deprecated)]
    pub async fn upload_backup(&self, backup: &EncryptedClientBackup) -> Result<()> {
        self.validate_backup(backup)?;
        let size = backup.len();
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploading backup to federation"
        );
        let backup_request = backup
            .clone()
            .into_backup_request(&self.get_derived_backup_signing_key())?;
        self.api.upload_backup(&backup_request).await?;
        info!(
            target: LOG_CLIENT_BACKUP,
            size, "Uploaded backup to federation"
        );
        Ok(())
    }

    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    #[allow(deprecated)]
    pub async fn download_backup_from_federation(&self) -> Result<Option<ClientBackup>> {
        Self::download_backup_from_federation_static(
            &self.api,
            &self.root_secret(),
            self.decoders(),
        )
        .await
    }

    /// Download most recent valid backup found from the Federation
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    #[allow(deprecated)]
    pub async fn download_backup_from_federation_static(
        api: &DynGlobalApi,
        root_secret: &DerivableSecret,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<Option<ClientBackup>> {
        debug!(target: LOG_CLIENT, "Downloading backup from the federation");
        let mut responses: Vec<_> = api
            .download_backup(&Client::get_backup_id_static(root_secret))
            .await?
            .into_iter()
            .filter_map(|(peer, backup)| {
                match EncryptedClientBackup(backup?.data).decrypt_with(
                    &Self::get_derived_backup_encryption_key_static(root_secret),
                    decoders,
                ) {
                    Ok(valid) => Some(valid),
                    Err(e) => {
                        warn!(
                            target: LOG_CLIENT_RECOVERY,
                            "Invalid backup returned by {peer}: {e}"
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
    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    pub fn get_backup_id(&self) -> PublicKey {
        self.get_derived_backup_signing_key().public_key()
    }

    #[deprecated(note = "Backup functionality is removed in v0.13.0")]
    pub fn get_backup_id_static(root_secret: &DerivableSecret) -> PublicKey {
        Self::get_derived_backup_signing_key_static(root_secret).public_key()
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
    fn get_derived_backup_signing_key_static(secret: &DerivableSecret) -> Keypair {
        secret
            .derive_backup_secret()
            .to_secp_key(&Secp256k1::<SignOnly>::gen_new())
    }

    fn get_derived_backup_encryption_key(&self) -> fedimint_aead::LessSafeKey {
        Self::get_derived_backup_encryption_key_static(&self.root_secret())
    }

    fn get_derived_backup_signing_key(&self) -> Keypair {
        Self::get_derived_backup_signing_key_static(&self.root_secret())
    }

    pub async fn get_decoded_client_secret<T: Decodable>(&self) -> anyhow::Result<T> {
        crate::db::get_decoded_client_secret::<T>(self.db()).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use anyhow::Result;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleRegistry;
    use fedimint_derive_secret::DerivableSecret;

    use crate::Client;
    use crate::backup::{ClientBackup, Metadata};

    #[test]
    fn sanity_ecash_backup_align() {
        assert_eq!(
            ClientBackup::get_alignment_size(1),
            ClientBackup::PADDING_ALIGNMENT
        );
        assert_eq!(
            ClientBackup::get_alignment_size(ClientBackup::PADDING_ALIGNMENT),
            ClientBackup::PADDING_ALIGNMENT
        );
        assert_eq!(
            ClientBackup::get_alignment_size(ClientBackup::PADDING_ALIGNMENT + 1),
            ClientBackup::PADDING_ALIGNMENT * 2
        );
    }

    #[test]
    fn sanity_ecash_backup_decode_encode() -> Result<()> {
        let orig = ClientBackup {
            session_count: 0,
            metadata: Metadata::from_raw(vec![1, 2, 3]),
            modules: BTreeMap::new(),
        };

        let encoded = orig.consensus_encode_to_vec();
        assert_eq!(
            orig,
            ClientBackup::consensus_decode_whole(&encoded, &ModuleRegistry::default())?
        );

        Ok(())
    }

    #[test]
    fn sanity_ecash_backup_encrypt_decrypt() -> Result<()> {
        const ENCRYPTION_HEADER_LEN: usize = 28;

        let orig = ClientBackup {
            modules: BTreeMap::new(),
            session_count: 1,
            metadata: Metadata::from_raw(vec![1, 2, 3]),
        };

        let secret = DerivableSecret::new_root(&[1; 32], &[1, 32]);
        let key = Client::get_derived_backup_encryption_key_static(&secret);

        let empty_encrypted = fedimint_aead::encrypt(vec![], &key)?;
        assert_eq!(empty_encrypted.len(), ENCRYPTION_HEADER_LEN);

        let encrypted = orig.encrypt_to(&key)?;
        assert_eq!(
            encrypted.len(),
            ClientBackup::PADDING_ALIGNMENT + ENCRYPTION_HEADER_LEN
        );

        let decrypted = encrypted.decrypt_with(&key, &ModuleRegistry::default())?;

        assert_eq!(orig, decrypted);

        Ok(())
    }
}
