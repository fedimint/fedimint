//! Backup and recovery of ecash notes
//!
//! Ecash backup is implemented by periodically taking a snapshot,
//! self-encrypting it and uploading it to federation.
//!
//! Recovery is done by deriving deterministic ecash nonces and checking,
//! them with federation. A successfully recovered snapshot can be used
//! to avoid having to scan the whole history.

use std::collections::BTreeMap;

use anyhow::Result;
use fedimint_api::{
    backup::{BackupRequest, SignedBackupRequest},
    core::Decoder,
};

use super::*;

const BACKUP_CHILD_ID: u64 = 0;

/// Some helpers to make `ring::aead` usable
mod aead {
    use anyhow::{bail, Result};
    use rand::rngs::OsRng;
    use rand::Rng;
    use ring::aead::Nonce;
    pub use ring::aead::{Aad, LessSafeKey, UnboundKey, NONCE_LEN};

    /// Get a random nonce.
    pub fn get_random_nonce() -> ring::aead::Nonce {
        Nonce::assume_unique_for_key(OsRng.gen())
    }

    /// Encrypt `plaintext` using `key`.
    ///
    /// Prefixes the ciphertext with a nonce.
    pub fn encrypt(mut plaintext: Vec<u8>, key: &LessSafeKey) -> Result<Vec<u8>> {
        let nonce = get_random_nonce();
        // prefix ciphertext with nonce
        let mut ciphertext: Vec<u8> = nonce.as_ref().to_vec();

        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
            .map_err(|_| anyhow::format_err!("Encryption failed due to unspecified aead error"))?;

        ciphertext.append(&mut plaintext);

        Ok(ciphertext)
    }

    /// Decrypts a `ciphertext` using `key`.
    ///
    /// Expect nonce in the prefix, like [`encrypt`] produces.
    pub fn decrypt<'c>(ciphertext: &'c mut [u8], key: &LessSafeKey) -> Result<&'c [u8]> {
        if ciphertext.len() < NONCE_LEN {
            bail!("Ciphertext too short: {}", ciphertext.len());
        }

        let (nonce_bytes, encrypted_bytes) = ciphertext.split_at_mut(NONCE_LEN);

        key.open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes.try_into().expect("nonce size known")),
            Aad::empty(),
            encrypted_bytes,
        )
        .map_err(|_| anyhow::format_err!("Decryption failed due to unspecified aead error"))?;

        Ok(encrypted_bytes)
    }
}

impl MintClient {
    /// Prepare an encrypted backup and send it to federation for storing
    pub async fn back_up_ecash_to_federation(&self) -> Result<()> {
        let backup = self.prepare_ecash_backup().await?;

        self.upload_ecash_backup(backup).await?;

        Ok(())
    }

    pub async fn download_ecash_backup_from_federation(&self) -> Result<PlaintextEcashBackup> {
        let encrypted = self
            .context
            .api
            .download_ecash_backup(&self.get_derived_backup_signing_key().x_only_public_key().0)
            .await?;

        EcashBackup(encrypted).decrypt_with(&self.get_derived_backup_encryption_key())
    }

    /// Static version of [`Self::get_derived_backup_encryption_key`] for testing without creating whole `MintClient`
    fn get_derived_backup_encryption_key_static(secret: &DerivableSecret) -> aead::LessSafeKey {
        // TODO: Do we need that one derivation level? This key is already derived for the mint itself, and internally another kdf will be done with key type tag.
        aead::LessSafeKey::new(
            secret
                .child_key(ChildId(BACKUP_CHILD_ID))
                .to_chacha20_poly1305_key(),
        )
    }

    /// Static version of [`Self::get_derived_backup_signing_key`] for testing without creating whole `MintClient`
    fn get_derived_backup_signing_key_static(secret: &DerivableSecret) -> secp256k1_zkp::KeyPair {
        // TODO: Do we need that one derivation level? This key is already derived for the mint itself, and internally another kdf will be done with key type tag.
        secret
            .child_key(ChildId(BACKUP_CHILD_ID))
            .to_secp_key(&Secp256k1::<secp256k1::SignOnly>::gen_new())
    }

    fn get_derived_backup_encryption_key(&self) -> aead::LessSafeKey {
        Self::get_derived_backup_encryption_key_static(&self.secret)
    }

    fn get_derived_backup_signing_key(&self) -> secp256k1::KeyPair {
        Self::get_derived_backup_signing_key_static(&self.secret)
    }

    async fn prepare_plaintext_ecash_backup(&self) -> Result<PlaintextEcashBackup> {
        // fetch consensus height first - so we dont miss anything when scanning
        let epoch = self.context.api.fetch_last_epoch().await?;

        let mut dbtx = self.start_dbtx();
        let notes = self.get_available_notes(&mut dbtx).await;
        let mut note_idxs = Vec::new();
        for &amount in self.config.tbs_pks.tiers() {
            note_idxs.push((amount, self.get_last_note_index(&mut dbtx, amount).await));
        }
        let last_idx = Tiered::from_iter(note_idxs.into_iter());

        Ok(PlaintextEcashBackup {
            notes,
            last_idx,
            epoch,
        })
    }

    async fn prepare_ecash_backup(&self) -> Result<EcashBackup> {
        let plaintext = self.prepare_plaintext_ecash_backup().await?;
        plaintext.encrypt_to(&self.get_derived_backup_encryption_key())
    }

    async fn upload_ecash_backup(&self, backup: EcashBackup) -> Result<()> {
        let backup_request = backup.into_backup_request(&self.get_derived_backup_signing_key())?;
        self.context
            .api
            .upload_ecash_backup(&backup_request)
            .await?;
        Ok(())
    }
}

/// Snapshot of a ecash state (notes)
///
/// Used to speed up and improve privacy of ecash recovery,
/// by avoiding scanning the whole history.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct PlaintextEcashBackup {
    notes: TieredMulti<SpendableNote>,
    epoch: u64,
    last_idx: Tiered<NoteIndex>,
}

impl PlaintextEcashBackup {
    /// Align an ecoded message size up for better privacy
    fn get_alignment_size(len: usize) -> usize {
        // TODO: should we align to power of 2 instead?
        let padding_alignment = 16 * 1024;
        ((len.saturating_sub(1) / padding_alignment) + 1) * padding_alignment
    }

    /// Encode `self` to a padded (but still plaintext) message
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        self.consensus_encode(&mut bytes)?;

        let padding_size = Self::get_alignment_size(bytes.len()) - bytes.len();

        bytes.extend(std::iter::repeat(0u8).take(padding_size));

        Ok(bytes)
    }

    /// Decode from a plaintext (possibly aligned) message
    fn decode(msg: &[u8]) -> Result<Self> {
        Ok(Decodable::consensus_decode::<Decoder, _>(
            &mut &msg[..],
            &BTreeMap::new(),
        )?)
    }

    pub fn encrypt_to(&self, key: &aead::LessSafeKey) -> Result<EcashBackup> {
        let encoded = self.encode()?;

        let encrypted = aead::encrypt(encoded, key)?;
        Ok(EcashBackup(encrypted))
    }
}

/// Encrypted version of [`PlaintextEcashBackup`].
pub struct EcashBackup(Vec<u8>);

impl EcashBackup {
    pub fn decrypt_with(mut self, key: &aead::LessSafeKey) -> Result<PlaintextEcashBackup> {
        let decrypted = aead::decrypt(&mut self.0, key)?;
        PlaintextEcashBackup::decode(decrypted)
    }

    pub fn into_backup_request(self, keypair: &KeyPair) -> Result<SignedBackupRequest> {
        let request = BackupRequest {
            id: keypair.x_only_public_key().0,
            timestamp: std::time::SystemTime::now(),
            payload: self.0,
        };

        request.sign(keypair)
    }
}

#[cfg(test)]
mod tests;
