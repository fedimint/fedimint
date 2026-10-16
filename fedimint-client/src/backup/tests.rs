use std::collections::BTreeMap;

use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
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
fn sanity_ecash_backup_decode_encode() -> Result<(), DecodeError> {
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
fn sanity_ecash_backup_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
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
