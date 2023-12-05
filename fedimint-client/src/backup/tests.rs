use std::io::Cursor;

use anyhow::Result;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_derive_secret::DerivableSecret;

use crate::backup::{ClientBackup, Metadata};
use crate::Client;

#[test]
fn sanity_ecash_backup_align() {
    assert_eq!(ClientBackup::get_alignment_size(1), 16 * 1024);
    assert_eq!(ClientBackup::get_alignment_size(16 * 1024), 16 * 1024);
    assert_eq!(
        ClientBackup::get_alignment_size(16 * 1024 + 1),
        16 * 1024 * 2
    );
}

#[test]
fn sanity_ecash_backup_decode_encode() -> Result<()> {
    let orig = ClientBackup {
        session_count: 0,
        metadata: Metadata::from_raw(vec![1, 2, 3]),
        modules: Default::default(),
    };

    let encoded = orig.consensus_encode_to_vec();
    assert_eq!(encoded.len(), 16 * 1024);
    assert_eq!(
        orig,
        ClientBackup::consensus_decode(&mut Cursor::new(encoded), &Default::default())?
    );

    Ok(())
}

#[test]
fn sanity_ecash_backup_encrypt_decrypt() -> Result<()> {
    let orig = ClientBackup {
        modules: Default::default(),
        session_count: 1,
        metadata: Metadata::from_raw(vec![1, 2, 3]),
    };

    let secret = DerivableSecret::new_root(&[1; 32], &[1, 32]);
    let key = Client::get_derived_backup_encryption_key_static(&secret);

    let encrypted = orig.encrypt_to(&key)?;

    let decrypted = encrypted.decrypt_with(&key, &Default::default())?;

    assert_eq!(orig, decrypted);

    Ok(())
}
