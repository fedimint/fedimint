use anyhow::Result;

use super::*;

#[test]
fn sanity_ecash_backup_align() {
    assert_eq!(PlaintextEcashBackup::get_alignment_size(1), 16 * 1024);
    assert_eq!(
        PlaintextEcashBackup::get_alignment_size(16 * 1024),
        16 * 1024
    );
    assert_eq!(
        PlaintextEcashBackup::get_alignment_size(16 * 1024 + 1),
        16 * 1024 * 2
    );
}

#[test]
fn sanity_ecash_backup_decode_encode() -> Result<()> {
    let orig = PlaintextEcashBackup {
        notes: TieredMulti::from_iter([]),
        next_note_idx: Tiered::from_iter(
            [(Amount::from_milli_sats(1), NoteIndex::from_u64(3))].into_iter(),
        ),
        epoch: 0,
    };

    let encoded = orig.encode()?;
    assert_eq!(encoded.len(), 16 * 1024);
    assert_eq!(orig, PlaintextEcashBackup::decode(&encoded)?);

    Ok(())
}

#[test]
fn sanity_ecash_backup_encrypt_decrypt() -> Result<()> {
    let orig = PlaintextEcashBackup {
        notes: TieredMulti::from_iter([]),
        next_note_idx: Tiered::from_iter(
            [(Amount::from_milli_sats(1), NoteIndex::from_u64(3))].into_iter(),
        ),
        epoch: 1,
    };

    let secret = DerivableSecret::new_root(&[1; 32], &[1, 32]);
    let key = MintClient::get_derived_backup_encryption_key_static(&secret);

    let encrypted = orig.encrypt_to(&key)?;

    let decrypted = encrypted.decrypt_with(&key)?;

    assert_eq!(orig, decrypted);

    Ok(())
}
