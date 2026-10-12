use bls12_381::G1Affine;
use clap::Parser;
use fedimint_core::TieredMulti;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use tbs::BlindedMessage;

use super::{
    BlindNonce, Nonce, OOBNotes, Opts, read_notes_file, resolve_nonce_argument, resolve_notes,
    resolve_notes_list,
};

fn notes() -> OOBNotes {
    let spend_key = fedimint_core::secp256k1::Keypair::from_seckey_slice(
        fedimint_core::secp256k1::SECP256K1,
        &[1; 32],
    )
    .unwrap();
    let note = crate::SpendableNote {
        spend_key,
        signature: tbs::Signature(G1Affine::generator()),
    };
    OOBNotes::new(
        FederationId::dummy().to_prefix(),
        [(fedimint_core::Amount::from_msats(1), note)]
            .into_iter()
            .collect::<TieredMulti<_>>(),
    )
}

#[test]
fn check_nonce_secret_source() {
    let encoded = notes().to_string();
    for args in [
        vec!["mint", "dev", "check-nonce", "--notes-file", "-"],
        vec!["mint", "dev", "check-nonce", &encoded],
        vec!["mint", "dev", "check-nonce", &encoded, "--notes-file", "-"],
    ] {
        assert!(Opts::try_parse_from(args).is_ok());
    }
    let error = resolve_nonce_argument(Some(encoded.clone()), Some("-".into())).unwrap_err();
    assert!(!format!("{error:?}").contains(&encoded));
    assert!(!error.to_string().contains(&encoded));
    assert!(resolve_nonce_argument(None, None).is_err());
    assert_eq!(
        resolve_nonce_argument(Some(encoded.clone()), None).unwrap(),
        encoded
    );
}

#[test]
fn secret_file_options_and_runtime_conflicts() {
    let encoded = notes().to_string();
    for command in ["reissue", "split", "validate"] {
        assert!(Opts::try_parse_from(["mint", command, "--notes-file", "-"]).is_ok());
        assert!(Opts::try_parse_from(["mint", command, &encoded]).is_ok());
        // Clap must not render a secret-containing positional in a conflict.
        assert!(Opts::try_parse_from(["mint", command, &encoded, "--notes-file", "-"]).is_ok());
    }
    assert!(
        Opts::try_parse_from(["mint", "combine", "--notes-file", "-", "--notes-file", "-"]).is_ok()
    );
    let error = resolve_notes(Some(notes()), Some("-".into())).unwrap_err();
    assert!(!format!("{error:?}").contains(&encoded));
    assert!(!error.to_string().contains(&encoded));
    assert!(resolve_notes(None, None).is_err());
    assert!(resolve_notes_list(vec![], &[]).is_err());
    assert!(resolve_notes_list(vec![notes()], &["-".into()]).is_err());
    assert!(resolve_notes_list(vec![], &["-".into(), "-".into()]).is_err());
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn secret_file_conversion_and_redaction() {
    let path = std::env::temp_dir().join(format!(
        "mint-cli-{}",
        fedimint_core::secp256k1::rand::random::<u64>()
    ));
    let encoded = notes().to_string();
    fedimint_core::util::write_new(&path, "").unwrap();
    for ending in ["", "\n", "\r\n"] {
        fedimint_core::util::write_overwrite(&path, format!("{encoded}{ending}")).unwrap();
        assert_eq!(read_notes_file(&path).unwrap().to_string(), encoded);
        assert_eq!(
            resolve_nonce_argument(None, Some(path.clone())).unwrap(),
            encoded
        );
        assert_eq!(
            resolve_notes_list(vec![], &[path.clone(), path.clone()])
                .unwrap()
                .len(),
            2
        );
    }
    fedimint_core::util::write_overwrite(&path, "private-invalid-notes").unwrap();
    // A semantic conflict wins over loading/parsing the invalid file.
    assert!(matches!(
        resolve_notes(Some(notes()), Some(path.clone())),
        Err(super::CliCommandError::ConflictingNotes)
    ));
    assert!(matches!(
        resolve_notes_list(vec![notes()], std::slice::from_ref(&path)),
        Err(super::CliCommandError::ConflictingNotes)
    ));
    assert!(matches!(
        resolve_nonce_argument(Some(encoded), Some(path.clone())),
        Err(super::CliCommandError::ConflictingNonceArgument)
    ));
    let error = read_notes_file(&path).unwrap_err();
    assert_eq!(error.to_string(), "Invalid e-cash notes in secret input");
    assert!(!format!("{error:?}").contains("private-invalid-notes"));
    assert_eq!(
        resolve_nonce_argument(None, Some(path.clone()))
            .unwrap_err()
            .to_string(),
        "Invalid e-cash notes in secret input"
    );
    fedimint_core::util::write_overwrite(&path, vec![b'x'; super::MAX_NOTES_BYTES + 1]).unwrap();
    assert!(read_notes_file(&path).is_err());
    std::fs::remove_file(path).unwrap();
}

/// The hex `dev check-nonce` accepts is the plain compressed public key, so
/// it matches what the JSON representation of a nonce shows.
#[test]
fn nonce_hex_round_trip() {
    let nonce_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let nonce = Nonce::consensus_decode_hex(nonce_hex, &ModuleDecoderRegistry::default())
        .expect("Valid compressed public key");

    assert_eq!(nonce.consensus_encode_to_hex(), nonce_hex);
}

/// Same for `dev check-blind-nonce` and the compressed G1 point.
#[test]
fn blind_nonce_hex_round_trip() {
    let blind_nonce = BlindNonce(BlindedMessage(G1Affine::generator()));
    let blind_nonce_hex = blind_nonce.consensus_encode_to_hex();

    assert_eq!(blind_nonce_hex.len(), 96);
    assert_eq!(
        BlindNonce::consensus_decode_hex(&blind_nonce_hex, &ModuleDecoderRegistry::default())
            .expect("Valid compressed G1 point"),
        blind_nonce
    );
}
