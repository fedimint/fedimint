use clap::Parser;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Encodable;

use super::{ECash, FEDIMINT_PREFIX, Opts, base32, resolve_ecash};

fn ecash() -> ECash {
    ECash::new(FederationId::dummy(), vec![])
}

#[test]
fn secret_file_option_and_runtime_conflicts() {
    let encoded = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash());
    assert!(Opts::try_parse_from(["mintv2", "receive", "--ecash-file", "-"]).is_ok());
    assert!(Opts::try_parse_from(["mintv2", "receive", &encoded]).is_ok());
    assert!(Opts::try_parse_from(["mintv2", "receive", &encoded, "--ecash-file", "-"]).is_ok());
    let error = resolve_ecash(Some(encoded.clone()), Some("-".into())).unwrap_err();
    assert!(!error.to_string().contains(&encoded));
    assert!(!format!("{error:?}").contains(&encoded));
    assert!(resolve_ecash(None, None).is_err());
    assert_eq!(
        resolve_ecash(Some(encoded), None)
            .unwrap()
            .consensus_encode_to_hex(),
        ecash().consensus_encode_to_hex()
    );
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn secret_file_conversion_and_redaction() {
    let path = std::env::temp_dir().join(format!("mintv2-cli-{}", rand::random::<u64>()));
    let encoded = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash());
    fedimint_core::util::write_new(&path, "").unwrap();
    for ending in ["", "\n", "\r\n"] {
        fedimint_core::util::write_overwrite(&path, format!("{encoded}{ending}")).unwrap();
        assert_eq!(
            resolve_ecash(None, Some(path.clone()))
                .unwrap()
                .consensus_encode_to_hex(),
            ecash().consensus_encode_to_hex()
        );
    }
    fedimint_core::util::write_overwrite(&path, "private-invalid-ecash").unwrap();
    assert!(matches!(
        resolve_ecash(Some(encoded), Some(path.clone())),
        Err(super::CliCommandError::ConflictingEcash)
    ));
    let error = resolve_ecash(None, Some(path.clone())).unwrap_err();
    assert_eq!(error.to_string(), "Invalid e-cash in secret input");
    assert!(!format!("{error:?}").contains("private-invalid-ecash"));
    fedimint_core::util::write_overwrite(&path, vec![b'x'; 16 * 1024 * 1024 + 1]).unwrap();
    assert!(resolve_ecash(None, Some(path.clone())).is_err());
    std::fs::remove_file(path).unwrap();
}
