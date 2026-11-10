use std::path::Path;

use bitcoin::secp256k1::SecretKey;
use clap::Parser;
use fedimint_core::hex;

use super::{
    CliCommandError, Opts, ensure_single_stdin, read_claim_sk, read_preimage, write_secret_key_file,
};

const SECRET_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);

    fedimint_core::util::write_new(&path, contents).expect("Failed to write the test file");

    path
}

#[test]
fn secrets_are_not_accepted_as_arguments() {
    for args in [
        vec!["lnv2", "htlc", "forfeit", "{}", SECRET_HEX],
        vec![
            "lnv2",
            "htlc",
            "claim",
            &"00".repeat(32),
            "{}",
            SECRET_HEX,
            SECRET_HEX,
        ],
        vec!["lnv2", "htlc", "new-claim-keypair"],
    ] {
        assert!(Opts::try_parse_from(args).is_err());
    }

    for args in [
        vec!["lnv2", "htlc", "forfeit", "{}", "--claim-sk-file", "-"],
        vec![
            "lnv2",
            "htlc",
            "claim",
            &"00".repeat(32),
            "{}",
            "--claim-sk-file",
            "sk",
            "--preimage-file",
            "-",
        ],
        vec![
            "lnv2",
            "htlc",
            "new-claim-keypair",
            "--secret-key-file",
            "sk",
        ],
    ] {
        assert!(Opts::try_parse_from(args).is_ok());
    }
}

#[test]
fn read_secrets_from_files() {
    let dir = tempfile::tempdir().expect("Failed to create a temporary directory");

    let claim_sk = read_claim_sk(&write_file(&dir, "sk", &format!("{SECRET_HEX}\n")))
        .expect("Failed to read the claim secret key");

    assert_eq!(claim_sk.display_secret().to_string(), SECRET_HEX);

    let preimage = read_preimage(&write_file(&dir, "preimage", &format!("{SECRET_HEX}\r\n")))
        .expect("Failed to read the preimage");

    assert_eq!(hex::encode(preimage), SECRET_HEX);
}

#[test]
fn invalid_secrets_are_not_echoed() {
    let dir = tempfile::tempdir().expect("Failed to create a temporary directory");

    let invalid = "zz".repeat(32);
    let path = write_file(&dir, "invalid", &invalid);

    for error in [
        read_claim_sk(&path).expect_err("Invalid secret key must be rejected"),
        read_preimage(&path).expect_err("Invalid preimage must be rejected"),
    ] {
        assert!(!error.to_string().contains(&invalid));
        assert!(!format!("{error:?}").contains(&invalid));
    }

    let too_long = write_file(&dir, "too-long", &format!("{SECRET_HEX}0000"));

    assert!(matches!(
        read_preimage(&too_long),
        Err(CliCommandError::SecretInput(_))
    ));

    let short = write_file(&dir, "short", "0101");

    assert!(matches!(
        read_preimage(&short),
        Err(CliCommandError::InvalidPreimageLength)
    ));
}

#[test]
fn only_one_input_may_read_stdin() {
    assert!(ensure_single_stdin(Path::new("-"), Path::new("-")).is_err());
    assert!(ensure_single_stdin(Path::new("-"), Path::new("preimage")).is_ok());
}

#[test]
fn secret_key_file_is_private_and_never_overwritten() {
    let dir = tempfile::tempdir().expect("Failed to create a temporary directory");
    let path = dir.path().join("sk");

    let secret_key = SecretKey::from_slice(&[1; 32]).expect("Valid secret key");

    write_secret_key_file(&path, &secret_key).expect("Failed to write the secret key file");

    assert_eq!(
        read_claim_sk(&path).expect("Failed to read back the secret key"),
        secret_key
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(&path)
            .expect("Failed to read the file metadata")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600);
    }

    let other_key = SecretKey::from_slice(&[2; 32]).expect("Valid secret key");

    assert!(write_secret_key_file(&path, &other_key).is_err());

    assert_eq!(
        read_claim_sk(&path).expect("Failed to read back the secret key"),
        secret_key
    );
}
