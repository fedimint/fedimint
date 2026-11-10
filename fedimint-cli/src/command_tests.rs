use std::io::Write;

use clap::Parser;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;

use super::cli::{Command, DecodeType, DevCmd, EncodeType, Opts};
use super::{CliOutput, FedimintCli, SALT_FILE, decrypt_config, encrypt_config};

/// Build a CLI with no database so local commands cannot accidentally open one.
fn local_cli() -> FedimintCli {
    let mut cli_args = Opts::try_parse_from(["fedimint-cli", "version-hash"]).expect("valid CLI");
    cli_args.data_dir = None;
    cli_args.federation_secret_hex = None;
    FedimintCli {
        module_inits: ClientModuleInitRegistry::new(),
        cli_args,
    }
}

#[tokio::test]
async fn invite_encoding_and_decoding_do_not_open_a_client() {
    let mut cli = local_cli();
    let url: SafeUrl = "wss://example.com".parse().expect("valid URL");
    let federation_id: FederationId = "00".repeat(32).parse().expect("valid ID");
    let mut opts = cli.cli_args.clone();
    opts.command = Command::Dev(DevCmd::Encode {
        encode_type: EncodeType::InviteCode {
            url: url.clone(),
            federation_id,
            peer: 3.into(),
            api_secret: Some("secret".to_owned()),
        },
    });
    let Ok(CliOutput::InviteCode {
        invite_code: encoded,
    }) = cli.handle_command(opts.clone()).await
    else {
        panic!("encoding must succeed without a database");
    };
    assert_eq!(encoded.api_secret().as_deref(), Some("secret"));
    opts.command = Command::Dev(DevCmd::Decode {
        decode_type: DecodeType::InviteCode {
            invite_code: encoded,
        },
    });
    match cli.handle_command(opts).await {
        Ok(CliOutput::DecodeInviteCode {
            url: decoded_url,
            federation_id: decoded_id,
        }) => {
            assert_eq!(decoded_url, url);
            assert_eq!(decoded_id, federation_id);
        }
        _ => panic!("decoding must succeed without a database"),
    }
}

#[tokio::test]
async fn malformed_transaction_is_rejected_before_opening_a_client() {
    let mut cli = local_cli();
    let mut opts = cli.cli_args.clone();
    opts.command = Command::Dev(DevCmd::Decode {
        decode_type: DecodeType::Transaction {
            hex_string: "not hex".to_owned(),
        },
    });
    match cli.handle_command(opts).await {
        Err(error) => assert!(error.error.starts_with("failed to decode transaction:")),
        Ok(_) => panic!("invalid transaction must fail"),
    }
}

#[tokio::test]
async fn join_secret_conflict_precedes_invite_parsing_and_database_access() {
    let mut cli = local_cli();
    let mut opts = cli.cli_args.clone();
    opts.federation_secret_hex = Some("invalid secret".to_owned());
    opts.command = Command::Join {
        invite_code: "invalid invite".to_owned(),
    };
    match cli.handle_command(opts).await {
        Err(error) => assert_eq!(
            error.error,
            "--federation-secret-hex cannot be used with join"
        ),
        Ok(_) => panic!("conflicting options must fail"),
    }
}

#[test]
fn config_crypto_uses_output_salt_for_encrypt_and_input_salt_for_decrypt() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let plaintext = dir.path().join("plain");
    let encrypted_dir = dir.path().join("encrypted");
    let restored_dir = dir.path().join("restored");
    std::fs::create_dir(&encrypted_dir).expect("encrypted directory");
    std::fs::create_dir(&restored_dir).expect("restored directory");
    std::fs::File::create_new(encrypted_dir.join(SALT_FILE))
        .expect("salt file")
        .write_all(b"test salt")
        .expect("salt");
    std::fs::File::create_new(&plaintext)
        .expect("plaintext file")
        .write_all(b"configuration")
        .expect("plaintext");
    let encrypted = encrypted_dir.join("config");
    let restored = restored_dir.join("config");
    assert!(encrypt_config(plaintext, encrypted.clone(), None, "password").is_ok());
    assert!(decrypt_config(encrypted, restored.clone(), None, "password").is_ok());
    assert_eq!(std::fs::read(restored).expect("restored"), b"configuration");
}
