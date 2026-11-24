#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

use clap::{CommandFactory, Parser};

use super::check_module_stdin;
use crate::cli::{AdminCmd, Command, DecodeType, DevCmd, EncodeType, Opts};
use crate::client::ClientCmd;

struct SecretFile(PathBuf);

impl SecretFile {
    fn new(contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "fedimint-secret-input-test-{}",
            rand::random::<u128>()
        ));
        std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap()
            .write_all(contents)
            .unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn parse(args: &[&str]) -> Opts {
    Opts::try_parse_from(std::iter::once("fedimint-cli").chain(args.iter().copied())).unwrap()
}

#[test]
fn resolves_global_and_restore_sources() {
    let file = SecretFile::new(b" sensitive words \r\n");
    let mut opts = parse(&["--password-file", file.path(), "info"]);
    opts.resolve_secret_inputs().unwrap();
    assert_eq!(opts.password.as_deref(), Some(" sensitive words "));
    let mut opts = parse(&["--federation-secret-hex-file", file.path(), "info"]);
    opts.resolve_secret_inputs().unwrap();
    assert_eq!(
        opts.federation_secret_hex.as_deref(),
        Some(" sensitive words ")
    );

    let mut opts = parse(&[
        "restore",
        "--mnemonic-file",
        file.path(),
        "--invite-code",
        "test-invite",
    ]);
    opts.resolve_secret_inputs().unwrap();
    let Command::Client(ClientCmd::Restore { mnemonic, .. }) = opts.command else {
        panic!("expected restore");
    };
    assert_eq!(mnemonic.as_deref(), Some(" sensitive words "));
}

#[test]
fn resolves_command_sources() {
    let file = SecretFile::new(b"sensitive-input\n");
    for args in [
        vec!["join", "--invite-code-file", file.path()],
        vec![
            "admin",
            "auth",
            "--peer-id",
            "0",
            "--password-file",
            file.path(),
        ],
        vec![
            "dev",
            "config-encrypt",
            "--in-file",
            "input",
            "--out-file",
            "output",
            "--password-file",
            file.path(),
        ],
        vec![
            "dev",
            "config-decrypt",
            "--in-file",
            "input",
            "--out-file",
            "output",
            "--password-file",
            file.path(),
        ],
        vec!["dev", "decode", "notes", "--file", file.path()],
        vec![
            "dev",
            "decode",
            "invite-code",
            "--invite-code-file",
            file.path(),
        ],
        vec!["dev", "encode", "notes", "--notes-json-file", file.path()],
        vec![
            "dev",
            "query-federation-ips",
            "--invite-code-file",
            file.path(),
        ],
        vec!["dev", "api", "method", "--params-file", file.path()],
        vec![
            "dev",
            "api",
            "--peer-id",
            "0",
            "--password-file",
            file.path(),
            "method",
        ],
        vec![
            "dev",
            "encode",
            "invite-code",
            "--url",
            "ws://localhost:8174",
            "--peer",
            "0",
            "--federation_id",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--api-secret-file",
            file.path(),
        ],
    ] {
        let mut opts = parse(&args);
        opts.resolve_secret_inputs().unwrap();
        let value = match opts.command {
            Command::Join { invite_code, .. } => invite_code,
            Command::Admin(AdminCmd::Auth { password, .. }) => password,
            Command::Dev(command) => match command {
                DevCmd::ConfigEncrypt { password, .. } | DevCmd::ConfigDecrypt { password, .. } => {
                    password
                }
                DevCmd::QueryFederationIps { invite_code, .. } => invite_code,
                DevCmd::Api {
                    params, password, ..
                } => params.or(password),
                DevCmd::Decode { decode_type } => match decode_type {
                    DecodeType::Notes { notes, .. } => notes,
                    DecodeType::InviteCode { invite_code, .. } => invite_code,
                    _ => panic!("unexpected decode command"),
                },
                DevCmd::Encode { encode_type } => match encode_type {
                    EncodeType::Notes { notes_json, .. } => notes_json,
                    EncodeType::InviteCode { api_secret, .. } => api_secret,
                },
                _ => panic!("unexpected dev command"),
            },
            _ => panic!("unexpected command"),
        };
        assert_eq!(value.as_deref(), Some("sensitive-input"));
    }
}

#[test]
fn rejects_conflicts_without_reading_or_echoing_values() {
    for args in [
        vec![
            "--password",
            "sensitive-input",
            "--password-file",
            "/nonexistent",
            "info",
        ],
        vec![
            "join",
            "sensitive-input",
            "--invite-code-file",
            "/nonexistent",
        ],
        vec![
            "dev",
            "encode",
            "notes",
            "sensitive-input",
            "--notes-json-file",
            "/nonexistent",
        ],
        vec![
            "--federation-secret-hex-file",
            "-",
            "restore",
            "--mnemonic-file",
            "-",
            "--invite-code",
            "sensitive-input",
        ],
    ] {
        let error = parse(&args).resolve_secret_inputs().unwrap_err();
        assert!(!format!("{error:#}").contains("sensitive-input"));
        assert!(!format!("{error:#}").contains("Could not open"));
    }
}

#[test]
fn rejects_multiple_stdin_sources_before_reading() {
    let mut opts = parse(&[
        "--password-file",
        "-",
        "restore",
        "--mnemonic-file",
        "-",
        "--invite-code",
        "test-invite",
    ]);
    let error = opts.resolve_secret_inputs().unwrap_err();
    assert!(error.to_string().contains("Only one"));
    for command in ["reissue", "split", "combine"] {
        let mut opts = parse(&["--password-file", "-", command, "--notes-file", "-"]);
        assert!(
            opts.resolve_secret_inputs()
                .unwrap_err()
                .to_string()
                .contains("Only one")
        );
    }

    for module_args in [
        vec!["--notes-file", "-"],
        vec!["--notes-file=-"],
        vec!["--ecash-file", "-"],
        vec!["--ecash-file=-"],
    ] {
        let mut args = vec!["--password-file", "-", "module", "mint", "reissue"];
        args.extend(module_args);
        assert!(check_module_stdin(&parse(&args)).is_err());
    }
    assert!(
        check_module_stdin(&parse(&[
            "module",
            "mint",
            "combine",
            "--notes-file",
            "-",
            "--notes-file=-",
        ]))
        .is_err()
    );
}

#[test]
fn required_sources_and_legacy_inputs() {
    for args in [
        vec!["join"],
        vec!["admin", "auth", "--peer-id", "0"],
        vec!["dev", "decode", "notes"],
        vec!["dev", "encode", "notes"],
        vec!["--password-file", "-", "restore", "--invite-code", "test"],
    ] {
        assert!(parse(&args).resolve_secret_inputs().is_err());
    }
    let mut opts = parse(&["--password", "legacy", "join", "legacy-invite"]);
    opts.resolve_secret_inputs().unwrap();
    assert_eq!(opts.password.as_deref(), Some("legacy"));
}

#[test]
fn actual_environment_conflicts_with_file_source() {
    const CHILD: &str = "FM_SECRET_INPUT_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut opts = parse(&["--password-file", "/nonexistent", "info"]);
        assert_eq!(opts.password.as_deref(), Some("sensitive-env"));
        assert!(
            !Opts::command()
                .render_long_help()
                .to_string()
                .contains("sensitive-env")
        );
        let error = opts.resolve_secret_inputs().unwrap_err();
        assert!(!format!("{error:#}").contains("sensitive-env"));
        assert!(!format!("{error:#}").contains("Could not open"));
        return;
    }
    // Isolate environment mutation in a child process instead of changing the
    // environment of concurrent tests.
    let status = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("secret_input::tests::actual_environment_conflicts_with_file_source")
        .env(CHILD, "1")
        .env(crate::envs::FM_PASSWORD_API_ENV, "sensitive-env")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn actual_stdin_source_preserves_password_whitespace() {
    const CHILD: &str = "FM_SECRET_INPUT_STDIN_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut opts = parse(&["--password-file", "-", "info"]);
        opts.resolve_secret_inputs().unwrap();
        assert_eq!(opts.password.as_deref(), Some(" sensitive password "));
        return;
    }
    let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("secret_input::tests::actual_stdin_source_preserves_password_whitespace")
        .env(CHILD, "1")
        .env_remove(crate::envs::FM_PASSWORD_API_ENV)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b" sensitive password \r\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn secret_decoding_errors_are_redacted() {
    let error = crate::decode_federation_secret_hex("sensitive-not-hex").unwrap_err();
    assert!(!format!("{error:?}").contains("sensitive-not-hex"));
}
