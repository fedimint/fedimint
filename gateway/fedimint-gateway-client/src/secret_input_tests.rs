use std::io::Write;

use clap::{CommandFactory, Parser};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::util::SafeUrl;
use fedimint_ln_common::client::GatewayApi;

use super::{Cli, CliOutput, Commands};
use crate::config_commands::ConfigCommands;
use crate::ecash_commands::EcashCommands;
use crate::general_commands::GeneralCommands;

fn secret_file(value: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(value.as_bytes()).unwrap();
    file
}

#[test]
fn clap_configuration_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn required_sources_and_legacy_arguments() {
    for args in [
        vec!["gateway-cli", "create-password-hash"],
        vec!["gateway-cli", "connect-fed"],
        vec!["gateway-cli", "ecash", "receive"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut cli = Cli::try_parse_from([
        "gateway-cli",
        "--rpcpassword",
        "legacy-password",
        "cfg",
        "set-mnemonic",
    ])
    .unwrap();
    cli.resolve_secret_inputs().unwrap();
    assert_eq!(cli.rpcpassword.as_deref(), Some("legacy-password"));
    assert!(matches!(
        cli.command,
        Commands::Cfg(ConfigCommands::SetMnemonic { words: None, .. })
    ));
}

#[test]
fn conflicting_sources_are_redacted_before_reading() {
    for args in [
        vec![
            "gateway-cli",
            "create-password-hash",
            "secret-marker",
            "--password-file",
            "-",
        ],
        vec![
            "gateway-cli",
            "connect-fed",
            "secret-marker",
            "--invite-code-file",
            "-",
        ],
        vec![
            "gateway-cli",
            "cfg",
            "set-mnemonic",
            "--words",
            "secret-marker",
            "--words-file",
            "-",
        ],
        vec![
            "gateway-cli",
            "ecash",
            "receive",
            "--notes",
            "secret-marker",
            "--notes-file",
            "-",
        ],
        vec![
            "gateway-cli",
            "--rpcpassword",
            "secret-marker",
            "--rpcpassword-file",
            "-",
            "info",
        ],
    ] {
        let mut cli = Cli::try_parse_from(args).unwrap();
        let error = cli.resolve_secret_inputs().unwrap_err().to_string();
        assert!(!error.contains("secret-marker"));
        assert!(error.contains("only one"));
    }
    let mut cli = Cli::try_parse_from([
        "gateway-cli",
        "--rpcpassword-file",
        "-",
        "create-password-hash",
        "--password-file",
        "-",
    ])
    .unwrap();
    assert!(cli.resolve_secret_inputs().is_err());
}

#[test]
fn file_values_reach_command_fields_without_truncation() {
    let file = secret_file(" first\nsecond \r\n");
    let path = file.path().to_str().unwrap();
    for command in [
        vec!["gateway-cli", "connect-fed", "--invite-code-file", path],
        vec!["gateway-cli", "cfg", "set-mnemonic", "--words-file", path],
        vec!["gateway-cli", "ecash", "receive", "--notes-file", path],
    ] {
        let mut cli = Cli::try_parse_from(command).unwrap();
        cli.resolve_secret_inputs().unwrap();
        let value = match cli.command {
            Commands::General(GeneralCommands::ConnectFed { invite_code, .. }) => invite_code,
            Commands::Cfg(ConfigCommands::SetMnemonic { words, .. }) => words,
            Commands::Ecash(EcashCommands::Receive { notes, .. }) => notes,
            _ => panic!("unexpected command"),
        };
        assert_eq!(value.as_deref(), Some(" first\nsecond "));
    }
    let mut cli = Cli::try_parse_from(["gateway-cli", "--rpcpassword-file", path, "info"]).unwrap();
    cli.resolve_secret_inputs().unwrap();
    assert_eq!(cli.rpcpassword.as_deref(), Some(" first\nsecond "));
}

#[tokio::test]
async fn password_file_reaches_hash_handler() {
    let file = secret_file(" first\nsecond \n");
    let mut cli = Cli::try_parse_from([
        "gateway-cli",
        "create-password-hash",
        "--password-file",
        file.path().to_str().unwrap(),
        "--cost",
        "4",
    ])
    .unwrap();
    cli.resolve_secret_inputs().unwrap();
    let Commands::General(command) = cli.command else {
        panic!("unexpected command");
    };
    let registry = ConnectorRegistry::build_from_client_defaults().bind().await;
    let client = GatewayApi::new(None, registry);
    let CliOutput::PasswordHash(hash) = command.handle(&client, &cli.address).await.unwrap() else {
        panic!("unexpected output");
    };
    assert!(bcrypt::verify(" first\nsecond ", &hash).unwrap());
    assert!(!bcrypt::verify(" first", &hash).unwrap());
}

#[tokio::test]
async fn file_values_reach_http_handlers() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    let file = secret_file(" first\nsecond \n");
    let password = secret_file("rpc-password\n");
    let path = file.path().to_str().unwrap();
    for (args, field) in [
        (vec!["cfg", "set-mnemonic", "--words-file", path], "words"),
        (vec!["ecash", "receive", "--notes-file", path], "notes"),
        (
            vec!["connect-fed", "--invite-code-file", path],
            "invite_code",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = fedimint_core::runtime::spawn("secret input test", async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            assert!(headers.to_ascii_lowercase().contains("authorization:"));
            // Assert the actual resolved password, not merely the presence
            // of some authorization header.
            assert!(headers.contains("Bearer rpc-password"));
            let content_length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse().ok())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let body: serde_json::Value = serde_json::from_slice(&request[header_end..]).unwrap();
            assert_eq!(body[field], " first\nsecond ");
            #[cfg(feature = "tor")]
            if field == "invite_code" {
                assert_eq!(body["use_tor"], true);
            }
            // A static failure response suffices: these tests verify the
            // serialized request, not server-side mnemonic/ecash validation.
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let mut argv = vec![
            "gateway-cli",
            "--rpcpassword-file",
            password.path().to_str().unwrap(),
        ];
        argv.extend(args);
        #[cfg(feature = "tor")]
        if field == "invite_code" {
            argv.extend(["--use-tor", "true"]);
        }
        let mut cli = Cli::try_parse_from(argv).unwrap();
        cli.resolve_secret_inputs().unwrap();
        let registry = ConnectorRegistry::build_from_testing_defaults()
            .bind()
            .await;
        let client = GatewayApi::new(cli.rpcpassword, registry);
        let base_url = SafeUrl::parse(&format!("http://{address}/")).unwrap();
        let result = match cli.command {
            Commands::General(command) => command.handle(&client, &base_url).await,
            Commands::Cfg(command) => command.handle(&client, &base_url).await,
            Commands::Ecash(command) => command.handle(&client, &base_url).await,
            _ => panic!("unexpected command"),
        };
        assert!(result.is_err());
        server.await.unwrap();
    }
}

#[cfg(feature = "tor")]
#[test]
fn tor_selection_preserves_legacy_and_file_forms() {
    let mut legacy =
        Cli::try_parse_from(["gateway-cli", "connect-fed", "invite-marker", "true"]).unwrap();
    legacy.resolve_secret_inputs().unwrap();
    assert!(matches!(
        legacy.command,
        Commands::General(GeneralCommands::ConnectFed {
            use_tor: Some(true),
            use_tor_option: None,
            ..
        })
    ));

    let mut conflict = Cli::try_parse_from([
        "gateway-cli",
        "connect-fed",
        "invite-marker",
        "true",
        "--use-tor",
        "false",
    ])
    .unwrap();
    let error = conflict.resolve_secret_inputs().unwrap_err().to_string();
    assert!(!error.contains("invite-marker"));
    assert!(error.contains("not both"));
}
