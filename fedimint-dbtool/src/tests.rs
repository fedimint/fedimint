use std::io::Write;
use std::path::Path;

use clap::Parser;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_server::core::ServerModuleInitRegistry;

use super::{FedimintDBTool, Options, resolve_hex_pair, resolve_hex_source};

fn input_file(contents: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new_in(".").unwrap();
    file.write_all(contents).unwrap();
    file
}

#[test]
fn hex_file_preserves_raw_database_framing() {
    let file = input_file(b"00ff1020\r\n");
    let direct = resolve_hex_source(Some("00ff1020"), None).unwrap();
    let from_file = resolve_hex_source(None, Some(file.path())).unwrap();
    assert_eq!(direct, from_file);
    assert_eq!(direct.as_ref(), &[0, 255, 16, 32]);
    assert!(resolve_hex_source(None, Some(input_file(b"00ff\n\n").path())).is_err());
}

#[test]
fn clap_sources_are_required_and_exclusive() {
    for command in ["list", "delete-prefix", "delete"] {
        let field = if command == "delete" { "key" } else { "prefix" };
        assert!(Options::try_parse_from(["dbtool", "--database-dir", "unused", command]).is_err());
        assert!(
            Options::try_parse_from([
                "dbtool",
                "--database-dir",
                "unused",
                command,
                &format!("--{field}"),
                "deadbeef",
                &format!("--{field}-file"),
                "unused",
            ])
            .is_err()
        );
        assert!(
            Options::try_parse_from([
                "dbtool",
                "--database-dir",
                "unused",
                command,
                &format!("--{field}-file"),
                "-",
            ])
            .is_ok()
        );
    }
    assert!(
        Options::try_parse_from([
            "dbtool",
            "--database-dir",
            "unused",
            "write",
            "--key",
            "00",
            "--value",
            "ff",
        ])
        .is_ok()
    );
}

#[tokio::test]
async fn rejects_multiple_stdin_and_bad_inputs_before_opening_database() {
    for args in [
        vec!["--key-file", "-", "--value-file", "-"],
        vec!["--key", "secret-not-hex", "--value", "00"],
        vec!["--key", "00", "--value-file", "/missing-secret-name"],
    ] {
        let mut argv = vec![
            "dbtool",
            "--database-dir",
            "/database-must-not-open",
            "write",
        ];
        argv.extend(args);
        let tool = FedimintDBTool {
            server_module_inits: ServerModuleInitRegistry::new(),
            client_module_inits: ClientModuleInitRegistry::new(),
            cli_args: Options::try_parse_from(argv).unwrap(),
        };
        let error = format!("{:#}", tool.run().await.unwrap_err());
        assert!(!error.contains("secret-not-hex"));
        assert!(!error.contains("missing-secret-name"));
    }
}

#[test]
fn malformed_file_errors_are_redacted() {
    for content in [b"secret-not-hex".as_slice(), b"\xff"] {
        let file = input_file(content);
        let error = format!(
            "{:#}",
            resolve_hex_source(None, Some(file.path())).unwrap_err()
        );
        assert!(!error.contains("secret-not-hex"));
        assert!(!error.contains(&file.path().display().to_string()));
    }
    assert!(resolve_hex_source(Some("00"), Some(Path::new("-"))).is_err());
    // Both source shape and stdin conflicts must fail before reading either.
    assert!(resolve_hex_pair(None, Some(Path::new("-")), None, None).is_err());
    assert!(
        resolve_hex_pair(Some("00"), Some(Path::new("-")), None, Some(Path::new("-"))).is_err()
    );
    let file = input_file(&vec![b'a'; 16 * 1024 * 1024 + 1]);
    assert!(resolve_hex_source(None, Some(file.path())).is_err());
}
