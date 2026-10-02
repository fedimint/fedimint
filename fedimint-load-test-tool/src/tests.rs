use std::io::Write;
use std::path::Path;

use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Decodable;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_mint_client::{OOBNotes, SpendableNote};

use super::{Command, Opts, resolve_input};

fn input_file(contents: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new_in(".").unwrap();
    file.write_all(contents).unwrap();
    file
}

fn invite() -> InviteCode {
    InviteCode::new(
        "wss://example.com".parse().unwrap(),
        0.into(),
        FederationId::dummy(),
        Some("access-secret-marker".to_owned()),
    )
}

#[test]
fn legacy_and_file_invites_and_notes_resolve_identically() {
    let invite = invite();
    // Reuse the mint client's fixed, non-live encoding fixture.
    let note = SpendableNote::consensus_decode_hex(
        "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd",
        &ModuleRegistry::default(),
    )
    .unwrap();
    let notes = OOBNotes::new(
        invite.federation_id().to_prefix(),
        [(Amount::from_sats(1), note)].into_iter().collect(),
    );
    let invite_file = input_file(format!("{invite}\r\n").as_bytes());
    let notes_file = input_file(format!("{notes}\n").as_bytes());
    for command in ["load-test", "ln-circular-load-test"] {
        let mut base = vec!["loadtool", command];
        if command == "ln-circular-load-test" {
            base.extend(["--strategy", "self-payment"]);
        }
        let invite_text = invite.to_string();
        let notes_text = notes.to_string();
        let mut direct = base.clone();
        direct.extend([
            "--invite-code",
            &invite_text,
            "--initial-notes",
            &notes_text,
        ]);
        let mut safe = base;
        safe.extend([
            "--invite-code-file",
            invite_file.path().to_str().unwrap(),
            "--initial-notes-file",
            notes_file.path().to_str().unwrap(),
        ]);
        for argv in [direct, safe] {
            let mut opts = Opts::try_parse_from(argv).unwrap();
            opts.command.resolve_inputs().unwrap();
            let inputs = match opts.command {
                Command::LoadTest(args) => args.inputs,
                Command::LnCircularLoadTest(args) => args.inputs,
                _ => panic!("wrong command"),
            };
            assert_eq!(inputs.resolved_invite.unwrap(), invite);
            assert_eq!(inputs.resolved_notes.unwrap().to_string(), notes_text);
        }
    }
}

#[test]
fn source_conflicts_and_multiple_stdin_are_rejected() {
    for command in ["load-test", "ln-circular-load-test"] {
        let mut base = vec!["loadtool", command];
        if command == "ln-circular-load-test" {
            base.extend(["--strategy", "self-payment"]);
        }
        for field in ["invite-code", "initial-notes"] {
            let mut argv = base.clone();
            let flag = format!("--{field}");
            let file_flag = format!("--{field}-file");
            argv.extend([&flag, "private-marker", &file_flag, "-"]);
            let error = Opts::try_parse_from(argv).err().unwrap().to_string();
            assert!(!error.contains("private-marker"));
        }
        base.extend(["--invite-code-file", "-", "--initial-notes-file", "-"]);
        let mut opts = Opts::try_parse_from(base).unwrap();
        assert!(opts.command.resolve_inputs().is_err());
    }
}

#[test]
fn connect_and_download_accept_file_sources_and_redact_parse_errors() {
    let invite_file = input_file(format!("{}\n", invite()).as_bytes());
    for command in ["test-connect", "test-download"] {
        let mut opts = Opts::try_parse_from([
            "loadtool",
            command,
            "--invite-code-file",
            invite_file.path().to_str().unwrap(),
        ])
        .unwrap();
        opts.command.resolve_inputs().unwrap();
        let mut opts =
            Opts::try_parse_from(["loadtool", command, "--invite-code", "private-marker"]).unwrap();
        let error = format!("{:#}", opts.command.resolve_inputs().unwrap_err());
        assert!(!error.contains("private-marker"));
    }
    for field in ["invite-code", "initial-notes"] {
        let flag = format!("--{field}-file");
        let file = input_file(b"private-marker\n");
        let mut opts = Opts::try_parse_from([
            "loadtool",
            "load-test",
            &flag,
            file.path().to_str().unwrap(),
        ])
        .unwrap();
        let error = format!("{:#}", opts.command.resolve_inputs().unwrap_err());
        assert!(!error.contains("private-marker"));
        assert!(!error.contains(&file.path().display().to_string()));
    }
}

#[test]
fn file_limits_and_utf8_are_enforced() {
    let file = input_file(&vec![b'a'; 1024 * 1024 + 1]);
    assert!(
        resolve_input::<InviteCode>(None, Some(file.path()), 1024 * 1024, "invite code").is_err()
    );
    let file = input_file(&vec![b'a'; 16 * 1024 * 1024 + 1]);
    assert!(
        resolve_input::<OOBNotes>(None, Some(file.path()), 16 * 1024 * 1024, "initial notes")
            .is_err()
    );
    let file = input_file(b"\xff");
    let error =
        resolve_input::<OOBNotes>(None, Some(file.path()), 16 * 1024 * 1024, "initial notes")
            .unwrap_err();
    assert!(!format!("{error:#}").contains(&file.path().display().to_string()));
    // Handler-level conflicts are rejected without attempting to read stdin.
    assert!(
        resolve_input::<OOBNotes>(
            Some("private-marker"),
            Some(Path::new("-")),
            16,
            "initial notes"
        )
        .is_err()
    );
}
