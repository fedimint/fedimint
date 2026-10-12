use clap::Parser;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_mint_client::{OOBNotes, SpendableNote};

use super::{ClientCmd, resolve_notes, resolve_notes_list};
use crate::cli::{Command, Opts};

// A real, non-empty serialized e-cash fixture shared by parser and loader
// tests.
fn notes() -> OOBNotes {
    let note = SpendableNote::consensus_decode_hex(
        "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd",
        &ModuleDecoderRegistry::default(),
    ).expect("Valid note fixture");
    OOBNotes::new(
        FederationId::dummy().to_prefix(),
        [(fedimint_core::Amount::from_msats(1), note)]
            .into_iter()
            .collect(),
    )
}

fn command(args: &[&str]) -> ClientCmd {
    let opts = Opts::try_parse_from(std::iter::once("fedimint-cli").chain(args.iter().copied()))
        .unwrap_or_else(|_| panic!("Command must parse without exposing input"));
    let Command::Client(command) = opts.command else {
        panic!("Expected client command");
    };
    command
}

#[test]
fn notes_file_parser_and_preflight() {
    for name in ["reissue", "split", "combine"] {
        let cmd = command(&[name, "--notes-file", "-"]);
        assert_eq!(cmd.notes_file_paths(), [std::path::Path::new("-")]);
        assert!(cmd.validate_notes_sources().is_ok());
        assert!(command(&[name]).validate_notes_sources().is_err());
        let encoded = notes().to_string();
        assert!(command(&[name, &encoded]).validate_notes_sources().is_ok());
        let error = command(&[name, &encoded, "--notes-file", "-"])
            .validate_notes_sources()
            .expect_err("Conflicting note sources");
        assert!(!format!("{error:#}").contains(&encoded));
    }
    assert!(
        command(&["combine", "--notes-file", "-", "--notes-file", "-"])
            .validate_notes_sources()
            .is_err()
    );
}

#[test]
fn notes_runtime_conflicts_are_redacted() {
    let notes = notes();
    let encoded = notes.to_string();
    let error =
        resolve_notes(Some(notes.clone()), Some("-".into())).expect_err("Conflicting note sources");
    assert!(!format!("{error:#}").contains(&encoded));
    assert!(resolve_notes_list(vec![notes], &["-".into()]).is_err());
    assert!(resolve_notes(None, None).is_err());
    assert!(resolve_notes_list(vec![], &[]).is_err());
}

#[test]
fn invalid_file_is_redacted() {
    let path = std::env::temp_dir().join(format!("legacy-mint-cli-{}", rand::random::<u64>()));
    fedimint_core::util::write_new(&path, "private-invalid-ecash").expect("Create test input");
    let error = resolve_notes(None, Some(path.clone())).expect_err("Invalid file must fail");
    assert_eq!(error.to_string(), "Invalid e-cash notes in secret input");
    assert!(!format!("{error:#}").contains("private-invalid-ecash"));
    for ending in ["", "\n", "\r\n"] {
        fedimint_core::util::write_overwrite(&path, format!("{}{ending}", notes()))
            .expect("Replace test input");
        assert_eq!(
            resolve_notes(None, Some(path.clone())).expect("Read test notes"),
            notes()
        );
        assert_eq!(
            resolve_notes_list(vec![], &[path.clone(), path.clone()])
                .expect("Read test notes")
                .len(),
            2
        );
    }
    std::fs::remove_file(path).expect("Remove test input");
}
