use clap::Parser;

use crate::{Opts, checked_total, validate_total_notes};

fn parse(args: &[&str]) -> Opts {
    Opts::try_parse_from(args).expect("test command line must parse")
}

fn assert_overflow(users: u16, notes_per_user: u16) {
    let error = checked_total(users, notes_per_user).expect_err("total must overflow");
    let message = error.to_string();
    assert!(message.contains(&format!("--users {users}")));
    assert!(message.contains(&format!("--notes-per-user {notes_per_user}")));
    assert!(message.contains("65535"));
}

#[test]
fn checked_total_accepts_defaults_and_boundaries() {
    assert_eq!(checked_total(10, 2).expect("load-test defaults fit"), 20);
    assert_eq!(
        checked_total(10, 1).expect("circular load-test defaults fit"),
        10
    );
    assert_eq!(
        checked_total(u16::MAX, 1).expect("maximum first factor fits"),
        u16::MAX
    );
    assert_eq!(
        checked_total(1, u16::MAX).expect("maximum second factor fits"),
        u16::MAX
    );
}

#[test]
fn checked_total_accepts_zero_factors() {
    for (users, notes_per_user) in [(0, 0), (0, u16::MAX), (u16::MAX, 0)] {
        assert_eq!(
            checked_total(users, notes_per_user).expect("zero-factor total fits"),
            0
        );
    }
}

#[test]
fn checked_total_rejects_overflowing_factors() {
    for (users, notes_per_user) in [(256, 256), (1000, 100), (u16::MAX, u16::MAX)] {
        assert_overflow(users, notes_per_user);
    }
}

#[test]
fn validates_load_test_command_before_setup() {
    let defaults = parse(&["fedimint-load-test-tool", "load-test"]);
    validate_total_notes(&defaults).expect("default load test must validate");

    let overflowing = parse(&[
        "fedimint-load-test-tool",
        "--users",
        "256",
        "load-test",
        "--notes-per-user",
        "256",
    ]);
    validate_total_notes(&overflowing).expect_err("overflowing load test must be rejected");
}

#[test]
fn validates_circular_load_test_command_before_setup() {
    let defaults = parse(&[
        "fedimint-load-test-tool",
        "ln-circular-load-test",
        "--strategy",
        "self-payment",
    ]);
    validate_total_notes(&defaults).expect("default circular load test must validate");

    let overflowing = parse(&[
        "fedimint-load-test-tool",
        "--users",
        "256",
        "ln-circular-load-test",
        "--notes-per-user",
        "256",
        "--strategy",
        "self-payment",
    ]);
    validate_total_notes(&overflowing)
        .expect_err("overflowing circular load test must be rejected");
}

#[test]
fn does_not_apply_note_total_rule_to_other_commands() {
    let test_connect = parse(&[
        "fedimint-load-test-tool",
        "--users",
        "65535",
        "test-connect",
        "--invite-code",
        "unused",
    ]);
    validate_total_notes(&test_connect).expect("test-connect has no note-total constraint");

    let test_download = parse(&[
        "fedimint-load-test-tool",
        "--users",
        "65535",
        "test-download",
        "--invite-code",
        "unused",
    ]);
    validate_total_notes(&test_download).expect("test-download has no note-total constraint");
}
