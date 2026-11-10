use clap::Parser;
use fedimint_core::core::OperationId;
use fedimint_ln_client::LnReceiveState;
use fedimint_ln_client::receive::LightningReceiveError;
use futures::stream;
use tokio::sync::mpsc;

use crate::{Opts, checked_total, validate_total_notes, wait_invoice_payment_updates};

const TEST_OPERATION_ID: OperationId = OperationId([0x49; 32]);

async fn wait_for_updates(updates: Vec<LnReceiveState>) -> (anyhow::Result<()>, Vec<String>) {
    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    let result = wait_invoice_payment_updates(
        "test",
        "test-gateway",
        TEST_OPERATION_ID,
        &event_sender,
        fedimint_core::time::now(),
        &mut stream::iter(updates),
    )
    .await;
    drop(event_sender);

    let mut metric_names = Vec::new();
    while let Some(event) = event_receiver.recv().await {
        metric_names.push(event.name);
    }

    (result, metric_names)
}

#[tokio::test]
async fn claimed_receive_succeeds_and_records_both_success_metrics() {
    let (result, metric_names) = wait_for_updates(vec![LnReceiveState::Claimed]).await;

    result.expect("claimed receive must succeed");
    assert_eq!(
        metric_names,
        [
            "gateway_payment_received_success",
            "gateway_test-gateway_payment_received_success"
        ]
    );
}

#[tokio::test]
async fn intermediate_receive_states_wait_for_claim() {
    let (result, metric_names) = wait_for_updates(vec![
        LnReceiveState::Created,
        LnReceiveState::Funded,
        LnReceiveState::AwaitingFunds,
        LnReceiveState::Claimed,
    ])
    .await;

    result.expect("eventually claimed receive must succeed");
    assert_eq!(metric_names.len(), 2);
}

#[tokio::test]
async fn canceled_receive_fails_with_reason_and_records_metric() {
    let (result, metric_names) = wait_for_updates(vec![LnReceiveState::Canceled {
        reason: LightningReceiveError::Timeout,
    }])
    .await;

    let error = result.expect_err("canceled receive must fail").to_string();
    assert!(error.contains("Incoming Lightning invoice was not paid within the timeout"));
    assert!(error.contains(&format!("{TEST_OPERATION_ID:?}")));
    assert!(error.contains("test-gateway"));
    assert_eq!(metric_names, ["gateway_payment_received_canceled"]);
}

#[tokio::test]
async fn receive_stream_end_before_claim_fails() {
    for updates in [
        vec![],
        vec![LnReceiveState::Created, LnReceiveState::AwaitingFunds],
    ] {
        let (result, metric_names) = wait_for_updates(updates).await;

        let error = result
            .expect_err("receive stream ending before claim must fail")
            .to_string();
        assert!(error.contains("ended before"));
        assert!(error.contains(&format!("{TEST_OPERATION_ID:?}")));
        assert!(error.contains("test-gateway"));
        assert!(metric_names.is_empty());
    }
}

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
