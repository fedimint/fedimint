use fedimint_core::core::OperationId;
use fedimint_ln_client::LnReceiveState;
use fedimint_ln_client::receive::LightningReceiveError;
use futures::stream;
use tokio::sync::mpsc;

use crate::wait_invoice_payment_updates;

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
