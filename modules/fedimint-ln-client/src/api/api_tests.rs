use std::pin::Pin;
use std::time::Duration;

use fedimint_api_client::api::{FederationError, FederationGeneralError, ServerError};
use fedimint_core::PeerId;
use futures::Future;

use super::{
    all_peer_query_results_are_connectivity, collect_all_peer_query_results_are_connectivity,
    original_failure_allows_reprobe,
};

type PeerResult = Result<serde_json::Value, ServerError>;

fn connection() -> PeerResult {
    Err(ServerError::Connection("no route".into()))
}

#[test]
fn original_mixed_or_general_failures_skip_reprobe() {
    let connectivity = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: None,
        peer_errors: [
            (PeerId::from(0), ServerError::Connection("offline".into())),
            (PeerId::from(1), ServerError::Transport("closed".into())),
        ]
        .into(),
    };
    let mixed = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: None,
        peer_errors: [
            (PeerId::from(0), ServerError::Connection("offline".into())),
            (
                PeerId::from(1),
                ServerError::ResponseDeserialization("wrong schema".into()),
            ),
        ]
        .into(),
    };
    let general = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: Some(FederationGeneralError::ThresholdFailed {
            message: "query failed".to_owned(),
        }),
        peer_errors: std::collections::BTreeMap::default(),
    };

    assert!(original_failure_allows_reprobe(&connectivity));
    assert!(!original_failure_allows_reprobe(&mixed));
    assert!(!original_failure_allows_reprobe(&general));
}

fn transport() -> PeerResult {
    Err(ServerError::Transport("connection closed".into()))
}

fn assert_not_connectivity(make_error: impl Fn() -> ServerError) {
    assert!(!all_peer_query_results_are_connectivity::<serde_json::Value>(&[Err(make_error())]));
    assert!(!all_peer_query_results_are_connectivity(&[
        connection(),
        Err(make_error()),
    ]));
}

#[test]
fn only_connectivity_failures_are_classified_as_unreachable() {
    assert!(all_peer_query_results_are_connectivity(&[
        connection(),
        transport(),
    ]));
    assert!(all_peer_query_results_are_connectivity(&[
        Ok(serde_json::Value::Null),
        connection(),
    ]));
    assert!(!all_peer_query_results_are_connectivity::<serde_json::Value>(&[]));
    assert!(!all_peer_query_results_are_connectivity(&[Ok(
        serde_json::Value::Null
    )]));

    assert_not_connectivity(|| ServerError::ServerError("server failed".into()));
    assert_not_connectivity(|| ServerError::InvalidRequest("invalid request".into()));
    assert_not_connectivity(|| ServerError::InvalidResponse("invalid response".into()));
    assert_not_connectivity(|| ServerError::ResponseDeserialization("malformed response".into()));
}

#[tokio::test]
async fn waits_for_slow_non_connectivity_failure_before_classifying() {
    let futures: Vec<Pin<Box<dyn Future<Output = PeerResult>>>> = vec![
        Box::pin(async { connection() }),
        Box::pin(async { transport() }),
        Box::pin(async {
            fedimint_core::task::sleep(Duration::from_millis(10)).await;
            Err(ServerError::ResponseDeserialization(
                "slow schema-invalid response".into(),
            ))
        }),
    ];
    assert!(
        !collect_all_peer_query_results_are_connectivity(futures).await,
        "the production collector must wait for and preserve the slow malformed response"
    );
}
