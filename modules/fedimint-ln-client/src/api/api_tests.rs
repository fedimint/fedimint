use std::pin::Pin;
use std::time::Duration;

use anyhow::anyhow;
use fedimint_api_client::api::{FederationError, ServerError};
use fedimint_core::PeerId;
use futures::Future;

use super::{
    all_peer_query_results_are_connectivity, collect_all_peer_query_results_are_connectivity,
    original_failure_allows_reprobe,
};

type PeerResult = Result<serde_json::Value, ServerError>;

fn connection() -> PeerResult {
    Err(ServerError::Connection(anyhow!("no route")))
}

#[test]
fn original_mixed_or_general_failures_skip_reprobe() {
    let connectivity = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: None,
        peer_errors: [
            (PeerId::from(0), ServerError::Connection(anyhow!("offline"))),
            (PeerId::from(1), ServerError::Transport(anyhow!("closed"))),
        ]
        .into(),
    };
    let mixed = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: None,
        peer_errors: [
            (PeerId::from(0), ServerError::Connection(anyhow!("offline"))),
            (
                PeerId::from(1),
                ServerError::ResponseDeserialization(anyhow!("wrong schema")),
            ),
        ]
        .into(),
    };
    let general = FederationError {
        method: "account".to_owned(),
        params: serde_json::Value::Null,
        general: Some(anyhow!("query failed")),
        peer_errors: std::collections::BTreeMap::default(),
    };

    assert!(original_failure_allows_reprobe(&connectivity));
    assert!(!original_failure_allows_reprobe(&mixed));
    assert!(!original_failure_allows_reprobe(&general));
}

fn transport() -> PeerResult {
    Err(ServerError::Transport(anyhow!("connection closed")))
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

    assert_not_connectivity(|| ServerError::ServerError(anyhow!("server failed")));
    assert_not_connectivity(|| ServerError::InvalidRequest(anyhow!("invalid request")));
    assert_not_connectivity(|| ServerError::InvalidResponse(anyhow!("invalid response")));
    assert_not_connectivity(|| ServerError::ResponseDeserialization(anyhow!("malformed response")));
}

#[tokio::test]
async fn waits_for_slow_non_connectivity_failure_before_classifying() {
    let futures: Vec<Pin<Box<dyn Future<Output = PeerResult>>>> = vec![
        Box::pin(async { connection() }),
        Box::pin(async { transport() }),
        Box::pin(async {
            fedimint_core::task::sleep(Duration::from_millis(10)).await;
            Err(ServerError::ResponseDeserialization(anyhow!(
                "slow schema-invalid response"
            )))
        }),
    ];
    assert!(
        !collect_all_peer_query_results_are_connectivity(futures).await,
        "the production collector must wait for and preserve the slow malformed response"
    );
}
