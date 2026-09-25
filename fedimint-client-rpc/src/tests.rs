//! Pins the response text the wasm SDK receives for a handful of cheap,
//! network-free failures, through the public `handle_rpc` entry point.
//!
//! Third-party error text (lightning-invoice, the invite-code parser's inner
//! cause, bip39) is never copied as a literal here: each such case renders
//! its own expected string from the same parse call the RPC makes, so the
//! test pins the chain's shape (fedimint's message, `": "`, the cause), not
//! upstream wording.

use std::sync::{Arc, Mutex};

use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::util::FmtCompact as _;

use crate::{
    HandledRpc, RpcGlobalState, RpcRequest, RpcRequestKind, RpcResponse, RpcResponseHandler,
};

/// Collects every response a request produces, in the order they arrive.
#[derive(Clone, Default)]
struct ResponseCollector(Arc<Mutex<Vec<RpcResponse>>>);

impl RpcResponseHandler for ResponseCollector {
    fn handle_response(&self, response: RpcResponse) {
        self.0.lock().expect("not poisoned").push(response);
    }
}

/// A state with an in-memory database and a connector registry that never
/// opens a connection: every case below fails before it would reach one.
async fn new_state() -> Arc<RpcGlobalState> {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .http(false)
        .bind()
        .await;

    Arc::new(RpcGlobalState::new(
        connectors,
        MemDatabase::default().into(),
    ))
}

/// Runs one request against a fresh state and returns every response it
/// produced, in order.
async fn run(kind: RpcRequestKind) -> Vec<RpcResponse> {
    let state = new_state().await;
    let collector = ResponseCollector::default();

    let HandledRpc { task } = state.handle_rpc(
        RpcRequest {
            request_id: 1,
            kind,
        },
        collector.clone(),
    );

    if let Some(task) = task {
        task.await;
    }

    collector.0.lock().expect("not poisoned").clone()
}

/// Asserts the first response is the serialized error the JS side receives.
fn assert_error_response(responses: &[RpcResponse], expected_error: &str) {
    let value = serde_json::to_value(&responses[0]).expect("a response always serializes");

    assert_eq!(
        value,
        serde_json::json!({
            "request_id": 1,
            "type": "error",
            "error": expected_error,
        }),
    );
}

#[tokio::test]
async fn no_mnemonic_set_is_a_plain_message() {
    // `OpenClient` checks the mnemonic before it touches the database or the
    // network, so it hits the same message a network operation would.
    let responses = run(RpcRequestKind::OpenClient {
        client_name: "irrelevant".to_string(),
    })
    .await;

    assert_error_response(
        &responses,
        "No wallet mnemonic set. Please set or generate a mnemonic first.",
    );
}

#[tokio::test]
async fn client_rpc_to_an_unknown_client_names_it() {
    let responses = run(RpcRequestKind::ClientRpc {
        client_name: "missing".to_string(),
        module: String::new(),
        method: String::new(),
        payload: serde_json::Value::Null,
    })
    .await;

    assert_error_response(&responses, "Client not found: missing");
}

#[tokio::test]
async fn closing_an_unknown_client_is_lower_case_and_unnamed() {
    let responses = run(RpcRequestKind::CloseClient {
        client_name: "missing".to_string(),
    })
    .await;

    assert_error_response(&responses, "client not found");
}

#[tokio::test]
async fn invalid_invoice_names_its_cause() {
    let cause = "not-an-invoice"
        .parse::<lightning_invoice::Bolt11Invoice>()
        .expect_err("not a valid invoice");

    let responses = run(RpcRequestKind::ParseBolt11Invoice {
        invoice: "not-an-invoice".to_string(),
    })
    .await;

    assert_error_response(
        &responses,
        &format!("Failed to parse Lightning invoice: {cause}"),
    );
}

#[tokio::test]
async fn invite_code_parse_failure_is_forwarded_unchanged() {
    let cause = "not-an-invite"
        .parse::<fedimint_core::invite_code::InviteCode>()
        .expect_err("not a valid invite code");

    let responses = run(RpcRequestKind::ParseInviteCode {
        invite_code: "not-an-invite".to_string(),
    })
    .await;

    assert_error_response(&responses, &cause.fmt_compact().to_string());
}

#[tokio::test]
async fn set_mnemonic_parse_failure_is_forwarded_unchanged() {
    let words = vec!["abandon".to_string()];
    let cause = fedimint_bip39::Mnemonic::parse_in_normalized(
        fedimint_bip39::Language::English,
        &words.join(" "),
    )
    .expect_err("wrong word count");

    let responses = run(RpcRequestKind::SetMnemonic { words }).await;

    assert_error_response(&responses, &cause.fmt_compact().to_string());
}
