use std::str::FromStr as _;

use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiMethod;
use fedimint_core::util::SafeUrl;

use super::{
    IROH_REQUEST_TIMEOUT_DEFAULT, IROH_REQUEST_TIMEOUT_LONG_POLL, IrohConnector,
    request_timeout_for_method,
};
use crate::error::ConnectorError;
use crate::{iroh_next_endpoint_url, is_iroh_next_endpoint_url, preserve_iroh_next_marker};

const TEST_ENDPOINT_ID: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

#[test]
fn advertised_iroh_next_url_selects_only_the_next_stack() {
    let next_url = iroh_next_endpoint_url(TEST_ENDPOINT_ID).expect("valid endpoint ID");
    assert!(is_iroh_next_endpoint_url(&next_url).expect("valid Iroh API URL path"));

    let invite = InviteCode::new(next_url, PeerId::from(0), FederationId::dummy(), None);
    let round_tripped = InviteCode::from_str(&invite.to_string()).expect("invite code round-trips");
    assert!(is_iroh_next_endpoint_url(&round_tripped.url()).expect("valid Iroh API URL path"));

    let stable_url = SafeUrl::parse(&format!("iroh://{TEST_ENDPOINT_ID}")).expect("valid Iroh URL");
    assert!(!is_iroh_next_endpoint_url(&stable_url).expect("valid Iroh API URL path"));

    let replacement =
        SafeUrl::parse("iroh://d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .expect("valid replacement URL");
    let replacement = preserve_iroh_next_marker(&round_tripped.url(), &replacement);
    assert!(is_iroh_next_endpoint_url(&replacement).expect("valid Iroh API URL path"));
}

#[test]
fn unsupported_iroh_url_path_is_typed() {
    let url = SafeUrl::parse("iroh://someendpoint/v2").expect("valid url");
    assert!(
        matches!(
            is_iroh_next_endpoint_url(&url),
            Err(ConnectorError::UnsupportedUrlPath { .. })
        ),
        "{:?}",
        is_iroh_next_endpoint_url(&url)
    );
}

#[test]
fn garbage_endpoint_id_is_an_invalid_node_id() {
    let err =
        iroh_next_endpoint_url("not-an-endpoint-id").expect_err("garbage is not an endpoint id");
    assert!(
        matches!(err, ConnectorError::InvalidNodeId { .. }),
        "{err:?}"
    );
}

#[test]
fn a_non_iroh_url_has_an_unsupported_scheme() {
    let url = SafeUrl::parse("ws://example.com").expect("valid url");
    let err = IrohConnector::node_id_from_url(&url).expect_err("ws is not iroh");
    assert!(
        matches!(err, ConnectorError::UnsupportedScheme { .. }),
        "{err:?}"
    );
}

/// Every `await_*` endpoint currently exposed by fedimint modules
/// should be classified as long-poll. If a new endpoint is added
/// without the prefix it will silently fall through to the default
/// 60s budget — this list documents the contract and will surface
/// renames as test churn.
const AWAIT_ENDPOINTS: &[&str] = &[
    // fedimint-core
    "await_output_outcome",
    "await_outputs_outcomes",
    "await_session_outcome",
    "await_signed_session_outcome",
    "await_transaction",
    // fedimint-ln-common
    "await_account",
    "await_block_height",
    "await_offer",
    "await_outgoing_contract_cancelled",
    "await_preimage_decryption",
    // fedimint-lnv2-common
    "await_incoming_contract",
    "await_incoming_contracts",
    "await_preimage",
];

/// A representative sample of prompt endpoints — anything that is
/// expected to respond without server-side blocking.
const PROMPT_ENDPOINTS: &[&str] = &[
    "block_count",
    "session_count",
    "session_status",
    "status",
    "version",
    "client_config",
    "audit",
    "account",
    "offer",
    "list_gateways",
    "submit_transaction",
    "consensus_block_count",
];

#[test]
fn await_prefix_gets_long_poll_timeout() {
    for name in AWAIT_ENDPOINTS {
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
            IROH_REQUEST_TIMEOUT_LONG_POLL,
            "core endpoint {name} should map to the long-poll timeout"
        );
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Module(0, (*name).to_owned())),
            IROH_REQUEST_TIMEOUT_LONG_POLL,
            "module endpoint {name} should map to the long-poll timeout"
        );
    }
}

#[test]
fn wait_prefix_also_gets_long_poll_timeout() {
    // No fedimint endpoint currently uses this prefix, but the
    // selector accepts it so future additions following the
    // alternate naming convention don't silently get the default.
    assert_eq!(
        request_timeout_for_method(&ApiMethod::Core("wait_for_event".to_owned())),
        IROH_REQUEST_TIMEOUT_LONG_POLL,
    );
}

#[test]
fn prompt_endpoints_get_default_timeout() {
    for name in PROMPT_ENDPOINTS {
        assert_eq!(
            request_timeout_for_method(&ApiMethod::Core((*name).to_owned())),
            IROH_REQUEST_TIMEOUT_DEFAULT,
            "endpoint {name} should map to the default timeout"
        );
    }
}

#[test]
fn endpoints_that_merely_contain_await_are_not_misclassified() {
    // The selector is prefix-based, so an endpoint name with
    // "await" elsewhere in the string must not get the long
    // budget by accident.
    assert_eq!(
        request_timeout_for_method(&ApiMethod::Core("submit_await_thing".to_owned())),
        IROH_REQUEST_TIMEOUT_DEFAULT,
    );
}
