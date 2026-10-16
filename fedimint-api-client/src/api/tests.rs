use std::collections::BTreeMap;
use std::error::Error as _;
use std::str::FromStr as _;

use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt as _, PeerId};

use crate::api::{ClientConfigDownloadError, FederationError, FederationGeneralError};

#[test]
fn converts_invite_code() {
    let connect = InviteCode::new(
        "ws://test1".parse().unwrap(),
        PeerId::from(1),
        FederationId::dummy(),
        Some("api_secret".into()),
    );

    let bech32 = connect.to_string();
    let connect_parsed = InviteCode::from_str(&bech32).expect("parses");
    assert_eq!(connect, connect_parsed);

    let json = serde_json::to_string(&connect).unwrap();
    let connect_as_string: String = serde_json::from_str(&json).unwrap();
    assert_eq!(connect_as_string, bech32);
    let connect_parsed_json: InviteCode = serde_json::from_str(&json).unwrap();
    assert_eq!(connect_parsed_json, connect_parsed);
}

#[test]
fn creates_essential_guardians_invite_code() {
    let mut peer_to_url_map = BTreeMap::new();
    peer_to_url_map.insert(PeerId::from(0), "ws://test1".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(1), "ws://test2".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(2), "ws://test3".parse().expect("URL fail"));
    peer_to_url_map.insert(PeerId::from(3), "ws://test4".parse().expect("URL fail"));
    let max_size = peer_to_url_map.to_num_peers().max_evil() + 1;

    let code =
        InviteCode::new_with_essential_num_guardians(&peer_to_url_map, FederationId::dummy());

    assert_eq!(FederationId::dummy(), code.federation_id());

    let expected_map: BTreeMap<PeerId, SafeUrl> =
        peer_to_url_map.into_iter().take(max_size).collect();
    assert_eq!(expected_map, code.peers());
}

#[test]
fn a_general_federation_error_keeps_its_condition() {
    let err =
        FederationError::general("some_method", (), FederationGeneralError::AdminPeerIdNotSet);
    assert!(
        matches!(
            err.get_general_error(),
            Some(FederationGeneralError::AdminPeerIdNotSet)
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("Admin peer id not set"), "{err}");
}

#[test]
fn a_federation_id_mismatch_names_both_ids() {
    let expected = FederationId::dummy();
    let found =
        FederationId::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("parses");
    let err = ClientConfigDownloadError::FederationIdMismatch { expected, found };

    assert!(
        matches!(err, ClientConfigDownloadError::FederationIdMismatch { .. }),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&expected.to_string()), "{msg}");
    assert!(msg.contains(&found.to_string()), "{msg}");
}

#[test]
fn a_download_error_keeps_the_federation_cause() {
    let cause =
        FederationError::general("some_method", (), FederationGeneralError::AdminPeerIdNotSet);
    let cause_msg = cause.to_string();
    let err = ClientConfigDownloadError::from(cause);

    assert!(
        matches!(err, ClientConfigDownloadError::Federation(_)),
        "{err:?}"
    );
    // The variant's own message must not repeat what its source already says.
    assert!(!err.to_string().contains("Admin peer id not set"), "{err}");
    assert_eq!(err.source().expect("has a source").to_string(), cause_msg);
}
