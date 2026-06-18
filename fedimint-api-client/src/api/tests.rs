use std::str::FromStr as _;

use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;

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
