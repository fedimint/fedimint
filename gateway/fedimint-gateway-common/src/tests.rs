use super::{ConnectPeerRequest, NodeAddress};

const NODE_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn node_address_defaults_lightning_port() {
    let node_address: NodeAddress = format!("{NODE_PUBKEY}@example.com")
        .parse()
        .expect("valid node address");

    assert_eq!(node_address.host_with_port(), "example.com:9735");
    assert_eq!(
        node_address.to_string(),
        format!("{NODE_PUBKEY}@example.com")
    );
}

#[test]
fn node_address_keeps_explicit_non_default_port() {
    let node_address: NodeAddress = format!("{NODE_PUBKEY}@example.com:9736")
        .parse()
        .expect("valid node address");

    assert_eq!(node_address.host_with_port(), "example.com:9736");
    assert_eq!(
        node_address.to_string(),
        format!("{NODE_PUBKEY}@example.com:9736")
    );
}

#[test]
fn node_address_handles_bracketed_ipv6_address() {
    let node_address: NodeAddress = format!("{NODE_PUBKEY}@[::1]")
        .parse()
        .expect("valid node address");

    assert_eq!(
        node_address.host_with_port(),
        "[0000:0000:0000:0000:0000:0000:0000:0001]:9735"
    );
    assert_eq!(
        node_address.to_string(),
        format!("{NODE_PUBKEY}@[0000:0000:0000:0000:0000:0000:0000:0001]")
    );

    let node_address: NodeAddress = format!("{NODE_PUBKEY}@[::1]:9736")
        .parse()
        .expect("valid node address");

    assert_eq!(
        node_address.host_with_port(),
        "[0000:0000:0000:0000:0000:0000:0000:0001]:9736"
    );
    assert_eq!(
        node_address.to_string(),
        format!("{NODE_PUBKEY}@[0000:0000:0000:0000:0000:0000:0000:0001]:9736")
    );
}

#[test]
fn node_address_serde_uses_display_format() {
    let request = ConnectPeerRequest {
        node_address: format!("{NODE_PUBKEY}@127.0.0.1:9735")
            .parse()
            .expect("valid node address"),
    };

    let json = serde_json::to_string(&request).expect("can serialize request");
    assert_eq!(
        json,
        format!(r#"{{"node_address":"{NODE_PUBKEY}@127.0.0.1"}}"#)
    );

    let request: ConnectPeerRequest = serde_json::from_str(&json).expect("can deserialize request");
    assert_eq!(request.node_address.host_with_port(), "127.0.0.1:9735");
}
