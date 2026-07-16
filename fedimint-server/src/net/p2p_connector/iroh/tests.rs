use std::collections::BTreeMap;
use std::net::SocketAddr;

use fedimint_core::PeerId;
use fedimint_server_core::dashboard_ui::ConnectionType;
use iroh::{NodeAddr, SecretKey};
use iroh_next::{RelayUrl, TransportAddr};

use super::endpoint::guardian_pkarr_addr_filter;
use super::{IP2PConnector, IrohConnector, endpoint_id_stable_to_next, secret_key_stable_to_next};

#[test]
fn stable_identity_converts_to_same_iroh_v1_identity() {
    let stable_secret = SecretKey::from_bytes(&[42; 32]);
    let next_secret = secret_key_stable_to_next(&stable_secret);
    let next_id =
        endpoint_id_stable_to_next(stable_secret.public()).expect("generated public key is valid");

    assert_eq!(next_secret.to_bytes(), stable_secret.to_bytes());
    assert_eq!(next_secret.public(), next_id);
    assert_eq!(
        next_secret.public().to_string(),
        stable_secret.public().to_string()
    );
}

#[test]
fn pkarr_prefers_relay_but_keeps_direct_addresses_without_one() {
    let direct_a = TransportAddr::Ip(SocketAddr::from(([192, 0, 2, 1], 8173)));
    let direct_b = TransportAddr::Ip(SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 8173)));
    let relay = TransportAddr::Relay(
        "https://relay.example.com"
            .parse::<RelayUrl>()
            .expect("test relay URL is valid"),
    );
    let filter = guardian_pkarr_addr_filter();

    assert_eq!(
        filter
            .apply(&vec![direct_a.clone(), relay.clone(), direct_b.clone()])
            .as_ref(),
        &[relay]
    );
    assert_eq!(
        filter
            .apply(&vec![direct_a.clone(), direct_b.clone()])
            .as_ref(),
        &[direct_a, direct_b]
    );
    assert!(filter.apply(&Vec::new()).is_empty());
}

#[tokio::test]
async fn production_connectors_exchange_messages_over_direct_override() -> anyhow::Result<()> {
    let secret_a = SecretKey::from_bytes(&[1; 32]);
    let secret_b = SecretKey::from_bytes(&[2; 32]);
    let node_id_b = secret_b.public();
    let peer_a = PeerId::from(0);
    let peer_b = PeerId::from(1);
    let node_ids = BTreeMap::from([(peer_a, secret_a.public()), (peer_b, secret_b.public())]);
    let connector_a = IrohConnector::new_no_overrides(
        secret_a,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        None,
        Vec::new(),
        node_ids.clone(),
    )
    .await?;
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let connector_b =
        IrohConnector::new_no_overrides(secret_b, bind_addr, None, Vec::new(), node_ids).await?;
    let bound_sockets = connector_b.endpoint.bound_sockets();
    assert_eq!(bound_sockets.len(), 1);
    assert_eq!(bound_sockets[0].ip(), bind_addr.ip());
    assert_ne!(bound_sockets[0].port(), 0);
    let connector_a = connector_a.with_connection_override(
        node_id_b,
        NodeAddr::new(node_id_b).with_direct_addresses(bound_sockets),
    );

    let (outgoing, incoming) = tokio::try_join!(
        <IrohConnector as IP2PConnector<u64>>::connect(&connector_a, peer_b),
        <IrohConnector as IP2PConnector<u64>>::accept(&connector_b),
    )?;
    let (authenticated_peer, mut incoming) = incoming;
    let mut outgoing = outgoing;
    assert_eq!(authenticated_peer, peer_a);

    outgoing.send(42).await?;
    assert_eq!(incoming.receive().await?.read_to_end().await?, 42);
    assert_eq!(outgoing.connection_type(), Some(ConnectionType::Direct));

    Ok(())
}
