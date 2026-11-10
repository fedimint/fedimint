use std::collections::BTreeMap;

use fedimint_core::PeerId;

use super::{IP2PConnector, TlsConfig, TlsTcpConnector, gen_cert_and_key};

#[tokio::test]
async fn generated_identity_authenticates_over_tls() -> anyhow::Result<()> {
    fedimint_core::rustls::install_crypto_provider().await;

    let names = BTreeMap::from([
        (PeerId::from(0), "Alice guardian".to_owned()),
        (PeerId::from(1), "Bob guardian".to_owned()),
    ]);
    let (alice_cert, alice_key) = gen_cert_and_key(&names[&PeerId::from(0)])?;
    let (bob_cert, bob_key) = gen_cert_and_key(&names[&PeerId::from(1)])?;
    let certificates = BTreeMap::from([(PeerId::from(0), alice_cert), (PeerId::from(1), bob_cert)]);
    let alice = TlsTcpConnector::new(
        TlsConfig {
            private_key: alice_key,
            certificates: certificates.clone(),
            peer_names: names.clone(),
        },
        "127.0.0.1:0".parse()?,
        BTreeMap::new(),
        PeerId::from(0),
    )
    .await;
    let mut bob = TlsTcpConnector::new(
        TlsConfig {
            private_key: bob_key,
            certificates,
            peer_names: names,
        },
        "127.0.0.1:0".parse()?,
        BTreeMap::new(),
        PeerId::from(1),
    )
    .await;
    bob.peers.insert(
        PeerId::from(0),
        format!("fedimint://{}", alice.listener.local_addr()?).parse()?,
    );

    let (accepted, connected) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            <TlsTcpConnector as IP2PConnector<Vec<u8>>>::accept(&alice),
            <TlsTcpConnector as IP2PConnector<Vec<u8>>>::connect(&bob, PeerId::from(0)),
        )
    })
    .await?;
    let (authenticated_peer, _) = accepted?;
    connected?;
    assert_eq!(authenticated_peer, PeerId::from(1));
    Ok(())
}
