use fedimint_core::secp256k1::SecretKey;

use super::{
    build_iroh_v1_endpoint, derive_iroh_v1_api_secret_key, guardian_connector_registry_builder,
};

#[test]
fn iroh_v1_api_key_derivation_is_stable() {
    let broadcast_sk = SecretKey::from_slice(&[1; 32]).expect("valid test key");
    assert_eq!(
        derive_iroh_v1_api_secret_key(&broadcast_sk)
            .public()
            .to_string(),
        "e4b678498c23a7444ac2daf4aed336e88c2fa51c10e973f4ec57ae493e25fcf3"
    );
}

#[tokio::test]
async fn guardian_ip_transport_option() -> anyhow::Result<()> {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    use fedimint_connectors::iroh_next_endpoint_url;
    use fedimint_core::envs::{
        FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV, FM_IROH_DHT_ENABLE_ENV,
        FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_P2P_ENABLE_ENV, FM_IROH_RELAYS_ENABLE_ENV,
    };
    use fedimint_core::module::FEDIMINT_API_ALPN;
    use tokio::process::Command;

    use crate::net::p2p_connector::IrohConnector;

    const CHILD_ENV: &str = "FM_TEST_GUARDIAN_IP_TRANSPORT_CHILD";
    const TARGET_ENV: &str = "FM_TEST_GUARDIAN_IP_TRANSPORT_TARGET";

    // Isolate environment changes from other tests, and exercise both production
    // builders rather than a copy of their configuration logic.
    let Ok(expected_direct) = std::env::var(CHILD_ENV) else {
        // A local direct-only API peer also verifies the guardian's outbound
        // connector policy, including its existing direct-address overrides.
        let direct_peer = iroh_next::Endpoint::builder(iroh_next::endpoint::presets::Minimal)
            .clear_ip_transports()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .alpns(vec![FEDIMINT_API_ALPN.to_vec()])
            .bind()
            .await?;
        let listener = direct_peer.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = listener.accept().await {
                let connection = incoming.await.expect("local test peer connects");
                tokio::spawn(async move { connection.closed().await });
            }
        });
        for (value, expected_direct) in [
            (None, true),
            (Some("true"), true),
            (Some("1"), true),
            (Some("false"), false),
            (Some("0"), false),
        ] {
            let mut child = Command::new(std::env::current_exe()?);
            child
                .args([
                    "--exact",
                    "net::iroh::tests::guardian_ip_transport_option",
                    "--nocapture",
                ])
                .env(CHILD_ENV, expected_direct.to_string())
                .env(FM_IROH_N0_DISCOVERY_ENABLE_ENV, "false")
                .env(FM_IROH_DHT_ENABLE_ENV, "false")
                .env(FM_IROH_RELAYS_ENABLE_ENV, "true")
                .env(TARGET_ENV, direct_peer.id().to_string())
                .env(
                    FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV,
                    format!("{}={}", direct_peer.id(), direct_peer.bound_sockets()[0]),
                );
            if let Some(value) = value {
                child.env(FM_IROH_P2P_ENABLE_ENV, value);
            } else {
                child.env_remove(FM_IROH_P2P_ENABLE_ENV);
            }
            let output = child.output().await?;
            assert!(
                output.status.success(),
                "{value:?}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        direct_peer.close().await;
        accept_task.await?;
        return Ok(());
    };
    let expected_direct: bool = expected_direct.parse()?;
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let p2p_secret = iroh::SecretKey::from_bytes(&[42; 32]);
    let node_ids = BTreeMap::from([(fedimint_core::PeerId::from(0), p2p_secret.public())]);
    let p2p =
        IrohConnector::new_no_overrides(p2p_secret, bind_addr, None, Vec::new(), node_ids).await?;
    let api = build_iroh_v1_endpoint(
        iroh_next::SecretKey::from_bytes(&[43; 32]),
        bind_addr,
        None,
        Vec::new(),
        b"test-api",
    )
    .await?;

    for endpoint in [&p2p.endpoint, &api] {
        let sockets = endpoint.bound_sockets();
        if expected_direct {
            assert_eq!(sockets.len(), 1);
            assert_eq!(sockets[0].ip(), bind_addr.ip());
            assert_ne!(sockets[0].port(), 0);
        } else {
            assert!(sockets.is_empty(), "relay-only must not bind IP sockets");
            assert!(
                endpoint.addr().ip_addrs().next().is_none(),
                "relay-only must not advertise IP addresses"
            );
        }
        endpoint.close().await;
    }
    let connectors = guardian_connector_registry_builder().bind().await;
    let url = iroh_next_endpoint_url(&std::env::var(TARGET_ENV)?)?;
    let connection = tokio::time::timeout(
        Duration::from_secs(2),
        connectors.connect_guardian(&url, None),
    )
    .await;
    assert_eq!(
        matches!(connection, Ok(Ok(_))),
        expected_direct,
        "only direct-enabled guardian connectors may reach a direct-only peer"
    );
    Ok(())
}
