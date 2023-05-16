use fedimint_core::config::ClientModuleConfig;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::sats;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::fixtures::Fixtures;

fn fixtures() -> Fixtures {
    Fixtures::default().with_primary(0, DummyClientGen, DummyGen, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_print_and_send_money() -> anyhow::Result<()> {
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;

    let (_, outpoint) = client1.print_money(sats(1000)).await?;
    client1.receive_money(outpoint).await?;
    assert_eq!(client1.total_funds().await, sats(1000));

    let outpoint = client1.send_money(client2.account(), sats(250)).await?;
    client2.receive_money(outpoint).await?;
    assert_eq!(client1.total_funds().await, sats(750));
    assert_eq!(client2.total_funds().await, sats(250));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_threshold_sign_message() {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;

    let message = "Hello fed!";
    let sig = client.fed_signature(message).await.unwrap();
    assert!(client.fed_public_key().verify(&sig, message));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_ignores_unknown_module() {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;

    let mut cfg = client.get_config().await.clone();
    let extra_mod = ClientModuleConfig {
        kind: ModuleKind::from_static_str("unknown_module"),
        version: ModuleConsensusVersion(0),
        config: vec![],
    };
    cfg.modules.insert(2142, extra_mod);

    // Test that building the client worked
    let _client = fed.new_client_with_config(cfg).await;
}
