use std::str::FromStr;

use assert_matches::assert_matches;
use fedimint_client::Client;
use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    InternalPayState, LightningClientExt, LightningClientGen, LnReceiveState, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_mint_client::MintClientGen;
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::GatewayTest;
use lightning_invoice::Invoice;

fn fixtures() -> Fixtures {
    // TODO: Remove dependency on mint (legacy gw client)
    let fixtures = Fixtures::new_primary(1, MintClientGen, MintGen, MintGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_rpc());
    fixtures
        .with_module(3, DummyClientGen, DummyGen, DummyGenParams::default())
        .with_module(0, LightningClientGen, LightningGen, ln_params)
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest, client: &Client) -> GatewayTest {
    let gateway = fixtures.new_connected_gateway(fed).await;
    let node_pub_key = gateway.last_registered().await.node_pub_key;
    client.set_active_gateway(&node_pub_key).await.unwrap();
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;

    // Client selects a gateway by default
    let gateway1 = fixtures
        .new_connected_gateway(&fed)
        .await
        .last_registered()
        .await;
    assert_eq!(
        client.select_active_gateway().await?.node_pub_key,
        gateway1.node_pub_key
    );

    let gateway2 = fixtures
        .new_connected_gateway(&fed)
        .await
        .last_registered()
        .await;
    let gateways = client.fetch_registered_gateways().await.unwrap();
    assert_eq!(gateways.len(), 2);

    client.set_active_gateway(&gateway2.node_pub_key).await?;
    assert_eq!(
        client.select_active_gateway().await?.node_pub_key,
        gateway2.node_pub_key
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn makes_internal_payments_within_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;

    // Print money for client2
    let (op, outpoint) = client2.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "with-markers".to_string(), None)
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let (pay_type, _) = client2.pay_bolt11_invoice(invoice).await?;
    match pay_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2.subscribe_internal_pay(op_id).await?.into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // TEST internal payment when there is a registered gateway
    let _gateway = gateway(&fixtures, &fed, &client1).await;

    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "with-gateway-hint".to_string(), None)
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let (pay_type, _) = client2.pay_bolt11_invoice(invoice).await?;
    match pay_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2.subscribe_internal_pay(op_id).await?.into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client1 = fed.new_client().await;
    let _gateway = gateway(&fixtures, &fed, &client1).await;

    // Signet invoice should fail on regtest
    let signet_invoice = Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .unwrap();

    let error = client1
        .pay_bolt11_invoice(signet_invoice)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Invalid invoice currency: expected=Regtest, got=Signet"
    );

    Ok(())
}
