use std::str::FromStr;

use anyhow::bail;
use assert_matches::assert_matches;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    InternalPayState, LightningClientExt, LightningClientGen, LightningOperationMeta, LnPayState,
    LnReceiveState, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::ln_operation;
use fedimint_ln_server::LightningGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};
use lightning_invoice::Bolt11Invoice;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures.with_module(LightningClientGen, LightningGen, ln_params)
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest) -> GatewayTest {
    let lnd = fixtures.lnd().await;
    let mut gateway = fixtures
        .new_gateway(lnd, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    gateway.connect_fed(fed).await;
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let mut gateway1 = fixtures
        .new_gateway(
            fixtures.lnd().await,
            0,
            Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
        )
        .await;
    let mut gateway2 = fixtures
        .new_gateway(
            fixtures.cln().await,
            0,
            Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
        )
        .await;

    // Client selects a gateway by default
    gateway1.connect_fed(&fed).await;
    let key1 = gateway1.get_gateway_id();
    assert_eq!(client.select_active_gateway().await?.gateway_id, key1);

    gateway2.connect_fed(&fed).await;
    let key2 = gateway1.get_gateway_id();
    let gateways = client.fetch_registered_gateways().await.unwrap();
    assert_eq!(gateways.len(), 2);

    client.set_active_gateway(&key2).await?;
    assert_eq!(client.select_active_gateway().await?.gateway_id, key2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_can_attach_extra_meta_to_receive_operation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;

    // Print money for client2
    let (op, outpoint) = client2.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let extra_meta = "internal payment with no gateway registered".to_string();
    let (op, invoice) = client1
        .create_bolt11_invoice(
            sats(250),
            "with-markers".to_string(),
            None,
            extra_meta.clone(),
        )
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    // Pay the invoice from client2
    let (pay_type, _, _fee) = client2.pay_bolt11_invoice(invoice).await?;
    match pay_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2.subscribe_internal_pay(op_id).await?.into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Verify that we can retrieve the extra metadata that was attached
    let operation = ln_operation(&client1, op).await?;
    let op_meta = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Receive {
            out_point: _,
            invoice: _,
            extra_meta,
        } => extra_meta.to_string(),
        _ => bail!("Operation is not a lightning payment"),
    };
    assert_eq!(serde_json::to_string(&extra_meta)?, op_meta);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_internal_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;

    // Print money for client2
    let (op, outpoint) = client2.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "with-markers".to_string(), None, ())
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let (pay_type, _, _) = client2.pay_bolt11_invoice(invoice.clone()).await?;
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

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let prev_balance = client2.get_balance().await;
    let (pay_type, _, _) = client2.pay_bolt11_invoice(invoice).await?;
    match pay_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2.subscribe_internal_pay(op_id).await?.into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
        }
        _ => panic!("Expected internal payment!"),
    }

    let same_balance = client2.get_balance().await;
    assert_eq!(prev_balance, same_balance);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_external_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let gw = gateway(&fixtures, &fed).await;

    // Print money for client
    let (op, outpoint) = client.print_money(sats(1000)).await?;
    client.await_primary_module_output(op, outpoint).await?;

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

    // Pay the invoice for the first time
    let (pay_type, _, _) = client.pay_bolt11_invoice(invoice.clone()).await?;
    match pay_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client.subscribe_ln_pay(operation_id).await?.into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let prev_balance = client.get_balance().await;

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let (pay_type, _, _) = client.pay_bolt11_invoice(invoice).await?;
    match pay_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client.subscribe_ln_pay(operation_id).await?.into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let same_balance = client.get_balance().await;
    assert_eq!(prev_balance, same_balance);

    drop(gw);

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
        .create_bolt11_invoice(sats(250), "with-markers".to_string(), None, ())
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let (pay_type, _, _fee) = client2.pay_bolt11_invoice(invoice).await?;
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

    // TEST internal payment when there is a registered gateway
    gateway(&fixtures, &fed).await;

    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "with-gateway-hint".to_string(), None, ())
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let (pay_type, _, _fee) = client2.pay_bolt11_invoice(invoice).await?;
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
    gateway(&fixtures, &fed).await;

    // Signet invoice should fail on regtest
    let signet_invoice = Bolt11Invoice::from_str(
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
