use fedimint_core::config::FederationId;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_lnv2_client::{
    LightningClientInit, LightningClientModule, SendPaymentError, SendState,
};
use fedimint_lnv2_common::config::LightningGenParams;
use fedimint_lnv2_server::LightningInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};
use fedimint_testing::ln::FakeLightningTest;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());

    let bitcoin_server = fixtures.bitcoin_server();

    let fixtures = fixtures.with_module(
        LightningClientInit,
        LightningInit,
        LightningGenParams::regtest(bitcoin_server.clone()),
    );

    // TODO: We still have to attach the legacy lightning module such that the
    // gateway can connect to a federation. Remove this once connection to a
    // federation does not require lightning legacy anymore.
    fixtures.with_module(
        fedimint_ln_client::LightningClientInit::default(),
        fedimint_ln_server::LightningInit,
        fedimint_ln_common::config::LightningGenParams::regtest(bitcoin_server),
    )
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest) -> GatewayTest {
    let mut gateway = fixtures
        .new_gateway(0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    gateway.connect_fed(fed).await;
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway_test = gateway(&fixtures, &fed).await;
    let gateway_api = gateway_test.gateway.versioned_api().clone();

    let other_ln = FakeLightningTest::new();
    let invoice = other_ln.invoice(Amount::from_sats(100), None)?;

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let operation_id = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api.clone(), invoice.clone())
        .await?;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()
            .send(gateway_api.clone(), invoice.clone())
            .await,
        Err(SendPaymentError::PendingPreviousPayment(operation_id)),
    );

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);
    assert_eq!(sub.ok().await?, SendState::Success);

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()
            .send(gateway_api, invoice)
            .await,
        Err(SendPaymentError::SuccessfulPreviousPayment(operation_id)),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_unpayable_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway_test = gateway(&fixtures, &fed).await;
    let gateway_api = gateway_test.gateway.versioned_api().clone();

    let other_ln = FakeLightningTest::new();
    let invoice = other_ln.unpayable_invoice(Amount::from_sats(100), None);

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let op = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, invoice)
        .await?;

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);
    assert_eq!(sub.ok().await?, SendState::Refunding);
    assert_eq!(sub.ok().await?, SendState::Refunded);

    Ok(())
}
