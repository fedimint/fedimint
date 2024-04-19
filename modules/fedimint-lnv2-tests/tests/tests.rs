use std::sync::Arc;

use fedimint_client::ClientHandle;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_lnv2_client::{
    LightningClientInit, LightningClientModule, ReceiveState, SendPaymentError, SendState,
};
use fedimint_lnv2_common::config::LightningGenParams;
use fedimint_lnv2_server::LightningInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};

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
        fedimint_ln_client::LightningClientInit,
        fedimint_ln_server::LightningInit,
        fedimint_ln_common::config::LightningGenParams::regtest(bitcoin_server),
    )
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

async fn print_liquidity(gateway: &GatewayTest, federation_id: FederationId) {
    let client = gateway.select_client(federation_id).await;

    let (op, outpoints) = client
        .get_first_module::<DummyClientModule>()
        .print_money(Amount::from_bitcoins(1))
        .await
        .expect("Could not print primary module liquidity");

    client
        .await_primary_module_output(op, outpoints)
        .await
        .expect("Could not await primary module liquidity");

    assert_eq!(client.get_balance().await, Amount::from_bitcoins(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    // TODO: remove this
    if Fixtures::is_real_test() {
        return Ok(());
    }

    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gateway_test = gateway(&fixtures, &fed).await;
    let gateway_api = gateway_test.gateway.versioned_api.clone();

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

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

    let send_result = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api.clone(), invoice.clone())
        .await;

    assert_eq!(
        Err(SendPaymentError::PendingPreviousPayment(operation_id)),
        send_result
    );

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);
    assert!(std::matches!(sub.ok().await?, SendState::Success(..)));

    let send_result = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, invoice)
        .await;

    assert_eq!(
        Err(SendPaymentError::SuccessfulPreviousPayment(operation_id)),
        send_result
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_unpayable_invoice() -> anyhow::Result<()> {
    // TODO: remove this
    if Fixtures::is_real_test() {
        return Ok(());
    }

    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gateway_test = gateway(&fixtures, &fed).await;
    let gateway_api = gateway_test.gateway.versioned_api.clone();

    let cln = fixtures.cln().await;
    let invoice = cln.unpayable_invoice(Amount::from_sats(100), None);

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

#[tokio::test(flavor = "multi_thread")]
async fn can_make_self_payment_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gateway_test = gateway(&fixtures, &fed).await;
    let gateway_api = gateway_test.gateway.versioned_api.clone();

    let client = fed.new_client().await;

    let (invoice, receive_op) = client
        .get_first_module::<LightningClientModule>()
        .receive(gateway_api.clone(), Amount::from_sats(100))
        .await?;

    let (print_op, print_outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(Amount::from_sats(10000))
        .await?;

    client
        .await_primary_module_output(print_op, print_outpoint)
        .await?;

    // this payment will fail and be refunded since the gateway does not have any
    // liquidity in the federation yet
    let send_op_refunded = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api.clone(), invoice.clone())
        .await?;

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(send_op_refunded)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);
    assert_eq!(sub.ok().await?, SendState::Refunding);
    assert_eq!(sub.ok().await?, SendState::Refunded);

    // now we print liquidity such that the second payment attempt is successful
    print_liquidity(&gateway_test, fed.id()).await;

    let send_op = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api.clone(), invoice.clone())
        .await?;

    // verify that the first and second payment attempt have different operation ids
    assert_ne!(send_op, send_op_refunded);

    // this will return an error as the second payment attempt is still pending
    let send_result = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api.clone(), invoice.clone())
        .await;

    assert_eq!(
        Err(SendPaymentError::PendingPreviousPayment(send_op)),
        send_result
    );

    // we await the success of the second payment attempt
    verify_payment_success(client.clone(), send_op, client.clone(), receive_op).await?;

    // this will return an error as the second payment attempt was successful
    let send_result = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, invoice)
        .await;

    assert_eq!(
        Err(SendPaymentError::SuccessfulPreviousPayment(send_op)),
        send_result
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_swap() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed_send = fixtures.new_fed().await;
    let fed_receive = fixtures.new_fed().await;

    let mut gateway_test = gateway(&fixtures, &fed_send).await;
    let gateway_api = gateway_test.gateway.versioned_api.clone();

    gateway_test.connect_fed(&fed_receive).await;

    print_liquidity(&gateway_test, fed_receive.id()).await;

    let client_receive = fed_receive.new_client().await;

    let (invoice, receive_op) = client_receive
        .get_first_module::<LightningClientModule>()
        .receive(gateway_api.clone(), Amount::from_sats(100))
        .await?;

    let client_send = fed_send.new_client().await;

    let (print_op, print_outpoint) = client_send
        .get_first_module::<DummyClientModule>()
        .print_money(Amount::from_sats(10000))
        .await?;

    client_send
        .await_primary_module_output(print_op, print_outpoint)
        .await?;

    let send_op = client_send
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, invoice)
        .await?;

    verify_payment_success(
        client_send.clone(),
        send_op,
        client_receive.clone(),
        receive_op,
    )
    .await
}

async fn verify_payment_success(
    client_send: Arc<ClientHandle>,
    send_op: OperationId,
    client_receive: Arc<ClientHandle>,
    receive_op: OperationId,
) -> anyhow::Result<()> {
    let mut receive_sub = client_receive
        .get_first_module::<LightningClientModule>()
        .subscribe_receive(receive_op)
        .await?
        .into_stream();

    assert_eq!(receive_sub.ok().await?, ReceiveState::Pending);
    assert_eq!(receive_sub.ok().await?, ReceiveState::Claiming);
    assert_eq!(receive_sub.ok().await?, ReceiveState::Claimed);

    let mut send_sub = client_send
        .get_first_module::<LightningClientModule>()
        .subscribe_send(send_op)
        .await?
        .into_stream();

    assert_eq!(send_sub.ok().await?, SendState::Funding);
    assert_eq!(send_sub.ok().await?, SendState::Funded);
    assert!(std::matches!(send_sub.ok().await?, SendState::Success(..)));

    Ok(())
}
