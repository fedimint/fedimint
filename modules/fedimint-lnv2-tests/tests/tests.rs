mod mock;

use std::sync::Arc;

use fedimint_client::transaction::{ClientInput, TransactionBuilder};
use fedimint_core::core::OperationId;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_lnv2_client::{
    Bolt11InvoiceDescription, LightningClientInit, LightningClientModule,
    LightningClientStateMachines, LightningOperationMeta, PaymentFee, ReceiveState,
    SendPaymentError, SendState, EXPIRATION_DELTA_LIMIT_DEFAULT,
};
use fedimint_lnv2_common::config::LightningGenParams;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use fedimint_lnv2_server::LightningInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::Gateway;

use crate::mock::{MockGatewayConnection, MOCK_INVOICE_PREIMAGE};

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());

    let bitcoin_server = fixtures.bitcoin_server();

    let fixtures = fixtures.with_module(
        LightningClientInit {
            gateway_conn: Arc::new(MockGatewayConnection::default()),
        },
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
async fn gateway(fixtures: &Fixtures, fed: &FederationTest) -> Gateway {
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway = gateway(&fixtures, &fed).await;
    let gateway_api = gateway.versioned_api().clone();

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let invoice = mock::payable_invoice();

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
async fn refund_failed_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway = gateway(&fixtures, &fed).await;
    let gateway_api = gateway.versioned_api().clone();

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let op = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, mock::unpayable_invoice())
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
async fn unilateral_refund_of_outgoing_contracts() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway = gateway(&fixtures, &fed).await;
    let gateway_api = gateway.versioned_api().clone();

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let op = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, mock::crash_invoice())
        .await?;

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);

    fixtures
        .bitcoin()
        .mine_blocks(EXPIRATION_DELTA_LIMIT_DEFAULT)
        .await;

    assert_eq!(sub.ok().await?, SendState::Refunding);
    assert_eq!(sub.ok().await?, SendState::Refunded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn claiming_outgoing_contract_triggers_success() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway = gateway(&fixtures, &fed).await;
    let gateway_api = gateway.versioned_api().clone();

    let client = fed.new_client().await;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()
        .print_money(sats(1000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let op = client
        .get_first_module::<LightningClientModule>()
        .send(gateway_api, mock::crash_invoice())
        .await?;

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_send(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);

    let operation = client
        .get_first_module::<LightningClientModule>()
        .client_ctx
        .get_operation(op)
        .await?;

    let contract = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Send(send_operation_meta) => send_operation_meta.contract,
        LightningOperationMeta::Receive(..) => panic!("Operation Meta is a Receive variant"),
    };

    let client_input = ClientInput::<LightningInput, LightningClientStateMachines> {
        input: LightningInput::V0(LightningInputV0::Outgoing(
            contract.contract_id(),
            OutgoingWitness::Claim(MOCK_INVOICE_PREIMAGE),
        )),
        amount: contract.amount,
        keys: vec![mock::gateway_keypair()],
        state_machines: Arc::new(|_, _| vec![]),
    };

    client
        .finalize_and_submit_transaction(
            OperationId::new_random(),
            "Claiming Outgoing Contract",
            |_, _| (),
            TransactionBuilder::new().with_input(
                client
                    .get_first_module::<LightningClientModule>()
                    .client_ctx
                    .make_client_input(client_input),
            ),
        )
        .await
        .expect("Failed to claim outgoing contract");

    assert_eq!(sub.ok().await?, SendState::Success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_operation_expires() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let gateway = gateway(&fixtures, &fed).await;
    let gateway_api = gateway.versioned_api().clone();

    let client = fed.new_client().await;

    let op = client
        .get_first_module::<LightningClientModule>()
        .receive_internal(
            gateway_api,
            Amount::from_sats(1000),
            5, // receive operation expires in 5 seconds
            Bolt11InvoiceDescription::Direct(String::new()),
            PaymentFee::one_percent(),
        )
        .await?
        .1;

    let mut sub = client
        .get_first_module::<LightningClientModule>()
        .subscribe_receive(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, ReceiveState::Pending);
    assert_eq!(sub.ok().await?, ReceiveState::Expired);

    Ok(())
}
