mod mock;

use std::sync::Arc;

use fedimint_client::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_core::bitcoin_migration::bitcoin30_to_bitcoin32_keypair;
use fedimint_core::core::OperationId;
use fedimint_core::util::NextOrPending as _;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_lnv2_client::{
    Bolt11InvoiceDescription, LightningClientInit, LightningClientModule, LightningOperationMeta,
    ReceiveState, SendPaymentError, SendState, CONTRACT_CONFIRMATION_BUFFER,
    EXPIRATION_DELTA_LIMIT_DEFAULT,
};
use fedimint_lnv2_common::config::LightningGenParams;
use fedimint_lnv2_common::{LightningInput, LightningInputV0, OutgoingWitness};
use fedimint_lnv2_server::LightningInit;
use fedimint_testing::fixtures::Fixtures;
use serde_json::Value;

use crate::mock::{MockGatewayConnection, MOCK_INVOICE_PREIMAGE};

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());

    let bitcoin_server = fixtures.bitcoin_server();

    fixtures.with_module(
        LightningClientInit {
            gateway_conn: Arc::new(MockGatewayConnection::default()),
        },
        LightningInit,
        LightningGenParams::regtest(bitcoin_server.clone()),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let client = fed.new_client().await;
    let lnv2 = client.get_first_module::<LightningClientModule>()?;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()?
        .print_money(sats(10_000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let gateway_api = mock::gateway();
    let invoice = mock::payable_invoice();
    let routing_info = lnv2
        .routing_info(&gateway_api)
        .await?
        .expect("Could not retrieve routing info");

    let operation_id = lnv2
        .send(
            invoice.clone(),
            gateway_api.clone(),
            routing_info,
            Value::Null,
        )
        .await?;

    assert_eq!(
        lnv2.send(
            invoice.clone(),
            gateway_api.clone(),
            routing_info,
            Value::Null
        )
        .await,
        Err(SendPaymentError::PendingPreviousPayment(operation_id)),
    );

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);
    assert_eq!(sub.ok().await?, SendState::Success);

    assert_eq!(
        lnv2.send(invoice, gateway_api, routing_info, Value::Null)
            .await,
        Err(SendPaymentError::SuccessfulPreviousPayment(operation_id)),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_failed_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let client = fed.new_client().await;
    let lnv2 = client.get_first_module::<LightningClientModule>()?;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()?
        .print_money(sats(10_000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;
    let routing_info = lnv2
        .routing_info(&mock::gateway())
        .await?
        .expect("Could not get routing info");

    let op = lnv2
        .send(
            mock::unpayable_invoice(),
            mock::gateway(),
            routing_info,
            Value::Null,
        )
        .await?;

    let mut sub = lnv2.subscribe_send(op).await?.into_stream();

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
    let client = fed.new_client().await;
    let lnv2 = client.get_first_module::<LightningClientModule>()?;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()?
        .print_money(sats(10_000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let routing_info = lnv2
        .routing_info(&mock::gateway())
        .await?
        .expect("Could not get routing info");

    let op = lnv2
        .send(
            mock::crash_invoice(),
            mock::gateway(),
            routing_info,
            Value::Null,
        )
        .await?;

    let mut sub = lnv2.subscribe_send(op).await?.into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);

    fixtures
        .bitcoin()
        .mine_blocks(EXPIRATION_DELTA_LIMIT_DEFAULT + CONTRACT_CONFIRMATION_BUFFER)
        .await;

    assert_eq!(sub.ok().await?, SendState::Refunding);
    assert_eq!(sub.ok().await?, SendState::Refunded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn claiming_outgoing_contract_triggers_success() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let client = fed.new_client().await;
    let lnv2 = client.get_first_module::<LightningClientModule>()?;

    // Print money for client
    let (op, outpoint) = client
        .get_first_module::<DummyClientModule>()?
        .print_money(sats(10_000))
        .await?;

    client.await_primary_module_output(op, outpoint).await?;

    let routing_info = lnv2
        .routing_info(&mock::gateway())
        .await?
        .expect("Could not get routing info");

    let op = lnv2
        .send(
            mock::crash_invoice(),
            mock::gateway(),
            routing_info,
            Value::Null,
        )
        .await?;

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendState::Funding);
    assert_eq!(sub.ok().await?, SendState::Funded);

    let operation = client
        .get_first_module::<LightningClientModule>()?
        .client_ctx
        .get_operation(op)
        .await?;

    let contract = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Send(send_operation_meta) => send_operation_meta.contract,
        LightningOperationMeta::Receive(..) => panic!("Operation Meta is a Receive variant"),
    };

    let client_input = ClientInput::<LightningInput> {
        input: LightningInput::V0(LightningInputV0::Outgoing(
            contract.contract_id(),
            OutgoingWitness::Claim(MOCK_INVOICE_PREIMAGE),
        )),
        amount: contract.amount,
        keys: vec![bitcoin30_to_bitcoin32_keypair(&mock::gateway_keypair())],
    };

    client
        .finalize_and_submit_transaction(
            OperationId::new_random(),
            "Claiming Outgoing Contract",
            |_, _| (),
            TransactionBuilder::new().with_inputs(
                client
                    .get_first_module::<LightningClientModule>()?
                    .client_ctx
                    .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input])),
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
    let client = fed.new_client().await;

    let op = client
        .get_first_module::<LightningClientModule>()?
        .receive(
            Amount::from_sats(1000),
            5, // receive operation expires in 5 seconds
            Bolt11InvoiceDescription::Direct(String::new()),
            Some(mock::gateway()),
            Value::Null,
        )
        .await?
        .1;

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_receive(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, ReceiveState::Pending);
    assert_eq!(sub.ok().await?, ReceiveState::Expired);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;
    let client = fed.new_client().await;
    let lnv2 = client.get_first_module::<LightningClientModule>()?;

    let routing_info = lnv2
        .routing_info(&mock::gateway())
        .await?
        .expect("Could not get routing info");

    assert_eq!(
        lnv2.send(
            mock::signet_bolt_11_invoice(),
            mock::gateway(),
            routing_info,
            Value::Null
        )
        .await
        .expect_err("send did not fail due to incorrect Currency"),
        SendPaymentError::WrongCurrency {
            invoice_currency: lightning_invoice::Currency::Signet,
            federation_currency: lightning_invoice::Currency::Regtest
        }
    );

    Ok(())
}
