mod mock;

use std::pin::pin;
use std::sync::Arc;

use async_stream::stream;
use fedimint_client::ClientHandleArc;
use fedimint_client::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_client_module::module::ClientModule;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::util::NextOrPending as _;
use fedimint_core::{Amount, OutPoint, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_lnv2_client::events::{
    ReceivePaymentEvent, SendPaymentEvent, SendPaymentStatus, SendPaymentUpdateEvent,
};
use fedimint_lnv2_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta, ReceiveOperationState,
    SendOperationState, SendPaymentError,
};
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, KIND, LightningInput, LightningInputV0, OutgoingWitness,
};
use fedimint_lnv2_server::LightningInit;
use fedimint_logging::LOG_TEST;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt;
use serde_json::Value;
use tracing::warn;

use crate::mock::{MOCK_INVOICE_PREIMAGE, MockGatewayConnection};

#[derive(Debug, PartialEq, Eq)]
enum LnEvent {
    Send(SendPaymentEvent),
    SendUpdate(SendPaymentUpdateEvent),
    Receive(ReceivePaymentEvent),
}

fn ln_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = LnEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_ln_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_ln_event(entry: &EventLogEntry) -> Option<LnEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(LnEvent::Send);
    }

    if entry.kind == SendPaymentUpdateEvent::KIND {
        return entry.to_event().map(LnEvent::SendUpdate);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(LnEvent::Receive);
    }

    None
}

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);

    fixtures.with_module(
        LightningClientInit {
            gateway_conn: Some(Arc::new(MockGatewayConnection::default())),
            custom_meta_fn: Arc::new(|| {
                serde_json::json!({
                    "timestamp": chrono::Utc::now().timestamp(),
                })
            }),
        },
        LightningInit,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let gateway_api = mock::gateway();
    let invoice = mock::payable_invoice();

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(invoice.clone(), Some(gateway_api.clone()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(invoice.clone(), Some(gateway_api.clone()), Value::Null)
            .await,
        Err(SendPaymentError::PaymentInProgress(operation_id)),
    );

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);
    assert_eq!(
        sub.ok().await?,
        SendOperationState::Success(MOCK_INVOICE_PREIMAGE)
    );

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(
        update.status,
        SendPaymentStatus::Success(MOCK_INVOICE_PREIMAGE)
    );

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(invoice, Some(gateway_api), Value::Null)
            .await,
        Err(SendPaymentError::InvoiceAlreadyPaid(operation_id)),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_failed_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(
            mock::unpayable_invoice(),
            Some(mock::gateway()),
            Value::Null,
        )
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);
    assert_eq!(sub.ok().await?, SendOperationState::Refunding);
    assert_eq!(sub.ok().await?, SendOperationState::Refunded);

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(update.status, SendPaymentStatus::Refunded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unilateral_refund_of_outgoing_contracts() -> anyhow::Result<()> {
    if Fixtures::is_real_test() {
        warn!(
            target: LOG_TEST,
            "Skipping test as mining so many blocks is too slow in real bitcoind setup"
        );
        return Ok(());
    }

    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(mock::crash_invoice(), Some(mock::gateway()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);

    fixtures.bitcoin().mine_blocks(1440 + 12).await;

    assert_eq!(sub.ok().await?, SendOperationState::Refunding);
    assert_eq!(sub.ok().await?, SendOperationState::Refunded);

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(update.status, SendPaymentStatus::Refunded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn claiming_outgoing_contract_triggers_success() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(mock::crash_invoice(), Some(mock::gateway()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);

    let operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    let (contract, txid) = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Send(meta) => (meta.contract, meta.change_outpoint_range.txid),
        LightningOperationMeta::Receive(..) => panic!("Operation Meta is a Receive variant"),
        LightningOperationMeta::LnurlReceive(..) => {
            panic!("Operation Meta is a LnurlReceive variant")
        }
    };

    let client_input = ClientInput::<LightningInput> {
        input: LightningInput::V0(LightningInputV0::Outgoing(
            OutPoint { txid, out_idx: 0 },
            OutgoingWitness::Claim(MOCK_INVOICE_PREIMAGE),
        )),
        amounts: Amounts::new_bitcoin(contract.amount),
        keys: vec![mock::gateway_keypair()],
    };

    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .unwrap();

    client
        .finalize_and_submit_transaction(
            OperationId::new_random(),
            "Claiming Outgoing Contract",
            |_| (),
            TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![client_input]).into_dyn(lnv2_module_id),
            ),
            vec![],
        )
        .await
        .expect("Failed to claim outgoing contract");

    assert_eq!(
        sub.ok().await?,
        SendOperationState::Success(MOCK_INVOICE_PREIMAGE)
    );

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(
        update.status,
        SendPaymentStatus::Success(MOCK_INVOICE_PREIMAGE)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_operation_expires() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
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
        .subscribe_receive_operation_state_updates(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, ReceiveOperationState::Pending);
    assert_eq!(sub.ok().await?, ReceiveOperationState::Expired);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(
                mock::signet_bolt_11_invoice(),
                Some(mock::gateway()),
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
