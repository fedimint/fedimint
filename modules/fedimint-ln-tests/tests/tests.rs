use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use assert_matches::assert_matches;
use bitcoin_hashes::{Hash, sha256};
use fedimint_client::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder, TxSubmissionStates,
    TxSubmissionStatesSM,
};
use fedimint_client::{Client, ClientHandleArc};
use fedimint_client_module::error::OperationLookupError;
use fedimint_client_module::oplog::OperationLogEntry;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::module::{AmountUnit, Amounts, CommonModuleInit as _};
use fedimint_core::util::backoff_util::aggressive_backoff_long;
use fedimint_core::util::{BoxStream, NextOrPending, retry};
use fedimint_core::{Amount, sats, secp256k1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::incoming::IncomingSmError;
use fedimint_ln_client::receive::{
    LightningReceiveError, LightningReceiveStateMachine, LightningReceiveStates,
    LightningReceiveSubmittedOffer,
};
use fedimint_ln_client::{
    ClaimIncomingContractError, GatewaySelectionError, InternalPayState, LightningClientInit,
    LightningClientModule, LightningClientStateMachines, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState, LnSubscribeError,
    MockGatewayConnection, OutgoingLightningPayment, PayBolt11InvoiceError, PayType, PaymentInfo,
    PaymentInfoError, ReceivingKey, ReclaimLnReceiveError, SpendableAmountError,
    create_incoming_contract_output,
};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::{EncryptedPreimage, PreimageKey};
use fedimint_ln_common::{LightningCommonInit, LightningOutput, MODULE_CONSENSUS_VERSION};
use fedimint_ln_server::LightningInit;
use fedimint_testing::Gateway;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::ln::FakeLightningTest;
use futures::StreamExt;
use lightning_invoice::{
    Bolt11Invoice, Bolt11InvoiceDescription, Currency, Description, InvoiceBuilder, PaymentSecret,
};
use rand::rngs::OsRng;
use secp256k1::Keypair;

pub async fn ln_operation(
    client: &ClientHandleArc,
    operation_id: OperationId,
) -> anyhow::Result<OperationLogEntry> {
    let operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    if operation.operation_module_kind() != LightningCommonInit::KIND.as_str() {
        bail!("Operation is not a lightning operation");
    }

    Ok(operation)
}

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);
    fixtures.with_module(
        LightningClientInit {
            gateway_conn: Some(Arc::new(MockGatewayConnection)),
        },
        LightningInit,
    )
}

/// Consensus version voting must actually reach activation: peers fetch each
/// other's supported version over the API, propose it as a consensus item, and
/// the active version rises to what their binaries support. Without this the
/// whole mechanism could silently never fire and every other test would still
/// pass, leaving the consensus rules it gates permanently inactive.
///
/// Automatic voting requires *every* peer to answer, and unlike walletv1 LNv1
/// has no manual activation override, so a degraded federation never
/// activates — hence the non-degraded fixture.
#[tokio::test(flavor = "multi_thread")]
async fn consensus_version_voting_activates() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client = fed.new_client().await;

    retry(
        "waiting for lnv1 consensus version activation",
        aggressive_backoff_long(),
        || async {
            let active_version = client
                .get_first_module::<LightningClientModule>()?
                .api
                .module_consensus_version()
                .await?;

            anyhow::ensure!(
                active_version == MODULE_CONSENSUS_VERSION,
                "active consensus version is {active_version}, waiting for {MODULE_CONSENSUS_VERSION}"
            );

            Ok(())
        },
    )
    .await
    .expect("LNv1 consensus version voting did not activate in time");

    Ok(())
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest) -> Gateway {
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;
    gateway
}

async fn pay_invoice(
    client: &Client,
    invoice: Bolt11Invoice,
    gateway_id: Option<secp256k1::PublicKey>,
) -> anyhow::Result<OutgoingLightningPayment> {
    let ln_module = client.get_first_module::<LightningClientModule>()?;
    ln_module.update_gateway_cache().await?;
    let gateway = if let Some(gateway_id) = gateway_id {
        ln_module.select_gateway(&gateway_id).await
    } else {
        None
    };
    Ok(ln_module.pay_bolt11_invoice(gateway, invoice, ()).await?)
}

async fn await_client_tx_accepted(
    tx_updates: BoxStream<'static, TxSubmissionStatesSM>,
) -> Result<(), String> {
    tx_updates
        .filter_map(|tx_update| {
            std::future::ready(match tx_update.state {
                TxSubmissionStates::Accepted(_) => Some(Ok(())),
                TxSubmissionStates::Rejected(_, submit_error) => Some(Err(submit_error)),
                _ => None,
            })
        })
        .next()
        .await
        .expect("tx either accepted or rejected")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_can_attach_extra_meta_to_receive_operation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    let extra_meta = "internal payment with no gateway registered".to_string();
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            extra_meta.clone(),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    // Pay the invoice from client2
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Verify that we can retrieve the extra metadata that was attached
    let operation = ln_operation(&client1, op).await?;
    let op_meta = operation
        .meta::<LightningOperationMeta>()
        .extra_meta
        .to_string();
    assert_eq!(serde_json::to_string(&extra_meta)?, op_meta);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_internal_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice.clone(), None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
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
    let prev_balance = client2.get_balance_for_btc().await?;
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
        }
        _ => panic!("Expected internal payment!"),
    }

    let same_balance = client2.get_balance_for_btc().await?;
    assert_eq!(prev_balance, same_balance);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_select_available_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let ln_module = client.get_first_module::<LightningClientModule>()?;

    ln_module.update_gateway_cache().await?;

    assert_matches!(
        ln_module.select_available_gateway(None, None).await,
        Err(GatewaySelectionError::NoGatewaysRegistered)
    );

    let gw1 = gateway(&fixtures, &fed).await;
    ln_module.update_gateway_cache().await?;

    let selected = ln_module.select_available_gateway(None, None).await?;
    assert_eq!(selected.gateway_id, gw1.http_gateway_id().await);

    let gw_info = ln_module
        .select_gateway(&gw1.http_gateway_id().await)
        .await
        .unwrap();
    let selected = ln_module
        .select_available_gateway(Some(gw_info.clone()), None)
        .await?;
    assert_eq!(selected.gateway_id, gw1.http_gateway_id().await);

    let gw2 = gateway(&fixtures, &fed).await;
    ln_module.update_gateway_cache().await?;

    let desc = Description::new("test-invoice".to_string())?;
    let (_, invoice, _) = ln_module
        .create_bolt11_invoice(
            sats(100),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            (),
            None,
        )
        .await?;

    let selected = ln_module
        .select_available_gateway(None, Some(invoice))
        .await?;

    assert!(
        selected.gateway_id == gw1.http_gateway_id().await
            || selected.gateway_id == gw2.http_gateway_id().await
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_external_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gw = gateway(&fixtures, &fed).await;
    let client = fed.new_client().await;
    let dummy_module = client.get_first_module::<DummyClientModule>()?;

    // Give client initial balance
    dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    let other_ln = FakeLightningTest::new();
    let invoice = other_ln.invoice(Amount::from_sats(100), None)?;

    // Pay the invoice for the first time
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice.clone(), Some(gw.http_gateway_id().await)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()?
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_matches!(sub.ok().await?, LnPayState::Funded { .. });
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let prev_balance = client.get_balance_for_btc().await?;

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice, Some(gw.http_gateway_id().await)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()?
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_matches!(sub.ok().await?, LnPayState::Funded { .. });
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let same_balance = client.get_balance_for_btc().await?;
    assert_eq!(prev_balance, same_balance);

    drop(gw);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn makes_internal_payments_within_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // TEST internal payment when there is a registered gateway
    let gw = gateway(&fixtures, &fed).await;

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    let ln_gateway = ln_module.select_gateway(&gw.http_gateway_id().await).await;
    let desc = Description::new("with-gateway-hint".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.http_gateway_id().await)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
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
#[allow(deprecated)]
async fn can_receive_for_other_user() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // generate a new keypair
    let keypair = Keypair::new_global(&mut OsRng);

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice_for_user(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            keypair.public_key(),
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to `Funded` because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>()?;
    let operation_id = new_ln_module.scan_receive_for_user(keypair, ()).await?;
    let mut sub3 = new_ln_module
        .subscribe_ln_claim(operation_id)
        .await?
        .into_stream();
    assert_eq!(sub3.ok().await?, LnReceiveState::AwaitingFunds);
    assert_eq!(sub3.ok().await?, LnReceiveState::Claimed);
    assert_eq!(new_client.get_balance_for_btc().await?, sats(250));

    // TEST internal payment when there is a registered gateway
    let gw = gateway(&fixtures, &fed).await;

    // generate a new keypair
    let keypair = Keypair::new_global(&mut OsRng);

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    let ln_gateway = ln_module.select_gateway(&gw.http_gateway_id().await).await;
    let desc = Description::new("with-gateway-hint".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice_for_user(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            keypair.public_key(),
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.http_gateway_id().await)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to `Funded` because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>()?;
    let operation_id = new_ln_module.scan_receive_for_user(keypair, ()).await?;
    let mut sub3 = new_ln_module
        .subscribe_ln_claim(operation_id)
        .await?
        .into_stream();
    assert_eq!(sub3.ok().await?, LnReceiveState::AwaitingFunds);
    assert_eq!(sub3.ok().await?, LnReceiveState::Claimed);
    assert_eq!(new_client.get_balance_for_btc().await?, sats(250));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(deprecated)]
async fn can_receive_for_other_user_tweaked() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gw = gateway(&fixtures, &fed).await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // generate a new keypair
    let keypair = Keypair::new_global(&mut OsRng);

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    let ln_gateway = ln_module.select_gateway(&gw.http_gateway_id().await).await;
    let desc = Description::new("with-gateway-hint-tweaked".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice_for_user_tweaked(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            keypair.public_key(),
            1, // tweak with index 1
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.http_gateway_id().await)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to `Funded` because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>()?;
    let claims = new_ln_module
        .scan_receive_for_user_tweaked(keypair, vec![1], ())
        .await;
    for operation_id in claims {
        let mut sub3 = new_ln_module
            .subscribe_ln_claim(operation_id)
            .await?
            .into_stream();
        assert_eq!(sub3.ok().await?, LnReceiveState::AwaitingFunds);
        assert_eq!(sub3.ok().await?, LnReceiveState::Claimed);
    }
    assert_eq!(new_client.get_balance_for_btc().await?, sats(250));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gw = gateway(&fixtures, &fed).await;
    let client1 = fed.new_client().await;

    // Build a signet invoice with a near-infinite expiry so the network
    // check fires before the expiry check.
    let ctx = secp256k1::Secp256k1::new();
    let kp = Keypair::new(&ctx, &mut OsRng);
    let payment_hash = sha256::Hash::hash(&[0; 32]);
    let signet_invoice = InvoiceBuilder::new(Currency::Signet)
        .description(String::new())
        .payment_hash(payment_hash)
        .current_timestamp()
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(100_000)
        .expiry_time(std::time::Duration::from_secs(365 * 24 * 60 * 60 * 100))
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &secp256k1::SecretKey::from_keypair(&kp)))
        .expect("Failed to build signet invoice");

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    ln_module.update_gateway_cache().await?;
    let gateway = ln_module.select_gateway(&gw.http_gateway_id().await).await;
    let error = ln_module
        .pay_bolt11_invoice(gateway, signet_invoice, ())
        .await
        .expect_err("Payment of a signet invoice should fail");
    assert_matches!(
        error,
        PayBolt11InvoiceError::WrongCurrency {
            expected: Currency::Regtest,
            found: Currency::Signet
        }
    );

    Ok(())
}

/// The payee controls the invoice's `min_final_cltv_expiry_delta`, which is
/// added to the contract's refund timelock. Like LNv2, the client refuses a
/// total timelock delta above 1440 blocks before funding, so a payee cannot
/// push the payer's refund out indefinitely or overflow the timelock.
#[tokio::test(flavor = "multi_thread")]
async fn rejects_invoice_with_excessive_min_final_cltv() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gw = gateway(&fixtures, &fed).await;
    let client = fed.new_client().await;
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    let ctx = secp256k1::Secp256k1::new();
    let kp = Keypair::new(&ctx, &mut OsRng);
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(942)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(100_000)
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &secp256k1::SecretKey::from_keypair(&kp)))
        .expect("Failed to build invoice");

    let error = pay_invoice(&client, invoice, Some(gw.http_gateway_id().await))
        .await
        .expect_err("Payment of an invoice with an excessive CLTV delta should fail");
    assert_matches!(
        error.downcast::<PayBolt11InvoiceError>()?,
        // 942 blocks plus the client's own 499 is one past the limit
        PayBolt11InvoiceError::TimelockDeltaTooLarge {
            found: 1441,
            max: 1440
        }
    );
    assert_eq!(client.get_balance_for_btc().await?, sats(1000));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_expired_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // Create an invoice with a 1-second expiry.
    let desc = Description::new("expired-invoice".to_string())?;
    let (_op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            Some(1),
            (),
            None,
        )
        .await?;

    // Wait for the offer to expire
    fedimint_core::task::sleep_in_test(
        "waiting for offer to expire",
        std::time::Duration::from_secs(2),
    )
    .await;

    // client2 attempts to pay the expired invoice — the send-side check in
    // pay_bolt11_invoice() rejects it before reaching the federation.
    let ln_module = client2.get_first_module::<LightningClientModule>()?;
    let error = ln_module
        .pay_bolt11_invoice(None, invoice, ())
        .await
        .expect_err("Payment of expired invoice should fail");
    assert_matches!(error, PayBolt11InvoiceError::InvoiceExpired);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn returns_completed_payment_for_expired_invoice_already_paid() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Give client2 initial balance
    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    // An invoice with a short expiry, paid (internally) well before it lapses.
    let desc = Description::new("paid-then-expired".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()?
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(desc),
            Some(5),
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()?
        .subscribe_ln_receive(op)
        .await?
        .into_stream();

    // Pay FIRST, before consuming any receive-stream states: the pre-payment
    // window against the short real-time expiry must stay minimal so a slow CI
    // cannot expire the invoice before the first attempt. The receive stream
    // replays all states in order, so the assertions below are unaffected.
    let OutgoingLightningPayment {
        payment_type: first_payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice.clone(), None).await?;
    match first_payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()?
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Created);
            assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Let the invoice lapse AFTER it was successfully paid.
    fedimint_core::task::sleep_in_test(
        "waiting for the paid invoice to expire",
        std::time::Duration::from_secs(6),
    )
    .await;

    // A caller recovering from a crash re-pays the same (now expired) invoice to
    // learn what happened to its earlier attempt. The completed payment must be
    // returned — not an "Invoice has expired" error, which would mask the
    // successful payment and push the caller toward paying again through a
    // fresh invoice.
    let prev_balance = client2.get_balance_for_btc().await?;
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    assert_eq!(
        payment_type.operation_id(),
        first_payment_type.operation_id(),
        "the completed payment is returned; no new attempt is started"
    );
    let same_balance = client2.get_balance_for_btc().await?;
    assert_eq!(prev_balance, same_balance);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_reclaim_receive_funded_after_invoice_expiry() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    client2_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    let amount = sats(250);

    let receiving_keypair = Keypair::new_global(&mut OsRng);
    let receiving_key = ReceivingKey::Personal(receiving_keypair);
    let preimage_key: [u8; 33] = receiving_key.public_key().serialize();
    let preimage = sha256::Hash::hash(&preimage_key);
    let payment_hash = sha256::Hash::hash(&preimage.to_byte_array());
    let operation_id = OperationId(payment_hash.to_byte_array());

    let secp = secp256k1::Secp256k1::new();
    let node_keypair = Keypair::new(&secp, &mut OsRng);
    let stale_timestamp = fedimint_core::time::duration_since_epoch()
        .checked_sub(Duration::from_secs(120))
        .expect("current time is after unix epoch");
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .amount_milli_satoshis(amount.msats)
        .description("stale receive".to_string())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([1; 32]))
        .duration_since_epoch(stale_timestamp)
        .min_final_cltv_expiry_delta(18)
        .payee_pub_key(node_keypair.public_key())
        .expiry_time(Duration::from_secs(1))
        .build_signed(|m| {
            secp.sign_ecdsa_recoverable(m, &secp256k1::SecretKey::from_keypair(&node_keypair))
        })?;

    let offer_output = LightningOutput::new_v0_offer(IncomingContractOffer {
        amount,
        hash: payment_hash,
        encrypted_preimage: EncryptedPreimage::new(
            &PreimageKey(preimage_key),
            &ln_module.cfg.threshold_pub_key,
        ),
        expiry_time: Some(1),
    });
    let sm_invoice = invoice.clone();
    let transaction_builder = TransactionBuilder::new().with_outputs(
        ClientOutputBundle::new(
            vec![ClientOutput {
                output: offer_output,
                amounts: Amounts::ZERO,
            }],
            vec![ClientOutputSM {
                state_machines: Arc::new(move |out_point_range| {
                    vec![LightningClientStateMachines::Receive(
                        LightningReceiveStateMachine {
                            operation_id,
                            state: LightningReceiveStates::SubmittedOffer(
                                LightningReceiveSubmittedOffer {
                                    offer_txid: out_point_range.txid(),
                                    invoice: sm_invoice.clone(),
                                    receiving_key,
                                },
                            ),
                        },
                    )]
                }),
            }],
        )
        .into_dyn(ln_module.id),
    );
    let meta_invoice = invoice.clone();
    client1
        .finalize_and_submit_transaction(
            operation_id,
            LightningCommonInit::KIND.as_str(),
            move |out_point_range| LightningOperationMeta {
                variant: LightningOperationMetaVariant::Receive {
                    out_point: fedimint_core::OutPoint {
                        txid: out_point_range.txid(),
                        out_idx: 0,
                    },
                    invoice: meta_invoice.clone(),
                    gateway_id: None,
                },
                extra_meta: serde_json::Value::Null,
            },
            transaction_builder,
        )
        .await?;

    let mut sub = ln_module
        .subscribe_ln_receive(operation_id)
        .await?
        .into_stream();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), sub.ok()).await?? {
            LnReceiveState::Canceled {
                reason: LightningReceiveError::Timeout,
            } => break,
            _ => continue,
        }
    }

    let gateway_redeem_key = Keypair::new_global(&mut OsRng);
    let (incoming_output, funded_amount, _contract_id) =
        create_incoming_contract_output(&ln_module.api, payment_hash, amount, &gateway_redeem_key)
            .await?;
    let funding_operation_id = OperationId::new_random();
    let funding_tx = TransactionBuilder::new().with_outputs(
        ClientOutputBundle::new_no_sm(vec![ClientOutput {
            output: LightningOutput::V0(incoming_output),
            amounts: Amounts::new_bitcoin(funded_amount),
        }])
        .into_dyn(ln_module.id),
    );
    client2
        .finalize_and_submit_transaction(
            funding_operation_id,
            LightningCommonInit::KIND.as_str(),
            |_| (),
            funding_tx,
        )
        .await?;
    await_client_tx_accepted(
        client2
            .transaction_updates(funding_operation_id)
            .await
            .update_stream,
    )
    .await
    .expect("late funding transaction should be accepted");

    let reclaim_operation_id = ln_module.reclaim_ln_receive(operation_id).await?;
    let mut reclaim_sub = ln_module
        .subscribe_ln_receive(reclaim_operation_id)
        .await?
        .into_stream();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), reclaim_sub.ok()).await?? {
            LnReceiveState::Claimed => break,
            _ => continue,
        }
    }

    assert_eq!(client1.get_balance_for_btc().await?, amount);

    Ok(())
}

/// A funder must refuse to fund a payment hash that already has a contract
/// account. An incoming contract's id is only its payment hash, so a second
/// funding is credited to the account the *first* funder created, under their
/// gateway key — an attacker can plant such an account cheaply and then publish
/// a fresh offer to bait a gateway into topping it up.
#[tokio::test(flavor = "multi_thread")]
async fn funder_refuses_to_fund_an_already_funded_payment_hash() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    client2
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

    let ln_module = client1.get_first_module::<LightningClientModule>()?;
    let threshold_pub_key = ln_module.cfg.threshold_pub_key;
    let amount = sats(250);

    let receiving_keypair = Keypair::new_global(&mut OsRng);
    let preimage_key: [u8; 33] = receiving_keypair.public_key().serialize();
    let payment_hash = sha256::Hash::hash(&sha256::Hash::hash(&preimage_key).to_byte_array());

    let submit_offer = async |client: &ClientHandleArc| -> anyhow::Result<()> {
        let offer_output = LightningOutput::new_v0_offer(IncomingContractOffer {
            amount,
            hash: payment_hash,
            encrypted_preimage: EncryptedPreimage::new(
                &PreimageKey(preimage_key),
                &threshold_pub_key,
            ),
            expiry_time: None,
        });
        let operation_id = OperationId::new_random();
        client
            .finalize_and_submit_transaction(
                operation_id,
                "",
                |_| (),
                TransactionBuilder::new().with_outputs(
                    ClientOutputBundle::new_no_sm(vec![ClientOutput {
                        output: offer_output,
                        amounts: Amounts::ZERO,
                    }])
                    .into_dyn(ln_module.id),
                ),
            )
            .await?;
        await_client_tx_accepted(client.transaction_updates(operation_id).await.update_stream)
            .await
            .map_err(|err| anyhow::anyhow!(err))
    };

    submit_offer(&client1).await.expect("first offer accepted");

    // first funding succeeds and consumes the offer
    let funder_key = Keypair::new_global(&mut OsRng);
    let (incoming_output, funded_amount, _) = create_incoming_contract_output(
        &client2.get_first_module::<LightningClientModule>()?.api,
        payment_hash,
        amount,
        &funder_key,
    )
    .await?;
    let operation_id = OperationId::new_random();
    client2
        .finalize_and_submit_transaction(
            operation_id,
            LightningCommonInit::KIND.as_str(),
            |_| (),
            TransactionBuilder::new().with_outputs(
                ClientOutputBundle::new_no_sm(vec![ClientOutput {
                    output: LightningOutput::V0(incoming_output),
                    amounts: Amounts::new_bitcoin(funded_amount),
                }])
                .into_dyn(ln_module.id),
            ),
        )
        .await?;
    await_client_tx_accepted(
        client2
            .transaction_updates(operation_id)
            .await
            .update_stream,
    )
    .await
    .expect("first funding accepted");

    // the offer was consumed, and since an incoming contract account exists
    // for the hash now, a fresh offer for it is rejected at submission time
    submit_offer(&client1)
        .await
        .expect_err("an offer for an already funded payment hash is rejected");

    // ... so a funder cannot even fetch an offer to fund the hash a second
    // time. The client-side `ContractAlreadyExists` guard in
    // `create_incoming_contract_output` remains as defense in depth for
    // federations whose guardians do not enforce the offer policy yet.
    assert_matches!(
        create_incoming_contract_output(
            &client2.get_first_module::<LightningClientModule>()?.api,
            payment_hash,
            amount,
            &funder_key,
        )
        .await,
        Err(IncomingSmError::TimeoutFetchingOffer { .. })
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn server_rejects_duplicate_offer() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client1 = fed.new_client().await;
    let ln_module = client1.get_first_module::<LightningClientModule>()?;

    let threshold_pub_key = ln_module.cfg.threshold_pub_key;

    let encrypted_preimage_1 = EncryptedPreimage::new(&PreimageKey([0x42; 33]), &threshold_pub_key);
    let offer_output_1 = LightningOutput::new_v0_offer(IncomingContractOffer {
        amount: sats(1000),
        hash: sha256::Hash::hash(&[]),
        encrypted_preimage: encrypted_preimage_1.clone(),
        expiry_time: None,
    });
    let transaction_builder_1 = TransactionBuilder::new().with_outputs(
        ClientOutputBundle::new_no_sm(vec![ClientOutput {
            output: offer_output_1,
            amounts: Amounts::ZERO,
        }])
        .into_dyn(ln_module.id),
    );
    let operation_id_1 = OperationId::new_random();

    let encrypted_preimage_2 = EncryptedPreimage::new(&PreimageKey([0x43; 33]), &threshold_pub_key);
    let offer_output_2 = LightningOutput::new_v0_offer(IncomingContractOffer {
        amount: sats(1000),
        hash: sha256::Hash::hash(&[]),
        encrypted_preimage: encrypted_preimage_2.clone(),
        expiry_time: None,
    });
    let transaction_builder_2 = TransactionBuilder::new().with_outputs(
        ClientOutputBundle::new_no_sm(vec![ClientOutput {
            output: offer_output_2,
            amounts: Amounts::ZERO,
        }])
        .into_dyn(ln_module.id),
    );
    let operation_id_2 = OperationId::new_random();

    assert_ne!(
        encrypted_preimage_1, encrypted_preimage_2,
        "The two should have different encrypted preimages"
    );

    async fn await_tx_accepted(
        tx_updates: BoxStream<'static, TxSubmissionStatesSM>,
    ) -> Result<(), String> {
        tx_updates
            .filter_map(|tx_update| {
                std::future::ready(match tx_update.state {
                    TxSubmissionStates::Accepted(_) => Some(Ok(())),
                    TxSubmissionStates::Rejected(_, submit_error) => Some(Err(submit_error)),
                    _ => None,
                })
            })
            .next()
            .await
            .expect("Tx either accepted or rejected")
    }

    client1
        .finalize_and_submit_transaction(operation_id_1, "", |_| (), transaction_builder_1)
        .await
        .expect("Tx finalization failed");
    await_tx_accepted(
        client1
            .transaction_updates(operation_id_1)
            .await
            .update_stream,
    )
    .await
    .expect("First offer should be accepted");

    client1
        .finalize_and_submit_transaction(operation_id_2, "", |_| (), transaction_builder_2)
        .await
        .expect("Tx finalization failed");
    await_tx_accepted(
        client1
            .transaction_updates(operation_id_2)
            .await
            .update_stream,
    )
    .await
    .expect_err("Second offer should be rejected");

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests;

/// A client with no gateway registered cannot say what it could spend over
/// Lightning, and says which of the two reasons applies instead of returning
/// one interchangeable string.
#[tokio::test(flavor = "multi_thread")]
async fn spendable_amount_without_a_gateway_names_the_reason() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let ln_module = client.get_first_module::<LightningClientModule>()?;

    assert_matches!(
        ln_module.spendable_amount(sats(1000), None).await,
        Err(SpendableAmountError::Gateway(
            GatewaySelectionError::NoGatewaysRegistered
        ))
    );

    Ok(())
}

/// Subscribing with the wrong operation says which kind of lightning
/// operation was expected, instead of one of five interchangeable strings.
#[tokio::test(flavor = "multi_thread")]
async fn subscribing_with_the_wrong_operation_names_the_kind() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let ln_module = client.get_first_module::<LightningClientModule>()?;

    assert_matches!(
        ln_module
            .subscribe_ln_receive(OperationId::new_random())
            .await,
        Err(LnSubscribeError::Operation(OperationLookupError::NotFound(
            _
        )))
    );

    let desc = Description::new("wrong-kind".to_string())?;
    let (receive_op, _invoice, _) = ln_module
        .create_bolt11_invoice(
            sats(100),
            Bolt11InvoiceDescription::Direct(desc),
            None,
            (),
            None,
        )
        .await?;

    assert_matches!(
        ln_module.subscribe_ln_pay(receive_op).await,
        Err(LnSubscribeError::NotAPayment)
    );
    assert_matches!(
        ln_module.get_ln_pay_details_for(receive_op).await,
        Err(LnSubscribeError::NotAPayment)
    );

    Ok(())
}

/// Claiming an incoming contract that was never funded says so, instead of
/// "No contract found for ..".
#[tokio::test(flavor = "multi_thread")]
#[allow(deprecated)]
async fn claiming_an_unfunded_contract_reports_not_found() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let ln_module = client.get_first_module::<LightningClientModule>()?;

    let keypair = Keypair::new(&secp256k1::Secp256k1::new(), &mut OsRng);
    assert_matches!(
        ln_module.scan_receive_for_user(keypair, ()).await,
        Err(ClaimIncomingContractError::ContractNotFound { .. })
    );

    Ok(())
}

/// Reclaiming something that is not a reclaimable receive says which of the
/// three refusals applies, instead of one of three interchangeable strings.
#[tokio::test(flavor = "multi_thread")]
async fn reclaiming_a_non_receive_reports_not_reclaimable() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let ln_module = client.get_first_module::<LightningClientModule>()?;

    assert_matches!(
        ln_module
            .reclaim_ln_receive(OperationId::new_random())
            .await,
        Err(ReclaimLnReceiveError::Operation(
            OperationLookupError::NotFound(_)
        ))
    );

    Ok(())
}

/// Parsing a payment target and turning it into an invoice each name their
/// own refusal, instead of returning one interchangeable string.
#[tokio::test(flavor = "multi_thread")]
async fn payment_info_names_its_refusals() -> anyhow::Result<()> {
    assert_matches!(
        PaymentInfo::parse("not an invoice and not an lnurl").await,
        Err(PaymentInfoError::NotAnInvoiceOrLnurl(_))
    );

    // A garbage LNURL and a malformed lightning address are both decoding
    // failures caught before any network request is made.
    assert_matches!(
        PaymentInfo::parse("lnurl1notvalidbech32").await,
        Err(PaymentInfoError::LnurlDecode(_))
    );
    assert_matches!(
        PaymentInfo::parse("not-an-email@").await,
        Err(PaymentInfoError::LnurlDecode(_))
    );

    let ctx = secp256k1::Secp256k1::new();
    let kp = Keypair::new(&ctx, &mut OsRng);
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(100_000)
        .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &secp256k1::SecretKey::from_keypair(&kp)))
        .expect("Failed to build invoice");

    assert_matches!(
        PaymentInfo::Bolt11(invoice)
            .get_invoice(Some(sats(100)), None)
            .await,
        Err(PaymentInfoError::AmountInInvoiceAndCommandLine)
    );

    Ok(())
}
