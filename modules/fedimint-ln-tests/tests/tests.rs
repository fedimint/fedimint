use std::str::FromStr;

use assert_matches::assert_matches;
use fedimint_client::Client;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::{
    InternalPayState, LightningClientInit, LightningClientModule, LightningOperationMeta,
    LnPayState, LnReceiveState, OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::ln_operation;
use fedimint_ln_server::LightningInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use rand::rngs::OsRng;
use secp256k1::KeyPair;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures.with_module(LightningClientInit, LightningInit, ln_params)
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

async fn pay_invoice(
    client: &Client,
    invoice: Bolt11Invoice,
    gateway_id: Option<secp256k1::PublicKey>,
) -> anyhow::Result<OutgoingLightningPayment> {
    let ln_module = client.get_first_module::<LightningClientModule>();
    let gateway = if let Some(gateway_id) = gateway_id {
        ln_module.select_gateway(&gateway_id).await
    } else {
        None
    };
    ln_module.pay_bolt11_invoice(gateway, invoice, ()).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_can_attach_extra_meta_to_receive_operation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let extra_meta = "internal payment with no gateway registered".to_string();
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            extra_meta.clone(),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
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
                .get_first_module::<LightningClientModule>()
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
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
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
                .get_first_module::<LightningClientModule>()
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
    let prev_balance = client2.get_balance().await;
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, None).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
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
async fn gateway_protects_preimage_for_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gw = gateway(&fixtures, &fed).await;
    let (client1, client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client1
    let (op, outpoint) = client1_dummy_module.print_money(sats(10000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(10000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

    // Pay invoice with client1
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client1, invoice.clone(), Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client1
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    // Verify that client2 cannot pay the same invoice and the preimage is not
    // returned
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice.clone(), Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::WaitingForRefund { .. });
            assert_matches!(sub.ok().await?, LnPayState::Refunded { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    drop(gw);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_external_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gw = gateway(&fixtures, &fed).await;
    let client = fed.new_client().await;
    let dummy_module = client.get_first_module::<DummyClientModule>();

    // Print money for client
    let (op, outpoint) = dummy_module.print_money(sats(1000)).await?;
    client.await_primary_module_output(op, outpoint).await?;

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

    // Pay the invoice for the first time
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice.clone(), Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let prev_balance = client.get_balance().await;

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice, Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

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
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
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
                .get_first_module::<LightningClientModule>()
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

    let ln_module = client1.get_first_module::<LightningClientModule>();
    let ln_gateway = ln_module.select_gateway(&gw.gateway.gateway_id).await;
    let desc = Description::new("with-gateway-hint".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
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
async fn can_receive_for_other_user() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // generate a new keypair
    let keypair = KeyPair::new_global(&mut OsRng);

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let desc = Description::new("with-markers".to_string())?;
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice_for_user(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            keypair.public_key(),
            (),
            None,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
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
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to immediate claim because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>();
    let operation_id = new_ln_module.scan_receive_for_user(keypair, ()).await?;
    let mut sub3 = new_ln_module
        .subscribe_ln_claim(operation_id)
        .await?
        .into_stream();
    assert_eq!(sub3.ok().await?, LnReceiveState::AwaitingFunds);
    assert_eq!(sub3.ok().await?, LnReceiveState::Claimed);
    assert_eq!(new_client.get_balance().await, sats(250));

    // TEST internal payment when there is a registered gateway
    let gw = gateway(&fixtures, &fed).await;

    // generate a new keypair
    let keypair = KeyPair::new_global(&mut OsRng);

    let ln_module = client1.get_first_module::<LightningClientModule>();
    let ln_gateway = ln_module.select_gateway(&gw.gateway.gateway_id).await;
    let desc = Description::new("with-gateway-hint".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice_for_user(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            keypair.public_key(),
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to immediate claim because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>();
    let operation_id = new_ln_module.scan_receive_for_user(keypair, ()).await?;
    let mut sub3 = new_ln_module
        .subscribe_ln_claim(operation_id)
        .await?
        .into_stream();
    assert_eq!(sub3.ok().await?, LnReceiveState::AwaitingFunds);
    assert_eq!(sub3.ok().await?, LnReceiveState::Claimed);
    assert_eq!(new_client.get_balance().await, sats(250));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_receive_for_other_user_tweaked() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gw = gateway(&fixtures, &fed).await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // generate a new keypair
    let keypair = KeyPair::new_global(&mut OsRng);

    let ln_module = client1.get_first_module::<LightningClientModule>();
    let ln_gateway = ln_module.select_gateway(&gw.gateway.gateway_id).await;
    let desc = Description::new("with-gateway-hint-tweaked".to_string())?;
    let (op, invoice, _) = ln_module
        .create_bolt11_invoice_for_user_tweaked(
            sats(250),
            Bolt11InvoiceDescription::Direct(&desc),
            None,
            keypair.public_key(),
            1, // tweak with index 1
            (),
            ln_gateway,
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice, Some(gw.gateway.gateway_id)).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            // goes from preimage to immediate claim because it is for another user
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Create a new client and try to receive the locked payment
    let new_client = fed.new_client().await;
    let new_ln_module = new_client.get_first_module::<LightningClientModule>();
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
    assert_eq!(new_client.get_balance().await, sats(250));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gw = gateway(&fixtures, &fed).await;
    let client1 = fed.new_client().await;

    // Signet invoice should fail on regtest
    let signet_invoice = Bolt11Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .unwrap();

    let error = pay_invoice(&client1, signet_invoice, Some(gw.gateway.gateway_id))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Invalid invoice currency: expected=Regtest, got=Signet"
    );

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;
    use std::time::Duration;

    use anyhow::ensure;
    use bitcoin_hashes::{sha256, Hash};
    use fedimint_client::module::init::DynClientModuleInit;
    use fedimint_core::core::OperationId;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::Encodable;
    use fedimint_core::module::DynServerModuleInit;
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{Amount, OutPoint, PeerId, TransactionId};
    use fedimint_ln_client::db::{
        MetaOverrides, MetaOverridesKey, MetaOverridesPrefix, PaymentResult, PaymentResultKey,
        PaymentResultPrefix,
    };
    use fedimint_ln_client::receive::{
        LightningReceiveStateMachine, LightningReceiveStates, LightningReceiveSubmittedOffer,
        LightningReceiveSubmittedOfferV0,
    };
    use fedimint_ln_client::{
        LightningClientInit, LightningClientModule, LightningClientStateMachines,
        OutgoingLightningPayment, ReceivingKey,
    };
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
    };
    use fedimint_ln_common::contracts::{
        outgoing, ContractId, DecryptedPreimage, EncryptedPreimage, FundedContract,
        PreimageDecryptionShare, PreimageKey,
    };
    use fedimint_ln_common::route_hints::{RouteHint, RouteHintHop};
    use fedimint_ln_common::{
        ContractAccount, LightningCommonInit, LightningGateway, LightningGatewayRegistration,
        LightningOutputOutcomeV0,
    };
    use fedimint_ln_server::db::{
        AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, BlockCountVoteKey,
        BlockCountVotePrefix, ContractKey, ContractKeyPrefix, ContractUpdateKey,
        ContractUpdateKeyPrefix, DbKeyPrefix, EncryptedPreimageIndexKey,
        EncryptedPreimageIndexKeyPrefix, LightningAuditItemKey, LightningAuditItemKeyPrefix,
        LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix,
        ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
    };
    use fedimint_logging::TracingSetup;
    use fedimint_testing::db::{
        snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
        validate_migrations_server, BYTE_32, BYTE_33, BYTE_8, STRING_64,
    };
    use futures::StreamExt;
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret, RoutingFees};
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::rngs::OsRng;
    use secp256k1::{All, KeyPair, Secp256k1, SecretKey};
    use strum::IntoEnumIterator;
    use threshold_crypto::G1Projective;
    use tracing::info;

    use crate::LightningInit;

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        let contract_id = ContractId::from_str(STRING_64).unwrap();
        let amount = fedimint_core::Amount { msats: 1000 };
        let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let incoming_contract = IncomingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(PreimageKey(BYTE_33), &threshold_key),
            decrypted_preimage: DecryptedPreimage::Some(PreimageKey(BYTE_33)),
            gateway_key: pk,
        };
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };
        let incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: incoming_contract,
            out_point,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: incoming_contract.clone(),
            },
        )
        .await;
        let outgoing_contract = FundedContract::Outgoing(outgoing::OutgoingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&[0, 2, 3, 4, 5, 6, 7, 8]),
            gateway_key: pk,
            timelock: 1000000,
            user_key: pk,
            cancelled: false,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: outgoing_contract.clone(),
            },
        )
        .await;

        let incoming_offer = IncomingContractOffer {
            amount: fedimint_core::Amount { msats: 1000 },
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(PreimageKey(BYTE_33), &threshold_key),
            expiry_time: None,
        };
        dbtx.insert_new_entry(&OfferKey(incoming_offer.hash), &incoming_offer)
            .await;

        let contract_update_key = ContractUpdateKey(OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        });
        let lightning_output_outcome = LightningOutputOutcomeV0::Offer {
            id: OfferId::from_str(STRING_64).unwrap(),
        };
        dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
            .await;

        let preimage_decryption_share = PreimageDecryptionShare(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(
            &ProposeDecryptionShareKey(contract_id),
            &preimage_decryption_share,
        )
        .await;

        dbtx.insert_new_entry(
            &AgreedDecryptionShareKey(contract_id, 0.into()),
            &preimage_decryption_share,
        )
        .await;

        let gateway = LightningGatewayRegistration {
            info: LightningGateway {
                mint_channel_id: 100,
                gateway_redeem_key: pk,
                node_pub_key: pk,
                lightning_alias: "FakeLightningAlias".to_string(),
                api: SafeUrl::parse("http://example.com")
                    .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
                route_hints: vec![],
                fees: RoutingFees {
                    base_msat: 0,
                    proportional_millionths: 0,
                },
                gateway_id: pk,
                supports_private_payments: false,
            },
            valid_until: fedimint_core::time::now(),
            vetted: false,
        };
        dbtx.insert_new_entry(&LightningGatewayKey(pk), &gateway)
            .await;

        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &1)
            .await;

        dbtx.insert_new_entry(&EncryptedPreimageIndexKey("foobar".consensus_hash()), &())
            .await;

        dbtx.insert_new_entry(
            &LightningAuditItemKey::from_funded_contract(&incoming_contract),
            &amount,
        )
        .await;

        dbtx.insert_new_entry(
            &LightningAuditItemKey::from_funded_contract(&outgoing_contract),
            &amount,
        )
        .await;

        dbtx.commit_tx().await;
    }

    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        // Generate fake private/public key
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let hop = RouteHintHop {
            src_node_id: pk,
            short_channel_id: 3,
            base_msat: 20,
            proportional_millionths: 3000,
            cltv_expiry_delta: 8,
            htlc_minimum_msat: Some(10),
            htlc_maximum_msat: Some(1000),
        };
        let route_hints = vec![RouteHint(vec![hop])];

        let gateway_info = LightningGateway {
            mint_channel_id: 3,
            gateway_redeem_key: pk,
            node_pub_key: pk,
            lightning_alias: "MyLightningNode".to_string(),
            api: SafeUrl::from_str("http://mylightningnode.com")
                .expect("SafeUrl parsing should not fail"),
            route_hints,
            fees: RoutingFees {
                base_msat: 10,
                proportional_millionths: 1000,
            },
            gateway_id: pk,
            supports_private_payments: false,
        };

        let lightning_gateway_registration = LightningGatewayRegistration {
            info: gateway_info,
            vetted: false,
            valid_until: fedimint_core::time::now(),
        };

        dbtx.insert_new_entry(
            &fedimint_ln_client::db::ActiveGatewayKey,
            &lightning_gateway_registration,
        )
        .await;

        dbtx.insert_new_entry(
            &fedimint_ln_client::db::LightningGatewayKey(pk),
            &lightning_gateway_registration,
        )
        .await;

        dbtx.insert_new_entry(
            &PaymentResultKey {
                payment_hash: sha256::Hash::hash(&BYTE_8),
            },
            &PaymentResult {
                index: 0,
                completed_payment: Some(OutgoingLightningPayment {
                    payment_type: fedimint_ln_client::PayType::Lightning(OperationId(BYTE_32)),
                    contract_id: sha256::Hash::hash(&BYTE_8).into(),
                    fee: Amount::from_sats(1000),
                }),
            },
        )
        .await;

        dbtx.insert_new_entry(
            &MetaOverridesKey,
            &MetaOverrides {
                value: "META OVERRIDE".to_string(),
                fetched_at: fedimint_core::time::now(),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    fn create_client_states() -> (
        Vec<LightningClientStateMachines>,
        Vec<LightningClientStateMachines>,
    ) {
        let secp: Secp256k1<All> = Secp256k1::gen_new();
        let invoice1 = InvoiceBuilder::new(Currency::Regtest)
            .amount_milli_satoshis(1000)
            .payment_hash(sha256::Hash::hash(&BYTE_32))
            .description("".to_string())
            .payment_secret(PaymentSecret([0; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(18)
            .expiry_time(Duration::from_secs(86400))
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &SecretKey::new(&mut OsRng)))
            .unwrap();
        let invoice2 = InvoiceBuilder::new(Currency::Regtest)
            .amount_milli_satoshis(1000)
            .payment_hash(sha256::Hash::hash(&BYTE_32))
            .description("".to_string())
            .payment_secret(PaymentSecret([0; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(18)
            .expiry_time(Duration::from_secs(86400))
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &SecretKey::new(&mut OsRng)))
            .unwrap();

        // Create an active state and inactive state that will not be migrated.
        let operation_id = OperationId::new_random();
        let input_state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id,
            state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                offer_txid: TransactionId::all_zeros(),
                invoice: invoice1,
                receiving_key: ReceivingKey::Personal(KeyPair::new_global(&mut OsRng)),
            }),
        });

        // Create and active state and inactive state that will be migrated.
        let operation_id = OperationId::new_random();
        let state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id,
            state: LightningReceiveStates::SubmittedOfferV0(LightningReceiveSubmittedOfferV0 {
                offer_txid: TransactionId::all_zeros(),
                invoice: invoice2,
                payment_keypair: KeyPair::new_global(&mut OsRng),
            }),
        });

        (
            vec![state.clone(), input_state.clone()],
            vec![state, input_state],
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, LightningCommonInit>("lightning-server-v0", |db| {
            Box::pin(async move {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynServerModuleInit::from(LightningInit);

        validate_migrations_server(
            module,
            "lightning-server",
            |db| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::Contract => {
                            let contracts = dbtx
                                .find_by_prefix(&ContractKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_contracts = contracts.len();
                            ensure!(
                                num_contracts > 0,
                                "validate_migrations was not able to read any contracts"
                            );
                            info!("Validated Contracts");
                        }
                        DbKeyPrefix::AgreedDecryptionShare => {
                            let agreed_decryption_shares = dbtx
                                .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = agreed_decryption_shares.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any AgreedDecryptionShares"
                            );
                            info!("Validated AgreedDecryptionShares");
                        }
                        DbKeyPrefix::ContractUpdate => {
                            let contract_updates = dbtx
                                .find_by_prefix(&ContractUpdateKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_updates = contract_updates.len();
                            ensure!(
                                num_updates > 0,
                                "validate_migrations was not able to read any ContractUpdates"
                            );
                            info!("Validated ContractUpdates");
                        }
                        DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            ensure!(
                                num_gateways > 0,
                                "validate_migrations was not able to read any LightningGateways"
                            );
                            info!("Validated LightningGateway");
                        }
                        DbKeyPrefix::Offer => {
                            let offers = dbtx
                                .find_by_prefix(&OfferKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_offers = offers.len();
                            ensure!(
                                num_offers > 0,
                                "validate_migrations was not able to read any Offers"
                            );
                            info!("Validated Offer");
                        }
                        DbKeyPrefix::ProposeDecryptionShare => {
                            let proposed_decryption_shares = dbtx
                                .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = proposed_decryption_shares.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any ProposeDecryptionShares"
                            );
                            info!("Validated ProposeDecryptionShare");
                        }
                        DbKeyPrefix::BlockCountVote => {
                            let block_count_vote = dbtx
                                .find_by_prefix(&BlockCountVotePrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_votes = block_count_vote.len();
                            ensure!(
                                num_votes > 0,
                                "validate_migrations was not able to read any BlockCountVote"
                            );
                            info!("Validated BlockCountVote");
                        }
                        DbKeyPrefix::EncryptedPreimageIndex => {
                            let encrypted_preimage_index = dbtx
                                .find_by_prefix(&EncryptedPreimageIndexKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = encrypted_preimage_index.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any EncryptedPreimageIndexKeys"
                            );
                            info!("Validated EncryptedPreimageIndex");
                        }
                        DbKeyPrefix::LightningAuditItem => {
                            let audit_keys = dbtx
                                .find_by_prefix(&LightningAuditItemKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;

                            let num_audit_items = audit_keys.len();
                            ensure!(
                                num_audit_items == 2,
                                "validate_migrations was not able to read both LightningAuditItemKeys"
                            );
                            info!("Validated LightningAuditItem");
                        }
                    }
                }

                Ok(())
            }
        ).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, LightningCommonInit, LightningClientModule>(
            "lightning-client-v0",
            |db| Box::pin(async move { create_client_db_with_v0_data(db).await }),
            create_client_states,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynClientModuleInit::from(LightningClientInit);
        validate_migrations_client::<_, _, LightningClientModule>(
            module,
            "lightning-client",
            |db, active_states, inactive_states| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in fedimint_ln_client::db::DbKeyPrefix::iter() {
                    match prefix {
                        fedimint_ln_client::db::DbKeyPrefix::ActiveGateway => {
                            // Active gateway is deprecated, there should be no records
                            let active_gateway = dbtx
                                .get_value(&fedimint_ln_client::db::ActiveGatewayKey)
                                .await;
                            ensure!(
                                active_gateway.is_none(),
                                "validate migrations found an active gateway"
                            );
                        }
                        fedimint_ln_client::db::DbKeyPrefix::PaymentResult => {
                            let payment_results = dbtx
                                .find_by_prefix(&PaymentResultPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_payment_results = payment_results.len();
                            ensure!(
                                num_payment_results > 0,
                                "validate_migrations was not able to read any PaymentResults"
                            );
                            info!("Validated PaymentResults");
                        }
                        fedimint_ln_client::db::DbKeyPrefix::MetaOverrides => {
                            let meta_overrides = dbtx
                                .find_by_prefix(&MetaOverridesPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_meta_overrides = meta_overrides.len();
                            ensure!(
                                num_meta_overrides > 0,
                                "validate_migrations was not able to read any MetaOverrides"
                            );
                            info!("Validated MetaOverrides");
                        }
                        fedimint_ln_client::db::DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            ensure!(
                                num_gateways > 0,
                                "validate_migrations was not able to read any LightningGateways"
                            );
                            info!("Validated LightningGateways");
                        }
                    }
                }

                // Verify that after the state machine migrations, there is two `SubmittedOffer` state and no `SubmittedOfferV0` states.
                let mut input_count = 0;
                for active_state in active_states {
                    if let LightningClientStateMachines::Receive(machine) = active_state {
                        match machine.state {
                            LightningReceiveStates::SubmittedOffer(_) => input_count += 1,
                            LightningReceiveStates::SubmittedOfferV0(_) => panic!("State machine migration failed, active states contain unexpected state"),
                            _ => panic!("State machine migration failed, active states contain unexpected state"),
                        }
                    }
                }

                // expecting two, one starting in `SubmittedOffer` and one from migrated from `SubmittedOfferV0`
                ensure!(input_count == 2, "Expecting two `SubmittedOffer` active state, found {input_count}");

                let mut input_count = 0;
                for inactive_state in inactive_states {
                    if let LightningClientStateMachines::Receive(machine) = inactive_state {
                        match machine.state {
                            LightningReceiveStates::SubmittedOffer(_) => input_count += 1,
                            LightningReceiveStates::SubmittedOfferV0(_) => panic!("State machine migration failed, active states contain unexpected state"),
                            _ => panic!("State machine migration failed, active states contain unexpected state"),
                        }
                    }
                }

                // expecting two, one starting in `SubmittedOffer` and one from migrated from `SubmittedOfferV0`
                ensure!(input_count == 2, "Expecting two `SubmittedOffer` inactive state, found {input_count}");

                Ok(())
            },
        )
        .await
    }
}
