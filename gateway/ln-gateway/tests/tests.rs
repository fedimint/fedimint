//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client::ClientHandleArc;
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_keypair, bitcoin32_to_bitcoin30_keypair,
    bitcoin32_to_bitcoin30_secp256k1_pubkey,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::NextOrPending;
use fedimint_core::{msats, sats, secp256k1_27 as secp256k1, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState, MockGatewayConnection,
    OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage, PreimageKey};
use fedimint_ln_common::{LightningGateway, LightningInput, LightningOutput, PrunedInvoice};
use fedimint_ln_server::LightningInit;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_logging::LOG_TEST;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::db::BYTE_33;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::ln::FakeLightningTest;
use fedimint_unknown_common::config::UnknownGenParams;
use fedimint_unknown_server::UnknownInit;
use futures::Future;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ln_gateway::config::LightningModuleMode;
use ln_gateway::gateway_module_v2::{FinalReceiveState, GatewayClientModuleV2};
use ln_gateway::rpc::{BalancePayload, FederationRoutingFees, SetConfigurationPayload};
use ln_gateway::state_machine::pay::{
    OutgoingContractError, OutgoingPaymentError, OutgoingPaymentErrorType,
};
use ln_gateway::state_machine::{
    GatewayClientModule, GatewayExtPayStates, GatewayExtReceiveStates, GatewayMeta, Htlc,
};
use ln_gateway::Gateway;
use secp256k1::{KeyPair, PublicKey};
use tpe::G1Affine;
use tracing::info;

async fn user_pay_invoice(
    ln_module: &LightningClientModule,
    invoice: Bolt11Invoice,
    gateway_id: &PublicKey,
) -> anyhow::Result<OutgoingLightningPayment> {
    let gateway = ln_module.select_gateway(gateway_id).await;
    ln_module.pay_bolt11_invoice(gateway, invoice, ()).await
}

fn fixtures() -> Fixtures {
    info!(target: LOG_TEST, "Setting up fixtures");
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default())
        .with_server_only_module(UnknownInit, UnknownGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    let fixtures = fixtures.with_module(
        LightningClientInit {
            gateway_conn: Arc::new(MockGatewayConnection),
        },
        LightningInit,
        ln_params,
    );

    let bitcoin_server = fixtures.bitcoin_server();

    fixtures.with_module(
        fedimint_lnv2_client::LightningClientInit::default(),
        fedimint_lnv2_server::LightningInit,
        fedimint_lnv2_common::config::LightningGenParams::regtest(bitcoin_server),
    )
}

async fn single_federation_test<B>(
    f: impl FnOnce(
            Gateway,
            FakeLightningTest,
            FederationTest,
            ClientHandleArc, // User Client
            Arc<dyn BitcoinTest>,
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = anyhow::Result<()>>,
{
    let fixtures = fixtures();
    let other_ln = FakeLightningTest::new();

    let fed = fixtures.new_default_fed().await;
    let gateway = fixtures.new_gateway(LightningModuleMode::LNv1).await;
    fed.connect_gateway(&gateway).await;
    let user_client = fed.new_client().await;

    // if lightning module is present, update the gateway cache
    if let Ok(ln_client) = user_client.get_first_module::<LightningClientModule>() {
        let _ = ln_client.update_gateway_cache().await;
    }

    let bitcoin = fixtures.bitcoin();
    f(gateway, other_ln, fed, user_client, bitcoin).await?;

    Ok(())
}

async fn multi_federation_test<B>(
    f: impl FnOnce(Gateway, FederationTest, FederationTest, Arc<dyn BitcoinTest>) -> B + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = anyhow::Result<()>>,
{
    let fixtures = fixtures();
    let fed1 = fixtures.new_default_fed().await;
    let fed2 = fixtures.new_default_fed().await;
    let gateway = fixtures.new_gateway(LightningModuleMode::LNv1).await;

    f(gateway, fed1, fed2, fixtures.bitcoin()).await?;
    Ok(())
}

fn sha256(data: &[u8]) -> sha256::Hash {
    sha256::Hash::hash(data)
}

/// Helper function for constructing the `PaymentData` that the gateway uses to
/// pay the invoice. LND supports "private" payments where the description is
/// stripped from the invoice.
fn get_payment_data(gateway: Option<LightningGateway>, invoice: Bolt11Invoice) -> PaymentData {
    match gateway {
        Some(g) if g.supports_private_payments => {
            let pruned_invoice: PrunedInvoice = invoice.try_into().expect("Invoice has amount");
            PaymentData::PrunedInvoice(pruned_invoice)
        }
        _ => PaymentData::Invoice(invoice),
    }
}

/// Test helper function for paying a valid BOLT11 invoice with a gateway
/// specified by `gateway_id`.
async fn gateway_pay_valid_invoice(
    invoice: Bolt11Invoice,
    user_client: &ClientHandleArc,
    gateway_client: &ClientHandleArc,
    gateway_id: &PublicKey,
) -> anyhow::Result<()> {
    let user_lightning_module = &user_client.get_first_module::<LightningClientModule>()?;
    let gateway = user_lightning_module.select_gateway(gateway_id).await;

    // User client pays test invoice
    let OutgoingLightningPayment {
        payment_type,
        contract_id,
        fee: _,
    } = user_pay_invoice(user_lightning_module, invoice.clone(), gateway_id).await?;
    match payment_type {
        PayType::Lightning(pay_op) => {
            let mut pay_sub = user_lightning_module
                .subscribe_ln_pay(pay_op)
                .await?
                .into_stream();
            assert_eq!(pay_sub.ok().await?, LnPayState::Created);
            let funded = pay_sub.ok().await?;
            assert_matches!(funded, LnPayState::Funded { .. });

            let payload = PayInvoicePayload {
                federation_id: user_client.federation_id(),
                contract_id,
                payment_data: get_payment_data(gateway, invoice),
                preimage_auth: Hash::hash(&[0; 32]),
            };

            let gw_pay_op = gateway_client
                .get_first_module::<GatewayClientModule>()?
                .gateway_pay_bolt11_invoice(payload)
                .await?;
            let mut gw_pay_sub = gateway_client
                .get_first_module::<GatewayClientModule>()?
                .gateway_subscribe_ln_pay(gw_pay_op)
                .await?
                .into_stream();
            assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage { .. });

            let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
            if let GatewayExtPayStates::Success { out_points, .. } = gw_pay_sub.ok().await? {
                for outpoint in out_points {
                    dummy_module.receive_money(outpoint).await?;
                }
            } else {
                panic!("Gateway pay state machine was not successful");
            }
        }
        _ => panic!("Expected Lightning payment!"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_valid_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invoice(sats(250), None)?;

            gateway_pay_valid_invoice(
                invoice,
                &user_client,
                &gateway_client,
                &bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway.gateway_id()),
            )
            .await?;

            assert_eq!(user_client.get_balance().await, sats(1000 - 250));
            assert_eq!(gateway_client.get_balance().await, sats(250));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_enforces_fees() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Change the fees of the gateway
            let fee = "10,10000".to_string();
            let federation_fee = FederationRoutingFees::from_str(&fee)?;
            let set_configuration_payload = SetConfigurationPayload {
                password: None,
                num_route_hints: None,
                routing_fees: None,
                network: None,
                per_federation_routing_fees: Some(vec![(fed.id(), federation_fee)]),
            };
            gateway
                .handle_set_configuration_msg(set_configuration_payload)
                .await?;

            info!("### Changed gateway routing fees");

            let user_lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let gateway_id = gateway.gateway_id();
            let ln_gateway = user_lightning_module
                .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
                .await;
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();

            let invoice_amount = sats(250);
            let invoice = other_lightning_client.invoice(invoice_amount, None)?;

            // Try to pay an invoice, this should fail since the client will not set the
            // gateway's fees.
            info!("### User client paying invoice");
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_lightning_module
                .pay_bolt11_invoice(ln_gateway.clone(), invoice.clone(), ())
                .await
                .expect("No Lightning Payment was started");
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = user_lightning_module
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded { .. });
                    info!("### User client funded contract");

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        payment_data: get_payment_data(ln_gateway, invoice),
                        preimage_auth: Hash::hash(&[0; 32]),
                    };

                    let gw_pay_op = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_pay_bolt11_invoice(payload)
                        .await?;
                    let mut gw_pay_sub = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_subscribe_ln_pay(gw_pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
                    info!("### Gateway client started payment");
                    assert_matches!(
                        gw_pay_sub.ok().await?,
                        GatewayExtPayStates::Canceled {
                            error: OutgoingPaymentError {
                                error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                                    error: OutgoingContractError::Underfunded(_, _)
                                },
                                ..
                            }
                        }
                    );
                    info!("### Gateway client canceled payment");
                }
                _ => panic!("Expected Lightning payment!"),
            }

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_cannot_claim_invalid_preimage() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.gateway_id();
            let gateway_client = gateway.select_client(fed.id()).await.unwrap().into_value();
            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>().unwrap();
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Fund outgoing contract that the user client expects the gateway to pay
            let invoice = other_lightning_client.invoice(sats(250), None)?;
            let OutgoingLightningPayment {
                payment_type: _,
                contract_id,
                fee: _,
            } = user_pay_invoice(
                &user_client
                    .get_first_module::<LightningClientModule>()
                    .unwrap(),
                invoice.clone(),
                &bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id),
            )
            .await?;

            // Try to directly claim the outgoing contract with an invalid preimage
            let gateway_module = gateway_client.get_first_module::<GatewayClientModule>()?;

            let account = gateway_module.api.wait_contract(contract_id).await?;
            let outgoing_contract = match account.contract {
                FundedContract::Outgoing(contract) => OutgoingContractAccount {
                    amount: account.amount,
                    contract,
                },
                _ => {
                    panic!("Expected OutgoingContract");
                }
            };

            // Bogus preimage
            let preimage = Preimage(rand::random());
            let claim_input = outgoing_contract.claim(preimage);
            let client_input = ClientInput::<LightningInput> {
                input: claim_input,
                amount: outgoing_contract.amount,
                keys: vec![bitcoin30_to_bitcoin32_keypair(&gateway_module.redeem_key)],
            };

            let tx = TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![client_input]).into_dyn(gateway_module.id),
            );
            let operation_meta_gen = |_: TransactionId, _: Vec<OutPoint>| GatewayMeta::Pay {};
            let operation_id = OperationId(invoice.payment_hash().to_byte_array());
            let (txid, _) = gateway_client
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_common::KIND.as_str(),
                    operation_meta_gen,
                    tx,
                )
                .await?;

            // Assert that we did not get paid for claiming a contract with a bogus preimage
            assert!(dummy_module
                .receive_money(OutPoint { txid, out_idx: 0 })
                .await
                .is_err());
            assert_eq!(gateway_client.get_balance().await, sats(0));
            Ok::<_, anyhow::Error>(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_unpayable_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.gateway_id();
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Print money for user client
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create invoice that cannot be paid
            let invoice = other_lightning_client.unpayable_invoice(sats(250), None);

            let gateway = lightning_module
                .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
                .await;

            // User client pays test invoice
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(
                &lightning_module,
                invoice.clone(),
                &bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id),
            )
            .await?;
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = lightning_module
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded { .. });

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        payment_data: get_payment_data(gateway, invoice),
                        preimage_auth: Hash::hash(&[0; 32]),
                    };

                    let gw_pay_op = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_pay_bolt11_invoice(payload)
                        .await?;
                    let mut gw_pay_sub = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_subscribe_ln_pay(gw_pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
                    assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled { .. });
                }
                _ => panic!("Expected Lightning payment!"),
            }

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_valid_htlc() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.gateway_id();
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        let (_, outpoint) = dummy_module.print_money(initial_gateway_balance).await?;
        dummy_module.receive_money(outpoint).await?;
        assert_eq!(gateway_client.get_balance().await, sats(1000));

        // User client creates invoice in federation
        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let ln_gateway = ln_module
            .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
            .await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(&desc),
                None,
                "test intercept valid HTLC",
                ln_gateway,
            )
            .await?;

        // Run gateway state machine
        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            incoming_expiry: u32::MAX,
            short_channel_id: Some(1),
            incoming_chan_id: 2,
            htlc_id: 1,
        };
        let intercept_op = gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_handle_intercepted_htlc(htlc)
            .await?;
        let mut intercept_sub = gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_subscribe_ln_receive(intercept_op)
            .await?
            .into_stream();
        assert_eq!(intercept_sub.ok().await?, GatewayExtReceiveStates::Funding);
        assert_matches!(
            intercept_sub.ok().await?,
            GatewayExtReceiveStates::Preimage { .. }
        );
        assert_eq!(
            initial_gateway_balance - invoice_amount,
            gateway_client.get_balance().await
        );

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_offer_does_not_exist() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, _, _| async move {
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        let (_, outpoint) = dummy_module.print_money(initial_gateway_balance).await?;
        dummy_module.receive_money(outpoint).await?;
        assert_eq!(gateway_client.get_balance().await, sats(1000));

        // Create HTLC that doesn't correspond to an offer in the federation
        let htlc = Htlc {
            payment_hash: sha256(&[15]),
            incoming_amount_msat: Amount::from_msats(100),
            outgoing_amount_msat: Amount::from_msats(100),
            incoming_expiry: u32::MAX,
            short_channel_id: Some(1),
            incoming_chan_id: 2,
            htlc_id: 1,
        };

        match gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_handle_intercepted_htlc(htlc)
            .await
        {
            Ok(_) => panic!(
                "Expected incoming offer validation to fail because the offer does not exist"
            ),
            Err(e) => assert_eq!(e.to_string(), "Timed out fetching the offer".to_string()),
        }

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_no_funds() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.gateway_id();
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // User client creates invoice in federation
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let ln_gateway = ln_module
            .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
            .await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                sats(100),
                Bolt11InvoiceDescription::Direct(&desc),
                None,
                "test intercept htlc but with no funds",
                ln_gateway,
            )
            .await?;

        // Run gateway state machine
        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            incoming_expiry: u32::MAX,
            short_channel_id: Some(1),
            incoming_chan_id: 2,
            htlc_id: 1,
        };

        // Attempt to route an HTLC while the gateway has no funds
        match gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_handle_intercepted_htlc(htlc)
            .await
        {
            Ok(_) => panic!("Expected incoming offer validation to fail due to lack of funds"),
            Err(e) => assert_eq!(e.to_string(), "Insufficient funds".to_string()),
        }

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_invalid_offer() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Print money for gateway client
            let initial_gateway_balance = sats(1000);
            let gateway_dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
            let (_, outpoint) = gateway_dummy_module
                .print_money(initial_gateway_balance)
                .await?;
            gateway_dummy_module.receive_money(outpoint).await?;
            assert_eq!(gateway_client.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.unpayable_invoice(sats(250), None);

            // Create offer with a preimage that doesn't correspond to the payment hash of
            // the invoice
            let user_lightning_module = user_client.get_first_module::<LightningClientModule>()?;

            let amount = sats(100);
            let preimage = BYTE_33;
            let ln_output = LightningOutput::new_v0_offer(IncomingContractOffer {
                amount,
                hash: *invoice.payment_hash(),
                encrypted_preimage: EncryptedPreimage::new(
                    &PreimageKey(preimage),
                    &user_lightning_module.cfg.threshold_pub_key,
                ),
                expiry_time: None,
            });
            let client_output = ClientOutput {
                output: ln_output,
                amount: Amount::ZERO,
            };
            // The client's receive state machine can be empty because the gateway should
            // not fund this contract
            let tx = TransactionBuilder::new().with_outputs(
                ClientOutputBundle::new_no_sm(vec![client_output])
                    .into_dyn(user_lightning_module.id),
            );
            let operation_meta_gen = |txid, _| LightningOperationMeta {
                variant: LightningOperationMetaVariant::Receive {
                    out_point: OutPoint { txid, out_idx: 0 },
                    invoice: invoice.clone(),
                    gateway_id: None,
                },
                extra_meta: serde_json::to_value("test intercept HTLC with invalid offer")
                    .expect("Failed to serialize string into json"),
            };

            let operation_id = OperationId(invoice.payment_hash().to_byte_array());
            let (txid, _) = user_client
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_common::KIND.as_str(),
                    operation_meta_gen,
                    tx,
                )
                .await?;
            user_client
                .transaction_updates(operation_id)
                .await
                .await_tx_accepted(txid)
                .await
                .unwrap();

            // Run gateway state machine
            let htlc = Htlc {
                payment_hash: *invoice.payment_hash(),
                incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
                outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
                incoming_expiry: u32::MAX,
                short_channel_id: Some(1),
                incoming_chan_id: 2,
                htlc_id: 1,
            };

            let intercept_op = gateway_client
                .get_first_module::<GatewayClientModule>()?
                .gateway_handle_intercepted_htlc(htlc)
                .await?;
            let mut intercept_sub = gateway_client
                .get_first_module::<GatewayClientModule>()?
                .gateway_subscribe_ln_receive(intercept_op)
                .await?
                .into_stream();
            assert_matches!(intercept_sub.ok().await?, GatewayExtReceiveStates::Funding);

            match intercept_sub.ok().await? {
                GatewayExtReceiveStates::RefundSuccess {
                    out_points,
                    error: _,
                } => {
                    // Assert that the gateway got it's refund
                    for outpoint in out_points {
                        gateway_dummy_module.receive_money(outpoint).await?;
                    }

                    assert_eq!(initial_gateway_balance, gateway_client.get_balance().await);
                }
                unexpected_state => panic!(
                    "Gateway receive state machine entered unexpected state: {unexpected_state:?}"
                ),
            }

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_cannot_pay_expired_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.gateway_id();
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            let invoice = other_lightning_client
                .invoice(sats(1000), 1.into())
                .unwrap();
            assert_eq!(invoice.expiry_time(), Duration::from_secs(1));

            // at seconds granularity, must wait `expiry + 1s` to make sure expired
            sleep_in_test("waiting for invoice to expire", Duration::from_secs(2)).await;

            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            let (_, outpoint) = dummy_module.print_money(sats(2000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(2000));

            // User client pays test invoice
            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let gateway_module = lightning_module
                .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
                .await;
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(
                &lightning_module,
                invoice.clone(),
                &bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id),
            )
            .await?;
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = lightning_module
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded { .. });

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        payment_data: get_payment_data(gateway_module, invoice),
                        preimage_auth: Hash::hash(&[0; 32]),
                    };

                    let gw_pay_op = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_pay_bolt11_invoice(payload)
                        .await?;
                    let mut gw_pay_sub = gateway_client
                        .get_first_module::<GatewayClientModule>()?
                        .gateway_subscribe_ln_pay(gw_pay_op)
                        .await?
                        .into_stream();

                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
                    assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled { .. });
                }
                _ => panic!("Expected Lightning payment!"),
            }

            // Balance should be unchanged
            assert_eq!(gateway_client.get_balance().await, sats(0));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_executes_swaps_between_connected_federations() -> anyhow::Result<()> {
    multi_federation_test(|gateway, fed1, fed2, _| async move {
        let gateway_id = gateway.gateway_id();
        let id1 = fed1.invite_code().federation_id();
        let id2 = fed2.invite_code().federation_id();

        fed1.connect_gateway(&gateway).await;
        fed2.connect_gateway(&gateway).await;

        // setting specific routing fees for fed1
        let fed_routing_fees = FederationRoutingFees::from_str("10,10000")?;
        let set_configuration_payload = SetConfigurationPayload {
            password: None,
            num_route_hints: None,
            routing_fees: None,
            network: None,
            per_federation_routing_fees: Some(vec![(id1, fed_routing_fees.clone())]),
        };
        gateway
            .handle_set_configuration_msg(set_configuration_payload)
            .await?;

        send_msats_to_gateway(&gateway, id1, 10_000).await;
        send_msats_to_gateway(&gateway, id2, 10_000).await;

        let client1 = fed1.new_client().await;
        // if lightning module is present, update the gateway cache
        if let Ok(ln_client) = client1.get_first_module::<LightningClientModule>() {
            let _ = ln_client.update_gateway_cache().await;
        }
        let client2 = fed2.new_client().await;
        // if lightning module is present, update the gateway cache
        if let Ok(ln_client) = client2.get_first_module::<LightningClientModule>() {
            let _ = ln_client.update_gateway_cache().await;
        }

        // Check gateway balances before facilitating direct swap between federations
        let pre_balances = get_balances(&gateway, &[id1, id2]).await;
        assert_eq!(pre_balances[0], 10_000);
        assert_eq!(pre_balances[1], 10_000);

        let deposit_amt = msats(5_000);
        let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
        let (_, outpoint) = client1_dummy_module.print_money(deposit_amt).await?;
        client1_dummy_module.receive_money(outpoint).await?;
        assert_eq!(client1.get_balance().await, deposit_amt);

        // User creates invoice in federation 2
        let invoice_amt = msats(2_500);
        let ln_module = client2.get_first_module::<LightningClientModule>()?;
        let ln_gateway = ln_module
            .select_gateway(&bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway_id))
            .await;
        let desc = Description::new("description".to_string())?;
        let (receive_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amt,
                Bolt11InvoiceDescription::Direct(&desc),
                None,
                "test gw swap between federations",
                ln_gateway,
            )
            .await?;
        let mut receive_sub = ln_module
            .subscribe_ln_receive(receive_op)
            .await?
            .into_stream();

        // A client pays invoice in federation 1
        let gateway_client = gateway.select_client(id1).await?.into_value();
        gateway_pay_valid_invoice(
            invoice,
            &client1,
            &gateway_client,
            &bitcoin32_to_bitcoin30_secp256k1_pubkey(&gateway.gateway_id()),
        )
        .await?;

        // A client receives cash via swap in federation 2
        assert_eq!(receive_sub.ok().await?, LnReceiveState::Created);
        let waiting_payment = receive_sub.ok().await?;
        assert_matches!(waiting_payment, LnReceiveState::WaitingForPayment { .. });
        let funded = receive_sub.ok().await?;
        assert_matches!(funded, LnReceiveState::Funded);
        let waiting_funds = receive_sub.ok().await?;
        assert_matches!(waiting_funds, LnReceiveState::AwaitingFunds { .. });
        let claimed = receive_sub.ok().await?;
        assert_matches!(claimed, LnReceiveState::Claimed);
        assert_eq!(client2.get_balance().await, invoice_amt);

        // Check gateway balances after facilitating direct swap between federations
        let gateway_fed1_balance = gateway_client.get_balance().await;
        let gateway_fed2_client = gateway.select_client(id2).await?.into_value();
        let gateway_fed2_balance = gateway_fed2_client.get_balance().await;

        // Balance in gateway of sending federation is deducted the invoice amount
        assert_eq!(
            gateway_fed2_balance.msats,
            pre_balances[1] - invoice_amt.msats
        );

        let fee = routing_fees_in_msats(&fed_routing_fees, &invoice_amt);

        // Balance in gateway of receiving federation is increased `invoice_amt` + `fee`
        assert_eq!(
            gateway_fed1_balance.msats,
            pre_balances[0] + invoice_amt.msats + fee
        );

        Ok(())
    })
    .await
}

fn routing_fees_in_msats(routing_fees: &FederationRoutingFees, amount: &Amount) -> u64 {
    ((amount.msats * routing_fees.proportional_millionths as u64) / 1_000_000)
        + routing_fees.base_msat as u64
}

/// Retrieves the balance of each federation the gateway is connected to.
async fn get_balances(gw: &Gateway, ids: impl IntoIterator<Item = &FederationId>) -> Vec<u64> {
    let mut balances = vec![];
    for id in ids.into_iter() {
        let balance_payload = BalancePayload { federation_id: *id };
        let balance = gw
            .handle_balance_msg(balance_payload)
            .await
            .expect("Could not get balance");
        balances.push(balance.msats);
    }

    balances
}

/// Prints msats for the gateway using the dummy module.
async fn send_msats_to_gateway(gateway: &Gateway, federation_id: FederationId, msats: u64) {
    let client = gateway
        .select_client(federation_id)
        .await
        .expect("Failed to selcet gateway client")
        .into_value();

    let (op, outpoints) = client
        .get_first_module::<DummyClientModule>()
        .unwrap()
        .print_money(Amount::from_msats(msats))
        .await
        .expect("Could not print primary module liquidity");

    client
        .await_primary_module_output(op, outpoints)
        .await
        .expect("Could not await primary module liquidity");

    assert_eq!(client.get_balance().await, Amount::from_msats(msats));
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_incoming_contract_with_invalid_preimage_is_refunded() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;

    let gateway = fixtures.new_gateway(LightningModuleMode::LNv2).await;

    fed.connect_gateway(&gateway).await;

    send_msats_to_gateway(&gateway, fed.id(), 1_000_000_000).await;

    let client = gateway.select_client(fed.id()).await?.into_value();

    // by encrypting the preimage with a incorrect aggregate public key the
    // decryption key generated by the federation will not yield the correct
    // preimage of the hash
    let contract = IncomingContract::new(
        tpe::AggregatePublicKey(G1Affine::generator()),
        [42; 32],
        [0; 32],
        PaymentImage::Hash([0_u8; 32].consensus_hash_bitcoin30()),
        Amount::from_sats(1000),
        u64::MAX,
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        bitcoin32_to_bitcoin30_keypair(
            &client.get_first_module::<GatewayClientModuleV2>()?.keypair,
        )
        .public_key(),
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract)
            .await?,
        FinalReceiveState::Refunded
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_expired_incoming_contract_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;

    let gateway = fixtures.new_gateway(LightningModuleMode::LNv2).await;

    fed.connect_gateway(&gateway).await;

    send_msats_to_gateway(&gateway, fed.id(), 1_000_000_000).await;

    let client = gateway.select_client(fed.id()).await?.into_value();

    let contract = IncomingContract::new(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .cfg
            .tpe_agg_pk,
        [42; 32],
        [0; 32],
        PaymentImage::Hash([0_u8; 32].consensus_hash_bitcoin30()),
        Amount::from_sats(1000),
        0, // this incoming contract expired on the 1st of January 1970
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        bitcoin32_to_bitcoin30_keypair(
            &client.get_first_module::<GatewayClientModuleV2>()?.keypair,
        )
        .public_key(),
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract)
            .await?,
        FinalReceiveState::Rejected
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_malleated_incoming_contract_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;

    let gateway = fixtures.new_gateway(LightningModuleMode::LNv2).await;

    fed.connect_gateway(&gateway).await;

    send_msats_to_gateway(&gateway, fed.id(), 1_000_000_000).await;

    let client = gateway.select_client(fed.id()).await?.into_value();

    let mut contract = IncomingContract::new(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .cfg
            .tpe_agg_pk,
        [42; 32],
        [0; 32],
        PaymentImage::Hash([0_u8; 32].consensus_hash_bitcoin30()),
        Amount::from_sats(1000),
        u64::MAX,
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        bitcoin32_to_bitcoin30_keypair(
            &client.get_first_module::<GatewayClientModuleV2>()?.keypair,
        )
        .public_key(),
        KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract.clone())
            .await?,
        FinalReceiveState::Success([0; 32])
    );

    contract.commitment.amount = Amount::from_sats(100);

    assert!(!contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract)
            .await?,
        FinalReceiveState::Rejected
    );

    Ok(())
}
