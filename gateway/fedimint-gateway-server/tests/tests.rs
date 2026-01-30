//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin::hashes::{Hash, sha256};
use fedimint_client::ClientHandleArc;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client_module::module::OutPointRange;
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::task::sleep_in_test;
use fedimint_core::time::now;
use fedimint_core::util::{NextOrPending, backoff_util, retry};
use fedimint_core::{Amount, OutPoint, msats, sats, secp256k1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::Event;
use fedimint_gateway_common::{PaymentLogPayload, SetFeesPayload};
use fedimint_gateway_server::Gateway;
use fedimint_gateway_ui::IAdminGateway;
use fedimint_gw_client::pay::{
    OutgoingContractError, OutgoingPaymentError, OutgoingPaymentErrorType,
};
use fedimint_gw_client::{
    GatewayClientModule, GatewayExtPayStates, GatewayExtReceiveStates, GatewayMeta, Htlc,
};
use fedimint_gwv2_client::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentStarted, IncomingPaymentSucceeded,
    OutgoingPaymentStarted, OutgoingPaymentSucceeded,
};
use fedimint_gwv2_client::{FinalReceiveState, GatewayClientModuleV2};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState, MockGatewayConnection,
    OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage, PreimageKey};
use fedimint_ln_common::{LightningGateway, LightningInput, LightningOutput, PrunedInvoice};
use fedimint_ln_server::LightningInit;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_logging::LOG_TEST;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::db::BYTE_33;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::ln::FakeLightningTest;
use fedimint_unknown_server::UnknownInit;
use futures::Future;
use itertools::Itertools;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description, RoutingFees};
use secp256k1::{Keypair, PublicKey};
use tpe::G1Affine;
use tracing::info;

async fn user_pay_invoice(
    ln_module: &LightningClientModule,
    invoice: Bolt11Invoice,
    gateway_id: &PublicKey,
) -> anyhow::Result<OutgoingLightningPayment> {
    ln_module.update_gateway_cache().await?;
    let gateway = ln_module.select_gateway(gateway_id).await;
    ln_module.pay_bolt11_invoice(gateway, invoice, ()).await
}

fn fixtures() -> Fixtures {
    info!(target: LOG_TEST, "Setting up fixtures");
    let fixtures =
        Fixtures::new_primary(DummyClientInit, DummyInit).with_server_only_module(UnknownInit);
    let fixtures = fixtures.with_module(
        LightningClientInit {
            gateway_conn: Some(Arc::new(MockGatewayConnection)),
        },
        LightningInit,
    );

    fixtures.with_module(
        fedimint_lnv2_client::LightningClientInit::default(),
        fedimint_lnv2_server::LightningInit,
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

    let fed = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
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
    let fed1 = fixtures.new_fed_degraded().await;
    let fed2 = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;

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

            // With simplified dummy module, balance is updated automatically
            // when create_final_inputs_and_outputs is called
            match gw_pay_sub.ok().await? {
                GatewayExtPayStates::Success { .. } => {}
                _ => {
                    panic!("Gateway pay state machine was not successful");
                }
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
            gateway
                .handle_set_fees_msg(SetFeesPayload {
                    federation_id: Some(fed.id()),
                    lightning_base: Some(Amount::ZERO),
                    lightning_parts_per_million: Some(0),
                    transaction_base: None,
                    transaction_parts_per_million: None,
                })
                .await?;

            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Give user_client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invoice(sats(250), None)?;

            gateway_pay_valid_invoice(
                invoice,
                &user_client,
                &gateway_client,
                &gateway.http_gateway_id().await,
            )
            .await?;

            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000 - 250));
            assert_eq!(gateway_client.get_balance_for_btc().await?, sats(250));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_enforces_fees() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            // Give user_client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000));

            let user_lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let gateway_id = gateway.http_gateway_id().await;
            let mut lightning_gateway = user_lightning_module
                .select_gateway(&gateway_id)
                .await
                .expect("Gateway should be available");
            lightning_gateway.fees = RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            };
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();

            let invoice_amount = sats(250);
            let invoice = other_lightning_client.invoice(invoice_amount, None)?;

            // Try to pay an invoice, this should fail since the client will not set the
            // gateway's fees.
            info!(target: LOG_TEST, "### User client paying invoice");
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_lightning_module
                .pay_bolt11_invoice(Some(lightning_gateway.clone()), invoice.clone(), ())
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
                    info!(target: LOG_TEST, "### User client funded contract");

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        payment_data: get_payment_data(Some(lightning_gateway), invoice),
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
                    info!(target: LOG_TEST, "### Gateway client started payment");
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
                    info!(target: LOG_TEST, "### Gateway client canceled payment");
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
            let gateway_id = gateway.http_gateway_id().await;
            let gateway_client = gateway.select_client(fed.id()).await.unwrap().into_value();
            // Give user_client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>().unwrap();
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000));

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
                &gateway_id,
            )
            .await?;

            // Try to directly claim the outgoing contract with an invalid preimage
            let gateway_module = gateway_client.get_first_module::<GatewayClientModule>()?;

            let account = gateway_module.api.await_contract(contract_id).await;
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
                amounts: Amounts::new_bitcoin(outgoing_contract.amount),
                keys: vec![gateway_module.redeem_key],
            };

            let tx = TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![client_input]).into_dyn(gateway_module.id),
            );
            let operation_meta_gen = |_: OutPointRange| GatewayMeta::Pay {};
            let operation_id = OperationId(*invoice.payment_hash().as_ref());
            let txid = gateway_client
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_common::KIND.as_str(),
                    operation_meta_gen,
                    tx,
                )
                .await?
                .txid();

            // Assert that transaction with bogus preimage was rejected
            assert!(
                gateway_client
                    .transaction_updates(operation_id)
                    .await
                    .await_tx_accepted(txid)
                    .await
                    .is_err()
            );
            assert_eq!(gateway_client.get_balance_for_btc().await?, sats(0));
            Ok::<_, anyhow::Error>(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_unpayable_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.http_gateway_id().await;
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Give user client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000));

            // Create invoice that cannot be paid
            let invoice = other_lightning_client.unpayable_invoice(sats(250), None);

            let gateway = lightning_module.select_gateway(&gateway_id).await;

            // User client pays test invoice
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(&lightning_module, invoice.clone(), &gateway_id).await?;
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
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // Give gateway client initial balance
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        dummy_module
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;
        assert_eq!(gateway_client.get_balance_for_btc().await?, sats(1000));

        // User client creates invoice in federation
        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(desc),
                None,
                "test intercept valid HTLC",
                lightning_gateway,
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
            initial_gateway_balance.saturating_sub(invoice_amount),
            gateway_client.get_balance_for_btc().await?
        );

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_offer_does_not_exist() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, _, _| async move {
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // Give gateway client initial balance
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        dummy_module
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;
        assert_eq!(gateway_client.get_balance_for_btc().await?, sats(1000));

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
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        // User client creates invoice in federation
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                sats(100),
                Bolt11InvoiceDescription::Direct(desc),
                None,
                "test intercept htlc but with no funds",
                lightning_gateway,
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
            // Give gateway client initial balance
            let initial_gateway_balance = sats(1000);
            let gateway_dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
            gateway_dummy_module
                .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
                .await?;
            assert_eq!(gateway_client.get_balance_for_btc().await?, sats(1000));

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
                amounts: Amounts::ZERO,
            };
            // The client's receive state machine can be empty because the gateway should
            // not fund this contract
            let tx = TransactionBuilder::new().with_outputs(
                ClientOutputBundle::new_no_sm(vec![client_output])
                    .into_dyn(user_lightning_module.id),
            );
            let operation_meta_gen = |change_range: OutPointRange| LightningOperationMeta {
                variant: LightningOperationMetaVariant::Receive {
                    out_point: OutPoint {
                        txid: change_range.txid(),
                        out_idx: 0,
                    },
                    invoice: invoice.clone(),
                    gateway_id: None,
                },
                extra_meta: serde_json::to_value("test intercept HTLC with invalid offer")
                    .expect("Failed to serialize string into json"),
            };

            let operation_id = OperationId(*invoice.payment_hash().as_ref());
            let txid = user_client
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_common::KIND.as_str(),
                    operation_meta_gen,
                    tx,
                )
                .await?
                .txid();
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
                    out_points: _,
                    error: _,
                } => {
                    // Assert that the gateway got it's refund
                    // With simplified dummy module, balance is automatically restored
                    assert_eq!(
                        initial_gateway_balance,
                        gateway_client.get_balance_for_btc().await?
                    );
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
            let gateway_id = gateway.http_gateway_id().await;
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            let invoice = other_lightning_client
                .invoice(sats(1000), 1.into())
                .unwrap();
            assert_eq!(invoice.expiry_time(), Duration::from_secs(1));

            // at seconds granularity, must wait `expiry + 1s` to make sure expired
            sleep_in_test("waiting for invoice to expire", Duration::from_secs(2)).await;

            // Give user_client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            dummy_module
                .mock_receive(sats(2000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(2000));

            // User client pays test invoice
            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let gateway_module = lightning_module.select_gateway(&gateway_id).await;
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(&lightning_module, invoice.clone(), &gateway_id).await?;
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
            assert_eq!(gateway_client.get_balance_for_btc().await?, sats(0));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_executes_swaps_between_connected_federations() -> anyhow::Result<()> {
    multi_federation_test(|gateway, fed1, fed2, _| async move {
        let gateway_id = gateway.http_gateway_id().await;
        let id1 = fed1.invite_code().federation_id();
        let id2 = fed2.invite_code().federation_id();

        fed1.connect_gateway(&gateway).await;
        fed2.connect_gateway(&gateway).await;

        // setting specific routing fees for fed1
        gateway
            .handle_set_fees_msg(SetFeesPayload {
                federation_id: Some(id1),
                lightning_base: Some(Amount::from_msats(10)),
                lightning_parts_per_million: Some(10000),
                transaction_base: None,
                transaction_parts_per_million: None,
            })
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
        let pre_balances = get_balances(&gateway, [id1, id2].to_vec()).await;
        assert_eq!(pre_balances[0], 10_000);
        assert_eq!(pre_balances[1], 10_000);

        let deposit_amt = msats(5_000);
        let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
        client1_dummy_module
            .mock_receive(deposit_amt, AmountUnit::BITCOIN)
            .await?;
        assert_eq!(client1.get_balance_for_btc().await?, deposit_amt);

        // User creates invoice in federation 2
        let invoice_amt = msats(2_500);
        let ln_module = client2.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let desc = Description::new("description".to_string())?;
        let (receive_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amt,
                Bolt11InvoiceDescription::Direct(desc),
                None,
                "test gw swap between federations",
                lightning_gateway,
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
            &gateway.http_gateway_id().await,
        )
        .await?;

        // A client receives cash via swap in federation 2
        assert_eq!(receive_sub.ok().await?, LnReceiveState::Created);
        let waiting_payment = receive_sub.ok().await?;
        assert_matches!(waiting_payment, LnReceiveState::WaitingForPayment { .. });
        let funded = receive_sub.ok().await?;
        assert_matches!(funded, LnReceiveState::Funded);
        let waiting_funds = receive_sub.ok().await?;
        assert_matches!(waiting_funds, LnReceiveState::AwaitingFunds);
        let claimed = receive_sub.ok().await?;
        assert_matches!(claimed, LnReceiveState::Claimed);
        assert_eq!(client2.get_balance_for_btc().await?, invoice_amt);

        // Check gateway balances after facilitating direct swap between federations
        let gateway_fed1_balance = gateway_client.get_balance_for_btc().await?;
        let gateway_fed2_client = gateway.select_client(id2).await?.into_value();
        let gateway_fed2_balance = gateway_fed2_client.get_balance_for_btc().await?;

        // Balance in gateway of sending federation is deducted the invoice amount
        assert_eq!(
            gateway_fed2_balance.msats,
            pre_balances[1] - invoice_amt.msats
        );

        let fee = routing_fees_in_msats(
            &PaymentFee {
                base: Amount::from_msats(10),
                parts_per_million: 10000,
            },
            &invoice_amt,
        );

        // Balance in gateway of receiving federation is increased `invoice_amt` + `fee`
        assert_eq!(
            gateway_fed1_balance.msats,
            pre_balances[0] + invoice_amt.msats + fee
        );

        Ok(())
    })
    .await
}

fn routing_fees_in_msats(routing_fees: &PaymentFee, amount: &Amount) -> u64 {
    ((amount.msats * routing_fees.parts_per_million) / 1_000_000) + routing_fees.base.msats
}

/// Retrieves the balance of each federation the gateway is connected to.
async fn get_balances(gw: &Gateway, ids: Vec<FederationId>) -> Vec<u64> {
    let balances = gw
        .handle_get_balances_msg()
        .await
        .expect("Could not get balances");
    balances
        .ecash_balances
        .into_iter()
        .filter_map(|info| {
            if ids.contains(&info.federation_id) {
                Some(info.ecash_balance_msats.msats)
            } else {
                None
            }
        })
        .collect()
}

/// Gives msats to the gateway using the dummy module.
async fn send_msats_to_gateway(gateway: &Gateway, federation_id: FederationId, msats: u64) {
    let client = gateway
        .select_client(federation_id)
        .await
        .expect("Failed to select gateway client")
        .into_value();

    client
        .get_first_module::<DummyClientModule>()
        .unwrap()
        .mock_receive(Amount::from_msats(msats), AmountUnit::BITCOIN)
        .await
        .expect("Could not mock receive liquidity");

    assert_eq!(
        client
            .get_balance_for_btc()
            .await
            .expect("Must have primary module"),
        Amount::from_msats(msats)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_incoming_contract_with_invalid_preimage_is_refunded() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    let gateway = fixtures.new_gateway().await;

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
        PaymentImage::Hash([0_u8; 32].consensus_hash()),
        Amount::from_sats(1000),
        u64::MAX,
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .keypair
            .public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract, 900)
            .await?,
        FinalReceiveState::Refunded
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_expired_incoming_contract_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    let gateway = fixtures.new_gateway().await;

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
        PaymentImage::Hash([0_u8; 32].consensus_hash()),
        Amount::from_sats(1000),
        0, // this incoming contract expired on the 1st of January 1970
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .keypair
            .public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract, 900)
            .await?,
        FinalReceiveState::Rejected
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lnv2_malleated_incoming_contract_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    let gateway = fixtures.new_gateway().await;

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
        PaymentImage::Hash([0_u8; 32].consensus_hash()),
        Amount::from_sats(1000),
        u64::MAX,
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .keypair
            .public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    assert!(contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract.clone(), 900)
            .await?,
        FinalReceiveState::Success([0; 32])
    );

    contract.commitment.amount = Amount::from_sats(100);

    assert!(!contract.verify());

    assert_eq!(
        client
            .get_first_module::<GatewayClientModuleV2>()?
            .relay_direct_swap(contract, 900)
            .await?,
        FinalReceiveState::Rejected
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_read_payment_log() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed1 = fixtures.new_fed_degraded().await;
    let fed2 = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    fed1.connect_gateway(&gateway).await;
    fed2.connect_gateway(&gateway).await;
    let client1 = gateway.select_client(fed1.id()).await?.into_value();
    let lnv2_module_id = client1
        .get_first_instance(&fedimint_lnv2_common::KIND)
        .expect("lnv2 module not found");
    let mut dbtx = client1.db().begin_transaction().await;
    for _ in 0..10 {
        let mut fed1_module_dbtx = dbtx
            .to_ref_with_prefix_module_id(lnv2_module_id)
            .0
            .into_nc();
        let fed1_lnv2 = client1.get_first_module::<GatewayClientModuleV2>()?;
        let outgoing_payment_event = OutgoingPaymentStarted {
            outgoing_contract: OutgoingContract {
                payment_image: PaymentImage::Hash([0_u8; 32].consensus_hash()),
                amount: Amount::from_msats(120000),
                expiration: 120,
                claim_pk: Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
                refund_pk: fed1_lnv2.keypair.public_key(),
                ephemeral_pk: Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng())
                    .public_key(),
            },
            min_contract_amount: Amount::from_msats(120000),
            invoice_amount: Amount::from_msats(10000),
            operation_start: now(),
            max_delay: 100,
        };
        fed1_lnv2
            .client_ctx
            .log_event(&mut fed1_module_dbtx, outgoing_payment_event)
            .await;

        fed1_lnv2
            .client_ctx
            .log_event(
                &mut fed1_module_dbtx,
                OutgoingPaymentSucceeded {
                    payment_image: PaymentImage::Hash([0_u8; 32].consensus_hash()),
                    target_federation: Some(fed2.id()),
                },
            )
            .await;
    }

    dbtx.commit_tx().await;

    let client2 = gateway.select_client(fed2.id()).await?.into_value();
    let lnv2_module_id2 = client2
        .get_first_instance(&fedimint_lnv2_common::KIND)
        .expect("lnv2 module not found");
    let mut dbtx = client2.db().begin_transaction().await;
    {
        let fed2_lnv2 = client2.get_first_module::<GatewayClientModuleV2>()?;
        let mut fed2_module_dbtx = dbtx
            .to_ref_with_prefix_module_id(lnv2_module_id2)
            .0
            .into_nc();

        let contract = IncomingContract::new(
            fed2_lnv2.cfg.tpe_agg_pk,
            [42; 32],
            [0; 32],
            PaymentImage::Hash([0_u8; 32].consensus_hash()),
            Amount::from_sats(1000),
            u64::MAX,
            Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
            fed2_lnv2.keypair.public_key(),
            Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        );

        let incoming_payment_event = IncomingPaymentStarted {
            incoming_contract_commitment: contract.commitment,
            invoice_amount: Amount::from_msats(1200),
            operation_start: now(),
        };
        fed2_lnv2
            .client_ctx
            .log_event(&mut fed2_module_dbtx, incoming_payment_event)
            .await;

        fed2_lnv2
            .client_ctx
            .log_event(
                &mut fed2_module_dbtx,
                IncomingPaymentSucceeded {
                    payment_image: PaymentImage::Hash([0_u8; 32].consensus_hash()),
                },
            )
            .await;

        let complete_payment_event = CompleteLightningPaymentSucceeded {
            payment_image: PaymentImage::Hash([0_u8; 32].consensus_hash()),
        };
        fed2_lnv2
            .client_ctx
            .log_event(&mut fed2_module_dbtx, complete_payment_event)
            .await;
    }

    dbtx.commit_tx().await;

    // Inserting log entries is async so we need to retry until they are available
    retry(
        "Get all transactions",
        backoff_util::custom_backoff(Duration::ZERO, Duration::ZERO, Some(10)),
        || async {
            // There are 10 transactions and 2 events per transaction, so verify that all 20
            // events are returned
            let transactions = gateway
                .handle_payment_log_msg(PaymentLogPayload {
                    end_position: None,
                    pagination_size: 20,
                    federation_id: fed1.id(),
                    event_kinds: vec![],
                })
                .await?;
            if transactions.0.len() == 20 {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Invalid number of transactions: {}, expected 20",
                    transactions.0.len()
                ))
            }
        },
    )
    .await?;

    // Verify the pagination API works (query 10 events at a time)
    let transactions = gateway
        .handle_payment_log_msg(PaymentLogPayload {
            end_position: None,
            pagination_size: 10,
            federation_id: fed1.id(),
            event_kinds: vec![],
        })
        .await?;
    assert_eq!(transactions.0.len(), 10);

    // Verify transactions are in descending order
    assert!(
        transactions
            .0
            .iter()
            .tuple_windows()
            .all(|(e1, e2)| e1.as_raw().ts_usecs > e2.as_raw().ts_usecs)
    );

    // Verify that we retrieve the rest of the events
    let start_event = transactions
        .0
        .last()
        .expect("no transactions")
        .id()
        .saturating_sub(1);

    let transactions = gateway
        .handle_payment_log_msg(PaymentLogPayload {
            end_position: Some(start_event),
            pagination_size: 20,
            federation_id: fed1.id(),
            event_kinds: vec![],
        })
        .await?;
    assert_eq!(transactions.0.len(), 10);

    // Verify filtering by `EventKind` works
    let transactions = gateway
        .handle_payment_log_msg(PaymentLogPayload {
            end_position: None,
            pagination_size: 20,
            federation_id: fed2.id(),
            event_kinds: vec![
                IncomingPaymentSucceeded::KIND,
                CompleteLightningPaymentSucceeded::KIND,
            ],
        })
        .await?;
    assert_eq!(transactions.0.len(), 2);

    Ok(())
}
