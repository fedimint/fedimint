//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use assert_matches::assert_matches;
use bitcoin::hashes::{Hash, sha256};
use fedimint_api_client::api::ServerError;
use fedimint_client::ClientHandleArc;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client_module::module::OutPointRange;
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::task::{TaskGroup, sleep_in_test, timeout};
use fedimint_core::time::now;
use fedimint_core::util::{NextOrPending, SafeUrl, backoff_util, retry};
use fedimint_core::{
    Amount, OutPoint, TransactionId, apply, async_trait_maybe_send, msats, sats, secp256k1,
};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::Event;
use fedimint_gateway_common::{PaymentLogPayload, SetFeesPayload};
use fedimint_gateway_server::{Gateway, GatewayState};
use fedimint_gateway_ui::IAdminGateway;
use fedimint_gw_client::pay::{
    OutgoingContractError, OutgoingPaymentError, OutgoingPaymentErrorType,
};
use fedimint_gw_client::{
    GatewayClientModule, GatewayExtPayStates, GatewayExtReceiveStates, GatewayMeta, Htlc,
    SwapParameters,
};
use fedimint_gwv2_client::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentStarted, IncomingPaymentSucceeded,
    OutgoingPaymentStarted, OutgoingPaymentSucceeded,
};
use fedimint_gwv2_client::{
    FinalReceiveState, GatewayClientModuleV2, GatewayClientStateMachinesV2, GatewayOperationMetaV2,
    IncomingCircuitKey,
};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState, MockGatewayConnection,
    OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{
    ContractId, EncryptedPreimage, FundedContract, Preimage, PreimageKey,
};
use fedimint_ln_common::{LightningGateway, LightningInput, LightningOutput, PrunedInvoice};
use fedimint_ln_server::LightningInit;
use fedimint_lnv2_common::LightningInvoice;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, PaymentFee, RoutingInfo, SendPaymentPayload,
};
use fedimint_logging::LOG_TEST;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::db::BYTE_33;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::ln::FakeLightningTest;
use fedimint_unknown_server::UnknownInit;
use futures::Future;
use itertools::Itertools;
use lightning_invoice::{
    Bolt11Invoice, Bolt11InvoiceDescription, Currency, Description, InvoiceBuilder, PaymentSecret,
    RoutingFees,
};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SecretKey};
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
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            // Give user_client initial balance
            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;
            assert_eq!(user_client.get_balance_for_btc().await?, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invoice(sats(250), None)?;
            let gw_fee = gateway
                .handle_get_info()
                .await?
                .federations
                .first()
                .expect("Only one federation")
                .config
                .lightning_fee;
            let outgoing_fee = gw_fee.fee(250000);

            gateway_pay_valid_invoice(
                invoice,
                &user_client,
                &gateway_client,
                &gateway.http_gateway_id().await,
            )
            .await?;

            assert_eq!(
                user_client.get_balance_for_btc().await?,
                sats(1000 - 250)
                    .checked_sub(outgoing_fee)
                    .expect("Should not be negative")
            );
            assert_eq!(
                gateway_client.get_balance_for_btc().await?,
                sats(250)
                    .checked_add(outgoing_fee)
                    .expect("Should not wrap around")
            );

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
            .gateway_handle_intercepted_htlc(htlc, async { Ok(0) })
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

/// `/stop` drains the payments that are still in flight before shutting the
/// gateway down. It must not hold the state write lock while it does, because
/// finishing an incoming payment goes through `complete_htlc`, which loops on
/// `get_lightning_context` and so needs to read that same lock. Holding it
/// deadlocks the shutdown: the HTLC expires, its sender is refunded, and the
/// ecash the gateway already spent buying the preimage is gone.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_shutdown_completes_in_flight_payment() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        dummy_module
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;

        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(desc),
                None,
                "test shutdown with a payment in flight",
                lightning_gateway,
            )
            .await?;

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
            .gateway_handle_intercepted_htlc(htlc, async { Ok(0) })
            .await?;
        let mut intercept_sub = gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_subscribe_ln_receive(intercept_op)
            .await?
            .into_stream();

        // Shut down before the payment had a chance to finish, so the drain has to
        // wait for a completion that calls `complete_htlc`. The task group is a
        // throwaway one: only the draining half of the shutdown is under test.
        timeout(
            Duration::from_secs(30),
            gateway.handle_shutdown_msg(TaskGroup::new()),
        )
        .await
        .expect("Shutdown deadlocked while draining an in-flight payment")?;

        // Shutting down is one-way, so the gateway accepts no further payments.
        assert_eq!(
            gateway.handle_get_info().await?.gateway_state,
            "ShuttingDown"
        );

        // The drained payment ran to completion, so the gateway holds the preimage
        // it paid the federation for.
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
async fn test_gateway_client_intercept_enforces_expiry_boundary() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        let initial_gateway_balance = sats(1000);
        gateway_client
            .get_first_module::<DummyClientModule>()?
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;

        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(Description::new("expiry boundary".to_string())?),
                None,
                "test intercept HTLC expiry boundary",
                lightning_gateway,
            )
            .await?;
        let route_hints = invoice.route_hints();
        let route_hint_last_hops = route_hints
            .iter()
            .filter_map(|route_hint| route_hint.0.last())
            .collect::<Vec<_>>();
        assert!(!route_hint_last_hops.is_empty());
        assert!(route_hint_last_hops.iter().all(|hop| {
            hop.cltv_expiry_delta == fedimint_ln_common::LNV1_INCOMING_HTLC_ADVERTISED_EXPIRY_DELTA
        }));

        let current_block_height = 1_000;
        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: invoice_amount,
            outgoing_amount_msat: invoice_amount,
            incoming_expiry: current_block_height
                + fedimint_gw_client::LNV1_HTLC_EXPIRY_SAFETY_MARGIN,
            short_channel_id: Some(1),
            incoming_chan_id: 2,
            htlc_id: 1,
        };
        let gateway_ln_module = gateway_client.get_first_module::<GatewayClientModule>()?;

        let err = gateway_ln_module
            .gateway_handle_intercepted_htlc(htlc.clone(), async { Ok(current_block_height) })
            .await
            .expect_err("HTLC at the expiry boundary must be rejected");
        assert!(err.to_string().contains("incoming HTLC expiry is unsafe"));
        assert_eq!(
            gateway_client.get_balance_for_btc().await?,
            initial_gateway_balance
        );

        let accepted_htlc = Htlc {
            incoming_expiry: htlc.incoming_expiry + 1,
            ..htlc
        };
        let operation_id = gateway_ln_module
            .gateway_handle_intercepted_htlc(accepted_htlc, async { Ok(current_block_height) })
            .await?;
        let mut receive_updates = gateway_ln_module
            .gateway_subscribe_ln_receive(operation_id)
            .await?
            .into_stream();
        assert_eq!(
            receive_updates.ok().await?,
            GatewayExtReceiveStates::Funding
        );
        assert_matches!(
            receive_updates.ok().await?,
            GatewayExtReceiveStates::Preimage { .. }
        );
        assert_eq!(
            gateway_client.get_balance_for_btc().await?,
            initial_gateway_balance.saturating_sub(invoice_amount)
        );

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_same_circuit_replay_is_idempotent() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();

        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway_client.get_first_module::<DummyClientModule>()?;
        dummy_module
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;

        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let desc = Description::new("description".to_string())?;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(desc),
                None,
                "test intercept same-circuit replay",
                lightning_gateway,
            )
            .await?;

        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            incoming_expiry: fedimint_gw_client::LNV1_HTLC_EXPIRY_SAFETY_MARGIN + 1,
            short_channel_id: Some(1),
            incoming_chan_id: 2,
            htlc_id: 1,
        };

        let gateway_ln_module = gateway_client.get_first_module::<GatewayClientModule>()?;
        let (first, second) = tokio::join!(
            gateway_ln_module.gateway_handle_intercepted_htlc(htlc.clone(), async { Ok(0) }),
            gateway_ln_module.gateway_handle_intercepted_htlc(htlc.clone(), async { Ok(0) }),
        );
        let first_op = first?;
        let second_op = second?;
        assert_eq!(first_op, second_op);

        let active_replay_op = gateway_ln_module
            .gateway_handle_intercepted_htlc(htlc.clone(), async {
                anyhow::bail!("backend info must not be queried for active replay")
            })
            .await?;
        assert_eq!(first_op, active_replay_op);

        let mut intercept_sub = gateway_ln_module
            .gateway_subscribe_ln_receive(first_op)
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
        gateway_ln_module.await_completion(first_op).await;

        let terminal_replay_op = gateway_ln_module
            .gateway_handle_intercepted_htlc(htlc, async {
                anyhow::bail!("backend info must not be queried for inactive replay")
            })
            .await?;
        assert_eq!(first_op, terminal_replay_op);
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
            .gateway_handle_intercepted_htlc(htlc, async { Ok(0) })
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
            .gateway_handle_intercepted_htlc(htlc, async { Ok(0) })
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
                .gateway_handle_intercepted_htlc(htlc, async { Ok(0) })
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
        |gateway, other_lightning_client, _fed, user_client, _| async move {
            let gateway_id = gateway.http_gateway_id().await;
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

            // User client attempts to pay the expired invoice — should be
            // rejected immediately by the client-side expiry check.
            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let error = user_pay_invoice(&lightning_module, invoice.clone(), &gateway_id)
                .await
                .expect_err("Payment of expired invoice should fail");
            assert!(
                error.to_string().contains("Invoice has expired"),
                "Expected 'Invoice has expired' error, got: {error}"
            );

            // Balance should be unchanged since no contract was created
            assert_eq!(user_client.get_balance_for_btc().await?, sats(2000));

            Ok(())
        },
    )
    .await
}

/// `/pay_invoice` is unauthenticated and its `payment_data` is caller-supplied,
/// so an amountless BOLT11 invoice reaches `gateway_pay_bolt11_invoice`
/// directly. It must be rejected as an error rather than panicking: the
/// gateway's iroh dispatch spawns handlers on the root task group, where a
/// panic takes down the whole `gatewayd` process.
///
/// No contract has to exist for this — `contract_id` only seeds the
/// `OperationId`, and nothing looks it up before the amount is read.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_rejects_amountless_invoice() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();

        let ctx = secp256k1::Secp256k1::new();
        let keypair = Keypair::from_secret_key(&ctx, &SecretKey::from_slice(&[1; 32])?);
        let amountless_invoice = InvoiceBuilder::new(Currency::Regtest)
            .payee_pub_key(keypair.public_key())
            .description(String::new())
            .payment_hash(sha256(&[0; 32]))
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &SecretKey::from_keypair(&keypair)))?;
        assert!(
            amountless_invoice.amount_milli_satoshis().is_none(),
            "Invoice must carry no amount for this test to be meaningful"
        );

        let payload = PayInvoicePayload {
            federation_id: user_client.federation_id(),
            contract_id: ContractId::from_raw_hash(sha256(&[42; 32])),
            payment_data: PaymentData::Invoice(amountless_invoice),
            preimage_auth: Hash::hash(&[0; 32]),
        };

        let error = gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_pay_bolt11_invoice(payload)
            .await
            .expect_err("Amountless invoice should be rejected");
        assert!(
            error
                .downcast_ref::<OutgoingContractError>()
                .is_some_and(|error| matches!(error, OutgoingContractError::InvoiceMissingAmount)),
            "Expected InvoiceMissingAmount, got: {error}"
        );

        Ok(())
    })
    .await
}

/// `set_fees` takes operator-supplied fees whose only bound is `u64`, and
/// `/set_fees` is reachable with the lesser liquidity-manager credential. Both
/// summing the two fee components and converting the result into `RoutingFees`
/// must therefore be total: the conversion runs on every LNv1 payment and on
/// the federation registration that happens at startup, so a persisted
/// out-of-range fee boot-loops an LND gateway.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_rejects_fees_it_cannot_announce() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, _, _| async move {
        let federation_id = fed.id();
        let routing_info_before = gateway
            .routing_info_v2(&federation_id)
            .await?
            .expect("Gateway is connected to the federation");

        let template = SetFeesPayload {
            federation_id: Some(federation_id),
            lightning_base: None,
            lightning_parts_per_million: None,
            transaction_base: None,
            transaction_parts_per_million: None,
        };

        let rejected = [
            // Overflows the addition of the lightning and transaction fee, which
            // happens before any limit can be checked.
            SetFeesPayload {
                lightning_base: Some(Amount::from_msats(u64::MAX)),
                ..template.clone()
            },
            SetFeesPayload {
                lightning_parts_per_million: Some(u64::MAX),
                ..template.clone()
            },
            // Sats entered where msats were expected: no overflow, but the value
            // does not fit into the `u32` components of `RoutingFees`.
            SetFeesPayload {
                lightning_base: Some(Amount::from_msats(u64::from(u32::MAX) + 1)),
                ..template.clone()
            },
            SetFeesPayload {
                transaction_parts_per_million: Some(u64::from(u32::MAX) + 1),
                ..template.clone()
            },
        ];

        for payload in rejected {
            let error = gateway
                .handle_set_fees_msg(payload.clone())
                .await
                .expect_err(&format!("Fee outside the limits was accepted: {payload:?}"));
            assert!(
                error.to_string().contains("Error configuring the gateway"),
                "Expected a gateway configuration error, got: {error}"
            );
        }

        // A rejected fee must not have been persisted.
        let routing_info_after = gateway
            .routing_info_v2(&federation_id)
            .await?
            .expect("Gateway is connected to the federation");
        assert_eq!(
            routing_info_before.send_fee_default,
            routing_info_after.send_fee_default
        );
        assert_eq!(
            routing_info_before.receive_fee,
            routing_info_after.receive_fee
        );

        Ok(())
    })
    .await
}

/// The fee limits used to be checked only for federations running LNv2, so a
/// federation with LNv1 alone accepted any fee at all — including one that
/// cannot be converted into the `RoutingFees` that LNv1 registration announces.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_enforces_fee_limits_without_lnv2() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_server_only_module(UnknownInit)
        .with_module(
            LightningClientInit {
                gateway_conn: Some(Arc::new(MockGatewayConnection)),
            },
            LightningInit,
        );

    let fed = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;

    let error = gateway
        .handle_set_fees_msg(SetFeesPayload {
            federation_id: Some(fed.id()),
            // A base fee in sats where msats were expected.
            lightning_base: Some(Amount::from_msats(u64::from(u32::MAX) + 1)),
            lightning_parts_per_million: None,
            transaction_base: None,
            transaction_parts_per_million: None,
        })
        .await
        .expect_err("Fee above the send limit was accepted for an LNv1-only federation");
    assert!(
        error.to_string().contains("Total Send fees exceeded"),
        "Expected the send fee limit to be enforced, got: {error}"
    );

    Ok(())
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
async fn lnv2_relay_persists_every_distinct_incoming_circuit() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;
    send_msats_to_gateway(&gateway, fed.id(), 1_000_000_000).await;

    let client = gateway.select_client(fed.id()).await?.into_value();
    let module = client.get_first_module::<GatewayClientModuleV2>()?;
    let preimage = [23; 32];
    let payment_hash = preimage.consensus_hash();
    let contract = IncomingContract::new(
        module.cfg.tpe_agg_pk,
        [42; 32],
        preimage,
        PaymentImage::Hash(payment_hash),
        Amount::from_sats(1000),
        u64::MAX,
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        module.keypair.public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );
    let receive_operation_id = OperationId::from_encodable(&contract);
    let completion_id = |circuit: IncomingCircuitKey| {
        OperationId::from_encodable(&(
            "gateway-lnv2-incoming-circuit",
            receive_operation_id,
            circuit,
        ))
    };
    let hold = IncomingCircuitKey {
        incoming_chan_id: 0,
        htlc_id: 0,
    };
    let forward = IncomingCircuitKey {
        incoming_chan_id: 42,
        htlc_id: 7,
    };

    let (hold_result, forward_result) = tokio::join!(
        module.relay_incoming_htlc(
            payment_hash,
            hold.incoming_chan_id,
            hold.htlc_id,
            contract.clone(),
            1_000_000,
        ),
        module.relay_incoming_htlc(
            payment_hash,
            forward.incoming_chan_id,
            forward.htlc_id,
            contract.clone(),
            1_000_000,
        ),
    );
    hold_result?;
    forward_result?;

    // Same-circuit replay must not add another operation or state machine.
    module
        .relay_incoming_htlc(
            payment_hash,
            forward.incoming_chan_id,
            forward.htlc_id,
            contract,
            1_000_000,
        )
        .await?;

    let receive_entry = client
        .operation_log()
        .get_operation(receive_operation_id)
        .await
        .expect("receive operation must be persisted");
    assert!(
        !receive_entry
            .meta::<GatewayOperationMetaV2>()
            .waits_for_completion()
    );

    for circuit in [hold, forward] {
        let operation_id = completion_id(circuit);
        let entry = client
            .operation_log()
            .get_operation(operation_id)
            .await
            .expect("circuit completion operation must be persisted");
        assert!(
            entry
                .meta::<GatewayOperationMetaV2>()
                .waits_for_completion()
        );

        let active = module
            .client_ctx
            .get_own_operation_active_states(operation_id)
            .await;
        let inactive = module
            .client_ctx
            .get_own_operation_inactive_states(operation_id)
            .await;
        assert_eq!(active.len() + inactive.len(), 1);
        assert!(
            active
                .into_iter()
                .map(|(state, _)| state)
                .chain(inactive.into_iter().map(|(state, _)| state))
                .all(|state| matches!(state, GatewayClientStateMachinesV2::CircuitComplete(_)))
        );
    }

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
    retry(
        "Get filtered transactions",
        backoff_util::custom_backoff(Duration::ZERO, Duration::ZERO, Some(10)),
        || async {
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
            if transactions.0.len() == 2 {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Invalid number of transactions: {}, expected 2",
                    transactions.0.len()
                ))
            }
        },
    )
    .await?;

    Ok(())
}

/// A federation only has to offer one of the two lightning modules, so a
/// gateway routinely serves federations with an LNv1 module and no LNv2 one.
fn lnv1_only_fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_server_only_module(UnknownInit)
        .with_module(
            LightningClientInit {
                gateway_conn: Some(Arc::new(MockGatewayConnection)),
            },
            LightningInit,
        )
}

/// The LNv2 routes are registered unauthenticated, so anyone can point them at
/// any federation the gateway serves. Looking up the LNv2 client module used to
/// `expect` it into existence, which panics for an LNv1-only federation and
/// takes the gateway process down with it over iroh.
#[tokio::test(flavor = "multi_thread")]
async fn lnv2_routes_reject_a_federation_without_an_lnv2_module() -> anyhow::Result<()> {
    let fixtures = lnv1_only_fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;

    assert!(
        gateway.routing_info_v2(&fed.id()).await?.is_none(),
        "a federation without an LNv2 module has no LNv2 routing info"
    );

    let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let payload = SendPaymentPayload {
        federation_id: fed.id(),
        outpoint: OutPoint {
            txid: TransactionId::from_slice(&[0; 32]).expect("32 bytes is a valid txid"),
            out_idx: 0,
        },
        contract: OutgoingContract {
            payment_image: PaymentImage::Hash([0_u8; 32].consensus_hash()),
            amount: Amount::from_msats(1000),
            expiration: 120,
            claim_pk: keypair.public_key(),
            refund_pk: keypair.public_key(),
            ephemeral_pk: keypair.public_key(),
        },
        invoice: LightningInvoice::Bolt11(FakeLightningTest::new().invoice(sats(1), None)?),
        auth: secp256k1::SECP256K1
            .sign_schnorr(&secp256k1::Message::from_digest([0; 32]), &keypair),
    };

    assert!(
        gateway.send_payment_v2(payload).await.is_err(),
        "a federation without an LNv2 module cannot be asked to send an LNv2 payment"
    );

    Ok(())
}

/// Captures the `SendPaymentPayload` its client built and then parks, leaving
/// the outgoing contract funded so a test can drive the gateway side itself.
#[derive(Debug, Default)]
struct CapturingGatewayConnection {
    routing_info: std::sync::Mutex<Option<RoutingInfo>>,
    captured: std::sync::Mutex<Option<SendPaymentPayload>>,
}

impl CapturingGatewayConnection {
    /// The client keys its contract to the gateway's `module_public_key`, which
    /// does not exist until after the fixtures this connection is built into.
    fn publish(&self, module_public_key: PublicKey) {
        *self.routing_info.lock().expect("Not poisoned") = Some(RoutingInfo {
            lightning_public_key: module_public_key,
            lightning_alias: Some("capturing-gateway".to_string()),
            module_public_key,
            send_fee_default: PaymentFee::TRANSACTION_FEE_DEFAULT,
            send_fee_minimum: PaymentFee::TRANSACTION_FEE_DEFAULT,
            expiration_delta_default: 500,
            expiration_delta_minimum: 144,
            receive_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
        });
    }

    async fn captured(&self) -> SendPaymentPayload {
        retry(
            "waiting for the client to send its payment to the gateway",
            backoff_util::aggressive_backoff(),
            || async {
                self.captured
                    .lock()
                    .expect("Not poisoned")
                    .clone()
                    .context("The client has not sent its payment yet")
            },
        )
        .await
        .expect("The client sends its payment once the contract is accepted")
    }
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for CapturingGatewayConnection {
    async fn routing_info(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, ServerError> {
        Ok(self.routing_info.lock().expect("Not poisoned").clone())
    }

    async fn bolt11_invoice(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: FederationId,
        _contract: IncomingContract,
        _amount: Amount,
        _description: fedimint_lnv2_common::Bolt11InvoiceDescription,
        _expiry_secs: u32,
    ) -> Result<Bolt11Invoice, ServerError> {
        unimplemented!("This connection only sends")
    }

    async fn send_payment(
        &self,
        _gateway_api: SafeUrl,
        federation_id: FederationId,
        outpoint: OutPoint,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        auth: Signature,
    ) -> Result<Result<[u8; 32], Signature>, ServerError> {
        *self.captured.lock().expect("Not poisoned") = Some(SendPaymentPayload {
            federation_id,
            outpoint,
            contract,
            invoice,
            auth,
        });

        // Never answer, so the client's state machine stays parked and does not
        // refund the contract out from under the test.
        std::future::pending().await
    }
}

fn capturing_lnv2_fixtures(gateway_conn: Arc<CapturingGatewayConnection>) -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_server_only_module(UnknownInit)
        .with_module(
            LightningClientInit {
                gateway_conn: Some(Arc::new(MockGatewayConnection)),
            },
            LightningInit,
        )
        .with_module(
            fedimint_lnv2_client::LightningClientInit {
                gateway_conn: Some(gateway_conn),
                ..Default::default()
            },
            fedimint_lnv2_server::LightningInit,
        )
}

/// `/send_payment` is unauthenticated and its operation id is derived from the
/// outgoing contract, which is public in the funding transaction. Joining that
/// operation yields the preimage, so the join has to stay behind the contract's
/// auth signature. It used to run first.
#[tokio::test(flavor = "multi_thread")]
async fn lnv2_send_payment_join_requires_the_contract_auth() -> anyhow::Result<()> {
    let gateway_conn = Arc::new(CapturingGatewayConnection::default());
    let fixtures = capturing_lnv2_fixtures(gateway_conn.clone());
    let fed = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    fed.connect_gateway(&gateway).await;

    let gateway_client = gateway.select_client(fed.id()).await?.into_value();
    gateway_conn.publish(
        gateway_client
            .get_first_module::<GatewayClientModuleV2>()?
            .keypair
            .public_key(),
    );

    let user_client = fed.new_client().await;
    user_client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    // Funds the outgoing contract and hands us the payload it would have posted.
    let sender = user_client.clone();
    let invoice = FakeLightningTest::new().invoice(sats(1000), None)?;
    fedimint_core::runtime::spawn("lnv2-user-send", async move {
        sender
            .get_first_module::<fedimint_lnv2_client::LightningClientModule>()
            .expect("The federation has an LNv2 module")
            .send(
                invoice,
                Some(SafeUrl::parse("http://capturing-gateway.test").expect("Valid url")),
                serde_json::Value::Null,
            )
            .await
    });

    let payload = gateway_conn.captured().await;

    // The genuine request. This puts the operation on record, and its preimage
    // is what the forged request below must not reach.
    gateway
        .send_payment_v2(payload.clone())
        .await?
        .expect("The gateway pays the invoice and answers with its preimage");

    assert!(
        gateway_client
            .operation_exists(OperationId::from_encodable(&payload.contract))
            .await,
        "the payment has to be on record for the join to be what is under test"
    );

    // Anyone can rebuild this payload from the funding transaction. What they
    // cannot do is sign for the contract's refund key.
    let attacker = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let forged = SendPaymentPayload {
        auth: secp256k1::SECP256K1.sign_schnorr(
            &secp256k1::Message::from_digest(
                *payload.invoice.consensus_hash::<sha256::Hash>().as_ref(),
            ),
            &attacker,
        ),
        ..payload
    };

    let error = gateway
        .send_payment_v2(forged)
        .await
        .expect_err("a forged auth signature must not be answered with the payment in flight")
        .to_string();

    // Naming the check keeps this from passing for an unrelated reason.
    assert!(
        error.contains("Invalid auth signature for the invoice data"),
        "the request must be refused by the auth check, got: {error}"
    );

    Ok(())
}

/// An amountless BOLT11 invoice is rejected by `validate_outgoing_account`, but
/// the operation log entry written when the payment starts needs the amount
/// before the state machine ever gets that far, and used to `expect` it.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_rejects_amountless_invoice() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();

        let ctx = secp256k1::Secp256k1::new();
        let keypair = Keypair::new(&ctx, &mut rand::thread_rng());
        let amountless_invoice =
            lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
                .description(String::new())
                .payment_hash(sha256(&[0; 32]))
                .current_timestamp()
                .min_final_cltv_expiry_delta(0)
                .payment_secret(lightning_invoice::PaymentSecret([0; 32]))
                .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &keypair.secret_key()))?;

        let error = gateway_client
            .get_first_module::<GatewayClientModule>()?
            .gateway_pay_bolt11_invoice(PayInvoicePayload {
                federation_id: user_client.federation_id(),
                contract_id: sha256(&[0; 32]).into(),
                payment_data: PaymentData::Invoice(amountless_invoice),
                preimage_auth: Hash::hash(&[0; 32]),
            })
            .await
            .expect_err("an invoice without an amount is rejected");

        assert_eq!(
            error.downcast::<OutgoingContractError>()?,
            OutgoingContractError::InvoiceMissingAmount
        );

        Ok(())
    })
    .await
}

/// `pay_invoice` is unauthenticated and keys its operation on the contract id,
/// but the state machine's dedupe key covers the whole payload, so a second
/// request that differs only in `preimage_auth` slips past it. That used to
/// panic on the duplicate operation log entry, taking the gateway down.
///
/// Not panicking is not enough on its own: nothing else pins a contract to a
/// single payment attempt, so the duplicate has to be recognised as one and
/// answered with the operation already in flight rather than buying the
/// preimage a second time out of the gateway's own funds.
///
/// Recognising it is only correct for the caller the payment belongs to, since
/// the returned operation yields the preimage and contract ids are visible to
/// every member of the federation. The duplicate is joined only on a matching
/// `preimage_auth`.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_invoice_is_idempotent_per_contract() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.http_gateway_id().await;
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();

            let dummy_module = user_client.get_first_module::<DummyClientModule>()?;
            dummy_module
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;

            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let invoice = other_lightning_client.invoice(sats(250), None)?;
            let selected_gateway = lightning_module.select_gateway(&gateway_id).await;

            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(&lightning_module, invoice.clone(), &gateway_id).await?;
            let PayType::Lightning(pay_op) = payment_type else {
                panic!("Expected Lightning payment!");
            };
            let mut pay_sub = lightning_module
                .subscribe_ln_pay(pay_op)
                .await?
                .into_stream();
            assert_eq!(pay_sub.ok().await?, LnPayState::Created);
            assert_matches!(pay_sub.ok().await?, LnPayState::Funded { .. });

            let payload = |preimage_auth| PayInvoicePayload {
                federation_id: user_client.federation_id(),
                contract_id,
                payment_data: get_payment_data(selected_gateway.clone(), invoice.clone()),
                preimage_auth,
            };

            let ours = Hash::hash(&[0; 32]);
            let theirs = Hash::hash(&[1; 32]);

            let gateway_module = gateway_client.get_first_module::<GatewayClientModule>()?;
            let first = gateway_module
                .gateway_pay_bolt11_invoice(payload(ours))
                .await?;
            // Same contract, different `preimage_auth`: a distinct state machine
            // state, so the executor's dedupe does not catch this one.
            assert!(
                gateway_module
                    .gateway_pay_bolt11_invoice(payload(theirs))
                    .await
                    .is_err(),
                "a duplicate request must not be answered with someone else's operation"
            );
            assert_eq!(
                gateway_client
                    .operation_log()
                    .paginate_operations_rev(10, None)
                    .await
                    .len(),
                1,
                "the duplicate request must not start a second payment for the contract"
            );

            let mut gw_pay_sub = gateway_module
                .gateway_subscribe_ln_pay(first)
                .await?
                .into_stream();
            assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage { .. });
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Success { .. });

            // The state machine pins the authentication, so only now is it
            // certainly on record and the rejection certainly a mismatch.
            assert!(
                gateway_module
                    .gateway_pay_bolt11_invoice(payload(theirs))
                    .await
                    .is_err(),
                "a mismatched `preimage_auth` must not reach the preimage"
            );
            assert_eq!(
                gateway_module
                    .gateway_pay_bolt11_invoice(payload(ours))
                    .await?,
                first,
                "our own retry still joins the payment already in flight"
            );

            // One purchase of the preimage, so exactly one claim of the contract.
            let outgoing_fee = gateway
                .handle_get_info()
                .await?
                .federations
                .first()
                .expect("Only one federation")
                .config
                .lightning_fee
                .fee(250_000);
            assert_eq!(
                gateway_client.get_balance_for_btc().await?,
                sats(250)
                    .checked_add(outgoing_fee)
                    .expect("Should not wrap around")
            );

            Ok(())
        },
    )
    .await
}

/// `Gateway::run` awaits `load_clients` before `start_gateway`, and building a
/// federation client starts its executor, so a `PayInvoice` state machine that
/// was persisted before a restart runs again while the gateway is still
/// `Disconnected`. `get_lightning_context` then reports `FailedToConnect`
/// without any RPC having been attempted, and the send path used to read that
/// local verdict as the lightning node refusing the payment: it cancelled the
/// outgoing contract, refunding a sender whose HTLC the previous process may
/// already have settled and leaving the gateway short the difference.
///
/// Only the lightning node knows whether an HTLC of ours is in flight, so the
/// gateway has to wait until it can ask, rather than answer for it.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_waits_to_reach_lightning_before_cancelling_outgoing_payment()
-> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway_id = gateway.http_gateway_id().await;
            let gateway_client = gateway.select_client(fed.id()).await?.into_value();
            user_client
                .get_first_module::<DummyClientModule>()?
                .mock_receive(sats(1000), AmountUnit::BITCOIN)
                .await?;

            let lightning_module = user_client.get_first_module::<LightningClientModule>()?;
            let invoice = other_lightning_client.invoice(sats(250), None)?;

            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = user_pay_invoice(&lightning_module, invoice.clone(), &gateway_id).await?;
            let PayType::Lightning(pay_op) = payment_type else {
                panic!("Expected Lightning payment!");
            };
            let mut pay_sub = lightning_module
                .subscribe_ln_pay(pay_op)
                .await?
                .into_stream();
            assert_eq!(pay_sub.ok().await?, LnPayState::Created);
            assert_matches!(pay_sub.ok().await?, LnPayState::Funded { .. });

            // Stand in for the restart: the outgoing contract is funded and the
            // gateway's state machine is about to run against a gateway that has
            // not (re-)established its lightning session yet.
            let lightning_context = gateway.get_lightning_context().await?;
            gateway
                .set_gateway_state_out_of_band(GatewayState::Disconnected)
                .await;

            let gateway_module = gateway_client.get_first_module::<GatewayClientModule>()?;
            let operation_id = gateway_module
                .gateway_pay_bolt11_invoice(PayInvoicePayload {
                    federation_id: user_client.federation_id(),
                    contract_id,
                    payment_data: PaymentData::Invoice(invoice),
                    preimage_auth: Hash::hash(&[0; 32]),
                })
                .await?;
            let mut gw_pay_sub = gateway_module
                .gateway_subscribe_ln_pay(operation_id)
                .await?
                .into_stream();
            assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);

            // Any verdict reached here is one the lightning node was never asked
            // for, and a cancellation cannot be taken back.
            if let Ok(state) = fedimint_core::task::timeout(
                Duration::from_secs(5),
                futures::StreamExt::next(&mut gw_pay_sub),
            )
            .await
            {
                panic!(
                    "Gateway settled the fate of an outgoing payment while not connected to its lightning node: {state:?}"
                );
            }

            // Reconnected, the payment resolves the way it always should have.
            gateway
                .set_gateway_state_out_of_band(GatewayState::Running { lightning_context })
                .await;

            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage { .. });
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Success { .. });

            Ok(())
        },
    )
    .await
}

/// A direct swap is the other half of an outgoing contract in a second
/// federation: the gateway funds an incoming contract here to buy the preimage
/// that claims that contract. `gateway_handle_direct_swap` used to have no
/// idempotency guard, so a `GatewayPayInvoice` state machine re-entering after
/// a gateway restart tried to fund the swap a second time. Funding consumed the
/// federation's offer the first time round, so the retry fails -- either
/// waiting out `fetch_and_validate_offer` or bailing on the operation that
/// already exists -- and `buy_preimage_via_direct_swap` reads that as
/// `SwapFailed` and cancels the outgoing contract. The sender is refunded while
/// the recipient is still paid out of the incoming contract the gateway funded.
///
/// The second call has nothing left to fund and everything to gain from the
/// preimage the first one is buying, so hand it that operation.
#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_direct_swap_reentry_joins_the_funded_swap() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, user_client, _| async move {
        let gateway_id = gateway.http_gateway_id().await;
        let gateway_client = gateway.select_client(fed.id()).await?.into_value();
        let initial_gateway_balance = sats(1000);
        gateway_client
            .get_first_module::<DummyClientModule>()?
            .mock_receive(initial_gateway_balance, AmountUnit::BITCOIN)
            .await?;

        let invoice_amount = sats(100);
        let ln_module = user_client.get_first_module::<LightningClientModule>()?;
        let lightning_gateway = ln_module.select_gateway(&gateway_id).await;
        let (_invoice_op, invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(Description::new("direct swap".to_string())?),
                None,
                "test direct swap re-entry",
                lightning_gateway,
            )
            .await?;

        let swap_params = SwapParameters {
            payment_hash: *invoice.payment_hash(),
            amount_msat: invoice_amount,
        };
        let gateway_module = gateway_client.get_first_module::<GatewayClientModule>()?;
        let first = gateway_module
            .gateway_handle_direct_swap(swap_params.clone())
            .await?;
        let mut receive_sub = gateway_module
            .gateway_subscribe_ln_receive(first)
            .await?
            .into_stream();
        assert_eq!(receive_sub.ok().await?, GatewayExtReceiveStates::Funding);
        assert_matches!(
            receive_sub.ok().await?,
            GatewayExtReceiveStates::Preimage { .. }
        );

        // The restart: the same swap is asked for again, with the offer that
        // funded it already consumed.
        let second = fedimint_core::task::timeout(
            Duration::from_secs(30),
            gateway_module.gateway_handle_direct_swap(swap_params),
        )
        .await
        .expect("a re-entrant direct swap must not wait on the offer it already consumed")?;

        assert_eq!(
            first, second,
            "the re-entrant swap joins the operation already holding the preimage"
        );
        assert_eq!(
            gateway_client.get_balance_for_btc().await?,
            initial_gateway_balance.saturating_sub(invoice_amount),
            "the incoming contract must only be funded once"
        );

        // The check above the funding helper cannot settle a race on its own, so
        // two callers that both get past it must still end up on one operation.
        let (_invoice_op, concurrent_invoice, _) = ln_module
            .create_bolt11_invoice(
                invoice_amount,
                Bolt11InvoiceDescription::Direct(Description::new("concurrent".to_string())?),
                None,
                "test concurrent direct swap",
                ln_module.select_gateway(&gateway_id).await,
            )
            .await?;
        let concurrent_swap_params = SwapParameters {
            payment_hash: *concurrent_invoice.payment_hash(),
            amount_msat: invoice_amount,
        };
        let (left, right) = tokio::join!(
            gateway_module.gateway_handle_direct_swap(concurrent_swap_params.clone()),
            gateway_module.gateway_handle_direct_swap(concurrent_swap_params),
        );
        assert_eq!(
            left?, right?,
            "concurrent requests for one swap must share the single funded operation"
        );
        assert_eq!(
            gateway_client.get_balance_for_btc().await?,
            initial_gateway_balance.saturating_sub(invoice_amount + invoice_amount),
            "the second swap's incoming contract must also only be funded once"
        );

        Ok(())
    })
    .await
}
