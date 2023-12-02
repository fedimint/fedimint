//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin::Network;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::ClientArc;
use fedimint_core::config::FederationId;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::task::sleep;
use fedimint_core::util::{NextOrPending, SafeUrl};
use fedimint_core::{msats, sats, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningClientStateMachines,
    LightningOperationMeta, LightningOperationMetaVariant, LnPayState, LnReceiveState,
    OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::{GatewayFee, LightningGenParams};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage, PreimageKey};
use fedimint_ln_common::{LightningInput, LightningOutput};
use fedimint_ln_server::LightningInit;
use fedimint_logging::LOG_TEST;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::db::BYTE_33;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, LightningNodeType, DEFAULT_GATEWAY_PASSWORD};
use fedimint_testing::ln::LightningTest;
use futures::Future;
use lightning_invoice::Bolt11Invoice;
use ln_gateway::gateway_lnrpc::GetNodeInfoResponse;
use ln_gateway::rpc::rpc_client::{GatewayRpcClient, GatewayRpcError, GatewayRpcResult};
use ln_gateway::rpc::{BalancePayload, ConnectFedPayload, SetConfigurationPayload};
use ln_gateway::state_machine::{
    GatewayClientModule, GatewayClientStateMachines, GatewayExtPayStates, GatewayExtReceiveStates,
    GatewayMeta, Htlc, GW_ANNOUNCEMENT_TTL,
};
use ln_gateway::utils::retry;
use ln_gateway::{GatewayState, DEFAULT_FEES, DEFAULT_NETWORK};
use reqwest::StatusCode;
use secp256k1::PublicKey;
use tracing::info;

fn fixtures() -> Fixtures {
    info!(target: LOG_TEST, "Setting up fixtures");
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures.with_module(LightningClientInit, LightningInit, ln_params)
}

async fn single_federation_test<B>(
    f: impl FnOnce(
            GatewayTest,
            Box<dyn LightningTest>,
            FederationTest,
            ClientArc, // User Client
            Arc<dyn BitcoinTest>,
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = anyhow::Result<()>>,
{
    let fixtures = fixtures();
    let lnd1 = fixtures.lnd().await;
    let cln1 = fixtures.cln().await;
    let lnd2 = fixtures.lnd().await;
    let cln2 = fixtures.cln().await;

    for (gateway_ln, other_node) in [(lnd1, cln1), (cln2, lnd2)] {
        let fed = fixtures.new_fed().await;
        let user_client = fed.new_client().await;
        let mut gateway = fixtures
            .new_gateway(gateway_ln, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
            .await;
        gateway.connect_fed(&fed).await;
        let bitcoin = fixtures.bitcoin();
        f(gateway, other_node, fed, user_client, bitcoin).await?;
    }
    Ok(())
}

async fn multi_federation_test<B>(
    lightning_node_type: LightningNodeType,
    f: impl FnOnce(
            GatewayTest,
            GatewayRpcClient,
            FederationTest,
            FederationTest,
            Arc<dyn BitcoinTest>,
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = anyhow::Result<()>>,
{
    let fixtures = fixtures();
    let fed1 = fixtures.new_fed().await;
    let fed2 = fixtures.new_fed().await;

    let lightning = match lightning_node_type {
        LightningNodeType::Lnd => fixtures.lnd().await,
        LightningNodeType::Cln => fixtures.cln().await,
        _ => {
            panic!("Unsupported lightning implementation");
        }
    };

    let gateway = fixtures
        .new_gateway(lightning, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    let client = gateway
        .get_rpc()
        .await
        .with_password(Some(DEFAULT_GATEWAY_PASSWORD.to_string()));

    f(gateway, client, fed1, fed2, fixtures.bitcoin()).await?;
    Ok(())
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

async fn pay_valid_invoice(
    invoice: Bolt11Invoice,
    user_client: &ClientArc,
    client: &ClientArc,
) -> anyhow::Result<()> {
    // User client pays test invoice
    let user_lightning_module = &user_client.get_first_module::<LightningClientModule>();
    let OutgoingLightningPayment {
        payment_type,
        contract_id,
        fee: _,
    } = user_lightning_module
        .pay_bolt11_invoice(invoice.clone(), ())
        .await?;
    match payment_type {
        PayType::Lightning(pay_op) => {
            let mut pay_sub = user_lightning_module
                .subscribe_ln_pay(pay_op)
                .await?
                .into_stream();
            assert_eq!(pay_sub.ok().await?, LnPayState::Created);
            let funded = pay_sub.ok().await?;
            assert_matches!(funded, LnPayState::Funded);

            let payload = PayInvoicePayload {
                federation_id: user_client.federation_id(),
                contract_id,
                invoice,
                preimage_auth: Hash::hash(&[0; 32]),
            };

            let gw_pay_op = client
                .get_first_module::<GatewayClientModule>()
                .gateway_pay_bolt11_invoice(payload)
                .await?;
            let mut gw_pay_sub = client
                .get_first_module::<GatewayClientModule>()
                .gateway_subscribe_ln_pay(gw_pay_op)
                .await?
                .into_stream();
            assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage { .. });

            let dummy_module = client.get_first_module::<DummyClientModule>();
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
async fn test_gateway_can_pay_ldk_node() -> anyhow::Result<()> {
    // Running LDK Node with the mock services doesnt provide any additional
    // coverage, since `FakeLightningTest` does not open any channels.
    if !Fixtures::is_real_test() {
        return Ok(());
    }

    single_federation_test(|gateway, _, fed, user_client, bitcoin| async move {
        let ldk = Fixtures::spawn_ldk(bitcoin.clone()).await;

        ldk.open_channel(
            Amount::from_msats(5_000_000_000),
            gateway.node_pub_key,
            gateway.listening_addr.clone(),
            bitcoin.lock_exclusive().await,
        )
        .await?;

        let gateway = gateway.remove_client(&fed).await;
        // Print money for user_client
        let dummy_module = user_client.get_first_module::<DummyClientModule>();
        let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
        dummy_module.receive_money(outpoint).await?;
        assert_eq!(user_client.get_balance().await, sats(1000));

        // Create test invoice
        let invoice = ldk.invoice(sats(250), None).await?;
        pay_valid_invoice(invoice, &user_client, &gateway).await?;

        assert_eq!(user_client.get_balance().await, sats(1000 - 250));
        assert_eq!(gateway.get_balance().await, sats(250));

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_valid_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>();
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invoice(sats(250), None).await?;

            pay_valid_invoice(invoice, &user_client, &gateway).await?;

            assert_eq!(user_client.get_balance().await, sats(1000 - 250));
            assert_eq!(gateway.get_balance().await, sats(250));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_cannot_claim_invalid_preimage() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>();
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Fund outgoing contract that the user client expects the gateway to pay
            let invoice = other_lightning_client.invoice(sats(250), None).await?;
            let OutgoingLightningPayment {
                payment_type: _,
                contract_id,
                fee: _,
            } = user_client
                .get_first_module::<LightningClientModule>()
                .pay_bolt11_invoice(invoice.clone(), ())
                .await?;

            // Try to directly claim the outgoing contract with an invalid preimage
            let gateway_module = gateway.get_first_module::<GatewayClientModule>();

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
            let client_input = ClientInput::<LightningInput, GatewayClientStateMachines> {
                input: claim_input,
                state_machines: Arc::new(|_, _| vec![]),
                keys: vec![gateway_module.redeem_key],
            };

            let tx = TransactionBuilder::new().with_input(client_input.into_dyn(gateway_module.id));
            let operation_meta_gen = |_: TransactionId, _: Vec<OutPoint>| GatewayMeta::Pay {};
            let operation_id = OperationId(invoice.payment_hash().into_inner());
            let (txid, _) = gateway
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
            assert_eq!(gateway.get_balance().await, sats(0));
            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_unpayable_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user client
            let dummy_module = user_client.get_first_module::<DummyClientModule>();
            let lightning_module = user_client.get_first_module::<LightningClientModule>();
            let (_, outpoint) = dummy_module.print_money(sats(1000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create invoice that cannot be paid
            let invoice = other_lightning_client
                .unpayable_invoice(sats(250), None)
                .unwrap();

            // User client pays test invoice
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = lightning_module
                .pay_bolt11_invoice(invoice.clone(), ())
                .await?;
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = lightning_module
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded);

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        invoice,
                        preimage_auth: Hash::hash(&[0; 32]),
                    };

                    let gw_pay_op = gateway
                        .get_first_module::<GatewayClientModule>()
                        .gateway_pay_bolt11_invoice(payload)
                        .await?;
                    let mut gw_pay_sub = gateway
                        .get_first_module::<GatewayClientModule>()
                        .gateway_subscribe_ln_pay(gw_pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
                    assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled { .. });

                    // Assert that the user receives a refund
                    assert_matches!(pay_sub.ok().await?, LnPayState::WaitingForRefund { .. });
                    assert_matches!(pay_sub.ok().await?, LnPayState::Refunded { .. });
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
        let gateway = gateway.remove_client(&fed).await;
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway.get_first_module::<DummyClientModule>();
        let (_, outpoint) = dummy_module.print_money(initial_gateway_balance).await?;
        dummy_module.receive_money(outpoint).await?;
        assert_eq!(gateway.get_balance().await, sats(1000));

        // User client creates invoice in federation
        let invoice_amount = sats(100);
        let (_invoice_op, invoice) = user_client
            .get_first_module::<LightningClientModule>()
            .create_bolt11_invoice(
                invoice_amount,
                "description".into(),
                None,
                "test intercept valid HTLC",
            )
            .await?;

        // Run gateway state machine
        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            incoming_expiry: u32::MAX,
            short_channel_id: 1,
            incoming_chan_id: 2,
            htlc_id: 1,
        };
        let intercept_op = gateway
            .get_first_module::<GatewayClientModule>()
            .gateway_handle_intercepted_htlc(htlc)
            .await?;
        let mut intercept_sub = gateway
            .get_first_module::<GatewayClientModule>()
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
            gateway.get_balance().await
        );

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_offer_does_not_exist() -> anyhow::Result<()> {
    single_federation_test(|gateway, _, fed, _, _| async move {
        let gateway = gateway.remove_client(&fed).await;
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let dummy_module = gateway.get_first_module::<DummyClientModule>();
        let (_, outpoint) = dummy_module.print_money(initial_gateway_balance).await?;
        dummy_module.receive_money(outpoint).await?;
        assert_eq!(gateway.get_balance().await, sats(1000));

        // Create HTLC that doesn't correspond to an offer in the federation
        let htlc = Htlc {
            payment_hash: sha256(&[15]),
            incoming_amount_msat: Amount::from_msats(100),
            outgoing_amount_msat: Amount::from_msats(100),
            incoming_expiry: u32::MAX,
            short_channel_id: 1,
            incoming_chan_id: 2,
            htlc_id: 1,
        };

        match gateway
            .get_first_module::<GatewayClientModule>()
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
        let gateway = gateway.remove_client(&fed).await;
        // User client creates invoice in federation
        let (_invoice_op, invoice) = user_client
            .get_first_module::<LightningClientModule>()
            .create_bolt11_invoice(
                sats(100),
                "description".into(),
                None,
                "test intercept htlc but with no funds",
            )
            .await?;

        // Run gateway state machine
        let htlc = Htlc {
            payment_hash: *invoice.payment_hash(),
            incoming_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            outgoing_amount_msat: Amount::from_msats(invoice.amount_milli_satoshis().unwrap()),
            incoming_expiry: u32::MAX,
            short_channel_id: 1,
            incoming_chan_id: 2,
            htlc_id: 1,
        };

        // Attempt to route an HTLC while the gateway has no funds
        match gateway
            .get_first_module::<GatewayClientModule>()
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
            let gateway = gateway.remove_client(&fed).await;
            // Print money for gateway client
            let initial_gateway_balance = sats(1000);
            let gateway_dummy_module = gateway.get_first_module::<DummyClientModule>();
            let (_, outpoint) = gateway_dummy_module
                .print_money(initial_gateway_balance)
                .await?;
            gateway_dummy_module.receive_money(outpoint).await?;
            assert_eq!(gateway.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.unpayable_invoice(sats(250), None)?;

            // Create offer with a preimage that doesn't correspond to the payment hash of
            // the invoice
            let user_lightning_module = user_client.get_first_module::<LightningClientModule>();

            let amount = sats(100);
            let preimage = BYTE_33;
            let ln_output = LightningOutput::new_v0_offer(IncomingContractOffer {
                amount,
                hash: *invoice.payment_hash(),
                encrypted_preimage: EncryptedPreimage::new(
                    PreimageKey(preimage),
                    &user_lightning_module.cfg.threshold_pub_key,
                ),
                expiry_time: None,
            });
            // The client's receive state machine can be empty because the gateway should
            // not fund this contract
            let state_machines = Arc::new(move |_txid: TransactionId, _input_idx: u64| {
                Vec::<LightningClientStateMachines>::new()
            });
            let client_output = ClientOutput {
                output: ln_output,
                state_machines,
            };
            let tx = TransactionBuilder::new()
                .with_output(client_output.into_dyn(user_lightning_module.id));
            let operation_meta_gen = |txid, _| LightningOperationMeta {
                variant: LightningOperationMetaVariant::Receive {
                    out_point: OutPoint { txid, out_idx: 0 },
                    invoice: invoice.clone(),
                },
                extra_meta: serde_json::to_value("test intercept HTLC with invalid offer")
                    .expect("Failed to serialize string into json"),
            };

            let operation_id = OperationId(invoice.payment_hash().into_inner());
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
                short_channel_id: 1,
                incoming_chan_id: 2,
                htlc_id: 1,
            };

            let intercept_op = gateway
                .get_first_module::<GatewayClientModule>()
                .gateway_handle_intercepted_htlc(htlc)
                .await?;
            let mut intercept_sub = gateway
                .get_first_module::<GatewayClientModule>()
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

                    assert_eq!(initial_gateway_balance, gateway.get_balance().await);
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
async fn test_gateway_register_with_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let node = fixtures.lnd().await;
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;
    let mut gateway_test = fixtures
        .new_gateway(node, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    gateway_test.connect_fed(&fed).await;
    let gateway = gateway_test.remove_client(&fed).await;

    let mut fake_api = SafeUrl::from_str("http://127.0.0.1:8175").unwrap();
    let fake_route_hints = Vec::new();
    // Register with the federation with a low TTL to verify it will re-register
    gateway
        .get_first_module::<GatewayClientModule>()
        .register_with_federation(
            fake_api.clone(),
            fake_route_hints.clone(),
            GW_ANNOUNCEMENT_TTL,
            gateway_test.get_gateway_id(),
        )
        .await?;
    let lightning_module = user_client.get_first_module::<LightningClientModule>();
    let gateways = lightning_module.fetch_registered_gateways().await?;
    assert!(gateways
        .into_iter()
        .any(|gateway| gateway.info.api == fake_api));

    // Update the URI for the gateway then re-register
    fake_api = SafeUrl::from_str("http://127.0.0.1:8176").unwrap();

    gateway
        .get_first_module::<GatewayClientModule>()
        .register_with_federation(
            fake_api.clone(),
            fake_route_hints,
            GW_ANNOUNCEMENT_TTL,
            gateway_test.get_gateway_id(),
        )
        .await?;
    let gateways = lightning_module.fetch_registered_gateways().await?;
    assert!(gateways
        .into_iter()
        .any(|gateway| gateway.info.api == fake_api));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_cannot_pay_expired_invoice() -> anyhow::Result<()> {
    single_federation_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            let invoice = other_lightning_client
                .invoice(sats(1000), 1.into())
                .await
                .unwrap();
            assert_eq!(invoice.expiry_time(), Duration::from_secs(1));

            // at seconds granularity, must wait `expiry + 1s` to make sure expired
            sleep(Duration::from_secs(2)).await;

            // Print money for user_client
            let dummy_module = user_client.get_first_module::<DummyClientModule>();
            let (_, outpoint) = dummy_module.print_money(sats(2000)).await?;
            dummy_module.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(2000));

            // User client pays test invoice
            let lightning_module = user_client.get_first_module::<LightningClientModule>();
            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee: _,
            } = lightning_module
                .pay_bolt11_invoice(invoice.clone(), ())
                .await?;
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = lightning_module
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded);

                    let payload = PayInvoicePayload {
                        federation_id: user_client.federation_id(),
                        contract_id,
                        invoice,
                        preimage_auth: Hash::hash(&[0; 32]),
                    };

                    let gw_pay_op = gateway
                        .get_first_module::<GatewayClientModule>()
                        .gateway_pay_bolt11_invoice(payload)
                        .await?;
                    let mut gw_pay_sub = gateway
                        .get_first_module::<GatewayClientModule>()
                        .gateway_subscribe_ln_pay(gw_pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
                    assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled { .. });

                    assert_matches!(pay_sub.ok().await?, LnPayState::WaitingForRefund { .. });
                    // Gateway should immediately refund the client
                    assert_matches!(pay_sub.ok().await?, LnPayState::Refunded { .. });
                }
                _ => panic!("Expected Lightning payment!"),
            }

            // Balance should be unchanged
            assert_eq!(user_client.get_balance().await, sats(2000));
            assert_eq!(gateway.get_balance().await, sats(0));

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_filters_route_hints_by_inbound() -> anyhow::Result<()> {
    if !Fixtures::is_real_test() {
        return Ok(());
    }

    let fixtures = fixtures();
    let lnd = fixtures.lnd().await;
    let cln = fixtures.cln().await;

    let GetNodeInfoResponse { pub_key, .. } = lnd.info().await?;
    let lnd_public_key = PublicKey::from_slice(&pub_key)?;

    let GetNodeInfoResponse { pub_key, .. } = cln.info().await?;
    let cln_public_key = PublicKey::from_slice(&pub_key)?;
    let all_keys = [lnd_public_key, cln_public_key];

    for gateway_type in [LightningNodeType::Cln, LightningNodeType::Lnd] {
        for num_route_hints in 0..=1 {
            let gateway_ln = match gateway_type {
                LightningNodeType::Cln => fixtures.cln().await,
                LightningNodeType::Lnd => fixtures.lnd().await,
                LightningNodeType::Ldk => unimplemented!("LDK Node is not supported as a gateway"),
            };

            let GetNodeInfoResponse { pub_key, .. } = gateway_ln.info().await?;
            let public_key = PublicKey::from_slice(&pub_key)?;

            tracing::info!("Creating federation with gateway type {gateway_type}. Number of route hints: {num_route_hints}");

            let fed = fixtures.new_fed().await;
            let user_client = fed.new_client().await;
            let mut gateway = fixtures
                .new_gateway(
                    gateway_ln,
                    num_route_hints,
                    Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
                )
                .await;
            gateway.connect_fed(&fed).await;

            let invoice_amount = sats(100);
            let (_invoice_op, invoice) = user_client
                .get_first_module::<LightningClientModule>()
                .create_bolt11_invoice(
                    invoice_amount,
                    "description".into(),
                    None,
                    format!(
                        "gateway type: {gateway_type} number of route hints: {num_route_hints}"
                    ),
                )
                .await?;
            let route_hints = invoice.route_hints();

            match num_route_hints {
                0 => {
                    // If there's no additional route hints, we're expecting a single route hint
                    // with a single hop on the invoice, where the hop is the
                    // public key of the gateway lightning node
                    assert_eq!(
                        route_hints.len(),
                        1,
                        "Found {} route hints when 1 was expected for {gateway_type} gateway",
                        route_hints.len()
                    );
                    let route_hint = route_hints.get(0).unwrap();
                    assert_eq!(
                        route_hint.0.len(),
                        1,
                        "Found {} hops when 1 was expected for {gateway_type} gateway",
                        route_hint.0.len()
                    );
                    let route_hint_pub_key = route_hint.0.get(0).unwrap().src_node_id;
                    assert_eq!(
                        route_hint_pub_key, public_key,
                        "Public key of route hint hop did not match expected public key"
                    );
                }
                _ => {
                    // If there's more than one route hint, we're expecting the invoice to contain
                    // `num_route_hints` + 1. There should be one single-hop route hint and the rest
                    // two-hop route hints.
                    assert_eq!(
                        route_hints.len() as u32,
                        num_route_hints + 1,
                        "Found {} route hints when {} was expected for {gateway_type} gateway",
                        route_hints.len(),
                        num_route_hints + 1
                    );

                    let mut num_one_hops = 0;
                    for route_hint in route_hints {
                        if route_hint.0.len() == 1 {
                            // If there's only one hop, it should contain the gateway's public key
                            let route_hint_pub_key = route_hint.0.get(0).unwrap().src_node_id;
                            assert_eq!(route_hint_pub_key, public_key);
                            num_one_hops += 1;
                        } else {
                            // If there's > 1 hop, it should exist in `all_keys`
                            for hop in route_hint.0 {
                                assert!(
                                    all_keys.contains(&hop.src_node_id),
                                    "Public key of route hint hop did not match expected public key"
                                );
                            }
                        }
                    }

                    assert_eq!(
                        num_one_hops, 1,
                        "Found incorrect number of one hop route hints"
                    );
                }
            }
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_configuration() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_fed().await;
    let lnd = fixtures.lnd().await;
    let gateway = fixtures.new_gateway(lnd, 0, None).await;
    let rpc_client = gateway.get_rpc().await;

    // Verify that we can't join a federation yet because the configuration is not
    // set
    let join_payload = ConnectFedPayload {
        invite_code: fed.invite_code().to_string(),
    };

    verify_rpc(
        || rpc_client.connect_federation(join_payload.clone()),
        StatusCode::NOT_FOUND,
    )
    .await;

    // Verify that the gateway's state is "Configuring"
    let gw_info = rpc_client.get_info().await?;
    assert_eq!(gw_info.gateway_state, "Configuring".to_string());

    // Verify that the gateway's fees, and network are `None`
    assert_eq!(gw_info.fees, None);
    assert_eq!(gw_info.network, None);

    let test_password = "test_password".to_string();
    let set_configuration_payload = SetConfigurationPayload {
        password: Some(test_password.clone()),
        num_route_hints: None,
        routing_fees: None,
        network: None,
    };
    verify_rpc(
        || rpc_client.set_configuration(set_configuration_payload.clone()),
        StatusCode::OK,
    )
    .await;

    GatewayTest::wait_for_gateway_state(gateway.gateway.clone(), |gw_state| {
        matches!(gw_state, GatewayState::Running { .. })
    })
    .await?;

    // Verify old password no longer works
    verify_rpc(|| rpc_client.get_info(), StatusCode::UNAUTHORIZED).await;

    // Verify the gateway's state is "Running" with default fee and default or
    // lightning node network
    let rpc_client = rpc_client.with_password(Some(test_password));
    let gw_info = rpc_client.get_info().await?;
    assert_eq!(gw_info.gateway_state, "Running".to_string());
    assert_eq!(gw_info.fees, Some(DEFAULT_FEES));
    assert_eq!(gw_info.network, Some(DEFAULT_NETWORK));

    // Verify we can change most configurations when the gateway is running
    let new_password = "new_password".to_string();
    let fee = "1000,2000".to_string();
    let set_configuration_payload = SetConfigurationPayload {
        password: Some(new_password.clone()),
        num_route_hints: Some(1),
        routing_fees: Some(fee.clone()),
        network: None,
    };
    verify_rpc(
        || rpc_client.set_configuration(set_configuration_payload.clone()),
        StatusCode::OK,
    )
    .await;

    // Verify info works with the new password.
    // Need to retry because the webserver might be restarting.
    let rpc_client = rpc_client.with_password(Some(new_password.clone()));
    let gw_info = retry(
        "Get info after restart".to_string(),
        || async {
            let info = rpc_client.get_info().await?;
            Ok(info)
        },
        Duration::from_secs(1),
        5,
    )
    .await?;

    assert_eq!(gw_info.gateway_state, "Running".to_string());
    assert_eq!(gw_info.fees, Some(GatewayFee::from_str(&fee)?.0));
    assert_eq!(gw_info.network, Some(DEFAULT_NETWORK));

    // Verify we can configure gateway to a network same as than the lightning nodes
    let set_configuration_payload = SetConfigurationPayload {
        password: Some(new_password.clone()),
        num_route_hints: None,
        routing_fees: None,
        network: Some(DEFAULT_NETWORK), // Same as connected lightning node's network
    };
    verify_rpc(
        || rpc_client.set_configuration(set_configuration_payload.clone()),
        StatusCode::OK,
    )
    .await;

    // Verify we cannot reconfigure gateway to a network different than the
    // lightning nodes
    let set_configuration_payload = SetConfigurationPayload {
        password: Some(new_password.clone()),
        num_route_hints: None,
        routing_fees: None,
        network: Some(Network::Testnet), // Different from connected lightning node's network
    };
    verify_rpc(
        || rpc_client.set_configuration(set_configuration_payload.clone()),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await;

    // Verify we can connect to a federation if the gateway is configured to use
    // the same network. Test federations are on Regtest by default
    verify_rpc(
        || rpc_client.connect_federation(join_payload.clone()),
        StatusCode::OK,
    )
    .await;
    verify_rpc(
        || {
            rpc_client.get_balance(BalancePayload {
                federation_id: fed.invite_code().federation_id(),
            })
        },
        StatusCode::OK,
    )
    .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_supports_connecting_multiple_federations() -> anyhow::Result<()> {
    multi_federation_test(
        LightningNodeType::Lnd,
        |gateway, rpc, fed1, fed2, _| async move {
            info!("Starting test_gateway_supports_connecting_multiple_federations");
            assert_eq!(rpc.get_info().await.unwrap().federations.len(), 0);

            let invite1 = fed1.invite_code();
            let info = rpc
                .connect_federation(ConnectFedPayload {
                    invite_code: invite1.to_string(),
                })
                .await
                .unwrap();

            assert_eq!(info.federation_id, invite1.federation_id());

            let invite2 = fed2.invite_code();
            let info = rpc
                .connect_federation(ConnectFedPayload {
                    invite_code: invite2.to_string(),
                })
                .await
                .unwrap();
            assert_eq!(info.federation_id, invite2.federation_id());
            drop(gateway); // keep until the end to avoid the gateway shutting down too early
            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_shows_info_about_all_connected_federations() -> anyhow::Result<()> {
    multi_federation_test(
        LightningNodeType::Lnd,
        |gateway, rpc, fed1, fed2, _| async move {
            assert_eq!(rpc.get_info().await.unwrap().federations.len(), 0);

            let id1 = fed1.invite_code().federation_id();
            let id2 = fed2.invite_code().federation_id();

            connect_federations(&rpc, &[fed1, fed2]).await.unwrap();

            let info = rpc.get_info().await.unwrap();

            assert_eq!(info.federations.len(), 2);
            assert!(info
                .federations
                .iter()
                .any(|info| info.federation_id == id1 && info.balance_msat == Amount::ZERO));
            assert!(info
                .federations
                .iter()
                .any(|info| info.federation_id == id2 && info.balance_msat == Amount::ZERO));
            drop(gateway); // keep until the end to avoid the gateway shutting down too early
            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_shows_balance_for_any_connected_federation() -> anyhow::Result<()> {
    multi_federation_test(
        LightningNodeType::Lnd,
        |gateway, rpc, fed1, fed2, _| async move {
            let id1 = fed1.invite_code().federation_id();
            let id2 = fed2.invite_code().federation_id();

            connect_federations(&rpc, &[fed1, fed2]).await.unwrap();

            let pre_balances = get_balances(&rpc, &[id1, id2]).await;

            send_msats_to_gateway(&gateway, id1, 5_000).await;
            send_msats_to_gateway(&gateway, id2, 1_000).await;

            let post_balances = get_balances(&rpc, &[id1, id2]).await;

            assert_eq!(pre_balances[0], 0);
            assert_eq!(pre_balances[1], 0);
            assert_eq!(post_balances[0], 5_000);
            assert_eq!(post_balances[1], 1_000);
            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_executes_swaps_between_connected_federations() -> anyhow::Result<()> {
    multi_federation_test(
        LightningNodeType::Lnd,
        |gateway, rpc, fed1, fed2, _| async move {
            let id1 = fed1.invite_code().federation_id();
            let id2 = fed2.invite_code().federation_id();

            let client1 = fed1.new_client().await;
            let client2 = fed2.new_client().await;

            connect_federations(&rpc, &[fed1, fed2]).await.unwrap();
            send_msats_to_gateway(&gateway, id1, 10_000).await;
            send_msats_to_gateway(&gateway, id2, 10_000).await;

            // Check gateway balances before facilitating direct swap between federations
            let pre_balances = get_balances(&rpc, &[id1, id2]).await;
            assert_eq!(pre_balances[0], 10_000);
            assert_eq!(pre_balances[1], 10_000);

            let deposit_amt = msats(5_000);
            let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
            let (_, outpoint) = client1_dummy_module.print_money(deposit_amt).await?;
            client1_dummy_module.receive_money(outpoint).await?;
            assert_eq!(client1.get_balance().await, deposit_amt);

            // User creates invoice in federation 2
            let invoice_amt = msats(2_500);
            let (receive_op, invoice) = client2
                .get_first_module::<LightningClientModule>()
                .create_bolt11_invoice(
                    invoice_amt,
                    "description".into(),
                    None,
                    "test gw swap between federations",
                )
                .await?;
            let mut receive_sub = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_receive(receive_op)
                .await?
                .into_stream();

            // A client pays invoice in federation 1
            let OutgoingLightningPayment {
                payment_type,
                contract_id: _,
                fee,
            } = client1
                .get_first_module::<LightningClientModule>()
                .pay_bolt11_invoice(invoice.clone(), ())
                .await?;
            match payment_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = client1
                        .get_first_module::<LightningClientModule>()
                        .subscribe_ln_pay(pay_op)
                        .await?
                        .into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded);
                    assert_eq!(client1.get_balance().await, deposit_amt - invoice_amt - fee);
                }
                _ => panic!("Expected Lightning payment!"),
            }

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
            //
            // We poll the gateway upto five times to give the gateway a chance to update
            // its balances on both federations.
            let post_balances = retry(
                "Gateway balance after swap".to_string(),
                || async {
                    let post_balances = get_balances(&rpc, &[id1, id2]).await;
                    if post_balances[0] == pre_balances[0] || post_balances[1] == pre_balances[1] {
                        return Err(anyhow::anyhow!("Gateway balance not updated"));
                    };
                    Ok(post_balances)
                },
                Duration::from_secs(1),
                15,
            )
            .await?;
            assert_eq!(
                post_balances[0],
                pre_balances[0] + (invoice_amt + fee).msats
            );
            assert_eq!(post_balances[1], pre_balances[1] - invoice_amt.msats);

            Ok(())
        },
    )
    .await
}

async fn verify_rpc<Fut, T>(func: impl Fn() -> Fut, status_code: StatusCode)
where
    Fut: Future<Output = GatewayRpcResult<T>>,
{
    if let Err(GatewayRpcError::BadStatus(status)) = func().await {
        assert_eq!(status, status_code)
    }
}

pub async fn connect_federations(
    rpc: &GatewayRpcClient,
    feds: &[FederationTest],
) -> anyhow::Result<()> {
    for fed in feds {
        let invite_code = fed.invite_code().to_string();
        rpc.connect_federation(ConnectFedPayload { invite_code })
            .await?;
    }
    Ok(())
}

async fn get_balances(
    rpc: &GatewayRpcClient,
    ids: impl IntoIterator<Item = &FederationId>,
) -> Vec<u64> {
    let mut balances = vec![];
    for id in ids.into_iter() {
        balances.push(
            rpc.get_balance(BalancePayload { federation_id: *id })
                .await
                .unwrap()
                .msats,
        )
    }

    balances
}

async fn send_msats_to_gateway(gateway: &GatewayTest, id: FederationId, msats: u64) {
    let client = gateway.select_client(id).await;
    let dummy_module = client.get_first_module::<DummyClientModule>();
    let (_, outpoint) = dummy_module
        .print_money(Amount::from_msats(msats))
        .await
        .unwrap();
    dummy_module.receive_money(outpoint).await.unwrap();
}
