use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::sm::OperationId;
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::Client;
use fedimint_core::core::IntoDynInstance;
use fedimint_core::task::sleep;
use fedimint_core::util::{NextOrPending, SafeUrl};
use fedimint_core::{sats, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    LightningClientExt, LightningClientGen, LightningClientModule, LightningClientStateMachines,
    LightningOperationMeta, LnPayState, PayType,
};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use fedimint_ln_server::LightningGen;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, LightningNodeType, DEFAULT_GATEWAY_PASSWORD};
use fedimint_testing::ln::LightningTest;
use futures::Future;
use lightning_invoice::Bolt11Invoice;
use ln_gateway::gateway_lnrpc::GetNodeInfoResponse;
use ln_gateway::ng::{
    GatewayClientExt, GatewayClientModule, GatewayClientStateMachines, GatewayExtPayStates,
    GatewayExtReceiveStates, GatewayMeta, Htlc, GW_ANNOUNCEMENT_TTL,
};
use ln_gateway::rpc::rpc_client::{GatewayRpcError, GatewayRpcResult};
use ln_gateway::rpc::{BalancePayload, ConnectFedPayload, SetConfigurationPayload};
use ln_gateway::utils::retry;
use ln_gateway::GatewayState;
use reqwest::StatusCode;
use secp256k1::PublicKey;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures.with_module(LightningClientGen, LightningGen, ln_params)
}

async fn gateway_test<B>(
    f: impl FnOnce(
            GatewayTest,
            Box<dyn LightningTest>,
            FederationTest,
            Client, // User Client
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

    for (gateway_ln, other_node) in vec![(lnd1, cln1), (cln2, lnd2)] {
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

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

async fn pay_valid_invoice(
    invoice: Bolt11Invoice,
    user_client: &Client,
    gateway: &Client,
) -> anyhow::Result<()> {
    // User client pays test invoice
    let (pay_type, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;
    match pay_type {
        PayType::Lightning(pay_op) => {
            let mut pay_sub = user_client.subscribe_ln_pay(pay_op).await?.into_stream();
            assert_eq!(pay_sub.ok().await?, LnPayState::Created);
            let funded = pay_sub.ok().await?;
            assert_matches!(funded, LnPayState::Funded);

            let gw_pay_op = gateway.gateway_pay_bolt11_invoice(contract_id).await?;
            let mut gw_pay_sub = gateway
                .gateway_subscribe_ln_pay(gw_pay_op)
                .await?
                .into_stream();
            assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
            assert_matches!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage { .. });
            if let GatewayExtPayStates::Success {
                preimage: _,
                outpoint: gw_outpoint,
            } = gw_pay_sub.ok().await?
            {
                gateway.receive_money(gw_outpoint).await?;
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

    gateway_test(|gateway, _, fed, user_client, bitcoin| async move {
        let ldk = Fixtures::spawn_ldk(bitcoin.clone()).await;

        ldk.open_channel(
            Amount::from_msats(5000000),
            gateway.node_pub_key,
            gateway.listening_addr.clone(),
            bitcoin.lock_exclusive().await,
        )
        .await?;

        let gateway = gateway.remove_client(&fed).await;
        // Print money for user_client
        let (_, outpoint) = user_client.print_money(sats(1000)).await?;
        user_client.receive_money(outpoint).await?;
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
    gateway_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user_client
            let (_, outpoint) = user_client.print_money(sats(1000)).await?;
            user_client.receive_money(outpoint).await?;
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
    gateway_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user_client
            let (_, outpoint) = user_client.print_money(sats(1000)).await?;
            user_client.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Fund outgoing contract that the user client expects the gateway to pay
            let invoice = other_lightning_client.invoice(sats(250), None).await?;
            let (_, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;

            // Try to directly claim the outgoing contract with an invalid preimage
            let (gateway_module, instance) =
                gateway.get_first_module::<GatewayClientModule>(&fedimint_ln_client::KIND);

            let account = instance.api.fetch_contract(contract_id).await?;
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

            let tx = TransactionBuilder::new().with_input(client_input.into_dyn(instance.id));
            let operation_meta_gen = |_: TransactionId, _: Option<OutPoint>| GatewayMeta::Pay {};
            let operation_id = OperationId(invoice.payment_hash().into_inner());
            let txid = gateway
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_client::KIND.as_str(),
                    operation_meta_gen,
                    tx,
                )
                .await?;

            // Assert that we did not get paid for claiming a contract with a bogus preimage
            assert!(gateway
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
    gateway_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user client
            let (_, outpoint) = user_client.print_money(sats(1000)).await?;
            user_client.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create invoice that cannout be paid
            let invoice = other_lightning_client
                .unpayable_invoice(sats(250), None)
                .unwrap();

            // User client pays test invoice
            let (pay_type, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;
            match pay_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = user_client.subscribe_ln_pay(pay_op).await?.into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded);

                    let gw_pay_op = gateway.gateway_pay_bolt11_invoice(contract_id).await?;
                    let mut gw_pay_sub = gateway
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
    gateway_test(|gateway, _, fed, user_client, _| async move {
        let gateway = gateway.remove_client(&fed).await;
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let (_, outpoint) = gateway.print_money(initial_gateway_balance).await?;
        gateway.receive_money(outpoint).await?;
        assert_eq!(gateway.get_balance().await, sats(1000));

        // User client creates invoice in federation
        let invoice_amount = sats(100);
        let (_invoice_op, invoice) = user_client
            .create_bolt11_invoice(invoice_amount, "description".into(), None)
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
        let intercept_op = gateway.gateway_handle_intercepted_htlc(htlc).await?;
        let mut intercept_sub = gateway
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
    gateway_test(|gateway, _, fed, _, _| async move {
        let gateway = gateway.remove_client(&fed).await;
        // Print money for gateway client
        let initial_gateway_balance = sats(1000);
        let (_, outpoint) = gateway.print_money(initial_gateway_balance).await?;
        gateway.receive_money(outpoint).await?;
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

        match gateway.gateway_handle_intercepted_htlc(htlc).await {
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
    gateway_test(|gateway, _, fed, user_client, _| async move {
        let gateway = gateway.remove_client(&fed).await;
        // User client creates invoice in federation
        let (_invoice_op, invoice) = user_client
            .create_bolt11_invoice(sats(100), "description".into(), None)
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
        match gateway.gateway_handle_intercepted_htlc(htlc).await {
            Ok(_) => panic!("Expected incoming offer validation to fail due to lack of funds"),
            Err(e) => assert_eq!(e.to_string(), "Insufficient funds".to_string()),
        }

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_invalid_offer() -> anyhow::Result<()> {
    gateway_test(
        |gateway, other_lightning_client, fed, user_client, _| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for gateway client
            let initial_gateway_balance = sats(1000);
            let (_, outpoint) = gateway.print_money(initial_gateway_balance).await?;
            gateway.receive_money(outpoint).await?;
            assert_eq!(gateway.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.unpayable_invoice(sats(250), None)?;

            // Create offer with a preimage that doesn't correspond to the payment hash of
            // the invoice
            let (lightning, instance) =
                user_client.get_first_module::<LightningClientModule>(&fedimint_ln_client::KIND);

            let amount = sats(100);
            let preimage = sha256(&[0]);
            let ln_output = LightningOutput::Offer(IncomingContractOffer {
                amount,
                hash: *invoice.payment_hash(),
                encrypted_preimage: EncryptedPreimage::new(
                    Preimage(preimage.into_inner()),
                    &lightning.cfg.threshold_pub_key,
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
            let tx = TransactionBuilder::new().with_output(client_output.into_dyn(instance.id));
            let operation_meta_gen = |txid, _| LightningOperationMeta::Receive {
                out_point: OutPoint { txid, out_idx: 0 },
                invoice: invoice.clone(),
            };
            let operation_id = OperationId(invoice.payment_hash().into_inner());
            let txid = user_client
                .finalize_and_submit_transaction(
                    operation_id,
                    fedimint_ln_client::KIND.as_str(),
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

            let intercept_op = gateway.gateway_handle_intercepted_htlc(htlc).await?;
            let mut intercept_sub = gateway
                .gateway_subscribe_ln_receive(intercept_op)
                .await?
                .into_stream();
            assert_matches!(intercept_sub.ok().await?, GatewayExtReceiveStates::Funding);

            match intercept_sub.ok().await? {
                GatewayExtReceiveStates::RefundSuccess {
                    outpoint: refund_outpoint,
                    error: _,
                } => {
                    // Assert that the gateway got it's refund
                    gateway.receive_money(refund_outpoint).await?;
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
        .register_with_federation(
            fake_api.clone(),
            fake_route_hints.clone(),
            GW_ANNOUNCEMENT_TTL,
            gateway_test.get_gateway_id(),
        )
        .await?;
    let gateways = user_client.fetch_registered_gateways().await?;
    assert!(gateways.into_iter().any(|gateway| gateway.api == fake_api));

    // Update the URI for the gateway then re-register
    fake_api = SafeUrl::from_str("http://127.0.0.1:8176").unwrap();

    gateway
        .register_with_federation(
            fake_api.clone(),
            fake_route_hints,
            GW_ANNOUNCEMENT_TTL,
            gateway_test.get_gateway_id(),
        )
        .await?;
    let gateways = user_client.fetch_registered_gateways().await?;
    assert!(gateways.into_iter().any(|gateway| gateway.api == fake_api));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_cannot_pay_expired_invoice() -> anyhow::Result<()> {
    gateway_test(
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
            let (_, outpoint) = user_client.print_money(sats(2000)).await?;
            user_client.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(2000));

            // User client pays test invoice
            let (pay_type, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;
            match pay_type {
                PayType::Lightning(pay_op) => {
                    let mut pay_sub = user_client.subscribe_ln_pay(pay_op).await?.into_stream();
                    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
                    let funded = pay_sub.ok().await?;
                    assert_matches!(funded, LnPayState::Funded);

                    let gw_pay_op = gateway.gateway_pay_bolt11_invoice(contract_id).await?;
                    let mut gw_pay_sub = gateway
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

    let GetNodeInfoResponse { pub_key, alias: _ } = lnd.info().await?;
    let lnd_public_key = PublicKey::from_slice(&pub_key)?;

    let GetNodeInfoResponse { pub_key, alias: _ } = cln.info().await?;
    let cln_public_key = PublicKey::from_slice(&pub_key)?;
    let all_keys = vec![lnd_public_key, cln_public_key];

    for gateway_type in vec![LightningNodeType::Cln, LightningNodeType::Lnd] {
        for num_route_hints in 0..=1 {
            let gateway_ln = match gateway_type {
                LightningNodeType::Cln => fixtures.cln().await,
                LightningNodeType::Lnd => fixtures.lnd().await,
                LightningNodeType::Ldk => unimplemented!("LDK Node is not supported as a gateway"),
            };

            let GetNodeInfoResponse { pub_key, alias: _ } = gateway_ln.info().await?;
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
                .create_bolt11_invoice(invoice_amount, "description".into(), None)
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
                        route_hints.len(),
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

    let test_password = "test_password".to_string();
    let set_configuration_payload = SetConfigurationPayload {
        password: test_password.clone(),
    };
    verify_rpc(
        || rpc_client.set_configuration(set_configuration_payload.clone()),
        StatusCode::OK,
    )
    .await;

    GatewayTest::wait_for_gateway_state(gateway.gateway.clone(), |gw_state| {
        matches!(gw_state, GatewayState::Running { .. })
    })
    .await;

    // Test authentication
    let rpc_client = rpc_client.with_password(Some(test_password));
    let bad_rpc_client = rpc_client.with_password(Some("invalid".to_string()));

    rpc_client.connect_federation(join_payload.clone()).await?;

    rpc_client.get_info().await?;
    verify_rpc(|| bad_rpc_client.get_info(), StatusCode::UNAUTHORIZED).await;

    let federation_id = fed.invite_code().id;

    let payload = BalancePayload { federation_id };
    rpc_client.get_balance(payload.clone()).await?;
    verify_rpc(
        || bad_rpc_client.get_balance(payload.clone()),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    // Verify that we can change the configuration after it is set
    let set_configuration_payload = SetConfigurationPayload {
        password: "new_password".to_string(),
    };
    rpc_client
        .set_configuration(set_configuration_payload.clone())
        .await?;

    // Verify info works with the new password.
    // Need to retry because the webserver might be restarting.
    retry(
        "Get info after restart".to_string(),
        || async {
            let rpc_client = rpc_client.with_password(Some("new_password".to_string()));
            rpc_client.get_info().await?;
            Ok(())
        },
        Duration::from_secs(1),
        5,
    )
    .await?;

    Ok(())
}

async fn verify_rpc<Fut, T>(func: impl Fn() -> Fut, status_code: StatusCode)
where
    Fut: Future<Output = GatewayRpcResult<T>>,
{
    if let Err(GatewayRpcError::BadStatus(status)) = func().await {
        assert_eq!(status, status_code)
    }
}
