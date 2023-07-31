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
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    LightningClientExt, LightningClientGen, LightningClientModule, LightningClientStateMachines,
    LightningMeta, LnPayState, PayType,
};
use fedimint_ln_common::api::LnFederationApi;
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use fedimint_ln_server::LightningGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::GatewayTest;
use fedimint_testing::ln::LightningTest;
use futures::Future;
use ln_gateway::ng::{
    GatewayClientExt, GatewayClientModule, GatewayClientStateMachines, GatewayExtPayStates,
    GatewayExtReceiveStates, GatewayMeta, Htlc, GW_ANNOUNCEMENT_TTL,
};
use url::Url;

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

    for (node, other_node) in vec![(lnd1, cln1), (cln2, lnd2)] {
        let fed = fixtures.new_fed().await;
        let user_client = fed.new_client().await;
        let mut gateway = fixtures.new_gateway(node).await;
        gateway.connect_fed(&fed).await;
        f(gateway, other_node, fed, user_client).await?;
    }
    Ok(())
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_valid_invoice() -> anyhow::Result<()> {
    gateway_test(
        |gateway, other_lightning_client, fed, user_client| async move {
            let gateway = gateway.remove_client(&fed).await;
            // Print money for user_client
            let (_, outpoint) = user_client.print_money(sats(1000)).await?;
            user_client.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invoice(sats(250), None).await?;

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
        |gateway, other_lightning_client, fed, user_client| async move {
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
        |gateway, other_lightning_client, fed, user_client| async move {
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
    gateway_test(|gateway, _, fed, user_client| async move {
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
    gateway_test(|gateway, _, fed, _| async move {
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
    gateway_test(|gateway, _, fed, user_client| async move {
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
        |gateway, other_lightning_client, fed, user_client| async move {
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
            let operation_meta_gen = |txid, _| LightningMeta::Receive {
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
    let mut gateway_test = fixtures.new_gateway(node).await;
    gateway_test.connect_fed(&fed).await;
    let gateway = gateway_test.remove_client(&fed).await;

    let mut fake_api = Url::from_str("http://127.0.0.1:8175").unwrap();
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
    fake_api = Url::from_str("http://127.0.0.1:8176").unwrap();

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
        |gateway, other_lightning_client, fed, user_client| async move {
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
