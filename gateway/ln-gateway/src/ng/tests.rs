use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::sm::OperationId;
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::Client;
use fedimint_client_legacy::api::LnFederationApi;
use fedimint_core::core::IntoDynInstance;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    LightningClientExt, LightningClientGen, LightningClientModule, LightningClientStateMachines,
    LightningMeta, LnPayState, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{EncryptedPreimage, FundedContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use fedimint_ln_server::LightningGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::{Fixtures, LightningFixtures};
use fedimint_testing::ln::{LightningNodeType, LightningTest};
use futures::Future;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::lnrpc_client::ILnRpcClient;
use ln_gateway::ng::{
    GatewayClientExt, GatewayClientGen, GatewayClientModule, GatewayClientStateMachines,
    GatewayExtPayStates, GatewayExtReceiveStates, GatewayExtRegisterStates, GatewayMeta, Htlc,
    GW_ANNOUNCEMENT_TTL,
};
use tracing::debug;
use url::Url;

async fn fixtures(gateway_node: &LightningNodeType) -> (Fixtures, LightningFixtures) {
    let fixtures = Fixtures::new_primary(1, DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_rpc());
    let fixtures = fixtures.with_module(0, LightningClientGen, LightningGen, ln_params);
    let lightning_fixtures = LightningFixtures::new(gateway_node).await;
    (fixtures, lightning_fixtures)
}

async fn new_gateway_client(
    fed: &FederationTest,
    gateway_lnrpc: Arc<dyn ILnRpcClient>,
) -> anyhow::Result<Client> {
    let mut registry = ClientModuleGenRegistry::new();
    registry.attach(DummyClientGen);
    registry.attach(GatewayClientGen {
        lightning_client: gateway_lnrpc.clone(),
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        timelock_delta: 10,
        mint_channel_id: 1,
    });
    let gateway = fed.new_gateway_client(registry).await;
    {
        let fake_api = Url::from_str("http://127.0.0.1:8175").unwrap();
        let fake_route_hints = Vec::new();
        let register_op = gateway
            .register_with_federation(fake_api, fake_route_hints, GW_ANNOUNCEMENT_TTL)
            .await?;
        let mut register_sub = gateway
            .gateway_subscribe_register(register_op)
            .await?
            .into_stream();
        assert_matches!(
            register_sub.ok().await?,
            GatewayExtRegisterStates::Registering
        );
        assert_matches!(register_sub.ok().await?, GatewayExtRegisterStates::Success);
    }

    Ok(gateway)
}

async fn gateway_test<B>(
    f: impl FnOnce(
            Fixtures,
            Arc<dyn LightningTest>,
            FederationTest,
            Client, // User Client
            Client, // Gateway Client
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = anyhow::Result<()>>,
{
    let gateway_nodes = [LightningNodeType::Cln, LightningNodeType::Lnd];
    for gateway_node in gateway_nodes {
        debug!("Running tests with {gateway_node:?}");
        let (fixtures, lightning_fixtures) = fixtures(&gateway_node).await;
        let fed = fixtures.new_fed().await;
        let user_client = fed.new_client().await;

        let gateway =
            new_gateway_client(&fed, lightning_fixtures.gateway_lightning_client.clone()).await?;
        f(
            fixtures,
            lightning_fixtures.other_lightning_client,
            fed,
            user_client,
            gateway,
        )
        .await?;
    }
    Ok(())
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_valid_invoice() -> anyhow::Result<()> {
    gateway_test(
        |_, other_lightning_client, _, user_client, gateway| async move {
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
        |_, other_lightning_client, _, user_client, gateway| async move {
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
async fn test_gateway_client_pay_invalid_invoice() -> anyhow::Result<()> {
    gateway_test(
        |_, other_lightning_client, _, user_client, gateway| async move {
            // Print money for user client
            let (_, outpoint) = user_client.print_money(sats(1000)).await?;
            user_client.receive_money(outpoint).await?;
            assert_eq!(user_client.get_balance().await, sats(1000));

            // Create test invalid invoice
            let invoice = other_lightning_client
                .invalid_invoice(sats(250), None)
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
                    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled);

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
    gateway_test(|_, _, _, user_client, gateway| async move {
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
    gateway_test(|_, _, _, _, gateway| async move {
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
            Err(e) => assert_eq!(e.to_string(), "Timeout".to_string()),
        }

        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_no_funds() -> anyhow::Result<()> {
    gateway_test(|_, _, _, user_client, gateway| async move {
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
        |_, other_lightning_client, _, user_client, gateway| async move {
            // Print money for gateway client
            let initial_gateway_balance = sats(1000);
            let (_, outpoint) = gateway.print_money(initial_gateway_balance).await?;
            gateway.receive_money(outpoint).await?;
            assert_eq!(gateway.get_balance().await, sats(1000));

            // Create test invoice
            let invoice = other_lightning_client.invalid_invoice(sats(250), None)?;

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
                GatewayExtReceiveStates::RefundSuccess(refund_outpoint) => {
                    // Assert that the gateway got it's refund
                    gateway.receive_money(refund_outpoint).await?;
                    assert_eq!(initial_gateway_balance, gateway.get_balance().await);
                }
                _ => panic!("Gateway receive state machine entered unexpected state"),
            }

            Ok(())
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_register_with_federation() -> anyhow::Result<()> {
    let (fixtures, lightning_fixtures) = fixtures(&LightningNodeType::Cln).await;
    let fed = fixtures.new_fed().await;

    let mut registry = ClientModuleGenRegistry::new();
    registry.attach(DummyClientGen);
    registry.attach(GatewayClientGen {
        lightning_client: lightning_fixtures.gateway_lightning_client.clone(),
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        timelock_delta: 10,
        mint_channel_id: 1,
    });
    let gateway = fed.new_gateway_client(registry).await;
    {
        let mut fake_api = Url::from_str("http://127.0.0.1:8175").unwrap();
        let fake_route_hints = Vec::new();
        // Register with the federation with a low TTL to verify it will re-register
        let register_op = gateway
            .register_with_federation(fake_api, fake_route_hints.clone(), Duration::from_secs(10))
            .await?;
        let mut register_sub = gateway
            .gateway_subscribe_register(register_op)
            .await?
            .into_stream();
        assert_matches!(
            register_sub.ok().await?,
            GatewayExtRegisterStates::Registering
        );
        assert_matches!(register_sub.ok().await?, GatewayExtRegisterStates::Success);
        // Verify that the gateway client will re-register after the TTL
        assert_matches!(
            register_sub.ok().await?,
            GatewayExtRegisterStates::Registering
        );
        assert_matches!(register_sub.ok().await?, GatewayExtRegisterStates::Success);

        // Update the URI for the gateway then re-register
        fake_api = Url::from_str("http://127.0.0.1:8176").unwrap();

        let reregister_op = gateway
            .register_with_federation(fake_api, fake_route_hints, GW_ANNOUNCEMENT_TTL)
            .await?;

        let mut reregister_sub = gateway
            .gateway_subscribe_register(reregister_op)
            .await?
            .into_stream();
        // Verify that the re-register was successful
        assert_matches!(
            reregister_sub.ok().await?,
            GatewayExtRegisterStates::Registering
        );
        assert_matches!(
            reregister_sub.ok().await?,
            GatewayExtRegisterStates::Success
        );

        // Verify that the previous register state machine expired and moved to `Done`
        assert_matches!(register_sub.ok().await?, GatewayExtRegisterStates::Done);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_set_lightning_invoice_expiry() -> anyhow::Result<()> {
    gateway_test(|_, other_lightning_client, _, _, _| async move {
        let invoice = other_lightning_client
            .invoice(sats(1000), 600.into())
            .await
            .unwrap();
        assert_eq!(invoice.expiry_time(), Duration::from_secs(600));
        Ok(())
    })
    .await
}
