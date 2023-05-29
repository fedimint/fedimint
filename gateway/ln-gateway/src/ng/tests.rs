use std::str::FromStr;
use std::sync::Arc;

use assert_matches::assert_matches;
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::sm::OperationId;
use fedimint_client::transaction::{ClientOutput, TransactionBuilder};
use fedimint_client::Client;
use fedimint_core::core::IntoDynInstance;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount, OutPoint, TransactionId};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{
    LightningClientExt, LightningClientGen, LightningClientModule, LightningClientStateMachines,
    LightningMeta,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::{EncryptedPreimage, Preimage};
use fedimint_ln_common::LightningOutput;
use fedimint_ln_server::LightningGen;
use fedimint_mint_client::MintClientGen;
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::WalletClientGen;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::ng::receive::Htlc;
use ln_gateway::ng::{GatewayClientExt, GatewayClientGen, GatewayExtReceiveStates};
use rand::rngs::OsRng;
use url::Url;

pub fn rng() -> OsRng {
    OsRng
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

pub fn secp() -> secp256k1::Secp256k1<secp256k1::All> {
    bitcoin::secp256k1::Secp256k1::new()
}

fn fixtures() -> Fixtures {
    // TODO: Remove dependency on mint (legacy gw client)
    let fixtures = Fixtures::new_primary(1, MintClientGen, MintGen, MintGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_rpc());
    fixtures
        .with_module(3, DummyClientGen, DummyGen, DummyGenParams::default())
        .with_module(0, LightningClientGen, LightningGen, ln_params)
}

async fn new_gateway_client(fed: &FederationTest, fixtures: &Fixtures) -> anyhow::Result<Client> {
    let mut registry = ClientModuleGenRegistry::new();
    registry.attach(MintClientGen);
    registry.attach(WalletClientGen);
    registry.attach(GatewayClientGen {
        lightning_client: fixtures.lightning().1,
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        timelock_delta: 10,
        api: Url::from_str("http://127.0.0.1:8175").unwrap(),
        mint_channel_id: 1,
    });
    registry.attach(DummyClientGen);
    let gateway = fed.new_gateway_client(registry).await;
    gateway.register_with_federation().await?;
    Ok(gateway)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_valid_htlc() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;
    let gateway = new_gateway_client(&fed, &fixtures).await?;

    // Print money for gateway client
    let initial_gateway_balance = sats(1000);
    let (print_op, outpoint) = gateway.print_money(initial_gateway_balance).await?;
    gateway
        .await_primary_module_output(print_op, outpoint)
        .await?;

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
        incoming_chan_id: 1,
        htlc_id: 1,
    };
    let intercept_op = gateway.gateway_intercept_htlc(htlc).await?;
    let mut intercept_sub = gateway
        .gateway_subscribe_ln_receive(intercept_op)
        .await?
        .into_stream();
    assert_eq!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::HtlcIntercepted
    );
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
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_offer_does_not_exist() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let gateway = new_gateway_client(&fed, &fixtures).await?;

    // Create HTLC that doesn't correspond to an offer in the federation
    let htlc = Htlc {
        payment_hash: sha256(&[15]),
        incoming_amount_msat: Amount::from_msats(100),
        outgoing_amount_msat: Amount::from_msats(100),
        incoming_expiry: u32::MAX,
        short_channel_id: 1,
        incoming_chan_id: 1,
        htlc_id: 1,
    };
    let intercept_op = gateway.gateway_intercept_htlc(htlc).await?;
    let mut intercept_sub = gateway
        .gateway_subscribe_ln_receive(intercept_op)
        .await?
        .into_stream();
    assert_eq!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::HtlcIntercepted
    );
    assert_matches!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::InvalidHtlc { .. }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_no_funds() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;
    let gateway = new_gateway_client(&fed, &fixtures).await?;

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
        incoming_chan_id: 1,
        htlc_id: 1,
    };

    // Attempt to route an HTLC while the gateway has no funds
    let intercept_op = gateway.gateway_intercept_htlc(htlc).await?;
    let mut intercept_sub = gateway
        .gateway_subscribe_ln_receive(intercept_op)
        .await?
        .into_stream();
    assert_eq!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::HtlcIntercepted
    );
    assert_matches!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::FundingFailed { .. }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_intercept_htlc_invalid_offer() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;
    let gateway = new_gateway_client(&fed, &fixtures).await?;

    // Print money for gateway client
    let initial_gateway_balance = sats(1000);
    let (print_op, outpoint) = gateway.print_money(initial_gateway_balance).await?;
    gateway
        .await_primary_module_output(print_op, outpoint)
        .await?;

    // Create test invoice
    let invoice = fixtures
        .lightning()
        .0
        .invalid_invoice(sats(250), None)
        .await?;

    // Create offer with bad preimage
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
    let states: Vec<LightningClientStateMachines> = vec![];
    let state_machines = Arc::new(move |_txid: TransactionId, _input_idx: u64| states.clone());
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
        incoming_chan_id: 1,
        htlc_id: 1,
    };

    let intercept_op = gateway.gateway_intercept_htlc(htlc).await?;
    let mut intercept_sub = gateway
        .gateway_subscribe_ln_receive(intercept_op)
        .await?
        .into_stream();
    assert_eq!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::HtlcIntercepted
    );
    assert_matches!(intercept_sub.ok().await?, GatewayExtReceiveStates::Funding);
    assert_matches!(
        intercept_sub.ok().await?,
        GatewayExtReceiveStates::RefundSuccess { .. }
    );

    // Gateway got it's refund
    assert_eq!(initial_gateway_balance, gateway.get_balance().await);

    Ok(())
}
