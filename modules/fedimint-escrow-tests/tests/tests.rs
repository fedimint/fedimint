use std::time::Duration;

use fedimint_core::module::AmountUnit;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::util::NextOrPending;
use fedimint_core::{Amount, anyhow};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_escrow_client::input::EscrowInputSMState;
use fedimint_escrow_client::output::EscrowOutputSMState;
use fedimint_escrow_client::{EscrowClientInit, EscrowClientModule};
use fedimint_escrow_common::{Outcome, compute_resolution_message};
use fedimint_escrow_server::EscrowInit;
use fedimint_testing::fixtures::Fixtures;
use rand::rngs::OsRng;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(EscrowClientInit, EscrowInit)
}

async fn fund_client(
    client: &fedimint_client::ClientHandleArc,
    amount: Amount,
) -> anyhow::Result<()> {
    let dummy = client.get_first_module::<DummyClientModule>()?;
    dummy.mock_receive(amount, AmountUnit::BITCOIN).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_buyer_resolution() -> Result<(), anyhow::Error> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.two_clients().await;
    let (seller_client, buyer_client) = client;
    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let seller_keypair = Keypair::new(&secp, &mut OsRng);
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let (operation_id, escrow_id) = buyer_escrow
        .create_escrow(
            seller_keypair.public_key(),
            arbiter_keypair.public_key(),
            Amount::from_sats(20),
            Amount::from_sats(1000),
            Duration::from_secs(3600),
        )
        .await?;

    let mut contract_stream = buyer_escrow
        .subscribe_escrow_creation(operation_id)
        .await?
        .into_stream();

    assert_eq!(contract_stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(contract_stream.ok().await?, EscrowOutputSMState::Active);

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    let buyer_sig = buyer_escrow.sign_release_message(escrow_id, &contract);

    let resolve_op = seller_escrow.resolve_escrow(escrow_id, buyer_sig).await?;

    let mut resolve_stream = seller_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Released);

    assert!(buyer_escrow.get_contract(escrow_id).await?.is_none());

    assert!(seller_client.get_balance_for_btc().await? > Amount::ZERO);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_resolution() -> Result<(), anyhow::Error> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.two_clients().await;
    let (seller_client, buyer_client) = client;
    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let _seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let seller_keypair = Keypair::new(&secp, &mut OsRng);
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let (operation_id, escrow_id) = buyer_escrow
        .create_escrow(
            seller_keypair.public_key(),
            arbiter_keypair.public_key(),
            Amount::from_sats(20),
            Amount::from_sats(1000),
            Duration::from_secs(3600),
        )
        .await?;

    let mut contract_stream = buyer_escrow
        .subscribe_escrow_creation(operation_id)
        .await?
        .into_stream();

    assert_eq!(contract_stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(contract_stream.ok().await?, EscrowOutputSMState::Active);

    fedimint_core::task::sleep_in_test("waiting for the escrow timeout", Duration::from_secs(2000))
        .await;

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();

    let msg_bytes = compute_resolution_message(
        &contract.federation_id,
        &escrow_id,
        &Outcome::Refund,
        &contract.contract_hash,
    );
    let msg = Message::from_digest(msg_bytes);
    let arbiter_sig = secp.sign_schnorr(&msg, &arbiter_keypair);

    let resolve_op = buyer_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await?;

    let mut resolve_stream = buyer_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Refunded);

    assert!(buyer_escrow.get_contract(escrow_id).await?.is_none());
    assert!(buyer_client.get_balance_for_btc().await? > Amount::ZERO);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_should_not_act_before_timeout() -> anyhow::Result<(), anyhow::Error> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let _ = fund_client(&client, Amount::from_sats(1000)).await;

    let escrow = client.get_first_module::<EscrowClientModule>()?;
    let secp = Secp256k1::new();
    let seller_keypair = Keypair::new(&secp, &mut OsRng);
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);

    let (_operation_id, escrow_id) = escrow
        .create_escrow(
            seller_keypair.public_key(),
            arbiter_keypair.public_key(),
            Amount::from_sats(10),
            Amount::from_sats(500),
            Duration::from_secs(9999),
        )
        .await?;

    let contract = escrow.get_contract(escrow_id).await?.unwrap();
    let msg_bytes = compute_resolution_message(
        &contract.federation_id,
        &escrow_id,
        &Outcome::Refund,
        &contract.contract_hash,
    );
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let arbiter_sig = secp.sign_schnorr(&msg, &arbiter_keypair);

    let resolve_op = escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await?;

    let mut stream = escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert!(matches!(
        stream.ok().await?,
        EscrowInputSMState::Failed { .. }
    ));

    Ok(())
}
