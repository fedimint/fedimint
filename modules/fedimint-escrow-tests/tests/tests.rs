use std::time::Duration;

use fedimint_client::OperationId;
use fedimint_core::bitcoin::hashes::{Hash, HashEngine, sha256};
use fedimint_core::db::DatabaseValue;
use fedimint_core::module::AmountUnit;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::util::NextOrPending;
use fedimint_core::{Amount, anyhow};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_escrow_client::api::EscrowFederationApi;
use fedimint_escrow_client::input::EscrowInputSMState;
use fedimint_escrow_client::output::EscrowOutputSMState;
use fedimint_escrow_client::{EscrowClientInit, EscrowClientModule};
use fedimint_escrow_common::{EscrowContract, EscrowId, Outcome, compute_resolution_message};
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

async fn create_test_escrow(
    buyer_escrow: &EscrowClientModule,
    seller_keypair: Keypair,
    arbiter_keypair: Keypair,
    amount: Amount,
    arbiter_fee: Amount,
    timeout: Duration,
) -> anyhow::Result<(OperationId, EscrowId)> {
    let (operation_id, escrow_id) = buyer_escrow
        .create_escrow(
            seller_keypair.public_key(),
            arbiter_keypair.public_key(),
            arbiter_fee,
            amount,
            timeout,
        )
        .await?;
    let mut stream = buyer_escrow
        .subscribe_escrow_creation(operation_id)
        .await?
        .into_stream();

    assert_eq!(stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Active);

    Ok((operation_id, escrow_id))
}

fn sign_arbiter_decision(
    secp: &Secp256k1<fedimint_core::secp256k1::All>,
    contract: &EscrowContract,
    escrow_id: EscrowId,
    outcome: Outcome,
    arbiter_keypair: &Keypair,
) -> fedimint_core::secp256k1::schnorr::Signature {
    let msg_bytes = compute_resolution_message(
        &contract.federation_id,
        &escrow_id,
        &outcome,
        &contract.contract_hash,
    );

    let msg = Message::from_digest(msg_bytes);

    secp.sign_schnorr(&msg, arbiter_keypair)
}

fn sign_fee_claim(
    secp: &Secp256k1<fedimint_core::secp256k1::All>,
    contract: &EscrowContract,
    arbiter_keypair: &Keypair,
) -> fedimint_core::secp256k1::schnorr::Signature {
    let mut engine = sha256::HashEngine::default();

    engine.input(b"arbiter_fee_claim");
    engine.input(&contract.escrow_id.0);
    engine.input(&contract.arbiter_fee.to_bytes());

    let msg = Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array());

    secp.sign_schnorr(&msg, arbiter_keypair)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_buyer_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;
    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let seller_keypair = seller_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        buyer_escrow.module,
        seller_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
    )
    .await?;

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
async fn test_arbiter_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let seller_keypair = seller_escrow.keypair;
    let arbiter_keypair = arbiter_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        buyer_escrow.module,
        seller_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(2),
    )
    .await?;

    fedimint_core::task::sleep_in_test("waiting for the escrow timeout", Duration::from_secs(4))
        .await;

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();

    let arbiter_sig = sign_arbiter_decision(
        &secp,
        &contract,
        escrow_id,
        Outcome::Refund,
        &arbiter_keypair,
    );

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

    // claiming arbiter's fee
    let arbiter_signature = sign_fee_claim(&secp, &contract, &arbiter_keypair);

    let balance_before = arbiter_client.get_balance_for_btc().await?;

    let claim_op = arbiter_escrow
        .claim_arbiter_fee(escrow_id, arbiter_signature)
        .await?;

    let mut resolve_stream = arbiter_escrow
        .subscribe_fee_claim(claim_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::FeeClaiming);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::FeeClaimed);

    for _i in 0..10 {
        let balance = arbiter_client.get_balance_for_btc().await?;

        if balance >= balance_before + contract.arbiter_fee {
            break;
        }

        fedimint_core::task::sleep_in_test(
            "waiting for balance update",
            Duration::from_millis(500),
        )
        .await;
    }

    let balance_after = arbiter_client.get_balance_for_btc().await?;

    assert_eq!(balance_after, balance_before + contract.arbiter_fee);
    assert!(
        arbiter_escrow
            .api
            .get_pending_arbiter_fee(escrow_id)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_should_not_act_before_timeout() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;

    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let seller_keypair = seller_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        buyer_escrow.module,
        seller_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
    )
    .await?;

    let contract = seller_escrow.get_contract(escrow_id).await?.unwrap();
    let arbiter_sig = sign_arbiter_decision(
        &secp,
        &contract,
        escrow_id,
        Outcome::Refund,
        &arbiter_keypair,
    );

    let resolve_op = buyer_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await?;

    let mut stream = buyer_escrow
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
