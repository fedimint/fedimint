use std::time::Duration;

use fedimint_client::OperationId;
use fedimint_core::module::AmountUnit;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::util::NextOrPending;
use fedimint_core::{Amount, anyhow};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_escrow_client::api::EscrowFederationApi;
use fedimint_escrow_client::input::EscrowInputSMState;
use fedimint_escrow_client::output::EscrowOutputSMState;
use fedimint_escrow_client::{EscrowClientInit, EscrowClientModule};
use fedimint_escrow_common::{
    EscrowContract, EscrowId, EscrowMessage, EscrowStatus, GET_PENDING_FEE_DOMAIN,
    GetPendinFeeParams, Outcome, compute_escrow_message, compute_proof_message,
};
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
    let result = buyer_escrow
        .create_escrow(
            seller_keypair.public_key(),
            arbiter_keypair.public_key(),
            arbiter_fee,
            amount,
            timeout,
        )
        .await?;
    let mut stream = buyer_escrow
        .subscribe_escrow_creation(result.operation_id)
        .await?
        .into_stream();

    assert_eq!(stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Active);

    Ok((result.operation_id, result.escrow_id))
}

fn sign_arbiter_decision(
    secp: &Secp256k1<fedimint_core::secp256k1::All>,
    contract: &EscrowContract,
    outcome: Outcome,
    arbiter_keypair: &Keypair,
) -> Signature {
    let resolution_message = contract.resolution_message(outcome);

    let msg_bytes = compute_escrow_message(&resolution_message);
    let msg = Message::from_digest(msg_bytes);

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

    let resolution_message = contract.resolution_message(Outcome::Release);
    let msg_bytes = compute_escrow_message(&resolution_message);
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let buyer_sig = Secp256k1::new().sign_schnorr(&msg, &buyer_escrow.keypair);

    let resolve_op = seller_escrow.resolve_escrow(escrow_id, buyer_sig).await?;

    let mut resolve_stream = seller_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Released);

    for _i in 0..10 {
        let balance = seller_client.get_balance_for_btc().await?;

        if balance > Amount::ZERO {
            break;
        }

        fedimint_core::task::sleep_in_test(
            "waiting for balance update",
            Duration::from_millis(500),
        )
        .await;
    }

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

    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);

    let resolve_op = buyer_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await?;

    let mut resolve_stream = buyer_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Refunded);

    assert!(buyer_client.get_balance_for_btc().await? > Amount::ZERO);

    // claiming arbiter's fee
    let arbiter_message = EscrowMessage::ArbiterFeeClaim {
        escrow_id: contract.escrow_id,
        fee_amount: contract.arbiter_fee,
    };
    let arbiter_signature = arbiter_escrow.sign_message(arbiter_message)?;

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

    let secp = Secp256k1::new();
    let msg_bytes = compute_proof_message(
        GET_PENDING_FEE_DOMAIN.as_bytes(),
        &escrow_id.0,
        &arbiter_keypair.public_key(),
        Some(&arbiter_client.federation_id()),
    );
    let get_arbiter_fee_signature =
        secp.sign_schnorr(&Message::from_digest(msg_bytes), &arbiter_keypair);

    assert_eq!(balance_after, balance_before + contract.arbiter_fee);
    assert!(
        arbiter_escrow
            .api
            .get_pending_arbiter_fee(GetPendinFeeParams {
                escrow_id,
                sign: get_arbiter_fee_signature,
                pubkey: arbiter_escrow.keypair.public_key()
            })
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

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);

    let result = buyer_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("arbiter cannot act before timeout")
    );

    // contract untouched
    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_buyer_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let seller_keypair = seller_escrow.keypair;
    let arbiter_keypair = arbiter_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        buyer_escrow.module,
        seller_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
    )
    .await?;

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();

    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Refund));
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let bad_buyer_sig = Secp256k1::new().sign_schnorr(&msg, &buyer_escrow.keypair);

    let operation_id = seller_escrow
        .resolve_escrow(escrow_id, bad_buyer_sig)
        .await?;
    let mut resolve_stream = seller_escrow
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert!(matches!(
        resolve_stream.ok().await?,
        EscrowInputSMState::Failed { .. }
    ));

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

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

    // wait for timeout
    fedimint_core::task::sleep_in_test("waiting for escrow timeout", Duration::from_secs(4)).await;

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();

    let resolution_message = contract.resolution_message(Outcome::Refund);
    let msg_bytes = compute_escrow_message(&resolution_message);
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let arbiter_sig = Secp256k1::new().sign_schnorr(&msg, &arbiter_escrow.keypair);

    let operation_id = seller_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Release, arbiter_sig)
        .await?;
    let mut resolve_stream = seller_escrow
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert!(matches!(
        resolve_stream.ok().await?,
        EscrowInputSMState::Failed { .. }
    ));

    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_contract_status_updated_after_buyer_release() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (seller_client, buyer_client) = fed.two_clients().await;
    let buyer_escrow = buyer_client.get_first_module::<EscrowClientModule>()?;
    let seller_escrow = seller_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&buyer_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);

    let (_op_id, escrow_id) = create_test_escrow(
        buyer_escrow.module,
        seller_escrow.keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
    )
    .await?;

    // before resolution: Active
    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Release));
    let buyer_sig = secp.sign_schnorr(&Message::from_digest(msg_bytes), &buyer_escrow.keypair);

    let resolve_op = seller_escrow.resolve_escrow(escrow_id, buyer_sig).await?;
    let mut stream = seller_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Released);

    // after resolution: Released
    let contract = buyer_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Released);

    Ok(())
}
