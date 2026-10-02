use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_client::OperationId;
use fedimint_core::module::AmountUnit;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, Secp256k1};
use fedimint_core::util::NextOrPending;
use fedimint_core::{Amount, anyhow};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_escrow_client::api::EscrowFederationApi;
use fedimint_escrow_client::frost::dkg::DkgResult;
use fedimint_escrow_client::frost::session::{FrostDkgSessionRecord, FrostParticipant, SessionId};
use fedimint_escrow_client::frost::transport::file::FileTransport;
use fedimint_escrow_client::frost::transport::iroh::{DKG_ALPN, IrohDkgTransport};
use fedimint_escrow_client::input::EscrowInputSMState;
use fedimint_escrow_client::output::EscrowOutputSMState;
use fedimint_escrow_client::{EscrowClientInit, EscrowClientModule};
use fedimint_escrow_common::{
    EscrowContract, EscrowId, EscrowMessage, EscrowStatus, FallbackPolicy, GET_PENDING_FEE_DOMAIN,
    GetPendinFeeParams, Outcome, compute_escrow_message, compute_proof_message,
};
use fedimint_escrow_server::EscrowInit;
use fedimint_testing::fixtures::Fixtures;
use frost_secp256k1_tr::round1::commit as Round1Commit;
use frost_secp256k1_tr::round2::sign as Round2Sign;
use frost_secp256k1_tr::{Signature as FrostSignature, SigningPackage, aggregate};
use iroh::{Endpoint, RelayMode, SecretKey};
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

async fn bind_endpoint() -> Endpoint {
    Endpoint::builder()
        .secret_key(SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
        .alpns(vec![DKG_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("bind endpoint")
}

fn sign(signers: &[&DkgResult], msg: &[u8]) -> Result<FrostSignature, frost_secp256k1_tr::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for s in signers {
        let id = *s.key_package.identifier();
        let (n, c) = Round1Commit(s.key_package.signing_share(), &mut OsRng);
        nonces.insert(id, n);
        commitments.insert(id, c);
    }

    let signing_package = SigningPackage::new(commitments, msg);

    let mut shares = BTreeMap::new();
    for s in signers {
        let id = *s.key_package.identifier();
        let share = Round2Sign(&signing_package, &nonces[&id], &s.key_package)?;
        shares.insert(id, share);
    }

    aggregate(&signing_package, &shares, &signers[0].pubkey_package)
}

#[allow(clippy::too_many_arguments)]
async fn create_test_escrow(
    funder_escrow: &EscrowClientModule,
    recipient_keypair: Keypair,
    arbiter_keypair: Keypair,
    amount: Amount,
    arbiter_fee: Amount,
    timeout: Duration,
    resolution_timeout: Duration,
    default_fallback: FallbackPolicy,
) -> anyhow::Result<(OperationId, EscrowId)> {
    let result = funder_escrow
        .create_escrow(
            recipient_keypair.public_key(),
            arbiter_keypair.public_key(),
            arbiter_fee,
            amount,
            timeout,
            resolution_timeout,
            default_fallback,
        )
        .await?;
    let mut stream = funder_escrow
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
async fn test_funder_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let recipient_keypair = recipient_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(4000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();

    let resolution_message = contract.resolution_message(Outcome::Release);
    let msg_bytes = compute_escrow_message(&resolution_message);
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let funder_sig = Secp256k1::new().sign_schnorr(&msg, &funder_escrow.keypair);

    let resolve_op = recipient_escrow
        .resolve_escrow(escrow_id, funder_sig)
        .await?;

    let mut resolve_stream = recipient_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Released);

    for _i in 0..10 {
        let balance = recipient_client.get_balance_for_btc().await?;

        if balance > Amount::ZERO {
            break;
        }

        fedimint_core::task::sleep_in_test(
            "waiting for balance update",
            Duration::from_millis(500),
        )
        .await;
    }

    assert!(recipient_client.get_balance_for_btc().await? > Amount::ZERO);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let recipient_keypair = recipient_escrow.keypair;
    let arbiter_keypair = arbiter_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(2),
        Duration::from_secs(100),
        FallbackPolicy::Refund,
    )
    .await?;

    fedimint_core::task::sleep_in_test("waiting for the escrow timeout", Duration::from_secs(4))
        .await;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();

    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);

    let resolve_op = funder_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig)
        .await?;

    let mut resolve_stream = funder_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Refunded);

    assert!(funder_client.get_balance_for_btc().await? > Amount::ZERO);

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
    let (recipient_client, funder_client) = fed.two_clients().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let recipient_keypair = recipient_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);

    let result = funder_escrow
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
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_funder_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let recipient_keypair = recipient_escrow.keypair;
    let arbiter_keypair = arbiter_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();

    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Refund));
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let bad_funder_sig = Secp256k1::new().sign_schnorr(&msg, &funder_escrow.keypair);

    let operation_id = recipient_escrow
        .resolve_escrow(escrow_id, bad_funder_sig)
        .await?;
    let mut resolve_stream = recipient_escrow
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert!(matches!(
        resolve_stream.ok().await?,
        EscrowInputSMState::Failed { .. }
    ));

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let recipient_keypair = recipient_escrow.keypair;
    let arbiter_keypair = arbiter_escrow.keypair;

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(2),
        Duration::from_secs(100),
        FallbackPolicy::Refund,
    )
    .await?;

    // wait for timeout
    fedimint_core::task::sleep_in_test("waiting for escrow timeout", Duration::from_secs(4)).await;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();

    let resolution_message = contract.resolution_message(Outcome::Refund);
    let msg_bytes = compute_escrow_message(&resolution_message);
    let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
    let arbiter_sig = Secp256k1::new().sign_schnorr(&msg, &arbiter_escrow.keypair);

    let operation_id = recipient_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Release, arbiter_sig)
        .await?;
    let mut resolve_stream = recipient_escrow
        .subscribe_escrow_resolution(operation_id)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert!(matches!(
        resolve_stream.ok().await?,
        EscrowInputSMState::Failed { .. }
    ));

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_contract_status_updated_after_funder_release() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let _ = fund_client(&funder_client, Amount::from_sats(2000)).await;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);

    let (_op_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.keypair,
        arbiter_keypair,
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    // before resolution: Active
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    let msg_bytes = compute_escrow_message(&contract.resolution_message(Outcome::Release));
    let funder_sig = secp.sign_schnorr(&Message::from_digest(msg_bytes), &funder_escrow.keypair);

    let resolve_op = recipient_escrow
        .resolve_escrow(escrow_id, funder_sig)
        .await?;
    let mut stream = recipient_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Released);

    // after resolution: Released
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Released);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_consortium_dkg_then_escrow() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;

    let n = 4;
    let mut arbiter_clients = Vec::new();
    for _ in 0..n {
        arbiter_clients.push(fed.new_client().await);
    }
    let (recipient_client, funder_client) = fed.two_clients().await;

    let arbiters: Vec<_> = arbiter_clients
        .iter()
        .map(|c| c.get_first_module::<EscrowClientModule>().unwrap())
        .collect();

    // every arbiter get its FROST identity from its own escrow key
    let participants = arbiters
        .iter()
        .map(|a| a.get_frost_identity())
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut endpoints = Vec::new();
    let mut peers = BTreeMap::new();
    for p in &participants {
        let endpoint = bind_endpoint().await;
        peers.insert(p.identifier, endpoint.node_addr().await?);
        endpoints.push(endpoint);
    }

    // the session id is the same for everyone, the transport needs it up front
    let record = FrostDkgSessionRecord::new(
        participants[0].clone(),
        participants.clone(),
        arbiter_clients[0].federation_id(),
        arbiters[0].client_ctx.module_db(),
    )
    .await?;

    let session_id = record.session_id;
    assert_eq!(record.max_signers, 4);
    assert_eq!(record.min_signers, 3);

    // all arbiters run the DKG at the same time, starting at different moments
    let runs = arbiters.iter().enumerate().map(|(i, arbiter)| {
        let endpoint = endpoints[i].clone();
        let peers = peers.clone();
        let participants = participants.clone();
        async move {
            sleep(Duration::from_millis(200 * i as u64)).await;
            let transport = IrohDkgTransport::from_endpoint(endpoint, session_id, peers);
            arbiter
                .create_arbiter_consortium_with_custom_transport(participants, transport)
                .await
                .expect("dkg failed")
        }
    });
    let results = futures::future::join_all(runs).await;

    // everyone ends with the same group key
    let group_key = results[0].pubkey_package.verifying_key();
    for r in &results {
        assert_eq!(
            r.pubkey_package.verifying_key().serialize(),
            group_key.serialize()
        );
    }

    // the result is stored in every arbiter's own database
    for arbiter in &arbiters {
        let state = serde_json::to_value(arbiter.get_consortium_state(session_id).await?)?;
        assert!(state["session"]["state"]["Finalized"].is_object());
        assert_eq!(state["record"]["min_signers"], 3);
    }

    // running again after it finished returns the same key and needs no peers
    let again = arbiters[0]
        .create_arbiter_consortium_with_custom_transport(
            participants.clone(),
            IrohDkgTransport::from_endpoint(bind_endpoint().await, session_id, peers.clone()),
        )
        .await
        .expect("second run failed");
    assert_eq!(
        again.pubkey_package.verifying_key().serialize(),
        group_key.serialize()
    );

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let dummy = funder_client.get_first_module::<DummyClientModule>()?;
    dummy
        .mock_receive(Amount::from_sats(2000), AmountUnit::BITCOIN)
        .await?;

    let arbiter_pubkey = PublicKey::from_slice(&group_key.serialize().expect("serialize"))?;
    let created = funder_escrow
        .create_escrow(
            recipient_escrow.keypair.public_key(),
            arbiter_pubkey,
            Amount::from_sats(20),
            Amount::from_sats(1000),
            Duration::from_secs(3600),
            Duration::from_secs(4000),
            FallbackPolicy::Refund,
        )
        .await?;
    let mut stream = funder_escrow
        .subscribe_escrow_creation(created.operation_id)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Active);

    let contract = funder_escrow
        .get_contract(created.escrow_id)
        .await?
        .unwrap();
    assert_eq!(contract.arbiter_key, arbiter_pubkey);

    let msg = compute_escrow_message(&contract.resolution_message(Outcome::Refund));
    let signers: Vec<&DkgResult> = results.iter().take(3).collect();
    let sig = sign(&signers, &msg).expect("signing failed");
    assert!(group_key.verify(&msg, &sig).is_ok());

    let signers: Vec<&DkgResult> = results.iter().take(2).collect();
    if let Ok(sig) = sign(&signers, &msg) {
        assert!(group_key.verify(&msg, &sig).is_err());
    }

    let sig_bytes = sig.serialize().expect("serialize");
    assert!(Signature::from_slice(&sig_bytes).is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_consortium_rejects_invalid_participants() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let escrow = client.get_first_module::<EscrowClientModule>()?;
    let me = escrow.get_frost_identity()?;

    let secp = Secp256k1::new();
    let others: Vec<FrostParticipant> = (0..3)
        .map(|_| {
            let kp = Keypair::new(&secp, &mut OsRng);
            FrostParticipant::from_pubkey(kp.public_key()).unwrap()
        })
        .collect();

    let session_id = SessionId([1u8; 32]);

    let transport = FileTransport::new(&session_id).await?;
    let result = escrow
        .create_arbiter_consortium_with_custom_transport(vec![me.clone()], transport)
        .await;
    assert!(result.is_err(), "a consortium of 1 must be rejected");

    let transport = FileTransport::new(&session_id).await?;
    let result = escrow
        .create_arbiter_consortium_with_custom_transport(others, transport)
        .await;
    assert!(result.is_err(), "I must be in the participant list");

    Ok(())
}
