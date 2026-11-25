use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_client::{Account, OperationId};
use fedimint_core::Amount;
use fedimint_core::module::AmountUnit;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, Secp256k1};
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_escrow_client::api::EscrowFederationApi;
use fedimint_escrow_client::frost::dkg::DkgResult;
use fedimint_escrow_client::frost::session::{FrostDkgSessionRecord, FrostParticipant, SessionId};
use fedimint_escrow_client::frost::transport::file::FileTransport;
use fedimint_escrow_client::frost::transport::iroh::{DKG_ALPN, IrohDkgTransport};
use fedimint_escrow_client::input::EscrowInputSMState;
use fedimint_escrow_client::output::EscrowOutputSMState;
use fedimint_escrow_client::{EscrowClientInit, EscrowClientModule, ExternalKey, SigningKind};
use fedimint_escrow_common::{
    DelegationAction, EscrowContract, EscrowId, EscrowStatus, FallbackPolicy, Outcome,
    compute_escrow_message,
};
use fedimint_escrow_server::EscrowInit;
use fedimint_testing::fixtures::Fixtures;
use frost_secp256k1_tr::round1::commit as Round1Commit;
use frost_secp256k1_tr::round2::sign as Round2Sign;
use frost_secp256k1_tr::{Signature as FrostSignature, SigningPackage, aggregate};
use iroh::{Endpoint, RelayMode, SecretKey};
use rand::rngs::OsRng;

// The federation clock only moves once a minute (votes are rounded to 60s),
// and a resolution period can't be shorter than 10 minutes. A timeout of 61s
// is therefore reached at the second minute boundary and can never already be
// in the past when the contract is created.
const DISPUTE_TIMEOUT: Duration = Duration::from_secs(61);
const RESOLUTION_PERIOD: Duration = Duration::from_secs(600);
const WAIT_FOR_TIMEOUT: Duration = Duration::from_secs(200);

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(EscrowClientInit, EscrowInit)
}

async fn fund_client(
    client: &fedimint_client::ClientHandleArc,
    amount: Amount,
) -> anyhow::Result<()> {
    let dummy = client.get_first_module::<DummyClientModule>()?;
    dummy.mock_receive(amount, AmountUnit::BITCOIN).await;

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

fn random_pubkey() -> PublicKey {
    Keypair::new(&Secp256k1::new(), &mut OsRng).public_key()
}

async fn wait_for_federation_time(
    escrow: &EscrowClientModule,
    target: u64,
    max_wait: Duration,
) -> anyhow::Result<()> {
    for _ in 0..max_wait.as_secs() * 2 {
        if escrow.client_ctx.module_api().consensus_unix_time().await? >= target {
            return Ok(());
        }

        fedimint_core::task::sleep_in_test(
            "waiting for the federation time",
            Duration::from_millis(500),
        )
        .await;
    }

    anyhow::bail!("federation time did not reach {target} within {max_wait:?}")
}

async fn wait_for_balance(
    client: &fedimint_client::ClientHandleArc,
    min: Amount,
) -> anyhow::Result<()> {
    for _ in 0..40 {
        if client.get_balance_for_btc(Account::Primary).await? >= min {
            return Ok(());
        }

        fedimint_core::task::sleep_in_test(
            "waiting for balance update",
            Duration::from_millis(500),
        )
        .await;
    }

    anyhow::bail!("balance did not reach {min:?}")
}

/// What the app does with a digest: sign it as it is, no hashing
fn sign_digest(key: &Keypair, digest: &str) -> Signature {
    let digest: [u8; 32] = fedimint_core::hex::decode(digest)
        .expect("digest is hex")
        .try_into()
        .expect("digest is 32 bytes");
    Secp256k1::new().sign_schnorr(&Message::from_digest(digest), key)
}

/// Ask the client what to sign and sign it with a key the client doesn't hold
async fn sign_kind(
    escrow: &EscrowClientModule,
    escrow_id: EscrowId,
    kind: SigningKind,
    key: &Keypair,
) -> anyhow::Result<Signature> {
    let request = escrow.digest_to_sign(escrow_id, kind).await?;
    Ok(sign_digest(key, &request.digest))
}

/// The key of the app, with a delegation made for the client that will submit
async fn external_key(
    submitting: &EscrowClientModule,
    escrow_id: EscrowId,
    key: &Keypair,
    action: DelegationAction,
) -> anyhow::Result<ExternalKey> {
    let kind = SigningKind::Delegation {
        action,
        actor: key.public_key(),
    };
    Ok(ExternalKey {
        pubkey: key.public_key(),
        delegation: sign_kind(submitting, escrow_id, kind, key).await?,
        engage_message: None,
    })
}

async fn create_app_key_escrow(
    creator: &EscrowClientModule,
    funder_key: PublicKey,
    recipient_key: PublicKey,
    arbiter_key: PublicKey,
    fee_key: PublicKey,
    timeout: Duration,
) -> anyhow::Result<EscrowId> {
    wait_for_federation_time(creator, 1, Duration::from_secs(60)).await?;

    let result = creator
        .create_escrow(
            Some(funder_key),
            recipient_key,
            arbiter_key,
            Amount::from_sats(20),
            Amount::from_sats(1000),
            timeout,
            vec![fee_key],
            RESOLUTION_PERIOD,
            FallbackPolicy::Refund,
        )
        .await?;
    let mut stream = creator
        .subscribe_escrow_creation(result.operation_id)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Creating);
    assert_eq!(stream.ok().await?, EscrowOutputSMState::Active);

    Ok(result.escrow_id)
}

#[allow(clippy::too_many_arguments)]
async fn create_test_escrow(
    funder_escrow: &EscrowClientModule,
    recipient_key: PublicKey,
    arbiter_key: PublicKey,
    fee_keys: Vec<PublicKey>,
    amount: Amount,
    arbiter_fee: Amount,
    timeout: Duration,
    resolution_period: Duration,
    default_fallback: FallbackPolicy,
) -> anyhow::Result<(OperationId, EscrowId)> {
    // until the first votes are in the federation time is 0
    wait_for_federation_time(funder_escrow, 1, Duration::from_secs(60)).await?;

    let result = funder_escrow
        .create_escrow(
            None,
            recipient_key,
            arbiter_key,
            arbiter_fee,
            amount,
            timeout,
            fee_keys,
            resolution_period,
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

fn disputed_until(contract: &EscrowContract) -> u64 {
    match &contract.status {
        EscrowStatus::Disputed { resolve_by, .. } => *resolve_by,
        other => panic!("expected a disputed contract, got {other}"),
    }
}

/// The client checks every action with the shared rules before it submits, so
/// bad input comes back as an error from the call itself.
fn assert_rejected(result: anyhow::Result<OperationId>, expected: &str) {
    let err = result.expect_err("the client should have rejected this");
    assert!(
        err.to_string().contains(expected),
        "unexpected error: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_funder_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_keypair = Keypair::new(&Secp256k1::new(), &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![random_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    let funder_sig = funder_escrow.sign_message(contract.resolution_message(Outcome::Release))?;

    let resolve_op = recipient_escrow
        .resolve_escrow(escrow_id, funder_sig, None)
        .await?;
    let mut resolve_stream = recipient_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();

    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Released);

    wait_for_balance(&recipient_client, Amount::from_msats(1)).await?;

    assert!(funder_escrow.get_claim_pool(escrow_id).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_only_recipient_can_submit_release() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_keypair = Keypair::new(&Secp256k1::new(), &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![random_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    let funder_sig = funder_escrow.sign_message(contract.resolution_message(Outcome::Release))?;

    // the funder cannot collect its own release: the call is taken as a refund by
    // the funder, and the funder's release signature is not the recipient's refund
    assert_rejected(
        funder_escrow
            .resolve_escrow(escrow_id, funder_sig, None)
            .await,
        "Invalid signature",
    );
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    let resolve_op = recipient_escrow
        .resolve_escrow(escrow_id, funder_sig, None)
        .await?;
    let mut resolve_stream = recipient_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(resolve_stream.ok().await?, EscrowInputSMState::Released);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_funder_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_keypair = Keypair::new(&Secp256k1::new(), &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![random_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();

    // the funder signed Refund, which is not a release
    let refund_sig = funder_escrow.sign_message(contract.resolution_message(Outcome::Refund))?;
    assert_rejected(
        recipient_escrow
            .resolve_escrow(escrow_id, refund_sig, None)
            .await,
        "Invalid signature",
    );

    // the recipient signed the release instead of the funder
    let recipient_sig =
        recipient_escrow.sign_message(contract.resolution_message(Outcome::Release))?;
    assert_rejected(
        recipient_escrow
            .resolve_escrow(escrow_id, recipient_sig, None)
            .await,
        "Invalid signature",
    );

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
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_keypair = Keypair::new(&Secp256k1::new(), &mut OsRng);

    let (_op_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![random_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    let funder_sig = funder_escrow.sign_message(contract.resolution_message(Outcome::Release))?;
    let resolve_op = recipient_escrow
        .resolve_escrow(escrow_id, funder_sig, None)
        .await?;
    let mut stream = recipient_escrow
        .subscribe_escrow_resolution(resolve_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Released);

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(contract.status, EscrowStatus::Released(_)));

    assert_rejected(
        recipient_escrow
            .resolve_escrow(escrow_id, funder_sig, None)
            .await,
        "already resolved",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_should_not_act_before_timeout() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![random_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(9999),
        Duration::from_secs(3000),
        FallbackPolicy::Refund,
    )
    .await?;

    // nobody can bring in the arbiter before the timeout
    assert_rejected(
        funder_escrow.engage_arbiter(escrow_id, None).await,
        "Timeout not reached",
    );
    assert_rejected(
        recipient_escrow.engage_arbiter(escrow_id, None).await,
        "Timeout not reached",
    );

    // a ruling or a fallback needs a disputed contract
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);
    assert_rejected(
        funder_escrow
            .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig, None)
            .await,
        "Contract not disputed",
    );
    assert_rejected(
        funder_escrow.trigger_fallback(escrow_id, None).await,
        "Contract not disputed",
    );

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_resolution() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_a_client = fed.new_client().await;
    let arbiter_b_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_a_escrow = arbiter_a_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_b_escrow = arbiter_b_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);
    let amount = Amount::from_sats(1000);
    let arbiter_fee = Amount::from_sats(20);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![
            arbiter_a_escrow.arbiter_fee_pubkey(),
            arbiter_b_escrow.arbiter_fee_pubkey(),
        ],
        amount,
        arbiter_fee,
        DISPUTE_TIMEOUT,
        RESOLUTION_PERIOD,
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    wait_for_federation_time(funder_escrow.module, contract.timeout, WAIT_FOR_TIMEOUT).await?;

    let engage_op = funder_escrow.engage_arbiter(escrow_id, None).await?;
    let mut stream = funder_escrow
        .subscribe_escrow_resolution(engage_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Disputed);

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(
        contract.status,
        EscrowStatus::Disputed { swaps_used: 0, .. }
    ));
    assert!(disputed_until(&contract) >= contract.timeout + contract.resolution_period);

    // release signature is useless after contract goes in disputed state
    let release_sig = funder_escrow.sign_message(contract.resolution_message(Outcome::Release))?;
    assert_rejected(
        recipient_escrow
            .resolve_escrow(escrow_id, release_sig, None)
            .await,
        "under dispute",
    );

    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);
    let ruling_op = recipient_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig, None)
        .await?;
    let mut stream = recipient_escrow
        .subscribe_escrow_resolution(ruling_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Refunded);

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(contract.status, EscrowStatus::Refunded(_)));

    // nobody is paid yet: the funder gets amount - fee, each fee key half the fee
    let pool = funder_escrow.get_claim_pool(escrow_id).await?.unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (contract.funder_key, amount - arbiter_fee),
            (arbiter_a_escrow.arbiter_fee_pubkey(), Amount::from_sats(10)),
            (arbiter_b_escrow.arbiter_fee_pubkey(), Amount::from_sats(10)),
        ]
    );

    // the same ruling cannot be applied twice
    assert_rejected(
        funder_escrow
            .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig, None)
            .await,
        "already resolved",
    );

    let balance_before = funder_client.get_balance_for_btc(Account::Primary).await?;
    let claim_op = funder_escrow.claim_payout(escrow_id, None).await?;
    let mut stream = funder_escrow
        .subscribe_claim_payout(claim_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Claimed);
    wait_for_balance(&funder_client, balance_before + Amount::from_msats(1)).await?;

    let pool = funder_escrow.get_claim_pool(escrow_id).await?.unwrap();
    assert_eq!(pool.claimer.len(), 2);

    // each arbiter claims its own share of the fee
    for (client, escrow) in [
        (&arbiter_a_client, &arbiter_a_escrow),
        (&arbiter_b_client, &arbiter_b_escrow),
    ] {
        let claim_op = escrow.claim_payout(escrow_id, None).await?;
        let mut stream = escrow.subscribe_claim_payout(claim_op).await?.into_stream();
        assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
        assert_eq!(stream.ok().await?, EscrowInputSMState::Claimed);
        wait_for_balance(client, Amount::from_msats(1)).await?;
    }

    assert!(funder_escrow.get_claim_pool(escrow_id).await?.is_none());
    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(contract.status, EscrowStatus::Refunded(_)));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_arbiter_signature_with_invalid_inputs() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;
    let stranger_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let stranger_escrow = stranger_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let arbiter_keypair = Keypair::new(&secp, &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![arbiter_escrow.arbiter_fee_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        DISPUTE_TIMEOUT,
        RESOLUTION_PERIOD,
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    wait_for_federation_time(funder_escrow.module, contract.timeout, WAIT_FOR_TIMEOUT).await?;

    let engage_op = recipient_escrow.engage_arbiter(escrow_id, None).await?;
    let mut stream = recipient_escrow
        .subscribe_escrow_resolution(engage_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Disputed);

    // the arbiter signed Refund but the ruling says Release
    let sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_keypair);
    assert_rejected(
        recipient_escrow
            .submit_arbiter_decision(escrow_id, Outcome::Release, sig, None)
            .await,
        "Invalid signature",
    );

    // signed by someone who is not the arbiter
    let impostor = Keypair::new(&secp, &mut OsRng);
    let sig = sign_arbiter_decision(&secp, &contract, Outcome::Release, &impostor);
    assert_rejected(
        recipient_escrow
            .submit_arbiter_decision(escrow_id, Outcome::Release, sig, None)
            .await,
        "Invalid signature",
    );

    let sig = sign_arbiter_decision(&secp, &contract, Outcome::Release, &arbiter_keypair);
    assert_rejected(
        stranger_escrow
            .submit_arbiter_decision(escrow_id, Outcome::Release, sig, None)
            .await,
        "Key is not part of this escrow",
    );

    let bad_split = Outcome::Split {
        funder_split_bps: 6_000,
        recipient_split_bps: 3_000,
    };
    let sig = sign_arbiter_decision(&secp, &contract, bad_split, &arbiter_keypair);
    assert_rejected(
        recipient_escrow
            .submit_arbiter_decision(escrow_id, bad_split, sig, None)
            .await,
        "Invalid split ratio",
    );

    let still_disputed = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(
        still_disputed.status,
        EscrowStatus::Disputed { swaps_used: 0, .. }
    ));
    assert!(funder_escrow.get_claim_pool(escrow_id).await?.is_none());

    let split = Outcome::Split {
        funder_split_bps: 2_500,
        recipient_split_bps: 7_500,
    };
    let sig = sign_arbiter_decision(&secp, &contract, split, &arbiter_keypair);
    let ruling_op = arbiter_escrow
        .submit_arbiter_decision(escrow_id, split, sig, None)
        .await?;
    let mut stream = arbiter_escrow
        .subscribe_escrow_resolution(ruling_op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Split);

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(contract.status, EscrowStatus::Split(_)));

    let pool = funder_escrow.get_claim_pool(escrow_id).await?.unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (contract.funder_key, Amount::from_sats(245)),
            (contract.recipient_key, Amount::from_sats(735)),
            (arbiter_escrow.arbiter_fee_pubkey(), Amount::from_sats(20)),
        ]
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_contract_is_listed_for_every_key_in_it() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (recipient_client, funder_client) = fed.two_clients().await;
    let arbiter_client = fed.new_client().await;
    let stranger_client = fed.new_client().await;

    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let recipient_escrow = recipient_client.get_first_module::<EscrowClientModule>()?;
    let arbiter_escrow = arbiter_client.get_first_module::<EscrowClientModule>()?;
    let stranger_escrow = stranger_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_keypair = Keypair::new(&Secp256k1::new(), &mut OsRng);

    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_keypair.public_key(),
        vec![arbiter_escrow.arbiter_fee_pubkey()],
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        FallbackPolicy::Refund,
    )
    .await?;

    for (escrow, key) in [
        (&funder_escrow, funder_escrow.escrow_pubkey()),
        (&recipient_escrow, recipient_escrow.escrow_pubkey()),
        (&arbiter_escrow, arbiter_escrow.arbiter_fee_pubkey()),
    ] {
        let listed = escrow.list_contracts(Some(key), None, None).await?;
        assert!(listed.iter().any(|c| c.escrow_id == escrow_id));
    }

    let listed = stranger_escrow.list_contracts(None, None, None).await?;
    assert!(!listed.iter().any(|c| c.escrow_id == escrow_id));
    let listed = arbiter_escrow.list_contracts(None, None, None).await?;
    assert!(!listed.iter().any(|c| c.escrow_id == escrow_id));

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

    for arbiter in &arbiters {
        let state = serde_json::to_value(arbiter.get_consortium_state(session_id).await?)?;
        assert_eq!(state["stage"], "Finalized");
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
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let arbiter_pubkey = PublicKey::from_slice(&group_key.serialize().expect("serialize"))?;
    let fee_keys: Vec<PublicKey> = arbiters.iter().map(|a| a.arbiter_fee_pubkey()).collect();
    let (_operation_id, escrow_id) = create_test_escrow(
        funder_escrow.module,
        recipient_escrow.escrow_pubkey(),
        arbiter_pubkey,
        fee_keys.clone(),
        Amount::from_sats(1000),
        Amount::from_sats(20),
        Duration::from_secs(3600),
        Duration::from_secs(4000),
        FallbackPolicy::Refund,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.arbiter_key, arbiter_pubkey);
    assert_eq!(contract.arbiter_fee_key, fee_keys);

    // every consortium member finds the escrow through its fee key
    for arbiter in &arbiters {
        let listed = arbiter
            .list_contracts(Some(arbiter.arbiter_fee_pubkey()), None, None)
            .await?;
        assert!(listed.iter().any(|c| c.escrow_id == escrow_id));
    }

    let msg = compute_escrow_message(&contract.resolution_message(Outcome::Refund));
    let signers: Vec<&DkgResult> = results.iter().take(3).collect();
    let sig = sign(&signers, &msg).expect("signing failed");
    assert!(group_key.verify(&msg, &sig).is_ok());

    let signers: Vec<&DkgResult> = results.iter().take(2).collect();
    if let Ok(sig) = sign(&signers, &msg) {
        assert!(group_key.verify(&msg, &sig).is_err());
    }

    let schnorr_sig = Signature::from_slice(&sig.serialize().expect("serialize"))
        .expect("a taproot FROST signature is 64 bytes");
    fedimint_core::secp256k1::global::SECP256K1
        .verify_schnorr(
            &schnorr_sig,
            &Message::from_digest(msg),
            &arbiter_pubkey.x_only_public_key().0,
        )
        .expect("the federation would accept this signature");

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

#[tokio::test(flavor = "multi_thread")]
async fn test_delegated_release_by_a_new_client() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let funder_client = fed.new_client().await;
    let new_client = fed.new_client().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let new_escrow = new_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    // the keys live in the app, no client has them
    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng);
    let recipient_key = Keypair::new(&secp, &mut OsRng);
    let arbiter_key = Keypair::new(&secp, &mut OsRng);

    let escrow_id = create_app_key_escrow(
        funder_escrow.module,
        funder_key.public_key(),
        recipient_key.public_key(),
        arbiter_key.public_key(),
        random_pubkey(),
        Duration::from_secs(3600),
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.funder_key, funder_key.public_key());

    // the app of the funder signs the release
    let release_sig = sign_kind(
        new_escrow.module,
        escrow_id,
        SigningKind::Resolution(Outcome::Release),
        &funder_key,
    )
    .await?;

    // a client that never saw the escrow submits it for the recipient's key
    let external = external_key(
        new_escrow.module,
        escrow_id,
        &recipient_key,
        DelegationAction::FunderRelease,
    )
    .await?;
    let op = new_escrow
        .resolve_escrow(escrow_id, release_sig, Some(external))
        .await?;
    let mut stream = new_escrow
        .subscribe_escrow_resolution(op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Released);

    // the ecash goes to the client that submitted
    wait_for_balance(&new_client, Amount::from_msats(1)).await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert!(matches!(contract.status, EscrowStatus::Released(_)));
    assert!(funder_escrow.get_claim_pool(escrow_id).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delegated_dispute_and_claim() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let funder_client = fed.new_client().await;
    let engage_client = fed.new_client().await;
    let ruling_client = fed.new_client().await;
    let claim_client = fed.new_client().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let engage_escrow = engage_client.get_first_module::<EscrowClientModule>()?;
    let ruling_escrow = ruling_client.get_first_module::<EscrowClientModule>()?;
    let claim_escrow = claim_client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng);
    let recipient_key = Keypair::new(&secp, &mut OsRng);
    let arbiter_key = Keypair::new(&secp, &mut OsRng);
    let fee_key = Keypair::new(&secp, &mut OsRng);

    let escrow_id = create_app_key_escrow(
        funder_escrow.module,
        funder_key.public_key(),
        recipient_key.public_key(),
        arbiter_key.public_key(),
        fee_key.public_key(),
        DISPUTE_TIMEOUT,
    )
    .await?;

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    wait_for_federation_time(funder_escrow.module, contract.timeout, WAIT_FOR_TIMEOUT).await?;

    let mut external = external_key(
        engage_escrow.module,
        escrow_id,
        &funder_key,
        DelegationAction::ArbiterEngaged,
    )
    .await?;
    external.engage_message = Some(
        sign_kind(
            engage_escrow.module,
            escrow_id,
            SigningKind::Engage,
            &funder_key,
        )
        .await?,
    );
    let op = engage_escrow
        .engage_arbiter(escrow_id, Some(external))
        .await?;
    let mut stream = engage_escrow
        .subscribe_escrow_resolution(op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Disputed);

    // the arbiter rules for the funder and the app of the recipient submits it
    let arbiter_sig = sign_arbiter_decision(&secp, &contract, Outcome::Refund, &arbiter_key);
    let external = external_key(
        ruling_escrow.module,
        escrow_id,
        &recipient_key,
        DelegationAction::ArbiterOutcome,
    )
    .await?;
    let op = ruling_escrow
        .submit_arbiter_decision(escrow_id, Outcome::Refund, arbiter_sig, Some(external))
        .await?;
    let mut stream = ruling_escrow
        .subscribe_escrow_resolution(op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Refunded);

    let pool = funder_escrow.get_claim_pool(escrow_id).await?.unwrap();
    assert_eq!(
        pool.claimer,
        vec![
            (funder_key.public_key(), Amount::from_sats(980)),
            (fee_key.public_key(), Amount::from_sats(20)),
        ]
    );

    // one client claims for both keys, each key signs its own delegation
    for key in [&funder_key, &fee_key] {
        let external = external_key(
            claim_escrow.module,
            escrow_id,
            key,
            DelegationAction::ClaimPayout,
        )
        .await?;
        let op = claim_escrow.claim_payout(escrow_id, Some(external)).await?;
        let mut stream = claim_escrow.subscribe_claim_payout(op).await?.into_stream();
        assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
        assert_eq!(stream.ok().await?, EscrowInputSMState::Claimed);
    }
    wait_for_balance(&claim_client, Amount::from_msats(1)).await?;

    assert!(funder_escrow.get_claim_pool(escrow_id).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delegation_only_works_for_its_own_client_key_and_action() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let funder_client = fed.new_client().await;
    let client_a = fed.new_client().await;
    let client_b = fed.new_client().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let escrow_a = client_a.get_first_module::<EscrowClientModule>()?;
    let escrow_b = client_b.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng);
    let recipient_key = Keypair::new(&secp, &mut OsRng);
    let stranger_key = Keypair::new(&secp, &mut OsRng);

    let escrow_id = create_app_key_escrow(
        funder_escrow.module,
        funder_key.public_key(),
        recipient_key.public_key(),
        random_pubkey(),
        random_pubkey(),
        Duration::from_secs(3600),
    )
    .await?;

    let release_sig = sign_kind(
        escrow_a.module,
        escrow_id,
        SigningKind::Resolution(Outcome::Release),
        &funder_key,
    )
    .await?;

    // made for the submitter key of client a
    let for_a = external_key(
        escrow_a.module,
        escrow_id,
        &recipient_key,
        DelegationAction::FunderRelease,
    )
    .await?;

    // client b has another submitter key, the delegation doesn't name it
    assert_rejected(
        escrow_b
            .resolve_escrow(escrow_id, release_sig, Some(for_a.clone()))
            .await,
        "Invalid delegation",
    );

    // the delegation is signed by a key that is not the recipient
    let by_stranger = ExternalKey {
        delegation: sign_kind(
            escrow_a.module,
            escrow_id,
            SigningKind::Delegation {
                action: DelegationAction::FunderRelease,
                actor: recipient_key.public_key(),
            },
            &stranger_key,
        )
        .await?,
        ..for_a.clone()
    };
    assert_rejected(
        escrow_a
            .resolve_escrow(escrow_id, release_sig, Some(by_stranger))
            .await,
        "Invalid delegation",
    );

    // a delegation for another action
    let wrong_action = external_key(
        escrow_a.module,
        escrow_id,
        &recipient_key,
        DelegationAction::ClaimPayout,
    )
    .await?;
    assert_rejected(
        escrow_a
            .resolve_escrow(escrow_id, release_sig, Some(wrong_action))
            .await,
        "Invalid delegation",
    );

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    // the right delegation still works for the client it was made for
    let op = escrow_a
        .resolve_escrow(escrow_id, release_sig, Some(for_a))
        .await?;
    let mut stream = escrow_a
        .subscribe_escrow_resolution(op)
        .await?
        .into_stream();
    assert_eq!(stream.ok().await?, EscrowInputSMState::Pending);
    assert_eq!(stream.ok().await?, EscrowInputSMState::Released);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_external_key_must_be_part_of_the_contract() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let funder_client = fed.new_client().await;
    let client = fed.new_client().await;
    let funder_escrow = funder_client.get_first_module::<EscrowClientModule>()?;
    let escrow = client.get_first_module::<EscrowClientModule>()?;
    fund_client(&funder_client, Amount::from_sats(2000)).await?;

    let secp = Secp256k1::new();
    let funder_key = Keypair::new(&secp, &mut OsRng);
    let recipient_key = Keypair::new(&secp, &mut OsRng);
    let stranger_key = Keypair::new(&secp, &mut OsRng);

    let escrow_id = create_app_key_escrow(
        funder_escrow.module,
        funder_key.public_key(),
        recipient_key.public_key(),
        random_pubkey(),
        random_pubkey(),
        Duration::from_secs(3600),
    )
    .await?;

    // the client only gives out a digest for keys of the escrow
    let err = escrow
        .digest_to_sign(
            escrow_id,
            SigningKind::Delegation {
                action: DelegationAction::FunderRelease,
                actor: stranger_key.public_key(),
            },
        )
        .await
        .expect_err("a stranger has no digest");
    assert!(
        err.to_string()
            .contains("actor is not a key of this escrow")
    );

    let bad_split = Outcome::Split {
        funder_split_bps: 6_000,
        recipient_split_bps: 3_000,
    };
    let err = escrow
        .digest_to_sign(escrow_id, SigningKind::Resolution(bad_split))
        .await
        .expect_err("a split must add up");
    assert!(err.to_string().contains("Invalid resolution outcome"));

    // a stranger can't resolve, even with a delegation of its own
    let release_sig = sign_kind(
        escrow.module,
        escrow_id,
        SigningKind::Resolution(Outcome::Release),
        &funder_key,
    )
    .await?;
    let stranger = ExternalKey {
        pubkey: stranger_key.public_key(),
        delegation: sign_kind(
            escrow.module,
            escrow_id,
            SigningKind::Delegation {
                action: DelegationAction::FunderRelease,
                actor: recipient_key.public_key(),
            },
            &stranger_key,
        )
        .await?,
        engage_message: None,
    };
    assert_rejected(
        escrow
            .resolve_escrow(escrow_id, release_sig, Some(stranger))
            .await,
        "only the recipient or the funder",
    );

    // engaging the arbiter needs the engage signature as well
    let without_engage = external_key(
        escrow.module,
        escrow_id,
        &recipient_key,
        DelegationAction::ArbiterEngaged,
    )
    .await?;
    assert_rejected(
        escrow.engage_arbiter(escrow_id, Some(without_engage)).await,
        "the engage signature is missing",
    );

    let contract = funder_escrow.get_contract(escrow_id).await?.unwrap();
    assert_eq!(contract.status, EscrowStatus::Active);

    Ok(())
}
