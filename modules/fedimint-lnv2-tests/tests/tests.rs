mod mock;

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_stream::stream;
use bitcoin::hashes::sha256;
use fedimint_client::db::CachedApiVersionSetKey;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::sm::executor::InactiveStateKeyDb;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_client_module::module::ClientModule;
use fedimint_client_module::sm::InactiveStateMeta;
use fedimint_client_module::sm::executor::InactiveStateKey;
use fedimint_core::base32::{FEDIMINT_PREFIX, decode_prefixed};
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, Scalar, SecretKey};
use fedimint_core::task::sleep_in_test;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{NextOrPending as _, SafeUrl, backoff_util, retry};
use fedimint_core::{Amount, BitcoinHash, OutPoint, TransactionId, msats, sats, secp256k1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_lnurl::parse_lnurl;
use fedimint_lnv2_client::db::IncomingContractStreamIndexKey;
use fedimint_lnv2_client::events::{
    ReceivePaymentEvent, SendPaymentEvent, SendPaymentStatus, SendPaymentUpdateEvent,
};
use fedimint_lnv2_client::{
    FinalReceiveOperationState, InvoiceSendStatus, LightningClientInit, LightningClientModule,
    LightningOperationMeta, LnurlReceiveOperationMeta, ReceiveOperationState, ReceiveSMCommon,
    ReceiveSMState, ReceiveStateMachine, RecoveredReceiveOperationMeta, SendOperationState,
    SendPaymentError,
};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::lnurl::LnurlRequest;
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, KIND, LightningInput, LightningInputV0, LightningOutput,
    LightningOutputV0, OutgoingWitness, tweak,
};
use fedimint_lnv2_server::LightningInit;
use fedimint_logging::LOG_TEST;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt;
use serde_json::Value;
use tpe::AggregatePublicKey;
use tracing::warn;

use crate::mock::{MOCK_INVOICE_PREIMAGE, MockGatewayConnection};

#[derive(Debug, PartialEq, Eq)]
enum LnEvent {
    Send(SendPaymentEvent),
    SendUpdate(SendPaymentUpdateEvent),
    Receive(ReceivePaymentEvent),
}

fn ln_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = LnEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_ln_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_ln_event(entry: &EventLogEntry) -> Option<LnEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(LnEvent::Send);
    }

    if entry.kind == SendPaymentUpdateEvent::KIND {
        return entry.to_event().map(LnEvent::SendUpdate);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(LnEvent::Receive);
    }

    None
}

fn lightning_client_init() -> LightningClientInit {
    LightningClientInit {
        gateway_conn: Some(Arc::new(MockGatewayConnection::default())),
        custom_meta_fn: Arc::new(|| {
            serde_json::json!({
                "timestamp": chrono::Utc::now().timestamp(),
            })
        }),
    }
}

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);

    fixtures.with_module(lightning_client_init(), LightningInit)
}

#[tokio::test(flavor = "multi_thread")]
async fn can_pay_external_invoice_exactly_once() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let gateway_api = mock::gateway();
    let invoice = mock::payable_invoice();

    let mut events = pin!(ln_event_stream(&client));

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .get_invoice_send_status(&invoice)
            .await?,
        InvoiceSendStatus::NotAttempted,
    );

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(invoice.clone(), Some(gateway_api.clone()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(invoice.clone(), Some(gateway_api.clone()), Value::Null)
            .await,
        Err(SendPaymentError::DuplicatePaymentAttempt(operation_id)),
    );

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);
    assert_eq!(
        sub.ok().await?,
        SendOperationState::Success(MOCK_INVOICE_PREIMAGE)
    );

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(
        update.status,
        SendPaymentStatus::Success(MOCK_INVOICE_PREIMAGE)
    );

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(invoice.clone(), Some(gateway_api), Value::Null)
            .await,
        Err(SendPaymentError::DuplicatePaymentAttempt(operation_id)),
    );

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .get_invoice_send_status(&invoice)
            .await?,
        InvoiceSendStatus::Succeeded(operation_id),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_failed_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let invoice = mock::unpayable_invoice();

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(invoice.clone(), Some(mock::gateway()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);
    assert_eq!(sub.ok().await?, SendOperationState::Refunding);
    assert_eq!(sub.ok().await?, SendOperationState::Refunded);

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(update.status, SendPaymentStatus::Refunded);

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .get_invoice_send_status(&invoice)
            .await?,
        InvoiceSendStatus::Failed(operation_id),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unilateral_refund_of_outgoing_contracts() -> anyhow::Result<()> {
    if Fixtures::is_real_test() {
        warn!(
            target: LOG_TEST,
            "Skipping test as mining so many blocks is too slow in real bitcoind setup"
        );
        return Ok(());
    }

    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let invoice = mock::crash_invoice();

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(invoice.clone(), Some(mock::gateway()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);

    fixtures.bitcoin().mine_blocks(1440 + 12).await;

    assert_eq!(sub.ok().await?, SendOperationState::Refunding);
    assert_eq!(sub.ok().await?, SendOperationState::Refunded);

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(update.status, SendPaymentStatus::Refunded);

    // Verify that fees were paid, which is always the case for LNv2
    let operation_fees = client
        .get_operation_fees(operation_id)
        .await
        .expect("Operation exists")
        .expect("Fee data is present for new operations");
    assert_eq!(operation_fees.get_bitcoin().msats, 2000);
    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .get_invoice_send_status(&invoice)
            .await?,
        InvoiceSendStatus::Failed(operation_id),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn claiming_outgoing_contract_triggers_success() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give client initial balance
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .send(mock::crash_invoice(), Some(mock::gateway()), Value::Null)
        .await?;

    let Some(LnEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_send_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, SendOperationState::Funding);
    assert_eq!(sub.ok().await?, SendOperationState::Funded);

    let operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    let (contract, txid) = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Send(meta) => (meta.contract, meta.change_outpoint_range.txid),
        LightningOperationMeta::Receive(..) => panic!("Operation Meta is a Receive variant"),
        LightningOperationMeta::LnurlReceive(..) => {
            panic!("Operation Meta is a LnurlReceive variant")
        }
        LightningOperationMeta::RecoveredReceive(..) => {
            panic!("Operation Meta is a RecoveredReceive variant")
        }
    };

    let client_input = ClientInput::<LightningInput> {
        input: LightningInput::V0(LightningInputV0::Outgoing(
            OutPoint { txid, out_idx: 0 },
            OutgoingWitness::Claim(MOCK_INVOICE_PREIMAGE),
        )),
        amounts: Amounts::new_bitcoin(contract.amount),
        keys: vec![mock::gateway_keypair()],
    };

    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .unwrap();

    client
        .finalize_and_submit_transaction(
            OperationId::new_random(),
            "Claiming Outgoing Contract",
            |_| (),
            TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![client_input]).into_dyn(lnv2_module_id),
            ),
        )
        .await
        .expect("Failed to claim outgoing contract");

    assert_eq!(
        sub.ok().await?,
        SendOperationState::Success(MOCK_INVOICE_PREIMAGE)
    );

    let Some(LnEvent::SendUpdate(update)) = events.next().await else {
        panic!("Expected SendUpdate event");
    };
    assert_eq!(update.operation_id, operation_id);
    assert_eq!(
        update.status,
        SendPaymentStatus::Success(MOCK_INVOICE_PREIMAGE)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_operation_expires() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    let op = client
        .get_first_module::<LightningClientModule>()?
        .receive(
            Amount::from_sats(1000),
            5, // receive operation expires in 5 seconds
            Bolt11InvoiceDescription::Direct(String::new()),
            Some(mock::gateway()),
            Value::Null,
        )
        .await?
        .1;

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_receive_operation_state_updates(op)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, ReceiveOperationState::Pending);
    assert_eq!(sub.ok().await?, ReceiveOperationState::Expired);

    Ok(())
}

/// Builds an incoming contract addressed to `recipient_pk`, the way a sender
/// does: the claim key is derived from the recipient's published static key and
/// a fresh ephemeral key, so anyone who knows that static key can address one.
fn incoming_contract_for(
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    amount: Amount,
) -> IncomingContract {
    let (ephemeral_tweak, ephemeral_pk) = tweak::generate(recipient_pk);

    let encryption_seed = ephemeral_tweak
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let preimage = encryption_seed
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let claim_pk = recipient_pk
        .mul_tweak(
            secp256k1::SECP256K1,
            &Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"),
        )
        .expect("Tweak is valid");

    IncomingContract::new(
        aggregate_pk,
        encryption_seed,
        preimage,
        PaymentImage::Hash(preimage.consensus_hash()),
        amount,
        duration_since_epoch().as_secs().saturating_add(3600),
        claim_pk,
        mock::gateway_keypair().public_key(),
        ephemeral_pk,
    )
}

/// A contract worth less than the fee to claim it must be left alone rather
/// than driven into a claim that cannot be funded.
///
/// Anyone can address an incoming contract to a published lnurl key, and
/// consensus funds one of any amount, so the amount is entirely the sender's
/// choice. The client used to start a claim for it regardless; with nothing in
/// the wallet to cover the shortfall the claim panicked inside the state
/// machine executor, and since nothing commits it panicked again on every
/// restart — a wallet bricked for the price of a few sats.
///
/// The victim here holds no balance at all, which is the state a fresh wallet
/// publishing an address is in.
#[tokio::test(flavor = "multi_thread")]
async fn unsolicited_dust_contract_does_not_wedge_the_client() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let victim = fed.new_client().await;
    let attacker = fed.new_client().await;

    attacker
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    // Everything the attacker needs is in what the victim publishes.
    let lnurl = victim
        .get_first_module::<LightningClientModule>()?
        .generate_lnurl(
            SafeUrl::parse("https://recurring.xyz/").expect("Valid Url"),
            Some(mock::gateway()),
        )
        .await?;
    let url = parse_lnurl(&lnurl).expect("Generated lnurl decodes");
    let payload = url.rsplit("pay/").next().expect("Url carries a payload");
    let request = decode_prefixed::<LnurlRequest>(FEDIMINT_PREFIX, payload)?;

    let dust = incoming_contract_for(request.recipient_pk, request.aggregate_pk, msats(1));
    fund_incoming_contract(&attacker, dust.clone()).await?;

    // A second, claimable contract behind the dust one. Waiting for its operation
    // proves the victim processed past the dust rather than dying on it: the
    // lnurl task handles the stream in order.
    let claimable = incoming_contract_for(
        request.recipient_pk,
        request.aggregate_pk,
        Amount::from_sats(100),
    );
    fund_incoming_contract(&attacker, claimable.clone()).await?;

    let claimable_operation = OperationId::from_encodable(&claimable);
    retry(
        "waiting for the claimable contract to be picked up",
        backoff_util::aggressive_backoff(),
        || async {
            victim
                .operation_log()
                .get_operation(claimable_operation)
                .await
                .context("Claimable contract was not picked up")
        },
    )
    .await?;

    // The dust never became an operation at all.
    assert!(
        victim
            .operation_log()
            .get_operation(OperationId::from_encodable(&dust))
            .await
            .is_none(),
        "Dust contract should have been ignored"
    );

    // And the client is still running: it claimed the contract that was worth it.
    assert_eq!(
        victim
            .get_first_module::<LightningClientModule>()?
            .await_final_receive_operation_state(claimable_operation)
            .await?,
        FinalReceiveOperationState::Claimed
    );

    Ok(())
}

/// Funds an incoming contract like a gateway would, waits for the funding
/// transaction to be accepted and returns the contract's funding outpoint.
async fn fund_incoming_contract(
    client: &ClientHandleArc,
    contract: IncomingContract,
) -> anyhow::Result<OutPoint> {
    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    let funding_operation_id = OperationId::new_random();

    let funding_range = client
        .finalize_and_submit_transaction(
            funding_operation_id,
            "Funding Incoming Contract",
            |_| (),
            TransactionBuilder::new().with_outputs(
                ClientOutputBundle::new_no_sm(vec![ClientOutput {
                    output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
                    amounts: Amounts::new_bitcoin(contract.commitment.amount),
                }])
                .into_dyn(lnv2_module_id),
            ),
        )
        .await?;

    client
        .transaction_updates(funding_operation_id)
        .await
        .await_tx_accepted(funding_range.txid())
        .await
        .map_err(|e| anyhow::anyhow!("Funding transaction was rejected: {e}"))?;

    // The lightning output is the first output of the funding transaction;
    // the primary module's change outputs follow it.
    Ok(OutPoint {
        txid: funding_range.txid(),
        out_idx: 0,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn funded_receive_is_claimed() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give the client an initial balance to fund the incoming contract with.
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let mut events = pin!(ln_event_stream(&client));

    let operation_id = client
        .get_first_module::<LightningClientModule>()?
        .receive(
            Amount::from_sats(1000),
            3600,
            Bolt11InvoiceDescription::Direct(String::new()),
            Some(mock::gateway()),
            Value::Null,
        )
        .await?
        .1;

    let mut sub = client
        .get_first_module::<LightningClientModule>()?
        .subscribe_receive_operation_state_updates(operation_id)
        .await?
        .into_stream();

    assert_eq!(sub.ok().await?, ReceiveOperationState::Pending);

    let operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    let contract = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Receive(meta) => meta.contract,
        _ => panic!("Operation meta is not a receive variant"),
    };

    fund_incoming_contract(&client, contract).await?;

    assert_eq!(sub.ok().await?, ReceiveOperationState::Claiming);
    assert_eq!(sub.ok().await?, ReceiveOperationState::Claimed);

    let Some(LnEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    Ok(())
}

fn root_secret(bytes: &[u8; 64]) -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(bytes))
}

/// Creates a direct receive on a client derived from `root_secret`, then
/// shuts the client down, simulating a database lost before the payment was
/// claimed. Returns the incoming contract and the contract-derived operation
/// id a rediscovering client will record it under.
async fn receive_and_lose_db(
    fed: &FederationTest,
    root_secret: RootSecret,
) -> anyhow::Result<(IncomingContract, OperationId)> {
    let original = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret)
        .await;

    let operation_id = original
        .get_first_module::<LightningClientModule>()?
        .receive(
            Amount::from_sats(1000),
            3600,
            Bolt11InvoiceDescription::Direct(String::new()),
            Some(mock::gateway()),
            Value::Null,
        )
        .await?
        .1;

    let operation = original
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    let contract = match operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::Receive(meta) => meta.contract,
        _ => panic!("Operation meta is not a receive variant"),
    };

    Arc::into_inner(original)
        .expect("The test holds the only handle")
        .shutdown()
        .await;

    Ok((contract, operation_id))
}

/// Waits until the recovered receive credits the client's balance and
/// asserts the operation was recorded with a recovered receive meta.
async fn await_recovered_receive(
    client: &ClientHandleArc,
    operation_id: OperationId,
) -> anyhow::Result<RecoveredReceiveOperationMeta> {
    let mut balance = Amount::ZERO;

    for _ in 0..300 {
        balance = client.get_balance_for_btc().await?;

        if balance != Amount::ZERO {
            break;
        }

        sleep_in_test(
            "Waiting for the contract scan to claim the recovered receive",
            Duration::from_millis(200),
        )
        .await;
    }

    // The claim credits the contract amount minus the lnv2 input fee.
    assert!(
        balance >= Amount::from_msats(900_000),
        "Expected the recovered contract to be claimed, balance is {balance}"
    );

    // The rediscovered operation is recorded under the contract-derived
    // operation id with a recovered receive meta.
    let recovered_operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Recovered operation not found"))?;

    let recovered_meta = match recovered_operation.meta::<LightningOperationMeta>() {
        LightningOperationMeta::RecoveredReceive(meta) => meta,
        meta => panic!("Operation meta is not a recovered receive variant: {meta:?}"),
    };

    // The invoice was lost with the original database, so the receive event
    // reports the contract amount with a zero gateway fee rather than
    // decoding the contract expiration as a fee.
    let mut events = pin!(ln_event_stream(client));

    let Some(LnEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    assert_eq!(receive.operation_id, operation_id);
    assert_eq!(receive.fee, Amount::ZERO);
    assert_eq!(receive.amount, recovered_meta.contract.commitment.amount);

    Ok(recovered_meta)
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_recovers_direct_receive_after_restore_from_seed() -> anyhow::Result<()> {
    const RESTORE_SK: [u8; 64] = [0x21; 64];

    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    // The original client creates an invoice, then loses its database before
    // the payment arrives.
    let (contract, operation_id) = receive_and_lose_db(&fed, root_secret(&RESTORE_SK)).await?;

    // A gateway funds the contract while the original client is gone.
    let funder = fed.new_client().await;

    funder
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    fund_incoming_contract(&funder, contract.clone()).await?;

    // The restored client has the seed but a fresh database. The incoming
    // contract scan rediscovers the funded contract via the static module
    // key and claims it without any local operation history.
    let restored = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RESTORE_SK))
        .await;

    let recovered_meta = await_recovered_receive(&restored, operation_id).await?;

    // The automatic scan attaches the client's configured custom metadata,
    // exactly like the lnurl branch of the same loop.
    assert!(
        recovered_meta.custom_meta.get("timestamp").is_some(),
        "Expected the configured custom meta, got {:?}",
        recovered_meta.custom_meta
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rescan_recovers_direct_receive_missed_by_earlier_scan() -> anyhow::Result<()> {
    const RESTORE_SK: [u8; 64] = [0x22; 64];

    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    let (contract, operation_id) = receive_and_lose_db(&fed, root_secret(&RESTORE_SK)).await?;

    let funder = fed.new_client().await;

    funder
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    fund_incoming_contract(&funder, contract.clone()).await?;

    // Simulate a database restored from seed by a client from before direct
    // receives were recovered by the scan: its persisted cursor has already
    // advanced past the funded contract, so the tail scan alone never
    // revisits it and only a manual rescan can rediscover it.
    let lnv2_module_id = funder
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    let db: Database = MemDatabase::new().into();

    {
        let (module_db, _) = db.with_prefix_module_id(lnv2_module_id);

        let mut dbtx = module_db.begin_transaction().await;

        // The module's own scan cursor, under the client's module instance
        // prefix: already at the stream tip of one funded contract.
        dbtx.insert_entry(&IncomingContractStreamIndexKey, &1).await;

        dbtx.commit_tx().await;
    }

    let restored = fed.join_client_with_db(db, root_secret(&RESTORE_SK)).await;

    // The tail scan starts at the cursor, which is already past the funded
    // contract, so it never records the recovery on its own.
    assert!(
        restored
            .operation_log()
            .get_operation(operation_id)
            .await
            .is_none(),
        "The tail scan must not recover a contract behind the persisted cursor"
    );

    let operation_ids = restored
        .get_first_module::<LightningClientModule>()?
        .rescan_incoming_contracts(Value::Null)
        .await?;

    assert!(
        operation_ids.contains(&operation_id),
        "Expected the rescan to record the recovery of the funded contract, got {operation_ids:?}"
    );

    let recovered_meta = await_recovered_receive(&restored, operation_id).await?;

    // A manual rescan uses the metadata passed by its caller.
    assert_eq!(recovered_meta.custom_meta, Value::Null);

    Ok(())
}

/// Reads the incoming contract scan cursor out of a client's database.
///
/// The cursor is the module's own `IncomingContractStreamIndexKey`, read under
/// the client's module instance prefix the way
/// `rescan_recovers_direct_receive_missed_by_earlier_scan` writes it. `None`
/// means the scan has never committed a cursor, i.e. it never got past its
/// first batch.
async fn scan_cursor(client: &Client) -> Option<u64> {
    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    let (module_db, _) = client.db().with_prefix_module_id(lnv2_module_id);

    module_db
        .begin_transaction_nc()
        .await
        .get_value(&IncomingContractStreamIndexKey)
        .await
}

/// A batch of nothing but dust must not hold the scan cursor.
///
/// Skipping a contract the claim fee would swallow is the point of the dust
/// check, but pricing one through a fee quote asks the primary module to
/// balance a claim the contract cannot fund, which fails outright on a wallet
/// with no balance to top the shortfall up from. Reading that failure as
/// "cannot price this yet" holds the cursor, and the cursor only ever moves
/// forward: the scan re-fetches the same batch every ten seconds forever, and
/// once 128 dust contracts fill a batch no later contract is ever seen again —
/// a wallet bricked for the price of a few sats, by a different route.
///
/// `unsolicited_dust_contract_does_not_wedge_the_client` cannot see this: it
/// funds a claimable contract in the same batch, which the victim claims
/// whether or not the cursor ever moved.
#[tokio::test(flavor = "multi_thread")]
async fn dust_alone_does_not_hold_the_scan_cursor() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let victim = fed.new_client().await;
    let attacker = fed.new_client().await;

    attacker
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    // Everything the attacker needs is in what the victim publishes.
    let lnurl = victim
        .get_first_module::<LightningClientModule>()?
        .generate_lnurl(
            SafeUrl::parse("https://recurring.xyz/").expect("Valid Url"),
            Some(mock::gateway()),
        )
        .await?;
    let url = parse_lnurl(&lnurl).expect("Generated lnurl decodes");
    let payload = url.rsplit("pay/").next().expect("Url carries a payload");
    let request = decode_prefixed::<LnurlRequest>(FEDIMINT_PREFIX, payload)?;

    // The stream holds nothing but the dust, and the victim holds no balance
    // at all — the state a fresh wallet publishing an address is in, and the
    // one in which no quote for the claim can be taken.
    let dust = incoming_contract_for(request.recipient_pk, request.aggregate_pk, msats(1));
    fund_incoming_contract(&attacker, dust.clone()).await?;

    let cursor = retry(
        "waiting for the scan cursor to advance past the dust contract",
        backoff_util::aggressive_backoff(),
        || async {
            scan_cursor(&victim)
                .await
                .context("The scan cursor never advanced past the dust contract")
        },
    )
    .await;

    assert!(
        matches!(cursor, Ok(1)),
        "The scan cursor must advance past the only dust contract in the stream, got {cursor:?}"
    );

    // Advancing past the dust is skipping it, not claiming it.
    assert!(
        victim
            .operation_log()
            .get_operation(OperationId::from_encodable(&dust))
            .await
            .is_none(),
        "Dust contract should have been ignored"
    );

    Ok(())
}

/// A claim that genuinely cannot be priced must hold the scan cursor, and the
/// contract must still be recovered once pricing works again.
///
/// This is the case the dust check must not swallow. The contract is worth
/// claiming; the client is simply in no position to price it, because a fee
/// quote is balanced by the primary module and no primary module is in the
/// registry. That is the real shape of a restore from seed: a module whose
/// recovery is still running stays out of the module registry until the client
/// is reopened with that recovery complete (the `initialize_module` branch in
/// `fedimint-client/src/client/builder.rs`). Advancing the cursor there would
/// abandon the contract, since the scan only ever moves forward.
///
/// The registry is emptied of everything but the lightning module to reach
/// that state, which is what
/// `scan_recovers_direct_receive_after_restore_from_seed` cannot do: it joins
/// with the fixture's registry, primary module included.
#[tokio::test(flavor = "multi_thread")]
async fn scan_holds_the_cursor_until_the_claim_can_be_priced() -> anyhow::Result<()> {
    const RESTORE_SK: [u8; 64] = [0x23; 64];
    const FILLER_SK: [u8; 64] = [0x24; 64];

    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    // `receive_and_lose_db` asks for a thousand satoshis, three orders of
    // magnitude clear of the one the lightning input fee costs, so the verdict
    // genuinely depends on the quote rather than being settled by the local
    // dust check ahead of it. Were that amount ever dropped into dust range,
    // the cursor assertion below is what fails: the dust check would skip the
    // contract and let the cursor advance.
    let (contract, operation_id) = receive_and_lose_db(&fed, root_secret(&RESTORE_SK)).await?;

    let funder = fed.new_client().await;

    funder
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    // Consume stream index zero, then claim the contract so the stream is
    // sparse. This lets the rescan below start before the persisted cursor and
    // still reach the target exactly at that cursor, proving the unpriceable
    // recovery path ran without moving the cursor past the target first.
    let (filler, filler_operation_id) = receive_and_lose_db(&fed, root_secret(&FILLER_SK)).await?;

    fund_incoming_contract(&funder, filler).await?;

    let filler_recipient = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&FILLER_SK))
        .await;

    await_recovered_receive(&filler_recipient, filler_operation_id).await?;

    fund_incoming_contract(&funder, contract.clone()).await?;

    let db: Database = MemDatabase::new().into();

    {
        let lnv2_module_id = funder
            .get_first_instance(&LightningClientModule::kind())
            .expect("lnv2 module is registered");
        let (module_db, _) = db.with_prefix_module_id(lnv2_module_id);
        let mut dbtx = module_db.begin_transaction().await;

        // The module's own scan cursor: index zero was claimed above, and the
        // target is at index one.
        dbtx.insert_entry(&IncomingContractStreamIndexKey, &1).await;

        dbtx.commit_tx().await;
    }

    // A client that runs the lightning module and nothing else, because
    // nothing else is in its registry. Its scan runs, and every fee quote it
    // takes fails for want of a primary module to balance against.
    let unpriceable = {
        let mut builder = Client::builder().await?;

        builder.with_module(lightning_client_init());

        builder
            .preview_with_existing_config(funder.endpoints().clone(), funder.config().await, None)
            .await?
            .join(db.clone(), root_secret(&RESTORE_SK))
            .await?
    };

    // The sparse rescan begins at index zero and reaches the target at index
    // one. The failed quote returns before `receive_incoming_contract` can
    // attempt to record the recovery, so the resulting rescan error proves the
    // direct-recovery verdict was attempted and could not be priced.
    unpriceable
        .get_first_module::<LightningClientModule>()?
        .rescan_incoming_contracts(Value::Null)
        .await
        .expect_err("The rescan must report an unpriceable recovery");

    // The rescan itself never writes the cursor, so this catches only the tail
    // scan advancing it. That the hold actually preserved the claim is what
    // the recovery after the reopen below proves.
    assert_eq!(
        scan_cursor(&unpriceable).await,
        Some(1),
        "The scan must not advance past a contract whose claim it could not price"
    );

    unpriceable.shutdown().await;

    // Joining with a registry short of the primary module also cached an API
    // version set short of it, and a cached set is reused on the next open —
    // which would drop the module from the reopened client too. That is an
    // artifact of how this test takes the module away, not of the state it
    // stands in for: a restore from seed negotiates against its whole
    // registry both times, and the module is missing only for as long as its
    // recovery runs. Dropping the cache lets the reopen negotiate afresh.
    let mut dbtx = db.begin_transaction().await;

    dbtx.remove_entry(&CachedApiVersionSetKey).await;

    dbtx.commit_tx().await;

    // Reopening the same database with a primary module present is the other
    // half of a restore from seed: the recovery is complete, the module is
    // back in the registry, and the scan resumes from the cursor it held.
    let restored = fed.open_client_with_db(db, root_secret(&RESTORE_SK)).await;

    await_recovered_receive(&restored, operation_id).await?;

    Ok(())
}

/// Crafts a claimable incoming contract with keys known to the test instead
/// of keys derived from a client's seed, so no live state machine races the
/// test for the claim.
fn craft_incoming_contract(
    tpe_agg_pk: tpe::AggregatePublicKey,
) -> (IncomingContract, Keypair, tpe::AggregateDecryptionKey) {
    let claim_keypair = SecretKey::new(&mut OsRng).keypair(SECP256K1);
    let encryption_seed = [42; 32];
    let preimage = encryption_seed
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let contract = IncomingContract::new(
        tpe_agg_pk,
        encryption_seed,
        preimage,
        PaymentImage::Hash(preimage.consensus_hash()),
        Amount::from_sats(1000),
        u64::MAX,
        claim_keypair.public_key(),
        claim_keypair.public_key(),
        claim_keypair.public_key(),
    );

    let agg_decryption_key = tpe::derive_agg_dk(&tpe_agg_pk, &encryption_seed);

    (contract, claim_keypair, agg_decryption_key)
}

async fn lnv2_tpe_agg_pk(client: &ClientHandleArc) -> anyhow::Result<tpe::AggregatePublicKey> {
    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    Ok(client
        .config()
        .await
        .modules
        .get(&lnv2_module_id)
        .expect("lnv2 module config exists")
        .cast::<LightningClientConfig>()?
        .tpe_agg_pk)
}

/// Records a rejected claim transaction and parks a legacy claiming record
/// referencing it under `operation_id`, exactly as the executor archived it
/// for clients from before the claim transaction was watched for rejection:
/// as a row in the inactive states table, which is not reachable via public
/// state machine APIs since the state is terminal.
async fn park_legacy_claim(
    client: &ClientHandleArc,
    operation_id: OperationId,
    contract: &IncomingContract,
    claim_keypair: Keypair,
    agg_decryption_key: tpe::AggregateDecryptionKey,
    operation_meta: LightningOperationMeta,
) -> anyhow::Result<()> {
    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    // Record a rejected claim transaction under the operation id by claiming
    // an outpoint that holds no contract.
    let rejected_range = client
        .finalize_and_submit_transaction(
            operation_id,
            KIND.as_str(),
            move |_| operation_meta.clone(),
            TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![ClientInput::<LightningInput> {
                    input: LightningInput::V0(LightningInputV0::Incoming(
                        OutPoint {
                            txid: TransactionId::from_byte_array([21; 32]),
                            out_idx: 0,
                        },
                        agg_decryption_key,
                    )),
                    amounts: Amounts::new_bitcoin(contract.commitment.amount),
                    keys: vec![claim_keypair],
                }])
                .into_dyn(lnv2_module_id),
            ),
        )
        .await?;

    anyhow::ensure!(
        client
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(rejected_range.txid())
            .await
            .is_err(),
        "The claim of a non-existent contract should be rejected"
    );

    park_legacy_record(
        client,
        operation_id,
        contract,
        claim_keypair,
        agg_decryption_key,
        rejected_range.txid(),
    )
    .await
}

/// Writes a legacy claiming record referencing `claim_txid` under
/// `operation_id` into the inactive states table, exactly as the executor
/// archived it for clients from before the claim transaction was watched for
/// rejection. The table is not reachable via public state machine APIs since
/// the state is terminal.
async fn park_legacy_record(
    client: &ClientHandleArc,
    operation_id: OperationId,
    contract: &IncomingContract,
    claim_keypair: Keypair,
    agg_decryption_key: tpe::AggregateDecryptionKey,
    claim_txid: TransactionId,
) -> anyhow::Result<()> {
    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    let parked_receive_sm = ReceiveStateMachine {
        common: ReceiveSMCommon {
            operation_id,
            contract: contract.clone(),
            claim_keypair,
            agg_decryption_key,
        },
        state: ReceiveSMState::ClaimingLegacy(vec![OutPoint {
            txid: claim_txid,
            out_idx: 0,
        }]),
    };

    let parked_state =
        fedimint_lnv2_client::LightningClientStateMachines::Receive(parked_receive_sm)
            .into_dyn(lnv2_module_id);

    let parked_state_meta = InactiveStateMeta {
        created_at: fedimint_core::time::now(),
        exited_at: fedimint_core::time::now(),
    };

    let mut dbtx = client.db().begin_transaction().await;

    dbtx.insert_entry(
        &InactiveStateKeyDb(InactiveStateKey::from_state(parked_state)),
        &parked_state_meta,
    )
    .await;

    dbtx.commit_tx().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reclaim_receive_recovers_parked_claim() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give the client an initial balance to fund the incoming contract with.
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let (contract, claim_keypair, agg_decryption_key) =
        craft_incoming_contract(lnv2_tpe_agg_pk(&client).await?);

    fund_incoming_contract(&client, contract.clone()).await?;

    let original_operation_id = OperationId::new_random();

    park_legacy_claim(
        &client,
        original_operation_id,
        &contract,
        claim_keypair,
        agg_decryption_key,
        LightningOperationMeta::LnurlReceive(LnurlReceiveOperationMeta {
            contract: contract.clone(),
            custom_meta: Value::Null,
        }),
    )
    .await?;

    let reclaim_operation_id = client
        .get_first_module::<LightningClientModule>()?
        .reclaim_receive(original_operation_id)
        .await?;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .await_final_receive_operation_state(reclaim_operation_id)
            .await?,
        FinalReceiveOperationState::Claimed
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reclaim_receive_fails_when_contract_already_claimed() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    // Give the client an initial balance to fund the incoming contract with.
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(sats(10_000), AmountUnit::BITCOIN)
        .await?;

    let lnv2_module_id = client
        .get_first_instance(&LightningClientModule::kind())
        .expect("lnv2 module is registered");

    let (contract, claim_keypair, agg_decryption_key) =
        craft_incoming_contract(lnv2_tpe_agg_pk(&client).await?);

    let funding_outpoint = fund_incoming_contract(&client, contract.clone()).await?;

    // Claim the contract directly, as another client derived from the same
    // seed would have, leaving nothing behind to reclaim. The operation is
    // recorded like an lnv2 receive so the accepted-claim guard below can be
    // exercised against it.
    let claim_operation_id = OperationId::new_random();

    let claim_meta_contract = contract.clone();

    let claim_range = client
        .finalize_and_submit_transaction(
            claim_operation_id,
            KIND.as_str(),
            move |_| {
                LightningOperationMeta::LnurlReceive(LnurlReceiveOperationMeta {
                    contract: claim_meta_contract.clone(),
                    custom_meta: Value::Null,
                })
            },
            TransactionBuilder::new().with_inputs(
                ClientInputBundle::new_no_sm(vec![ClientInput::<LightningInput> {
                    input: LightningInput::V0(LightningInputV0::Incoming(
                        funding_outpoint,
                        agg_decryption_key,
                    )),
                    amounts: Amounts::new_bitcoin(contract.commitment.amount),
                    keys: vec![claim_keypair],
                }])
                .into_dyn(lnv2_module_id),
            ),
        )
        .await?;

    client
        .transaction_updates(claim_operation_id)
        .await
        .await_tx_accepted(claim_range.txid())
        .await
        .map_err(|e| anyhow::anyhow!("Claim of the funded contract was rejected: {e}"))?;

    let original_operation_id = OperationId::new_random();

    park_legacy_claim(
        &client,
        original_operation_id,
        &contract,
        claim_keypair,
        agg_decryption_key,
        LightningOperationMeta::LnurlReceive(LnurlReceiveOperationMeta {
            contract: contract.clone(),
            custom_meta: Value::Null,
        }),
    )
    .await?;

    // The reclaim rebuilds a fresh claim, which the federation rejects since
    // the contract is already spent. A rejected claim is not retried, so the
    // operation fails terminally.
    let reclaim_event_log_start = client.get_next_event_log_id().await;

    let reclaim_operation_id = client
        .get_first_module::<LightningClientModule>()?
        .reclaim_receive(original_operation_id)
        .await?;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .await_final_receive_operation_state(reclaim_operation_id)
            .await?,
        FinalReceiveOperationState::Failure
    );

    assert!(
        !client
            .get_event_log(Some(reclaim_event_log_start), 100)
            .await
            .iter()
            .any(|entry| matches!(
                try_parse_ln_event(entry.as_raw()),
                Some(LnEvent::Receive(event)) if event.operation_id == reclaim_operation_id
            )),
        "A rejected claim must not log a received payment"
    );

    // The failed reclaim itself parked in the new-style `Failed` state and
    // can be reclaimed again, which fails the same way since the contract
    // remains spent.
    let second_reclaim_operation_id = client
        .get_first_module::<LightningClientModule>()?
        .reclaim_receive(reclaim_operation_id)
        .await?;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .await_final_receive_operation_state(second_reclaim_operation_id)
            .await?,
        FinalReceiveOperationState::Failure
    );

    // A legacy record whose recorded claim transaction was accepted must be
    // refused: reclaiming it would double count a settled receive.
    park_legacy_record(
        &client,
        claim_operation_id,
        &contract,
        claim_keypair,
        agg_decryption_key,
        claim_range.txid(),
    )
    .await?;

    let accepted_reclaim_error = client
        .get_first_module::<LightningClientModule>()?
        .reclaim_receive(claim_operation_id)
        .await
        .expect_err("Reclaiming an accepted legacy claim should be refused");

    assert!(
        accepted_reclaim_error
            .to_string()
            .contains("there is nothing to reclaim"),
        "Unexpected error: {accepted_reclaim_error}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()?
            .send(
                mock::signet_bolt_11_invoice(),
                Some(mock::gateway()),
                Value::Null
            )
            .await
            .expect_err("send did not fail due to incorrect Currency"),
        SendPaymentError::WrongCurrency {
            invoice_currency: lightning_invoice::Currency::Signet,
            federation_currency: lightning_invoice::Currency::Regtest
        }
    );

    Ok(())
}

mod db {
    use std::collections::BTreeMap;

    use anyhow::{Context, ensure};
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::bitcoin::hashes::sha256;
    use fedimint_core::core::{DynInput, DynOutput};
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::epoch::ConsensusItem;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};
    use fedimint_core::session_outcome::{AcceptedItem, SessionOutcome, SignedSessionOutcome};
    use fedimint_core::transaction::{Transaction, TransactionSignature};
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{Amount, BitcoinHash, OutPoint, PeerId};
    use fedimint_lnv2_client::db;
    use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract, PaymentImage};
    use fedimint_lnv2_common::{
        LightningCommonInit, LightningInput, LightningInputV0, LightningOutput, LightningOutputV0,
        OutgoingWitness,
    };
    use fedimint_lnv2_server::db::{
        DbKeyPrefix, IncomingContractIndexKey, IncomingContractIndexPrefix,
        IncomingContractStreamIndexKey, IncomingContractStreamKey,
    };
    use fedimint_logging::TracingSetup;
    use fedimint_server::consensus::db::{AcceptedItemKey, SignedSessionOutcomeKey};
    use fedimint_server::core::DynServerModuleInit;
    use fedimint_testing::db::{
        TEST_MODULE_INSTANCE_ID, snapshot_db_migrations_client,
        snapshot_db_migrations_with_decoders, validate_migrations_client,
        validate_migrations_server,
    };
    use futures::StreamExt;
    use strum::IntoEnumIterator;
    use tpe::{AggregateDecryptionKey, AggregatePublicKey, G1Affine};

    use crate::{LightningClientInit, LightningClientModule, LightningInit};

    /// An incoming contract that is only well-formed enough to survive a
    /// round-trip through the database. `migrate_to_v1` never inspects the
    /// contract, it only moves it, so the cryptography does not have to check
    /// out.
    fn incoming_contract(seed: u8) -> IncomingContract {
        let key = SecretKey::from_slice(&[seed; 32])
            .expect("a repeated non-zero byte is a valid secret key")
            .public_key(SECP256K1);

        IncomingContract::new(
            AggregatePublicKey(G1Affine::generator()),
            [seed; 32],
            [seed; 32],
            PaymentImage::Hash(sha256::Hash::hash(&[seed; 32])),
            Amount::from_sats(1000),
            u64::from(seed),
            key,
            key,
            key,
        )
    }

    /// An outgoing contract, seeded purely so the replayed history contains an
    /// output `migrate_to_v1` has to skip. Like `incoming_contract`, it is
    /// never inspected, so the cryptography does not have to check out.
    fn outgoing_contract(seed: u8) -> OutgoingContract {
        let key = SecretKey::from_slice(&[seed; 32])
            .expect("a repeated non-zero byte is a valid secret key")
            .public_key(SECP256K1);

        OutgoingContract {
            payment_image: PaymentImage::Hash(sha256::Hash::hash(&[seed; 32])),
            amount: Amount::from_sats(1000),
            expiration: u64::from(seed),
            claim_pk: key,
            refund_pk: key,
            ephemeral_pk: key,
        }
    }

    /// A transaction carrying the given lnv2 inputs and outputs, with `nonce`
    /// keeping the transaction ids of the seeded transactions apart.
    fn transaction(
        nonce: u8,
        inputs: Vec<LightningInput>,
        outputs: Vec<LightningOutput>,
    ) -> Transaction {
        Transaction {
            inputs: inputs
                .into_iter()
                .map(|input| DynInput::from_typed(TEST_MODULE_INSTANCE_ID, input))
                .collect(),
            outputs: outputs
                .into_iter()
                .map(|output| DynOutput::from_typed(TEST_MODULE_INSTANCE_ID, output))
                .collect(),
            nonce: [nonce; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        }
    }

    /// The transaction that funds the seeded contracts. Deterministic, so the
    /// validation side can name its transaction id when checking the outpoints
    /// the migration wrote.
    ///
    /// `migrate_to_v1` assigns the incoming contracts stream indices 0 and 1,
    /// in output order, and skips the outgoing one: it must neither be
    /// indexed nor allowed to advance the stream index.
    fn funding_transaction() -> Transaction {
        transaction(
            0,
            vec![],
            vec![
                LightningOutput::V0(LightningOutputV0::Incoming(incoming_contract(1))),
                LightningOutput::V0(LightningOutputV0::Incoming(incoming_contract(2))),
                LightningOutput::V0(LightningOutputV0::Outgoing(outgoing_contract(3))),
            ],
        )
    }

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only intended to
    /// provide coverage when reading the database in future code versions. This
    /// function should not be updated when database keys or values change -
    /// instead a new function should be added that creates a new database
    /// backup that can be tested.
    ///
    /// `db` is the global database: `migrate_to_v1` replays the module history
    /// out of the session log, which lives in the global namespace, while the
    /// module's own rows live in the namespace isolated to
    /// `TEST_MODULE_INSTANCE_ID`. Both have to be seeded here.
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Two incoming contracts and one outgoing contract, funded by one transaction.
        let funding_tx = funding_transaction();

        // Spending the first contract, in a later session item so that the migration
        // sees the output before the input that consumes it.
        //
        // The outgoing input names the outpoint of the contract that survives, which
        // nothing in the migration cross-checks. That is what makes the input's type
        // filter observable: without it the input would evict a live contract.
        let spend_tx = transaction(
            1,
            vec![
                LightningInput::V0(LightningInputV0::Incoming(
                    OutPoint {
                        txid: funding_tx.tx_hash(),
                        out_idx: 0,
                    },
                    AggregateDecryptionKey(G1Affine::generator()),
                )),
                LightningInput::V0(LightningInputV0::Outgoing(
                    OutPoint {
                        txid: funding_tx.tx_hash(),
                        out_idx: 1,
                    },
                    OutgoingWitness::Refund,
                )),
            ],
            vec![],
        );

        // The funding transaction goes into a completed session and the spend into
        // the current one. `get_typed_module_history_stream` reads
        // `SignedSessionOutcomePrefix` and only then chains `AcceptedItemPrefix`, so
        // splitting the two here exercises the completed-session path — which supplies
        // nearly all of the history on an existing federation, and which a
        // current-session-only fixture would leave untested — and pins the ordering
        // across the boundary between the two.
        dbtx.insert_new_entry(
            &SignedSessionOutcomeKey(0),
            &SignedSessionOutcome {
                session_outcome: SessionOutcome {
                    items: vec![AcceptedItem {
                        item: ConsensusItem::Transaction(funding_tx),
                        peer: PeerId::from(0),
                    }],
                },
                signatures: BTreeMap::new(),
            },
        )
        .await;

        dbtx.insert_new_entry(
            &AcceptedItemKey(0),
            &AcceptedItem {
                item: ConsensusItem::Transaction(spend_tx),
                peer: PeerId::from(0),
            },
        )
        .await;

        dbtx.commit_tx().await;

        let module_db = db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID).0;
        let mut module_dbtx = module_db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        module_dbtx
            .insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        module_dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_with_decoders(
            "lightningv2-server-v0",
            |db| {
                Box::pin(async {
                    create_server_db_with_v0_data(db).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                TEST_MODULE_INSTANCE_ID,
                LightningCommonInit::KIND,
                LightningCommonInit::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynServerModuleInit::from(LightningInit);

        validate_migrations_server(module, "lightningv2-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            // Matching every variant explicitly, with no catch-all, is the point of this
            // pattern: adding a new prefix breaks the build here until someone decides
            // how the migration test should cover it.
            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::IncomingContractStreamIndex => {
                        // The index counts every incoming contract output the replayed
                        // history contained, spent ones included, and nothing else: of
                        // the three seeded outputs the outgoing one must not advance
                        // it, so it stays at 2 even though only one contract survives.
                        let stream_index = dbtx
                            .get_value(&IncomingContractStreamIndexKey)
                            .await
                            .context("migrate_to_v1 did not write the stream index")?;

                        ensure!(
                            stream_index == 2,
                            "both seeded contract outputs must have advanced the stream \
                             index, got {stream_index}"
                        );
                    }
                    DbKeyPrefix::IncomingContractStream => {
                        // The stream is read as a range, the way the module itself reads
                        // it: `IncomingContractStreamPrefix` encodes its start index, so
                        // as a key prefix it only ever matches that single index.
                        let stream = dbtx
                            .find_by_range(
                                IncomingContractStreamKey(0)..IncomingContractStreamKey(u64::MAX),
                            )
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            stream.len() == 1,
                            "the stream must hold exactly the unspent contract, \
                             got {} entries",
                            stream.len()
                        );

                        // Indices are handed out per output seen and removing a spent
                        // contract does not renumber the survivors, so the second
                        // contract keeps the sparse index 1.
                        ensure!(
                            stream[0].0 == IncomingContractStreamKey(1),
                            "the surviving contract must keep its original sparse index, \
                             got {:?}",
                            stream[0].0
                        );
                        ensure!(
                            stream[0].1 == incoming_contract(2),
                            "the surviving contract must be the unspent one"
                        );
                    }
                    DbKeyPrefix::IncomingContractIndex => {
                        // The reverse lookup `migrate_to_v1` writes alongside every
                        // stream entry, so it mirrors the stream exactly.
                        let index = dbtx
                            .find_by_prefix(&IncomingContractIndexPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            index.len() == 1,
                            "the reverse lookup must hold exactly the unspent contract, \
                             got {} entries",
                            index.len()
                        );

                        let (IncomingContractIndexKey(outpoint), stream_index) = &index[0];

                        // The whole outpoint, not just the output index: the point of
                        // this assertion is that the reverse index was rebuilt from
                        // module history, and an index-only check would still pass if
                        // the transaction id were reconstructed wrongly.
                        ensure!(
                            *outpoint
                                == OutPoint {
                                    txid: funding_transaction().tx_hash(),
                                    out_idx: 1,
                                },
                            "the reverse lookup must point at the unspent contract's \
                             outpoint, got {outpoint}"
                        );
                        ensure!(
                            *stream_index == 1,
                            "the reverse lookup must agree with the stream index, \
                             got {stream_index}"
                        );
                    }
                    DbKeyPrefix::BlockCountVote
                    | DbKeyPrefix::UnixTimeVote
                    | DbKeyPrefix::IncomingContract
                    | DbKeyPrefix::IncomingContractOutpoint
                    | DbKeyPrefix::OutgoingContract
                    | DbKeyPrefix::DecryptionKeyShare
                    | DbKeyPrefix::Preimage
                    | DbKeyPrefix::Gateway => {
                        // Neither read nor written by `migrate_to_v1`, and
                        // the v0 snapshot holds no rows under them, so there
                        // is nothing to validate. Seeding them would widen
                        // decode coverage for the next migration.
                    }
                }
            }

            Ok(())
        })
        .await
    }

    /// The gateway the client-side snapshot remembers. Nothing dials it, so the
    /// key and the url only have to survive a database round-trip.
    fn gateway_key() -> PublicKey {
        SecretKey::from_slice(&[9; 32])
            .expect("a repeated non-zero byte is a valid secret key")
            .public_key(SECP256K1)
    }

    fn gateway_url() -> SafeUrl {
        SafeUrl::parse("https://gateway.example/").expect("a hardcoded https url parses")
    }

    /// The client-side counterpart of `create_server_db_with_v0_data`, seeding
    /// the module's isolated namespace. The lnv2 client has no migrations yet,
    /// so what the paired test checks is that these rows still decode.
    async fn create_client_db_with_v0_data(database: Database) {
        let mut dbtx = database.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&db::GatewayKey(gateway_key()), &gateway_url())
            .await;

        dbtx.insert_new_entry(&db::IncomingContractStreamIndexKey, &7)
            .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, LightningCommonInit>(
            "lightningv2-client-v0",
            |database| Box::pin(async { create_client_db_with_v0_data(database).await }),
            || (Vec::new(), Vec::new()),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynClientModuleInit::from(LightningClientInit::default());

        validate_migrations_client::<_, _, LightningClientModule>(
            module,
            "lightningv2-client",
            |database, _, _| async move {
                let mut dbtx = database.begin_transaction_nc().await;

                for prefix in db::DbKeyPrefix::iter() {
                    match prefix {
                        db::DbKeyPrefix::Gateway => {
                            let url = dbtx
                                .get_value(&db::GatewayKey(gateway_key()))
                                .await
                                .context("the seeded gateway must still decode")?;

                            ensure!(
                                url == gateway_url(),
                                "the gateway url must round-trip unchanged, got {url}"
                            );
                        }
                        db::DbKeyPrefix::IncomingContractStreamIndex => {
                            let index = dbtx
                                .get_value(&db::IncomingContractStreamIndexKey)
                                .await
                                .context("the seeded stream index must still decode")?;

                            ensure!(
                                index == 7,
                                "the stream index must round-trip unchanged, got {index}"
                            );
                        }
                        db::DbKeyPrefix::ExternalReservedStart
                        | db::DbKeyPrefix::CoreInternalReservedStart
                        | db::DbKeyPrefix::CoreInternalReservedEnd => {
                            // Range markers, not prefixes the client writes
                            // under, so there is no row to seed or read back.
                        }
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
