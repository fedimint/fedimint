mod mock;

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin::hashes::sha256;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::sm::executor::InactiveStateKeyDb;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_client_module::module::ClientModule;
use fedimint_client_module::sm::InactiveStateMeta;
use fedimint_client_module::sm::executor::InactiveStateKey;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::NextOrPending as _;
use fedimint_core::{Amount, BitcoinHash, OutPoint, TransactionId, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
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
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, KIND, LightningInput, LightningInputV0, LightningOutput,
    LightningOutputV0, OutgoingWitness,
};
use fedimint_lnv2_server::LightningInit;
use fedimint_logging::LOG_TEST;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt;
use serde_json::Value;
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

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);

    fixtures.with_module(
        LightningClientInit {
            gateway_conn: Some(Arc::new(MockGatewayConnection::default())),
            custom_meta_fn: Arc::new(|| {
                serde_json::json!({
                    "timestamp": chrono::Utc::now().timestamp(),
                })
            }),
        },
        LightningInit,
    )
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

        // Raw write of the module's IncomingContractStreamIndexKey (prefix
        // 0x42), which is private to the module: cursor already at the
        // stream tip of one funded contract.
        dbtx.raw_insert_bytes(&[0x42], &1u64.consensus_encode_to_vec())
            .await?;

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
