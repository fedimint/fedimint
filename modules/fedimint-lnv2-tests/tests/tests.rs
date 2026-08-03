mod mock;

use std::pin::pin;
use std::sync::Arc;

use async_stream::stream;
use fedimint_client::ClientHandleArc;
use fedimint_client::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_client_module::module::ClientModule;
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::util::NextOrPending as _;
use fedimint_core::{Amount, OutPoint, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_lnv2_client::events::{
    ReceivePaymentEvent, SendPaymentEvent, SendPaymentStatus, SendPaymentUpdateEvent,
};
use fedimint_lnv2_client::{
    InvoiceSendStatus, LightningClientInit, LightningClientModule, LightningOperationMeta,
    ReceiveOperationState, SendOperationState, SendPaymentError,
};
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, KIND, LightningInput, LightningInputV0, OutgoingWitness,
};
use fedimint_lnv2_server::LightningInit;
use fedimint_logging::LOG_TEST;
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
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};
    use fedimint_core::session_outcome::{
        AcceptedItem, ConsensusItem, SessionOutcome, SignedSessionOutcome,
    };
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
