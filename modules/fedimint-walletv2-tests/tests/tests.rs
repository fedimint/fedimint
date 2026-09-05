use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::events::{
    ReceivePaymentEvent, ReceivePaymentUpdateEvent, SendPaymentEvent, SendPaymentStatus,
    SendPaymentUpdateEvent,
};
use fedimint_walletv2_client::{
    FinalSendOperationState, ReceiveProgress, SendError, WalletClientInit, WalletClientModule,
};
use fedimint_walletv2_common::KIND;
use fedimint_walletv2_server::{CONFIRMATION_FINALITY_DELAY, WalletInit};
use futures::StreamExt;
use tracing::info;

#[derive(Debug)]
enum WalletEvent {
    Send(SendPaymentEvent),
    SendStatus(SendPaymentUpdateEvent),
    Receive(ReceivePaymentEvent),
    ReceiveStatus(ReceivePaymentUpdateEvent),
}

fn wallet_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = WalletEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_wallet_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_wallet_event(entry: &EventLogEntry) -> Option<WalletEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Send);
    }

    if entry.kind == SendPaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::SendStatus);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Receive);
    }

    if entry.kind == ReceivePaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::ReceiveStatus);
    }

    None
}

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(WalletClientInit, WalletInit)
}

// We need the consensus block count to reach a non-zero value before we send in
// any funds such that the UTXO is tracked by the federation.
async fn initialize_consensus(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, 1).await
}

async fn await_finality_delay(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the finality delay of six blocks...");

    let current_consensus = client
        .get_first_module::<WalletClientModule>()?
        .block_count()
        .await?;

    bitcoin.mine_blocks(CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, current_consensus + CONFIRMATION_FINALITY_DELAY).await
}

async fn await_consensus_block_count(
    client: &ClientHandleArc,
    block_count: u64,
) -> anyhow::Result<()> {
    loop {
        if client
            .get_first_module::<WalletClientModule>()?
            .block_count()
            .await?
            >= block_count
        {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for consensus to reach block count {block_count}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

async fn await_federation_total_value(
    client: &ClientHandleArc,
    min_value: bitcoin::Amount,
) -> anyhow::Result<()> {
    loop {
        let current_value = client
            .get_first_module::<WalletClientModule>()?
            .total_value()
            .await?;

        if current_value >= min_value {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for federation total value of {current_value} to reach {min_value}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

/// A peg-in should report progress while it waits out the finality delay,
/// rather than leaving the user with no feedback at all between broadcasting
/// and the ecash being issued.
///
/// Also covers an address paid twice: `receive` hands out the same address
/// until a deposit is detected at it, so two deposits to one address is an
/// ordinary flow and each must be tracked separately rather than one
/// overwriting the other.
#[tokio::test(flavor = "multi_thread")]
async fn receive_reports_confirmation_progress() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    let module = client.get_first_module::<WalletClientModule>()?;

    // Read before handing out the address, so that the claims for both deposits
    // fall at or after this position.
    let position = client.get_next_event_log_id().await;

    let address = module.receive().await;

    assert!(
        module.address_receive_progress(&address).await?.is_empty(),
        "An address with nothing sent to it has no deposits to report"
    );

    info!("Broadcast the first deposit without mining it...");

    let mined_tx = bitcoin
        .send_without_mining(&address, Amount::from_int_btc(1))
        .await;

    // Guardians report the unmined deposit straight out of their mempools,
    // which is the whole point: the user gets feedback before the first block.
    let mined_outpoint = await_receive_mempool(&client, &address, mined_tx.compute_txid()).await?;

    // The per-deposit lookup must agree with the address-wide one.
    assert_eq!(
        module.receive_progress(mined_outpoint).await?,
        ReceiveProgress::Mempool {
            value: Amount::from_int_btc(1)
        },
    );

    bitcoin.mine_blocks(1).await;

    // The tip is the block that just mined the deposit, and `get_block_count`
    // returns a count rather than a height.
    let mined_height = bitcoin.get_block_count().await - 1;

    // The deposit is now mined but still short of the finality delay, so the
    // federation has not recorded it and only the advisory view can see it.
    let confirmations = await_receive_confirmations(&client, &address, 1).await?;

    assert_eq!(
        confirmations,
        CONFIRMATION_FINALITY_DELAY + 1,
        "Progress should count up to the depth at which the federation claims"
    );

    info!("Send a second deposit to the same address and leave it unmined...");

    let unmined_tx = bitcoin
        .send_without_mining(&address, Amount::from_int_btc(2))
        .await;

    let unmined_outpoint = await_deposit_count(&client, &address, 2)
        .await?
        .into_iter()
        .find_map(|(outpoint, _)| (outpoint.txid == unmined_tx.compute_txid()).then_some(outpoint))
        .expect("The second deposit must be reported against its own transaction");

    // The two deposits sit at different stages, so neither may mask the other.
    let progress = module.address_receive_progress(&address).await?;

    let mined = lookup_progress(&progress, mined_outpoint);
    let unmined = lookup_progress(&progress, unmined_outpoint);

    assert_eq!(
        unmined,
        ReceiveProgress::Mempool {
            value: Amount::from_int_btc(2)
        },
        "The unmined deposit must be reported from the mempool, with its own value"
    );

    match mined {
        ReceiveProgress::Confirming {
            value,
            height,
            confirmations,
            required,
        } => {
            assert_eq!(
                value,
                Amount::from_int_btc(1),
                "Each deposit reports its own value, not a combined one"
            );
            assert!(
                (1..required).contains(&confirmations),
                "The mined deposit is confirming, got {confirmations} of {required}"
            );
            assert_eq!(
                height, mined_height,
                "The deposit must report the height of the block that mined it"
            );
        }
        state => panic!("The mined deposit should still be confirming, got {state:?}"),
    }

    assert_eq!(
        module.receive_progress(mined_outpoint).await?,
        mined,
        "The per-deposit lookup must agree with the address-wide one"
    );

    info!("Mine both deposits to finality and confirm they are claimed...");

    // The second deposit is still unmined, so it is mined by the first of these
    // blocks and needs the full delay on top of that. Mining only the delay
    // would leave it one block short of claimable forever.
    let consensus_block_count = module.block_count().await?;

    bitcoin.mine_blocks(CONFIRMATION_FINALITY_DELAY + 1).await;

    await_consensus_block_count(
        &client,
        consensus_block_count + CONFIRMATION_FINALITY_DELAY + 1,
    )
    .await?;

    let mut progress = pin!(
        module
            .subscribe_receive_progress(&address, position)
            .await?
    );

    loop {
        match progress.next().await {
            Some(states)
                if states.len() == 2
                    && states
                        .iter()
                        .all(|(_, state)| *state == ReceiveProgress::Claimed) =>
            {
                break;
            }
            Some(states) => info!("Receive progress: {states:?}"),
            None => panic!("Progress stream ended before both peg-ins were claimed"),
        }
    }

    Ok(())
}

/// Returns the progress reported for `outpoint`, panicking if it is absent.
fn lookup_progress(
    progress: &[(bitcoin::OutPoint, ReceiveProgress)],
    outpoint: bitcoin::OutPoint,
) -> ReceiveProgress {
    progress
        .iter()
        .find(|(reported, _)| *reported == outpoint)
        .map(|(_, state)| state.clone())
        .unwrap_or_else(|| panic!("No progress reported for {outpoint}, got {progress:?}"))
}

/// Polls until the address reports exactly `count` deposits.
async fn await_deposit_count(
    client: &ClientHandleArc,
    address: &bitcoin::Address,
    count: usize,
) -> anyhow::Result<Vec<(bitcoin::OutPoint, ReceiveProgress)>> {
    loop {
        let progress = client
            .get_first_module::<WalletClientModule>()?
            .address_receive_progress(address)
            .await?;

        assert!(
            progress.len() <= count,
            "More deposits reported than were sent: {progress:?}"
        );

        if progress.len() == count {
            return Ok(progress);
        }

        sleep_in_test(
            format!("Waiting for the address to report {count} deposits"),
            Duration::from_secs(1),
        )
        .await;
    }
}

/// Polls receive progress until the unmined peg-in is visible in the
/// guardians' mempools, returning its outpoint.
///
/// Asserts it is reported against the expected transaction and value, and as
/// exactly one deposit.
async fn await_receive_mempool(
    client: &ClientHandleArc,
    address: &bitcoin::Address,
    txid: bitcoin::Txid,
) -> anyhow::Result<bitcoin::OutPoint> {
    loop {
        let progress = client
            .get_first_module::<WalletClientModule>()?
            .address_receive_progress(address)
            .await?;

        match progress.as_slice() {
            [(outpoint, ReceiveProgress::Mempool { value })] => {
                assert_eq!(*value, Amount::from_int_btc(1));
                assert_eq!(outpoint.txid, txid);

                return Ok(*outpoint);
            }
            [] => {}
            states => panic!("Peg-in reached {states:?} while still unmined"),
        }

        sleep_in_test(
            "Waiting for the peg-in to appear in the mempool",
            Duration::from_secs(1),
        )
        .await;
    }
}

/// Polls receive progress until the peg-in is at least `min` confirmations
/// deep, returning the `required` depth it is counting towards.
///
/// Asserts along the way that a mined-but-not-final peg-in is never reported as
/// claimable, and that its reported value matches what was sent.
async fn await_receive_confirmations(
    client: &ClientHandleArc,
    address: &bitcoin::Address,
    min: u64,
) -> anyhow::Result<u64> {
    loop {
        let progress = client
            .get_first_module::<WalletClientModule>()?
            .address_receive_progress(address)
            .await?;

        match progress.as_slice() {
            [
                (
                    _,
                    ReceiveProgress::Confirming {
                        value,
                        confirmations,
                        required,
                        ..
                    },
                ),
            ] => {
                assert_eq!(*value, Amount::from_int_btc(1));

                if *confirmations >= min {
                    return Ok(*required);
                }
            }
            // Still legitimate here: the scanner may not have observed the new
            // block yet, so the peg-in can briefly read as unmined.
            [] | [(_, ReceiveProgress::Mempool { .. })] => {}
            states => panic!("Peg-in reached {states:?} before the finality delay elapsed"),
        }

        sleep_in_test(
            format!("Waiting for the peg-in to reach {min} confirmations"),
            Duration::from_secs(1),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_exceeds_one_bitcoin_with_many_pending_txs() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_int_btc(100))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposit to be auto-claimed...");

    await_federation_total_value(&client, Amount::from_sat(99_000_000)).await?;

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    let mut events = pin!(wallet_event_stream(&client));

    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    let Some(WalletEvent::ReceiveStatus(status)) = events.next().await else {
        panic!("Expected ReceiveStatus event");
    };
    assert_eq!(status.operation_id, receive.operation_id);

    for _ in 0..19 {
        let send_fee = client
            .get_first_module::<WalletClientModule>()?
            .send_fee()
            .await?;

        if send_fee >= Amount::from_int_btc(1) {
            return Ok(());
        }

        let send_op = client
            .get_first_module::<WalletClientModule>()?
            .send(
                address.clone(),
                Amount::from_sat(10_000),
                None,
                serde_json::Value::Null,
            )
            .await?;

        let state = client
            .get_first_module::<WalletClientModule>()?
            .await_final_send_operation_state(send_op)
            .await?;

        assert!(matches!(state, FinalSendOperationState::Success(_)));

        let Some(WalletEvent::Send(e)) = events.next().await else {
            panic!("Expected Send event");
        };
        assert_eq!(e.operation_id, send_op);

        let Some(WalletEvent::SendStatus(e)) = events.next().await else {
            panic!("Expected SendStatus event");
        };
        assert_eq!(e.operation_id, send_op);
        assert!(matches!(e.status, SendPaymentStatus::Success(_)));
    }

    panic!("Transaction fee did not exceed one bitcoin")
}

#[tokio::test(flavor = "multi_thread")]
async fn send_to_a_mainnet_address_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    // A well-known mainnet P2PKH address. The federation runs on regtest.
    let mainnet_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse()?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(
                mainnet_address,
                Amount::from_sat(100_000),
                None,
                serde_json::Value::Null,
            )
            .await
            .err(),
        Some(SendError::WrongNetwork),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_below_the_dust_limit_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(address, Amount::from_sat(1), None, serde_json::Value::Null)
            .await
            .err(),
        Some(SendError::DustValue),
    );

    Ok(())
}

mod db {
    use anyhow::{Context, bail, ensure};
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::{OutPoint, PeerId, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_server_core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_32, snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
        validate_migrations_server,
    };
    use fedimint_walletv2_client::WalletClientModule;
    use fedimint_walletv2_client::db::{
        self, NextOutputIndexKey, ValidAddressIndexKey, ValidAddressIndexPrefix,
    };
    use fedimint_walletv2_common::{FederationWallet, TxInfo, WalletCommonInit};
    use fedimint_walletv2_server::db::{
        BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, FederationWalletKey, FeeRateVoteKey,
        FeeRateVotePrefix, Output, OutputKey, OutputPrefix, SignaturesKey, SignaturesPrefix,
        SpentOutputKey, SpentOutputPrefix, TxInfoIndexKey, TxInfoIndexPrefix, TxInfoKey,
        TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix, UnsignedTxKey, UnsignedTxPrefix,
    };
    use fedimint_walletv2_server::{FederationTx, SpentTxOut};
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::{WalletClientInit, WalletInit};

    /// The peer every vote in the snapshot is attributed to.
    fn peer() -> PeerId {
        PeerId::from(0)
    }

    /// The fedimint transaction id the client state machines refer to. Nothing
    /// looks it up, it only has to survive a database round-trip.
    fn fedimint_txid() -> TransactionId {
        TransactionId::from_slice(&BYTE_32).expect("BYTE_32 is 32 bytes long")
    }

    /// The wallet's tweak, reused for every record so the validation closure
    /// can compare against a single expected value.
    fn tweak() -> sha256::Hash {
        sha256::Hash::hash(&BYTE_32)
    }

    /// A transaction that is only well-formed enough to survive a database
    /// round-trip; it spends nothing and is never broadcast.
    fn transaction(value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn federation_tx(value: u64) -> FederationTx {
        FederationTx {
            tx: transaction(value),
            spent_tx_outs: vec![SpentTxOut {
                value: Amount::from_sat(value),
                tweak: tweak(),
            }],
            vbytes: 200,
            fee: Amount::from_sat(1_000),
        }
    }

    /// A signature that parses but verifies against nothing; it only has to
    /// survive a database round-trip.
    fn signature() -> Signature {
        Signature::from_compact(&[BYTE_32, BYTE_32].concat())
            .expect("two 32 byte scalars below the curve order parse as a signature")
    }

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only intended to
    /// provide coverage when reading the database in future code versions. This
    /// function should not be updated when database keys or values change -
    /// instead a new function should be added that creates a new database
    /// backup that can be tested.
    ///
    /// walletv2 has no server migrations yet, so what the paired test asserts
    /// is that every one of these rows still decodes under current code.
    async fn create_server_db_with_v0_data(db: Database) {
        let unsigned = federation_tx(100_000);
        let unconfirmed = federation_tx(200_000);
        let unsigned_txid = unsigned.tx.compute_txid();
        let unconfirmed_txid = unconfirmed.tx.compute_txid();

        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(
            &OutputKey(0),
            &Output(
                bitcoin::OutPoint {
                    txid: unsigned_txid,
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
        )
        .await;

        dbtx.insert_new_entry(&SpentOutputKey(0), &()).await;

        dbtx.insert_new_entry(&BlockCountVoteKey(peer()), &128)
            .await;

        dbtx.insert_new_entry(&FeeRateVoteKey(peer()), &Some(2))
            .await;

        dbtx.insert_new_entry(
            &TxInfoKey(0),
            &TxInfo {
                index: 0,
                txid: unsigned_txid,
                input: Amount::from_sat(200_000),
                output: Amount::from_sat(100_000),
                fee: Amount::from_sat(1_000),
                vbytes: 200,
                created: 1,
            },
        )
        .await;

        dbtx.insert_new_entry(
            &TxInfoIndexKey(OutPoint {
                txid: fedimint_txid(),
                out_idx: 0,
            }),
            &0,
        )
        .await;

        dbtx.insert_new_entry(&UnsignedTxKey(unsigned_txid), &unsigned)
            .await;

        dbtx.insert_new_entry(
            &SignaturesKey(unsigned_txid, peer()),
            &vec![signature(), signature()],
        )
        .await;

        dbtx.insert_new_entry(&UnconfirmedTxKey(unconfirmed_txid), &unconfirmed)
            .await;

        dbtx.insert_new_entry(
            &FederationWalletKey,
            &FederationWallet {
                value: Amount::from_sat(300_000),
                outpoint: bitcoin::OutPoint {
                    txid: unconfirmed_txid,
                    vout: 0,
                },
                tweak: tweak(),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, WalletCommonInit>("walletv2-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynServerModuleInit::from(WalletInit);

        validate_migrations_server(module, "walletv2-server", |db| async move {
            let unsigned_txid = transaction(100_000).compute_txid();
            let unconfirmed_txid = transaction(200_000).compute_txid();

            let mut dbtx = db.begin_transaction_nc().await;

            // Matching every variant explicitly, with no catch-all, is the point of this
            // pattern: adding a new prefix breaks the build here until someone decides
            // how the migration test should cover it.
            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::Output => {
                        let outputs = dbtx
                            .find_by_prefix(&OutputPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(OutputKey(index), Output(outpoint, tx_out))] = outputs.as_slice()
                        else {
                            bail!("the seeded output must still decode, got {outputs:?}");
                        };

                        ensure!(
                            *index == 0
                                && *outpoint
                                    == bitcoin::OutPoint {
                                        txid: unsigned_txid,
                                        vout: 0,
                                    }
                                && *tx_out
                                    == TxOut {
                                        value: Amount::from_sat(100_000),
                                        script_pubkey: ScriptBuf::new(),
                                    },
                            "the output must round-trip unchanged, got {outputs:?}"
                        );
                    }
                    DbKeyPrefix::SpentOutput => {
                        let spent = dbtx
                            .find_by_prefix(&SpentOutputPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            spent == vec![(SpentOutputKey(0), ())],
                            "the seeded spent output marker must round-trip unchanged, got \
                             {spent:?}"
                        );
                    }
                    DbKeyPrefix::BlockCountVote => {
                        let votes = dbtx
                            .find_by_prefix(&BlockCountVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(BlockCountVoteKey(voter), count)] = votes.as_slice() else {
                            bail!("the seeded block count vote must still decode, got {votes:?}");
                        };

                        ensure!(
                            *voter == peer() && *count == 128,
                            "the seeded block count vote must round-trip unchanged, got {votes:?}"
                        );
                    }
                    DbKeyPrefix::FeeRateVote => {
                        let votes = dbtx
                            .find_by_prefix(&FeeRateVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(FeeRateVoteKey(voter), feerate)] = votes.as_slice() else {
                            bail!("the seeded fee rate vote must still decode, got {votes:?}");
                        };

                        ensure!(
                            *voter == peer() && *feerate == Some(2),
                            "the seeded fee rate vote must round-trip unchanged, got {votes:?}"
                        );
                    }
                    DbKeyPrefix::TxLog => {
                        let log = dbtx
                            .find_by_prefix(&TxInfoPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        let [(TxInfoKey(index), info)] = log.as_slice() else {
                            bail!(
                                "the seeded transaction log entry must still decode, got {log:?}"
                            );
                        };

                        ensure!(
                            *index == 0
                                && *info
                                    == TxInfo {
                                        index: 0,
                                        txid: unsigned_txid,
                                        input: Amount::from_sat(200_000),
                                        output: Amount::from_sat(100_000),
                                        fee: Amount::from_sat(1_000),
                                        vbytes: 200,
                                        created: 1,
                                    },
                            "the transaction log entry must round-trip unchanged, got {log:?}"
                        );
                    }
                    DbKeyPrefix::TxInfoIndex => {
                        let index = dbtx
                            .find_by_prefix(&TxInfoIndexPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            index.len() == 1
                                && index[0].0.0
                                    == OutPoint {
                                        txid: fedimint_txid(),
                                        out_idx: 0,
                                    }
                                && index[0].1 == 0,
                            "the seeded transaction log index must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::UnsignedTx => {
                        let unsigned = dbtx
                            .find_by_prefix(&UnsignedTxPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            unsigned.len() == 1
                                && unsigned[0].0.0 == unsigned_txid
                                && unsigned[0].1 == federation_tx(100_000),
                            "the seeded unsigned transaction must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::Signatures => {
                        let signatures = dbtx
                            .find_by_prefix(&SignaturesPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            signatures.len() == 1
                                && signatures[0].0.0 == unsigned_txid
                                && signatures[0].0.1 == peer()
                                && signatures[0].1 == vec![signature(), signature()],
                            "the seeded signatures must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::UnconfirmedTx => {
                        let unconfirmed = dbtx
                            .find_by_prefix(&UnconfirmedTxPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            unconfirmed.len() == 1
                                && unconfirmed[0].0.0 == unconfirmed_txid
                                && unconfirmed[0].1 == federation_tx(200_000),
                            "the seeded unconfirmed transaction must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::FederationWallet => {
                        let wallet = dbtx
                            .get_value(&FederationWalletKey)
                            .await
                            .context("the seeded federation wallet must still decode")?;

                        ensure!(
                            wallet
                                == FederationWallet {
                                    value: Amount::from_sat(300_000),
                                    outpoint: bitcoin::OutPoint {
                                        txid: unconfirmed_txid,
                                        vout: 0,
                                    },
                                    tweak: tweak(),
                                },
                            "the federation wallet must round-trip unchanged"
                        );
                    }
                }
            }

            Ok(())
        })
        .await
    }

    /// The client-side counterpart of `create_server_db_with_v0_data`, seeding
    /// the module's isolated namespace.
    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&NextOutputIndexKey, &3).await;

        dbtx.insert_new_entry(&ValidAddressIndexKey(0), &()).await;
        dbtx.insert_new_entry(&ValidAddressIndexKey(1), &()).await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, WalletCommonInit>(
            "walletv2-client-v0",
            |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
            || (Vec::new(), Vec::new()),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        let module = DynClientModuleInit::from(WalletClientInit);

        validate_migrations_client::<_, _, WalletClientModule>(
            module,
            "walletv2-client",
            |db, _, _| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in db::DbKeyPrefix::iter() {
                    match prefix {
                        db::DbKeyPrefix::NextOutputIndex => {
                            let index = dbtx
                                .get_value(&NextOutputIndexKey)
                                .await
                                .context("the seeded next output index must still decode")?;

                            ensure!(
                                index == 3,
                                "the next output index must round-trip unchanged, got {index}"
                            );
                        }
                        db::DbKeyPrefix::ValidAddressIndex => {
                            let indices = dbtx
                                .find_by_prefix(&ValidAddressIndexPrefix)
                                .await
                                .map(|(key, ())| key.0)
                                .collect::<Vec<_>>()
                                .await;

                            ensure!(
                                indices == vec![0, 1],
                                "both seeded valid address indices must round-trip unchanged, \
                                 got {indices:?}"
                            );
                        }
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
