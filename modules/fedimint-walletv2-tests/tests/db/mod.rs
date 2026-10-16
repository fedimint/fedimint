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
    SpentOutputKey, SpentOutputPrefix, TxInfoIndexKey, TxInfoIndexPrefix, TxInfoKey, TxInfoPrefix,
    UnconfirmedTxKey, UnconfirmedTxPrefix, UnsignedTxKey, UnsignedTxPrefix,
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

                    let [(OutputKey(index), Output(outpoint, tx_out))] = outputs.as_slice() else {
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
                        bail!("the seeded transaction log entry must still decode, got {log:?}");
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
