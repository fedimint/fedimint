use anyhow::ensure;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Input, Psbt};
use bitcoin::{
    Amount, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, secp256k1,
};
use fedimint_client::module_init::DynClientModuleInit;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseVersion, DatabaseVersionKey, DatabaseVersionKeyV0,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{Feerate, OutPoint, PeerId, TransactionId};
use fedimint_logging::TracingSetup;
use fedimint_server::core::DynServerModuleInit;
use fedimint_testing::db::{
    BYTE_20, BYTE_32, BYTE_33, snapshot_db_migrations, snapshot_db_migrations_client,
    validate_migrations_client, validate_migrations_server,
};
use fedimint_wallet_client::client_db::{self, NextPegInTweakIndexKey, TweakIdx};
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use fedimint_wallet_common::{
    PegOutFees, Rbf, SpendableUTXO, WalletCommonInit, WalletOutputOutcome,
};
use fedimint_wallet_server::db::{
    BlockCountVoteKey, BlockCountVotePrefix, BlockHashByHeightKey, BlockHashByHeightKeyPrefix,
    BlockHashByHeightValue, BlockHashKey, BlockHashKeyPrefix, ClaimedPegInOutpointKey,
    ClaimedPegInOutpointPrefixKey, ConsensusVersionVoteKey, ConsensusVersionVotePrefix,
    ConsensusVersionVotingActivationKey, ConsensusVersionVotingActivationPrefix, DbKeyPrefix,
    FeeRateVoteKey, FeeRateVotePrefix, PegOutBitcoinTransaction, PegOutBitcoinTransactionPrefix,
    PegOutNonceKey, PegOutTxSignatureCI, PegOutTxSignatureCIPrefix, PendingTransactionKey,
    PendingTransactionPrefixKey, UTXOKey, UTXOPrefixKey, UnsignedTransactionKey,
    UnsignedTransactionPrefixKey, UnspentTxOutKey, UnspentTxOutPrefix,
};
use fedimint_wallet_server::{PendingTransaction, UnsignedTransaction};
use futures::StreamExt;
use rand::rngs::OsRng;
use secp256k1::Message;
use strum::IntoEnumIterator;
use tracing::info;

use crate::WalletInit;

/// Legacy wallet module instance ID used in old federations.
/// This constant is only used for migration testing of old database
/// formats.
const LEGACY_WALLET_MODULE_INSTANCE_ID: ModuleInstanceId = 2;

/// Create a database with version 0 data. The database produced is not
/// intended to be real data or semantically correct. It is only
/// intended to provide coverage when reading the database
/// in future code versions. This function should not be updated when
/// database keys/values change - instead a new function should be added
/// that creates a new database backup that can be tested.
async fn create_server_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    dbtx.insert_new_entry(&BlockHashKey(BlockHash::from_byte_array(BYTE_32)), &())
        .await;

    let utxo = UTXOKey(bitcoin::OutPoint {
        txid: Txid::from_byte_array(BYTE_32),
        vout: 0,
    });
    let spendable_utxo = SpendableUTXO {
        tweak: BYTE_33,
        amount: Amount::from_sat(10000),
    };

    dbtx.insert_new_entry(&utxo, &spendable_utxo).await;

    dbtx.insert_new_entry(&PegOutNonceKey, &1).await;

    dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &1)
        .await;

    dbtx.insert_new_entry(
        &ConsensusVersionVoteKey(PeerId::from(0)),
        &ModuleConsensusVersion::new(2, 0),
    )
    .await;

    dbtx.insert_new_entry(
        &FeeRateVoteKey(PeerId::from(0)),
        &Feerate { sats_per_kvb: 10 },
    )
    .await;

    let unsigned_transaction_key = UnsignedTransactionKey(Txid::from_byte_array(BYTE_32));

    let selected_utxos: Vec<(UTXOKey, SpendableUTXO)> = vec![(utxo.clone(), spendable_utxo)];

    let destination = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_slice(&BYTE_20).unwrap());
    let output: Vec<TxOut> = vec![TxOut {
        value: bitcoin::Amount::from_sat(10_000),
        script_pubkey: destination.clone(),
    }];

    dbtx.insert_new_entry(&UnspentTxOutKey(utxo.0), &output[0])
        .await;

    dbtx.insert_new_entry(&ConsensusVersionVotingActivationKey, &())
        .await;

    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.0,
            script_sig: Default::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output,
    };

    let inputs = vec![Input {
        non_witness_utxo: None,
        witness_utxo: Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: destination.clone(),
        }),
        partial_sigs: Default::default(),
        sighash_type: None,
        redeem_script: None,
        witness_script: Some(destination.clone()),
        bip32_derivation: Default::default(),
        final_script_sig: None,
        final_script_witness: None,
        ripemd160_preimages: Default::default(),
        sha256_preimages: Default::default(),
        hash160_preimages: Default::default(),
        hash256_preimages: Default::default(),
        proprietary: Default::default(),
        tap_key_sig: Default::default(),
        tap_script_sigs: Default::default(),
        tap_scripts: Default::default(),
        tap_key_origins: Default::default(),
        tap_internal_key: Default::default(),
        tap_merkle_root: Default::default(),
        unknown: Default::default(),
    }];

    let psbt = Psbt {
        unsigned_tx: tx.clone(),
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs,
        outputs: vec![Default::default()],
    };

    let unsigned_transaction = UnsignedTransaction {
        psbt,
        signatures: vec![],
        change: Amount::from_sat(0),
        fees: PegOutFees {
            fee_rate: Feerate { sats_per_kvb: 1000 },
            total_weight: 40000,
        },
        destination: destination.clone(),
        selected_utxos: selected_utxos.clone(),
        peg_out_amount: Amount::from_sat(10000),
        rbf: None,
    };

    dbtx.insert_new_entry(&unsigned_transaction_key, &unsigned_transaction)
        .await;

    let pending_transaction_key = PendingTransactionKey(Txid::from_byte_array(BYTE_32));

    let pending_tx = PendingTransaction {
        tx,
        tweak: BYTE_33,
        change: Amount::from_sat(0),
        destination,
        fees: PegOutFees {
            fee_rate: Feerate { sats_per_kvb: 1000 },
            total_weight: 40000,
        },
        selected_utxos: selected_utxos.clone(),
        peg_out_amount: Amount::from_sat(10000),
        rbf: Some(Rbf {
            fees: PegOutFees {
                fee_rate: Feerate { sats_per_kvb: 1000 },
                total_weight: 40000,
            },
            txid: Txid::from_byte_array(BYTE_32),
        }),
    };
    dbtx.insert_new_entry(&pending_transaction_key, &pending_tx)
        .await;

    let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
    let secp = secp256k1::Secp256k1::new();
    let signature = secp.sign_ecdsa(&Message::from_digest_slice(&BYTE_32).unwrap(), &sk);
    dbtx.insert_new_entry(
        &PegOutTxSignatureCI(Txid::from_byte_array(BYTE_32)),
        &vec![signature],
    )
    .await;

    let peg_out_bitcoin_tx = PegOutBitcoinTransaction(OutPoint {
        txid: TransactionId::from_slice(&BYTE_32).unwrap(),
        out_idx: 0,
    });

    dbtx.insert_new_entry(
        &peg_out_bitcoin_tx,
        &WalletOutputOutcome::new_v0(Txid::from_slice(&BYTE_32).unwrap()),
    )
    .await;

    dbtx.commit_tx().await;
}

async fn create_client_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    dbtx.insert_new_entry(&NextPegInTweakIndexKey, &TweakIdx(2))
        .await;

    dbtx.commit_tx().await;
}

async fn create_server_db_with_v1_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_new_entry(
        &DatabaseVersionKey(LEGACY_WALLET_MODULE_INSTANCE_ID),
        &DatabaseVersion(1),
    )
    .await;

    dbtx.insert_new_entry(&ClaimedPegInOutpointKey(bitcoin::OutPoint::null()), &())
        .await;

    dbtx.insert_new_entry(
        &BlockHashByHeightKey(13),
        &BlockHashByHeightValue(BlockHash::from_byte_array(BYTE_32)),
    )
    .await;

    dbtx.commit_tx().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
    skip_if_not_wallet_test_group!("1");
    snapshot_db_migrations::<_, WalletCommonInit>("wallet-server-v0", |db| {
        Box::pin(async {
            create_server_db_with_v0_data(db.clone()).await;
            create_server_db_with_v1_data(db).await;
        })
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_db_migrations() -> anyhow::Result<()> {
    skip_if_not_wallet_test_group!("1");
    let _ = TracingSetup::default().init();

    let module = DynServerModuleInit::from(WalletInit);
    validate_migrations_server(module, "wallet-server", |db| async move {
        let mut dbtx = db.begin_transaction_nc().await;

        for prefix in DbKeyPrefix::iter() {
            match prefix {
                DbKeyPrefix::BlockHash => {
                    let blocks = dbtx
                        .find_by_prefix(&BlockHashKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_blocks = blocks.len();
                    ensure!(
                        num_blocks > 0,
                        "validate_migrations was not able to read any BlockHashes"
                    );
                    info!("Validated BlockHash");
                }
                DbKeyPrefix::BlockHashByHeight => {
                    let blocks = dbtx
                        .find_by_prefix(&BlockHashByHeightKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_blocks = blocks.len();
                    ensure!(
                        num_blocks == 1,
                        "validate_migrations was not able to read any BlockHashByHeightes"
                    );
                    info!("Validated BlockHashByHeight");
                }
                DbKeyPrefix::PegOutBitcoinOutPoint => {
                    let outpoints = dbtx
                        .find_by_prefix(&PegOutBitcoinTransactionPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_outpoints = outpoints.len();
                    ensure!(
                        num_outpoints > 0,
                        "validate_migrations was not able to read any PegOutBitcoinTransactions"
                    );
                    info!("Validated PegOutBitcoinOutPoint");
                }
                DbKeyPrefix::PegOutTxSigCi => {
                    let sigs = dbtx
                        .find_by_prefix(&PegOutTxSignatureCIPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_sigs = sigs.len();
                    ensure!(
                        num_sigs > 0,
                        "validate_migrations was not able to read any PegOutTxSigCi"
                    );
                    info!("Validated PegOutTxSigCi");
                }
                DbKeyPrefix::PendingTransaction => {
                    let pending_txs = dbtx
                        .find_by_prefix(&PendingTransactionPrefixKey)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_txs = pending_txs.len();
                    ensure!(
                        num_txs > 0,
                        "validate_migrations was not able to read any PendingTransactions"
                    );
                    info!("Validated PendingTransaction");
                }
                DbKeyPrefix::PegOutNonce => {
                    ensure!(dbtx.get_value(&PegOutNonceKey).await.is_some());
                    info!("Validated PegOutNonce");
                }
                DbKeyPrefix::UnsignedTransaction => {
                    let unsigned_txs = dbtx
                        .find_by_prefix(&UnsignedTransactionPrefixKey)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_txs = unsigned_txs.len();
                    ensure!(
                        num_txs > 0,
                        "validate_migrations was not able to read any UnsignedTransactions"
                    );
                    info!("Validated UnsignedTransaction");
                }
                DbKeyPrefix::Utxo => {
                    let utxos = dbtx
                        .find_by_prefix(&UTXOPrefixKey)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_utxos = utxos.len();
                    ensure!(
                        num_utxos > 0,
                        "validate_migrations was not able to read any UTXOs"
                    );
                    info!("Validated Utxo");
                }
                DbKeyPrefix::BlockCountVote => {
                    let heights = dbtx
                        .find_by_prefix(&BlockCountVotePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_heights = heights.len();
                    ensure!(
                        num_heights > 0,
                        "validate_migrations was not able to read any block height votes"
                    );
                    info!("Validated BlockCountVote");
                }
                DbKeyPrefix::FeeRateVote => {
                    let rates = dbtx
                        .find_by_prefix(&FeeRateVotePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_rates = rates.len();
                    ensure!(
                        num_rates > 0,
                        "validate_migrations was not able to read any fee rate votes"
                    );
                    info!("Validated FeeRateVote");
                }
                DbKeyPrefix::ClaimedPegInOutpoint => {
                    let claimed_peg_ins = dbtx
                        .find_by_prefix(&ClaimedPegInOutpointPrefixKey)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_peg_ins = claimed_peg_ins.len();
                    ensure!(
                        num_peg_ins > 0,
                        "validate_migrations was not able to read any claimed peg-in outpoints"
                    );
                    info!("Validated PeggedInOutpoint");
                }
                DbKeyPrefix::ConsensusVersionVote => {
                    let votes = dbtx
                        .find_by_prefix(&ConsensusVersionVotePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_votes = votes.len();
                    ensure!(
                        num_votes > 0,
                        "validate_migrations was not able to read any consensus version votes"
                    );
                    info!("Validated ConsensusVersionVote");
                }
                DbKeyPrefix::UnspentTxOut => {
                    let utxos = dbtx
                        .find_by_prefix(&UnspentTxOutPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_utxos = utxos.len();
                    ensure!(
                        num_utxos > 0,
                        "validate_migrations was not able to read any utxos"
                    );
                    info!("Validated UnspendTxOut");
                }
                DbKeyPrefix::ConsensusVersionVotingActivation => {
                    let activations = dbtx
                        .find_by_prefix(&ConsensusVersionVotingActivationPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_activations = activations.len();
                    ensure!(
                        num_activations > 0,
                        "validate_migrations was not able to read any version voting activation"
                    );
                    info!("Validated ConsensusVersionVotingActivation");
                }
                DbKeyPrefix::RecoveryItem => {
                    // Recovery items are new and won't be in old snapshots
                }
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
    skip_if_not_wallet_test_group!("1");
    snapshot_db_migrations_client::<_, _, WalletCommonInit>(
        "wallet-client-v0",
        |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
        || (Vec::new(), Vec::new()),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_db_migrations() -> anyhow::Result<()> {
    skip_if_not_wallet_test_group!("1");
    let _ = TracingSetup::default().init();

    let module = DynClientModuleInit::from(WalletClientInit::default());
    validate_migrations_client::<_, _, WalletClientModule>(
        module,
        "wallet-client",
        |db, _, _| async move {
            let mut dbtx = db.begin_transaction_nc().await;
            for prefix in client_db::DbKeyPrefix::iter() {
                match prefix {
                    client_db::DbKeyPrefix::NextPegInTweakIndex => {
                        let next_peg_in_tweak = dbtx.get_value(&NextPegInTweakIndexKey).await;
                        ensure!(
                            next_peg_in_tweak.is_some(),
                            "validate_migrations was not able to read any peg in tweak index"
                        );
                        info!("Validated next peg in tweak index");
                    }
                    client_db::DbKeyPrefix::PegInTweakIndex => {}
                    client_db::DbKeyPrefix::ClaimedPegIn => {}
                    client_db::DbKeyPrefix::RecoveryFinalized => {}
                    client_db::DbKeyPrefix::RecoveryState => {}
                    client_db::DbKeyPrefix::SupportsSafeDeposit => {}
                    client_db::DbKeyPrefix::PegInPoolCursor => {}
                    client_db::DbKeyPrefix::ExternalReservedStart
                    | client_db::DbKeyPrefix::CoreInternalReservedStart
                    | client_db::DbKeyPrefix::CoreInternalReservedEnd => {}
                }
            }

            Ok(())
        },
    )
    .await
}
