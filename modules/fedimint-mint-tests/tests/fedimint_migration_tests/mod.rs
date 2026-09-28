use std::collections::BTreeMap;

use anyhow::ensure;
use bls12_381::Scalar;
use fedimint_client::module_init::DynClientModuleInit;
use fedimint_client_module::module::init::recovery::{
    RecoveryFromHistory, RecoveryFromHistoryCommon,
};
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{
    Database, DatabaseVersion, DatabaseVersionKey, DatabaseVersionKeyV0,
    IDatabaseTransactionOpsCoreTyped, apply_migrations,
};
use fedimint_core::module::CommonModuleInit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::session_outcome::{
    AcceptedItem, ConsensusItem, SessionOutcome, SignedSessionOutcome,
};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::{
    Amount, BitcoinHash, OutPoint, PeerId, Tiered, TieredMulti, TransactionId, secp256k1,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::TracingSetup;
use fedimint_mint_client::backup::recovery::{
    MintRecovery, MintRecoveryState, MintRecoveryStateV2,
};
use fedimint_mint_client::backup::{EcashBackup, EcashBackupV0};
use fedimint_mint_client::client_db::{
    CancelledOOBSpendKey, CancelledOOBSpendKeyPrefix, NextECashNoteIndexKey,
    NextECashNoteIndexKeyPrefix, NoteKey, NoteKeyPrefix, RecoveryFinalizedKey, RecoveryStateKey,
};
use fedimint_mint_client::output::NoteIssuanceRequest;
use fedimint_mint_client::{MintClientInit, MintClientModule, NoteIndex, SpendableNote};
use fedimint_mint_common::{BlindNonce, MintCommonInit, MintOutput, MintOutputOutcome, Nonce};
use fedimint_mint_server::db::{
    DbKeyPrefix, MintAuditItemKey, MintAuditItemKeyPrefix, MintOutputOutcomeKey,
    MintOutputOutcomePrefix, NonceKey, NonceKeyPrefix, RecoveryBlindNonceOutpointKey,
};
use fedimint_server::consensus::db::{ServerDbMigrationContext, SignedSessionOutcomeKey};
use fedimint_server::core::DynServerModuleInit;
use fedimint_testing::db::{
    BYTE_8, BYTE_32, TEST_MODULE_INSTANCE_ID, snapshot_db_migrations,
    snapshot_db_migrations_client, validate_migrations_client, validate_migrations_server,
};
use ff::Field;
use futures::StreamExt;
use rand::rngs::OsRng;
use secp256k1::Keypair;
use strum::IntoEnumIterator;
use tbs::{
    AggregatePublicKey, BlindingKey, Message, PublicKeyShare, SecretKeyShare, Signature,
    blind_message, sign_message,
};
use threshold_crypto::{G1Affine, G2Affine};
use tracing::info;

use crate::MintInit;

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

    let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
    let nonce_key = NonceKey(Nonce(pk));
    dbtx.insert_new_entry(&nonce_key, &()).await;

    let out_point = OutPoint {
        txid: TransactionId::from_slice(&BYTE_32).unwrap(),
        out_idx: 0,
    };

    let blinding_key = BlindingKey::random();
    let message = Message::from_bytes(&BYTE_8);
    let blinded_message = blind_message(message, blinding_key);
    let secret_key_share = SecretKeyShare(Scalar::random(&mut OsRng));
    let blind_signature_share = sign_message(blinded_message, secret_key_share);
    dbtx.insert_new_entry(
        &MintOutputOutcomeKey(out_point),
        &MintOutputOutcome::new_v0(blind_signature_share),
    )
    .await;

    let mint_audit_issuance = MintAuditItemKey::Issuance(out_point);
    let mint_audit_issuance_total = MintAuditItemKey::IssuanceTotal;
    let mint_audit_redemption = MintAuditItemKey::Redemption(nonce_key);
    let mint_audit_redemption_total = MintAuditItemKey::RedemptionTotal;

    dbtx.insert_new_entry(&mint_audit_issuance, &Amount::from_sats(1000))
        .await;
    dbtx.insert_new_entry(&mint_audit_issuance_total, &Amount::from_sats(5000))
        .await;
    dbtx.insert_new_entry(&mint_audit_redemption, &Amount::from_sats(10000))
        .await;
    dbtx.insert_new_entry(&mint_audit_redemption_total, &Amount::from_sats(15000))
        .await;

    dbtx.commit_tx().await;
}

async fn create_client_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    let (_, pubkey) = secp256k1::generate_keypair(&mut OsRng);
    let keypair = Keypair::new_global(&mut OsRng);

    let sig = Signature(G1Affine::generator());

    let spendable_note = SpendableNote {
        signature: sig,
        spend_key: keypair,
    };

    dbtx.insert_new_entry(
        &NoteKey {
            amount: Amount::from_sats(1000),
            nonce: Nonce(pubkey),
        },
        &spendable_note.to_undecoded(),
    )
    .await;

    dbtx.insert_new_entry(&NextECashNoteIndexKey(Amount::from_sats(1000)), &3)
        .await;

    dbtx.insert_new_entry(&CancelledOOBSpendKey(OperationId(BYTE_32)), &())
        .await;

    let mut spendable_notes = BTreeMap::new();
    spendable_notes.insert(Nonce(pubkey), (Amount::from_sats(1000), spendable_note));

    let key_share = PublicKeyShare(G2Affine::generator());
    let agg_pub_key = AggregatePublicKey(G2Affine::generator());
    let secret = DerivableSecret::new_root(&BYTE_8, &BYTE_8)
        .child_key(ChildId(0))
        .child_key(ChildId(1));
    let mut pub_key_shares = BTreeMap::new();
    let mut keys = Tiered::default();
    keys.insert(Amount::from_sats(1000), key_share);
    pub_key_shares.insert(1.into(), keys);

    let mut tbs_pks = Tiered::default();
    tbs_pks.insert(Amount::from_sats(1000), agg_pub_key);

    let backup = create_ecash_backup_v0(spendable_note, secret.clone());

    let mint_recovery_state = MintRecoveryState::V2(MintRecoveryStateV2::from_backup(
        backup,
        10,
        tbs_pks,
        pub_key_shares,
        &secret,
    ));

    MintRecovery::store_finalized(&mut dbtx.to_ref_nc(), true).await;
    dbtx.insert_new_entry(
        &RecoveryStateKey,
        &(mint_recovery_state, RecoveryFromHistoryCommon::new(0, 0, 0)),
    )
    .await;

    dbtx.commit_tx().await;
}

fn create_ecash_backup_v0(note: SpendableNote, secret: DerivableSecret) -> EcashBackupV0 {
    let mut map = BTreeMap::new();
    map.insert(Amount::from_sats(100), vec![note]);
    let spendable_notes = TieredMulti::new(map);
    let pending_note = (
        OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).expect("TransactionId from slice failed"),
            out_idx: 0,
        },
        Amount::from_sats(10000),
        NoteIssuanceRequest::new(secp256k1::SECP256K1, &secret).0,
    );
    let pending_notes = vec![pending_note];
    let session_count = 0;
    let mut next_note_idx = Tiered::default();
    next_note_idx.insert(Amount::from_sats(1000), NoteIndex::from_u64(3));

    let backup = EcashBackup::new_v0(spendable_notes, pending_notes, session_count, next_note_idx);

    match backup {
        EcashBackup::V0(v0) => v0,
        _ => panic!("Expected V0 ecash backup"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations::<_, MintCommonInit>("mint-server-v0", |db| {
        Box::pin(async {
            create_server_db_with_v0_data(db).await;
        })
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_db_migrations() -> anyhow::Result<()> {
    let _ = TracingSetup::default().init();

    let module = DynServerModuleInit::from(MintInit);
    validate_migrations_server(module, "mint-server", |db| async move {
        let mut dbtx = db.begin_transaction_nc().await;

        for prefix in DbKeyPrefix::iter() {
            match prefix {
                DbKeyPrefix::NoteNonce => {
                    let nonces = dbtx
                        .find_by_prefix(&NonceKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_nonces = nonces.len();
                    ensure!(
                        num_nonces > 0,
                        "validate_migrations was not able to read any NoteNonces"
                    );
                    info!("Validated NoteNonce");
                }
                DbKeyPrefix::OutputOutcome => {
                    let outcomes = dbtx
                        .find_by_prefix(&MintOutputOutcomePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_outcomes = outcomes.len();
                    ensure!(
                        num_outcomes > 0,
                        "validate_migrations was not able to read any OutputOutcomes"
                    );
                    info!("Validated OutputOutcome");
                }
                DbKeyPrefix::MintAuditItem => {
                    let audit_items = dbtx
                        .find_by_prefix(&MintAuditItemKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;
                    let num_items = audit_items.len();
                    ensure!(
                        num_items > 0,
                        "validate_migrations was not able to read any MintAuditItems"
                    );
                    info!("Validated MintAuditItem");
                }
                DbKeyPrefix::BlindNonce => {
                    // Would require an entire re-design of the way we test
                    // here, manually testing instead for now
                }
                DbKeyPrefix::RecoveryItem => {
                    // New prefix for slice-based recovery, no migration
                    // needed
                }
                DbKeyPrefix::RecoveryBlindNonceOutpoint => {
                    // New prefix for slice-based recovery, no migration
                    // needed
                }
            }
        }

        Ok(())
    })
    .await
}

// Regression test for #8582: `migrate_db_v2` walks `ModuleHistoryItem`s
// assembled from `SignedSessionOutcome`s and used to call
// `insert_new_entry(RecoveryBlindNonceOutpointKey, _)`, which panics on a
// duplicate. Federations that had previously accepted a duplicate blind
// nonce therefore failed to migrate on the v0.11.0 -> v0.11.1 upgrade —
// that on-upgrade crash is what motivated cutting v0.11.1.
//
// Seed a session outcome containing one transaction with two `MintOutput`s
// that share a blind nonce, pin the on-disk db version to 2 so
// `apply_migrations` actually runs `migrate_db_v2`, and assert it
// completes without panic.
#[tokio::test(flavor = "multi_thread")]
async fn test_migrate_db_v2_handles_duplicate_blind_nonce() -> anyhow::Result<()> {
    use std::sync::Arc;

    let _ = TracingSetup::default().init();

    let decoders = ModuleDecoderRegistry::from_iter([(
        TEST_MODULE_INSTANCE_ID,
        MintCommonInit::KIND,
        MintCommonInit::decoder(),
    )]);
    let db = Database::new(MemDatabase::new(), decoders);

    let blind_nonce = BlindNonce(blind_message(
        Message::from_bytes(&BYTE_8),
        BlindingKey::random(),
    ));
    let mint_output = MintOutput::new_v0(Amount::from_sats(1), blind_nonce);
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![
            mint_output.clone().into_dyn(TEST_MODULE_INSTANCE_ID),
            mint_output.into_dyn(TEST_MODULE_INSTANCE_ID),
        ],
        nonce: [0u8; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    let txid = tx.tx_hash();

    let signed_outcome = SignedSessionOutcome {
        session_outcome: SessionOutcome {
            items: vec![AcceptedItem {
                item: ConsensusItem::Transaction(tx),
                peer: PeerId::from(0),
            }],
        },
        signatures: BTreeMap::new(),
    };

    // Seed global namespace with the session-outcome record, and pin the
    // module's DB version to 2 so `apply_migrations` runs `migrate_db_v2`.
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&SignedSessionOutcomeKey(0), &signed_outcome)
        .await;
    dbtx.insert_new_entry(
        &DatabaseVersionKey(TEST_MODULE_INSTANCE_ID),
        &DatabaseVersion(2),
    )
    .await;
    dbtx.commit_tx().await;

    // Pre-fix, this panics on the duplicate via `insert_new_entry`.
    let module = DynServerModuleInit::from(MintInit);
    apply_migrations(
        &db,
        Arc::new(ServerDbMigrationContext) as Arc<_>,
        module.module_kind().to_string(),
        module.get_database_migrations(),
        Some(TEST_MODULE_INSTANCE_ID),
        None,
    )
    .await?;

    // Sanity-check the backfill: the recovery index must be populated, and
    // — since `insert_entry` overwrites — it must hold the second outpoint
    // (last-writer wins), consistent with the unit test in
    // `fedimint-mint-server`.
    let module_db = db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID).0;
    let mut module_dbtx = module_db.begin_transaction_nc().await;
    let entry = module_dbtx
        .get_value(&RecoveryBlindNonceOutpointKey(blind_nonce))
        .await;
    ensure!(
        entry == Some(OutPoint { txid, out_idx: 1 }),
        "migrate_db_v2 must backfill the recovery index (last-writer wins): got {entry:?}",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations_client::<_, _, MintCommonInit>(
        "mint-client-v0",
        |dbtx| Box::pin(async { create_client_db_with_v0_data(dbtx).await }),
        || (Vec::new(), Vec::new()),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_db_migrations() -> anyhow::Result<()> {
    let _ = TracingSetup::default().init();

    let module = DynClientModuleInit::from(MintClientInit);
    validate_migrations_client::<_, _, MintClientModule>(
        module,
        "mint-client",
        |db, _, _| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in fedimint_mint_client::client_db::DbKeyPrefix::iter() {
                match prefix {
                    fedimint_mint_client::client_db::DbKeyPrefix::Note => {
                        let notes = dbtx
                            .find_by_prefix(&NoteKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_notes = notes.len();
                        ensure!(
                            num_notes > 0,
                            "validate_migrations was not able to read any Notes"
                        );
                        info!("Validated Notes");
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::NextECashNoteIndex => {
                        let next_index = dbtx
                            .find_by_prefix(&NextECashNoteIndexKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_next_indices = next_index.len();
                        ensure!(
                            num_next_indices > 0,
                            "validate_migrations was not able to read any NextECashNoteIndices"
                        );
                        info!("Validated NextECashNoteIndex");
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::CancelledOOBSpend => {
                        let canceled_spend = dbtx
                            .find_by_prefix(&CancelledOOBSpendKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_cancel_spends = canceled_spend.len();
                        ensure!(
                            num_cancel_spends > 0,
                            "validate_migrations was not able to read any CancelledOOBSpendKeys"
                        );
                        info!("Validated CancelledOOBSpendKey");
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::RecoveryState => {
                        let restore_state = dbtx.get_value(&RecoveryStateKey).await;
                        ensure!(
                            restore_state.is_none(),
                            "validate_migrations expect the restore state to get deleted"
                        );
                        info!("Validated RecoveryState");
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::RecoveryFinalized => {
                        let recovery_finalized = dbtx.get_value(&RecoveryFinalizedKey).await;
                        ensure!(
                            recovery_finalized.is_some(),
                            "validate_migrations was not able to read any RecoveryFinalized"
                        );
                        info!("Validated RecoveryFinalized");
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::ReusedNoteIndices => {}
                    fedimint_mint_client::client_db::DbKeyPrefix::RecoveryStateV2 => {
                        // New prefix for slice-based recovery, no migration
                        // needed
                    }
                    fedimint_mint_client::client_db::DbKeyPrefix::ExternalReservedStart
                    | fedimint_mint_client::client_db::DbKeyPrefix::CoreInternalReservedEnd
                    | fedimint_mint_client::client_db::DbKeyPrefix::CoreInternalReservedStart => {}
                }
            }

            Ok(())
        },
    )
    .await
}
