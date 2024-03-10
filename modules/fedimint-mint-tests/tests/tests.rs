use std::io::Cursor;
use std::time::Duration;

use fedimint_client::backup::{ClientBackup, Metadata};
use fedimint_core::config::EmptyGenParams;
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, OOBNotes, ReissueExternalNotesState, SpendOOBState,
};
use fedimint_mint_common::config::{FeeConsensus, MintGenParams, MintGenParamsConsensus};
use fedimint_mint_server::MintInit;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};
use futures::StreamExt;
use tracing::info;

const EXPECTED_MAXIMUM_FEE: Amount = Amount::from_sats(50);

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(
        MintClientInit,
        MintInit,
        MintGenParams {
            consensus: MintGenParamsConsensus::new(
                2,
                FeeConsensus {
                    note_issuance_abs: Amount::ZERO,
                    note_spend_abs: Amount::from_sats(1),
                },
            ),
            local: EmptyGenParams {},
        },
    );

    fixtures.with_module(DummyClientInit, DummyInit, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let client1_mint = client1.get_first_module::<MintClientModule>();
    let client2_mint = client2.get_first_module::<MintClientModule>();
    info!("### SPEND NOTES");
    let (op, notes) = client1_mint
        .spend_notes(sats(750), TIMEOUT, false, ())
        .await?;
    let sub1 = &mut client1_mint.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    info!("### REISSUE");
    let op = client2_mint.reissue_external_notes(notes, ()).await?;
    let sub2 = client2_mint.subscribe_reissue_external_notes(op).await?;
    let mut sub2 = sub2.into_stream();
    info!("### SUB2: WAIT CREATED");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Created);
    info!("### SUB2: WAIT ISSUING");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Issuing);
    info!("### SUB2: WAIT DONE");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Done);
    info!("### SUB1: WAIT SUCCESS");
    assert_eq!(sub1.ok().await?, SpendOOBState::Success);
    info!("### REISSUE: DONE");

    assert!(client1.get_balance().await >= sats(250) - EXPECTED_MAXIMUM_FEE);
    assert!(client2.get_balance().await >= sats(750) - EXPECTED_MAXIMUM_FEE);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_oob_highly_parallel() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let client1 = fed.new_client_rocksdb().await;
    let client2 = fed.new_client_rocksdb().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // We currently have a limit on DB retries, if this number is increased too much
    // we might hit it
    const NUM_PAR: u64 = 10;
    // Tests are prety slow in CI, using the default 10s timeout worked locally but
    // failed in CI
    const ECASH_TIMEOUT: Duration = Duration::from_secs(60);

    // Spend from client1 to client2 10 times in parallel
    let mut spend_tasks = vec![];
    for num_spend in 0..NUM_PAR {
        let task_client1 = client1.clone();
        spend_tasks.push(
            fedimint_core::task::spawn(&format!("spend_ecash_{num_spend}"), async move {
                info!("Starting spend {num_spend}");
                let client1_mint = task_client1.get_first_module::<MintClientModule>();
                let (op, notes) = client1_mint
                    .spend_notes(sats(30), ECASH_TIMEOUT, false, ())
                    .await
                    .unwrap();
                let sub1 = &mut client1_mint
                    .subscribe_spend_notes(op)
                    .await
                    .unwrap()
                    .into_stream();
                assert_eq!(sub1.ok().await.unwrap(), SpendOOBState::Created);
                notes
            })
            .expect("Returns a handle if not run in WASM"),
        );
    }

    let note_bags = futures::stream::iter(spend_tasks)
        .then(|handle| async move { handle.await.expect("Spend task failed") })
        .collect::<Vec<_>>()
        .await;
    // Since we are overspending as soon as the right denominations aren't available
    // anymore we have to use the amount actually sent and not the one requested
    let total_amount_spent: Amount = note_bags.iter().map(|bag| bag.total_amount()).sum();

    assert_eq!(client1.get_balance().await, sats(1000) - total_amount_spent);

    info!(%total_amount_spent, "Sent notes");

    let mut reissue_tasks = vec![];
    for (num_reissue, notes) in note_bags.into_iter().enumerate() {
        let task_client2 = client2.clone();
        reissue_tasks.push(
            fedimint_core::task::spawn(&format!("reissue_ecash_{num_reissue}"), async move {
                info!("Starting reissue {num_reissue}");
                let client2_mint = task_client2.get_first_module::<MintClientModule>();
                let op = client2_mint
                    .reissue_external_notes(notes, ())
                    .await
                    .unwrap();
                let sub2 = client2_mint
                    .subscribe_reissue_external_notes(op)
                    .await
                    .unwrap();
                let mut sub2 = sub2.into_stream();
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Created);
                info!("Reissuance {num_reissue} created");
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Issuing);
                info!("Reissuance {num_reissue} accepted");
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Done);
                info!("Reissuance {num_reissue} finished");
            })
            .expect("Returns a handle if not run in WASM"),
        );
    }

    for task in reissue_tasks {
        task.await.expect("reissue task failed");
    }

    assert!(client2.get_balance().await >= total_amount_spent - EXPECTED_MAXIMUM_FEE);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_encode_decode_roundtrip() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    let backup = client1.create_backup(Metadata::empty()).await?;

    let backup_bin = fedimint_core::encoding::Encodable::consensus_encode_to_vec(&backup);

    let backup_decoded: ClientBackup = fedimint_core::encoding::Decodable::consensus_decode(
        &mut Cursor::new(&backup_bin),
        client1.decoders(),
    )
    .expect("decode");

    assert_eq!(backup, backup_decoded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band_cancel() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;
    let dummy_module = client.get_first_module::<DummyClientModule>();
    let (op, outpoint) = dummy_module.print_money(sats(1000)).await?;
    client.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let mint_module = client.get_first_module::<MintClientModule>();
    let (op, _) = mint_module
        .spend_notes(sats(750), TIMEOUT, false, ())
        .await?;
    let sub1 = &mut mint_module.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    mint_module.try_cancel_spend_notes(op).await;
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledProcessing);
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledSuccess);

    info!("Refund tx accepted, waiting for refunded e-cash");

    // FIXME: UserCanceledSuccess should mean the money is in our wallet
    for _ in 0..200 {
        sleep_in_test("sats not in wallet yet", Duration::from_millis(100)).await;
        if client.get_balance().await >= sats(1000) - EXPECTED_MAXIMUM_FEE {
            return Ok(());
        }
    }

    panic!("Did not receive refund in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_spend() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()
        .spend_notes(Amount::ZERO, TIMEOUT, false, ())
        .await
        .expect_err("Zero-amount spends should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_receive() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()
        .reissue_external_notes(
            OOBNotes::new(client1.federation_id().to_prefix(), Default::default()),
            (),
        )
        .await
        .expect_err("Zero-amount receives should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;

    use anyhow::ensure;
    use bitcoin_hashes::Hash;
    use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
    use fedimint_client::module::init::recovery::{RecoveryFromHistory, RecoveryFromHistoryCommon};
    use fedimint_client::module::init::DynClientModuleInit;
    use fedimint_core::core::OperationId;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::module::DynServerModuleInit;
    use fedimint_core::time::now;
    use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_mint_client::backup::recovery::{MintRecovery, MintRecoveryState};
    use fedimint_mint_client::backup::{EcashBackup, EcashBackupV0};
    use fedimint_mint_client::client_db::{
        CancelledOOBSpendKey, CancelledOOBSpendKeyPrefix, NextECashNoteIndexKey,
        NextECashNoteIndexKeyPrefix, NoteKey, NoteKeyPrefix, RecoveryStateKey,
    };
    use fedimint_mint_client::output::NoteIssuanceRequest;
    use fedimint_mint_client::{MintClientInit, MintClientModule, NoteIndex, SpendableNote};
    use fedimint_mint_common::db::{
        DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix,
        MintAuditItemKey, MintAuditItemKeyPrefix, MintOutputOutcomeKey, MintOutputOutcomePrefix,
        NonceKey, NonceKeyPrefix,
    };
    use fedimint_mint_common::{MintCommonInit, MintOutputOutcome, Nonce};
    use fedimint_testing::db::{
        snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
        validate_migrations_server, BYTE_32, BYTE_8,
    };
    use ff::Field;
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use secp256k1::KeyPair;
    use strum::IntoEnumIterator;
    use tbs::{
        blind_message, sign_blinded_msg, AggregatePublicKey, BlindingKey, Message, PublicKeyShare,
        Scalar, SecretKeyShare, Signature,
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
        let blind_signature_share = sign_blinded_msg(blinded_message, secret_key_share);
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

        let backup_key = EcashBackupKey(pk);
        let ecash_backup = ECashUserBackupSnapshot {
            timestamp: now(),
            data: BYTE_32.to_vec(),
        };
        dbtx.insert_new_entry(&backup_key, &ecash_backup).await;

        dbtx.commit_tx().await;
    }

    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        let (_, pubkey) = secp256k1::generate_keypair(&mut OsRng);
        let keypair = KeyPair::new_global(&mut OsRng);

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
            &spendable_note,
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

        let mint_recovery_state =
            MintRecoveryState::from_backup(backup, 10, tbs_pks, pub_key_shares, &secret);

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
            NoteIssuanceRequest::new(secp256k1::SECP256K1, secret).0,
        );
        let pending_notes = vec![pending_note];
        let session_count = 0;
        let mut next_note_idx = Tiered::default();
        next_note_idx.insert(Amount::from_sats(1000), NoteIndex::from_u64(3));

        let backup =
            EcashBackup::new_v0(spendable_notes, pending_notes, session_count, next_note_idx);

        match backup {
            EcashBackup::V0(v0) => v0,
            _ => panic!("Expected V0 ecash backup"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, MintCommonInit>("mint-server-v0", |db| {
            Box::pin(async move {
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
                    DbKeyPrefix::EcashBackup => {
                        let backups = dbtx
                            .find_by_prefix(&EcashBackupKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_backups = backups.len();
                        ensure!(
                            num_backups > 0,
                            "validate_migrations was not able to read any EcashBackups"
                        );
                        info!("Validated EcashBackup");
                    }
                }
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, MintCommonInit, MintClientModule>(
            "mint-client-v0",
            |dbtx| Box::pin(async move { create_client_db_with_v0_data(dbtx).await }),
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
                                restore_state.is_some(),
                                "validate_migrations was not able to read any RecoveryState"
                            );
                            info!("Validated RecoveryState");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::RecoveryFinalized => {
                            let recovery_finalized = dbtx.get_value(&RecoveryStateKey).await;
                            ensure!(
                                recovery_finalized.is_some(),
                                "validate_migrations was not able to read any RecoveryFinalized"
                            );
                            info!("Validated RecoveryFinalized");
                        }
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
