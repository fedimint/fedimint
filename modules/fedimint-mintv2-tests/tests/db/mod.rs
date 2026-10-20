use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, ensure};
use bitcoin_hashes::{Hash as _, hash160};
use bls12_381::G1Affine;
use fedimint_client::module_init::DynClientModuleInit;
use fedimint_core::db::{
    Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::{OutPoint, TransactionId};
use fedimint_logging::TracingSetup;
use fedimint_mintv2_client::client_db::{
    self, RecoveryState, RecoveryStateKey, SpendableNoteKey, SpendableNotePrefix,
};
use fedimint_mintv2_client::issuance::NoteIssuanceRequest;
use fedimint_mintv2_common::{MintCommonInit, RecoveryItem};
use fedimint_mintv2_server::db::{
    BlindedSignatureShareKey, BlindedSignatureSharePrefix, BlindedSignatureShareRecoveryKey,
    BlindedSignatureShareRecoveryPrefix, DbKeyPrefix, IssuanceCounterKey, IssuanceCounterPrefix,
    NonceKey, NonceKeyPrefix, RecoveryItemKey, RecoveryItemPrefix,
};
use fedimint_server_core::DynServerModuleInit;
use fedimint_testing::db::{
    BYTE_32, snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
    validate_migrations_server,
};
use futures::StreamExt;
use strum::IntoEnumIterator;
use tbs::{BlindedMessage, BlindedSignatureShare, BlindingKey};

use crate::{Denomination, MintClientInit, MintClientModule, MintInit, SpendableNote};

/// The denomination every seeded record is filed under, so the validation
/// closure can look the records back up by an exact key.
const DENOMINATION: Denomination = Denomination(10);

/// A keypair derived from a repeated byte, so the snapshot is reproducible.
fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[seed; 32])
        .expect("a repeated non-zero byte is a valid secret key")
}

/// The transaction id every seeded record refers to. Nothing in these tests
/// looks the transaction up, it only has to survive a database round-trip.
fn txid() -> TransactionId {
    TransactionId::from_slice(&BYTE_32).expect("BYTE_32 is 32 bytes long")
}

/// A note that is only well-formed enough to survive a database round-trip;
/// the signature is not a valid threshold signature over the nonce.
fn spendable_note(seed: u8) -> SpendableNote {
    SpendableNote {
        denomination: DENOMINATION,
        keypair: keypair(seed),
        signature: tbs::Signature(G1Affine::generator()),
    }
}

fn issuance_request(seed: u8) -> NoteIssuanceRequest {
    NoteIssuanceRequest {
        denomination: DENOMINATION,
        tweak: [seed; 16],
        keypair: keypair(seed),
        blinding_key: BlindingKey(bls12_381::Scalar::from(u64::from(seed) + 1)),
    }
}

fn nonce_hash(seed: u8) -> hash160::Hash {
    hash160::Hash::hash(&[seed; 32])
}

/// Create a database with version 0 data. The database produced is not
/// intended to be real data or semantically correct. It is only intended to
/// provide coverage when reading the database in future code versions. This
/// function should not be updated when database keys or values change -
/// instead a new function should be added that creates a new database
/// backup that can be tested.
///
/// mintv2 has no server migrations yet, so what the paired test asserts is
/// that every one of these rows still decodes under current code.
async fn create_server_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
    dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
        .await;

    dbtx.insert_new_entry(&NonceKey(keypair(1).public_key()), &())
        .await;

    dbtx.insert_new_entry(
        &BlindedSignatureShareKey(OutPoint {
            txid: txid(),
            out_idx: 0,
        }),
        &BlindedSignatureShare(G1Affine::generator()),
    )
    .await;

    dbtx.insert_new_entry(
        &BlindedSignatureShareRecoveryKey(BlindedMessage(G1Affine::generator())),
        &BlindedSignatureShare(G1Affine::generator()),
    )
    .await;

    dbtx.insert_new_entry(&IssuanceCounterKey(DENOMINATION), &7)
        .await;

    // Both variants, since they encode differently and a change to either
    // would only show up if both are on disk.
    dbtx.insert_new_entry(
        &RecoveryItemKey(0),
        &RecoveryItem::Output {
            denomination: DENOMINATION,
            nonce_hash: nonce_hash(1),
            tweak: [1; 16],
        },
    )
    .await;

    dbtx.insert_new_entry(
        &RecoveryItemKey(1),
        &RecoveryItem::Input {
            nonce_hash: nonce_hash(2),
        },
    )
    .await;

    dbtx.commit_tx().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations::<_, MintCommonInit>("mintv2-server-v0", |db| {
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

    validate_migrations_server(module, "mintv2-server", |db| async move {
        let mut dbtx = db.begin_transaction_nc().await;

        // Matching every variant explicitly, with no catch-all, is the point of this
        // pattern: adding a new prefix breaks the build here until someone decides
        // how the migration test should cover it.
        for prefix in DbKeyPrefix::iter() {
            match prefix {
                DbKeyPrefix::NoteNonce => {
                    let nonces = dbtx
                        .find_by_prefix(&NonceKeyPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    ensure!(
                        nonces.len() == 1,
                        "the seeded spent nonce must still decode, got {} entries",
                        nonces.len()
                    );
                    ensure!(
                        nonces[0].0.0 == keypair(1).public_key(),
                        "the nonce must round-trip unchanged"
                    );
                }
                DbKeyPrefix::BlindedSignatureShare => {
                    let shares = dbtx
                        .find_by_prefix(&BlindedSignatureSharePrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    ensure!(
                        shares.len() == 1,
                        "the seeded signature share must still decode, got {} entries",
                        shares.len()
                    );
                    ensure!(
                        shares[0].1 == BlindedSignatureShare(G1Affine::generator()),
                        "the signature share must round-trip unchanged"
                    );
                }
                DbKeyPrefix::BlindedSignatureShareRecovery => {
                    let shares = dbtx
                        .find_by_prefix(&BlindedSignatureShareRecoveryPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    ensure!(
                        shares.len() == 1,
                        "the seeded recovery signature share must still decode, got {} \
                         entries",
                        shares.len()
                    );
                    ensure!(
                        shares[0].0.0 == BlindedMessage(G1Affine::generator()),
                        "the blinded message key must round-trip unchanged"
                    );
                }
                DbKeyPrefix::MintAuditItem => {
                    let counter = dbtx
                        .get_value(&IssuanceCounterKey(DENOMINATION))
                        .await
                        .context("the seeded issuance counter must still decode")?;

                    ensure!(
                        counter == 7,
                        "the issuance counter must round-trip unchanged, got {counter}"
                    );

                    let counters = dbtx
                        .find_by_prefix(&IssuanceCounterPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    ensure!(
                        counters.len() == 1,
                        "exactly one denomination was seeded, got {} entries",
                        counters.len()
                    );
                }
                DbKeyPrefix::RecoveryItem => {
                    let items = dbtx
                        .find_by_prefix(&RecoveryItemPrefix)
                        .await
                        .collect::<Vec<_>>()
                        .await;

                    ensure!(
                        items.len() == 2,
                        "both seeded recovery items must still decode, got {} entries",
                        items.len()
                    );
                    ensure!(
                        items[0].1
                            == RecoveryItem::Output {
                                denomination: DENOMINATION,
                                nonce_hash: nonce_hash(1),
                                tweak: [1; 16],
                            },
                        "the output recovery item must round-trip unchanged"
                    );
                    ensure!(
                        items[1].1
                            == RecoveryItem::Input {
                                nonce_hash: nonce_hash(2),
                            },
                        "the input recovery item must round-trip unchanged"
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

    dbtx.insert_new_entry(&SpendableNoteKey(spendable_note(1).into()), &())
        .await;

    dbtx.insert_new_entry(
        &RecoveryStateKey,
        &RecoveryState {
            next_index: 3,
            total_items: 10,
            requests: BTreeMap::from([(nonce_hash(1), issuance_request(1))]),
            nonces: BTreeSet::from([nonce_hash(2)]),
        },
    )
    .await;

    dbtx.commit_tx().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations_client::<_, _, MintCommonInit>(
        "mintv2-client-v0",
        |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
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
        "mintv2-client",
        |db, _, _| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in client_db::DbKeyPrefix::iter() {
                match prefix {
                    client_db::DbKeyPrefix::Note => {
                        let notes = dbtx
                            .find_by_prefix(&SpendableNotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            notes.len() == 1,
                            "the seeded spendable note must still decode, got {} entries",
                            notes.len()
                        );
                        ensure!(
                            notes[0].0.0.decode().ok() == Some(spendable_note(1)),
                            "the spendable note must round-trip unchanged"
                        );
                    }
                    client_db::DbKeyPrefix::RecoveryState => {
                        let state = dbtx
                            .get_value(&RecoveryStateKey)
                            .await
                            .context("the seeded recovery state must still decode")?;

                        ensure!(
                            state.next_index == 3 && state.total_items == 10,
                            "the recovery progress must round-trip unchanged, got {}/{}",
                            state.next_index,
                            state.total_items
                        );
                        ensure!(
                            state.requests
                                == BTreeMap::from([(nonce_hash(1), issuance_request(1))]),
                            "the pending issuance requests must round-trip unchanged"
                        );
                        ensure!(
                            state.nonces == BTreeSet::from([nonce_hash(2)]),
                            "the seen nonces must round-trip unchanged"
                        );
                    }
                }
            }

            Ok(())
        },
    )
    .await
}
