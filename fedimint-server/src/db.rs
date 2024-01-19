use std::fmt::Debug;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped, MigrationMap,
    MODULE_GLOBAL_PREFIX,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::{impl_db_lookup, impl_db_record, TransactionId};
use futures::FutureExt;
use serde::Serialize;
use strum_macros::EnumIter;

pub const GLOBAL_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedSessionOutcome = 0x04,
    AlephUnits = 0x05,
    SignedSessionOutcomeCount = 0x06,
    Module = MODULE_GLOBAL_PREFIX,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct AcceptedItemPrefix;

impl_db_record!(
    key = AcceptedItemKey,
    value = AcceptedItem,
    db_prefix = DbKeyPrefix::AcceptedItem,
    notify_on_modify = false,
);
impl_db_lookup!(key = AcceptedItemKey, query_prefix = AcceptedItemPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl_db_record!(
    key = AcceptedTransactionKey,
    value = Vec<ModuleInstanceId>,
    db_prefix = DbKeyPrefix::AcceptedTransaction,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = AcceptedTransactionKey,
    query_prefix = AcceptedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomeKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomePrefix;

impl_db_record!(
    key = SignedSessionOutcomeKey,
    value = SignedSessionOutcome,
    db_prefix = DbKeyPrefix::SignedSessionOutcome,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = SignedSessionOutcomeKey,
    query_prefix = SignedSessionOutcomePrefix
);

/// Database entry that caches the current number of [`SignedSessionOutcome`]s
/// in the database.
#[derive(Debug, Encodable, Decodable)]
pub struct SignedSessionOutcomeCountKey;

impl_db_record!(
    key = SignedSessionOutcomeCountKey,
    value = u64,
    db_prefix = DbKeyPrefix::SignedSessionOutcomeCount,
);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct AlephUnitsPrefix;

impl_db_record!(
    key = AlephUnitsKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::AlephUnits,
    notify_on_modify = false,
);
impl_db_lookup!(key = AlephUnitsKey, query_prefix = AlephUnitsPrefix);

pub fn get_global_database_migrations() -> MigrationMap {
    let mut mm = MigrationMap::new();
    mm.insert(DatabaseVersion(0), |dbtx| migrate_to_v1(dbtx).boxed());
    mm
}

/// Adds a database key that contains the current session count so that we don't
/// have to scan the entire session history every time just to count the
/// entries.
async fn migrate_to_v1(dbtx: &mut DatabaseTransaction<'_>) -> Result<(), anyhow::Error> {
    use futures::StreamExt;

    let session_count = dbtx
        .find_by_prefix(&SignedSessionOutcomePrefix)
        .await
        .count()
        .await as u64;
    dbtx.insert_new_entry(&SignedSessionOutcomeCountKey, &session_count)
        .await;
    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use anyhow::{ensure, Context};
    use bitcoin::{secp256k1, KeyPair};
    use bitcoin_hashes::Hash;
    use fedimint_core::core::{DynInput, DynOutput};
    use fedimint_core::db::{
        apply_migrations, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey,
        IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::epoch::ConsensusItem;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::session_outcome::{SessionOutcome, SignedSessionOutcome};
    use fedimint_core::transaction::{Transaction, TransactionSignature};
    use fedimint_core::{Amount, PeerId, ServerModule, TransactionId};
    use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyOutput};
    use fedimint_dummy_server::Dummy;
    use fedimint_testing::db::{prepare_db_migration_snapshot, validate_migrations, BYTE_32};
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use secp256k1_zkp::Message;
    use strum::IntoEnumIterator;

    use super::{AcceptedTransactionKey, SignedSessionOutcomeCountKey};
    use crate::db::{
        get_global_database_migrations, AcceptedItem, AcceptedItemKey, AcceptedItemPrefix,
        AcceptedTransactionKeyPrefix, AlephUnitsKey, AlephUnitsPrefix, DbKeyPrefix,
        SignedSessionOutcomeKey, SignedSessionOutcomePrefix, GLOBAL_DATABASE_VERSION,
    };

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let accepted_tx_id = AcceptedTransactionKey(TransactionId::from_slice(&BYTE_32).unwrap());

        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await;

        let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let key_pair = KeyPair::from_secret_key(&secp, &sk);
        let schnorr = secp.sign_schnorr(&Message::from_slice(&BYTE_32).unwrap(), &key_pair);
        let transaction = Transaction {
            inputs: vec![DynInput::from_typed(
                0,
                DummyInput {
                    amount: Amount::ZERO,
                    account: key_pair.public_key(),
                },
            )],
            outputs: vec![DynOutput::from_typed(
                0,
                DummyOutput {
                    amount: Amount::ZERO,
                    account: key_pair.public_key(),
                },
            )],
            nonce: [0x42; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![schnorr]),
        };

        let module_ids = transaction
            .outputs
            .iter()
            .map(|output| output.module_instance_id())
            .collect::<Vec<_>>();

        dbtx.insert_new_entry(&accepted_tx_id, &module_ids).await;

        dbtx.insert_new_entry(
            &AcceptedItemKey(0),
            &AcceptedItem {
                item: ConsensusItem::Transaction(transaction.clone()),
                peer: PeerId::from_str("0").unwrap(),
            },
        )
        .await;

        dbtx.insert_new_entry(
            &SignedSessionOutcomeKey(0),
            &SignedSessionOutcome {
                session_outcome: SessionOutcome { items: Vec::new() },
                signatures: BTreeMap::new(),
            },
        )
        .await;

        dbtx.insert_new_entry(&AlephUnitsKey(0), &vec![42, 42, 42])
            .await;

        let _consensus_items = vec![ConsensusItem::Transaction(transaction)];
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_server_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "fedimint-server-v0",
            |dbtx| {
                Box::pin(async move {
                    create_server_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                0,
                DummyCommonInit::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() -> anyhow::Result<()> {
        validate_migrations(
            "fedimint-server",
            |db| async move {
                apply_migrations(
                    &db,
                    "Global".to_string(),
                    GLOBAL_DATABASE_VERSION,
                    get_global_database_migrations(),
                )
                .await
                .context("Error applying migrations to temp database")?;

                // Verify that all of the data from the global namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::AcceptedItem => {
                            let accepted_items = dbtx
                                .find_by_prefix(&AcceptedItemPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let accepted_items = accepted_items.len();
                            ensure!(
                                accepted_items > 0,
                                "validate_migrations was not able to read any AcceptedItems"
                            );
                        }
                        DbKeyPrefix::AcceptedTransaction => {
                            let accepted_transactions = dbtx
                                .find_by_prefix(&AcceptedTransactionKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_accepted_transactions = accepted_transactions.len();
                            ensure!(
                                num_accepted_transactions > 0,
                                "validate_migrations was not able to read any AcceptedTransactions"
                            );
                        }
                        DbKeyPrefix::SignedSessionOutcome => {
                            let signed_session_outcomes = dbtx
                                .find_by_prefix(&SignedSessionOutcomePrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_signed_session_outcomes = signed_session_outcomes.len();
                            ensure!(
                                num_signed_session_outcomes > 0,
                                "validate_migrations was not able to read any SignedSessionOutcomes"
                            );
                        }
                        DbKeyPrefix::AlephUnits => {
                            let aleph_units = dbtx
                                .find_by_prefix(&AlephUnitsPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_aleph_units = aleph_units.len();
                            ensure!(
                                num_aleph_units > 0,
                                "validate_migrations was not able to read any AlephUnits"
                            );
                        }
                        DbKeyPrefix::SignedSessionOutcomeCount => {
                            let session_outcome_count = dbtx
                                .get_value(&SignedSessionOutcomeCountKey)
                                .await
                                .expect("Count key should have been created");

                            let real_session_outcome_count =
                                dbtx.find_by_prefix(&SignedSessionOutcomePrefix)
                                    .await
                                    .count()
                                    .await as u64;

                            assert_eq!(
                                session_outcome_count, real_session_outcome_count,
                                "Session outcome count cash is inconsistent"
                            );
                        }
                        // Module prefix is reserved for modules, no migration testing is needed
                        DbKeyPrefix::Module => {}
                    }
                }
                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                0,
                DummyCommonInit::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}
