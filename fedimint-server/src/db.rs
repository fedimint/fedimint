use std::collections::BTreeMap;
use std::fmt::Debug;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseVersion, ServerMigrationFn, MODULE_GLOBAL_PREFIX};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::{impl_db_lookup, impl_db_record, TransactionId};
use serde::Serialize;
use strum_macros::EnumIter;

pub const GLOBAL_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedSessionOutcome = 0x04,
    AlephUnits = 0x05,
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

pub fn get_global_database_migrations() -> BTreeMap<DatabaseVersion, ServerMigrationFn> {
    BTreeMap::new()
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use anyhow::ensure;
    use bitcoin::key::KeyPair;
    use bitcoin::secp256k1;
    use bitcoin_hashes::Hash;
    use fedimint_core::bitcoin_migration::{
        bitcoin29_to_bitcoin30_message, bitcoin29_to_bitcoin30_secp256k1_secret_key,
        bitcoin30_to_bitcoin29_schnorr_signature, bitcoin30_to_bitcoin29_secp256k1_public_key,
    };
    use fedimint_core::core::{DynInput, DynOutput};
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::epoch::ConsensusItem;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::session_outcome::{SessionOutcome, SignedSessionOutcome};
    use fedimint_core::transaction::{Transaction, TransactionSignature};
    use fedimint_core::{Amount, PeerId, ServerModule, TransactionId};
    use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyOutput};
    use fedimint_dummy_server::Dummy;
    use fedimint_logging::{TracingSetup, LOG_DB};
    use fedimint_testing::db::{
        snapshot_db_migrations_with_decoders, validate_migrations_global, BYTE_32,
        TEST_MODULE_INSTANCE_ID,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use rand::thread_rng;
    use secp256k1_zkp::Message;
    use strum::IntoEnumIterator;
    use tracing::info;

    use super::AcceptedTransactionKey;
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
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        let accepted_tx_id = AcceptedTransactionKey(TransactionId::from_slice(&BYTE_32).unwrap());

        let (sk, _) = secp256k1_zkp::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let key_pair =
            KeyPair::from_secret_key(&secp, &bitcoin29_to_bitcoin30_secp256k1_secret_key(sk));
        let schnorr = secp.sign_schnorr_with_rng(
            &bitcoin29_to_bitcoin30_message(Message::from_slice(&BYTE_32).unwrap()),
            &key_pair,
            &mut thread_rng(),
        );
        let transaction = Transaction {
            inputs: vec![DynInput::from_typed(
                0,
                DummyInput {
                    amount: Amount::ZERO,
                    account: bitcoin30_to_bitcoin29_secp256k1_public_key(key_pair.public_key()),
                },
            )],
            outputs: vec![DynOutput::from_typed(
                0,
                DummyOutput {
                    amount: Amount::ZERO,
                    account: bitcoin30_to_bitcoin29_secp256k1_public_key(key_pair.public_key()),
                },
            )],
            nonce: [0x42; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![
                bitcoin30_to_bitcoin29_schnorr_signature(schnorr),
            ]),
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

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_with_decoders(
            "fedimint-server",
            |db| {
                Box::pin(async move {
                    create_server_db_with_v0_data(db).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                TEST_MODULE_INSTANCE_ID,
                DummyCommonInit::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        validate_migrations_global(
            |db| async move {
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
                            info!(target: LOG_DB, "Validated AcceptedItems");
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
                            info!(target: LOG_DB, "Validated AcceptedTransactions");
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
                            info!(target: LOG_DB, "Validated SignedSessionOutcome");
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
                            info!(target: LOG_DB, "Validated AlephUnits");
                        }
                        // Module prefix is reserved for modules, no migration testing is needed
                        DbKeyPrefix::Module => {}
                    }
                }
                Ok(())
            },
            "fedimint-server",
            GLOBAL_DATABASE_VERSION,
            get_global_database_migrations(),
            ModuleDecoderRegistry::from_iter([(
                TEST_MODULE_INSTANCE_ID,
                DummyCommonInit::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}
