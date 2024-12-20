use std::collections::BTreeMap;
use std::fmt::Debug;

use fedimint_core::core::{DynInput, DynModuleConsensusItem, DynOutput, ModuleInstanceId};
use fedimint_core::db::{
    CoreMigrationFn, DatabaseVersion, IDatabaseTransactionOpsCoreTyped, MigrationContext,
    MODULE_GLOBAL_PREFIX,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::ModuleCommon;
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::util::BoxStream;
use fedimint_core::{apply, async_trait_maybe_send, impl_db_lookup, impl_db_record, TransactionId};
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedSessionOutcome = 0x04,
    AlephUnits = 0x05,
    // TODO: do we want to split the server DB into consensus/non-consensus?
    ApiAnnouncements = 0x06,
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

pub fn get_global_database_migrations() -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
    BTreeMap::new()
}

pub enum ModuleHistoryItem {
    ConsensusItem(DynModuleConsensusItem),
    Input(DynInput),
    Output(DynOutput),
}

pub enum TypedModuleHistoryItem<M: ModuleCommon> {
    ConsensusItem(M::ConsensusItem),
    Input(M::Input),
    Output(M::Output),
}

#[apply(async_trait_maybe_send!)]
pub trait MigrationContextExt {
    async fn get_module_history_stream(&mut self) -> BoxStream<ModuleHistoryItem>;

    async fn get_typed_module_history_stream<M: ModuleCommon>(
        &mut self,
    ) -> BoxStream<TypedModuleHistoryItem<M>>;
}

#[apply(async_trait_maybe_send!)]
impl MigrationContextExt for MigrationContext<'_> {
    async fn get_module_history_stream(&mut self) -> BoxStream<ModuleHistoryItem> {
        let module_instance_id = self
            .module_instance_id()
            .expect("module_instance_id must be set");

        // Items of the currently ongoing session, that have already been processed. We
        // have to query them in full first and collect them into a vector so we don't
        // hold two references to the dbtx at the same time.
        let active_session_items = self
            .__global_dbtx()
            .find_by_prefix(&AcceptedItemPrefix)
            .await
            .map(|(_, item)| item)
            .collect::<Vec<_>>()
            .await;

        let stream = self
            .__global_dbtx()
            .find_by_prefix(&SignedSessionOutcomePrefix)
            .await
            // Transform the session stream into an accepted item stream
            .flat_map(|(_, signed_session_outcome): (_, SignedSessionOutcome)| {
                futures::stream::iter(signed_session_outcome.session_outcome.items)
            })
            // Append the accepted items from the current session after all the signed session items
            // have been processed
            .chain(futures::stream::iter(active_session_items))
            .flat_map(move |item| {
                let history_items = match item.item {
                    ConsensusItem::Transaction(tx) => tx
                        .inputs
                        .into_iter()
                        .filter_map(|input| {
                            (input.module_instance_id() == module_instance_id)
                                .then_some(ModuleHistoryItem::Input(input))
                        })
                        .chain(tx.outputs.into_iter().filter_map(|output| {
                            (output.module_instance_id() == module_instance_id)
                                .then_some(ModuleHistoryItem::Output(output))
                        }))
                        .collect::<Vec<_>>(),
                    ConsensusItem::Module(mci) => {
                        if mci.module_instance_id() == module_instance_id {
                            vec![ModuleHistoryItem::ConsensusItem(mci)]
                        } else {
                            vec![]
                        }
                    }
                    ConsensusItem::Default { .. } => {
                        unreachable!("We never save unknown CIs on the server side")
                    }
                };
                futures::stream::iter(history_items)
            });

        Box::pin(stream)
    }

    async fn get_typed_module_history_stream<M: ModuleCommon>(
        &mut self,
    ) -> BoxStream<TypedModuleHistoryItem<M>> {
        Box::pin(self.get_module_history_stream().await.map(|item| {
            match item {
                ModuleHistoryItem::ConsensusItem(ci) => TypedModuleHistoryItem::ConsensusItem(
                    ci.as_any()
                        .downcast_ref::<M::ConsensusItem>()
                        .expect("Wrong module type")
                        .clone(),
                ),
                ModuleHistoryItem::Input(input) => TypedModuleHistoryItem::Input(
                    input
                        .as_any()
                        .downcast_ref::<M::Input>()
                        .expect("Wrong module type")
                        .clone(),
                ),
                ModuleHistoryItem::Output(output) => TypedModuleHistoryItem::Output(
                    output
                        .as_any()
                        .downcast_ref::<M::Output>()
                        .expect("Wrong module type")
                        .clone(),
                ),
            }
        }))
    }
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use anyhow::ensure;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1;
    use fedimint_core::core::{DynInput, DynOutput};
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::epoch::ConsensusItem;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::net::api_announcement::{ApiAnnouncement, SignedApiAnnouncement};
    use fedimint_core::session_outcome::{SessionOutcome, SignedSessionOutcome};
    use fedimint_core::transaction::{Transaction, TransactionSignature};
    use fedimint_core::{Amount, BitcoinHash, PeerId, ServerModule, TransactionId};
    use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyOutput};
    use fedimint_dummy_server::Dummy;
    use fedimint_logging::{TracingSetup, LOG_DB};
    use fedimint_testing_core::db::{
        snapshot_db_migrations_with_decoders, validate_migrations_global, BYTE_32,
        TEST_MODULE_INSTANCE_ID,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use rand::thread_rng;
    use secp256k1::Message;
    use strum::IntoEnumIterator;
    use tracing::info;

    use super::{
        get_global_database_migrations, AcceptedItem, AcceptedItemKey, AcceptedItemPrefix,
        AcceptedTransactionKey, AcceptedTransactionKeyPrefix, AlephUnitsKey, AlephUnitsPrefix,
        DbKeyPrefix, SignedSessionOutcomeKey, SignedSessionOutcomePrefix,
    };
    use crate::net::api::announcement::{ApiAnnouncementKey, ApiAnnouncementPrefix};

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

        let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let key_pair = Keypair::from_secret_key(&secp, &sk);
        let schnorr = secp.sign_schnorr_with_rng(
            &Message::from_digest_slice(&BYTE_32).unwrap(),
            &key_pair,
            &mut thread_rng(),
        );
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
            .map(DynOutput::module_instance_id)
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

        dbtx.insert_new_entry(
            &ApiAnnouncementKey(PeerId::from(42)),
            &SignedApiAnnouncement {
                api_announcement: ApiAnnouncement {
                    api_url: "wss://foo.bar".parse().expect("valid url"),
                    nonce: 0,
                },
                signature: secp256k1::schnorr::Signature::from_slice(&[42; 64]).unwrap(),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_with_decoders(
            "fedimint-server",
            |db| {
                Box::pin(async {
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
                let mut dbtx = db.begin_transaction_nc().await;

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
                        DbKeyPrefix::ApiAnnouncements => {
                            let announcements = dbtx
                                .find_by_prefix(&ApiAnnouncementPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;

                            assert_eq!(announcements.len(), 1);
                        }
                    }
                }
                Ok(())
            },
            "fedimint-server",
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
