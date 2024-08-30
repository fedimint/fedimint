use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    CoreMigrationFn, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
    MODULE_GLOBAL_PREFIX,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusVersionVote;
use fedimint_core::module::{ConsensusVersion, CoreConsensusVersion, ModuleConsensusVersion};
use fedimint_core::session_outcome::{AcceptedItem, SignedSessionOutcome};
use fedimint_core::{impl_db_lookup, impl_db_record, NumPeers, NumPeersExt, PeerId, TransactionId};
use futures::stream;
use serde::Serialize;
use strum_macros::EnumIter;
use tokio_stream::StreamExt as _;

use crate::config::ServerConfigConsensus;

pub const GLOBAL_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedSessionOutcome = 0x04,
    AlephUnits = 0x05,
    // TODO: do we want to split the server DB into consensus/non-consensus?
    ApiAnnouncements = 0x06,
    ConsensusVersionVote = 0x07,
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

#[derive(Copy, Clone, Debug, Encodable, Decodable)]
pub struct ConsensusVersionVoteKey {
    pub module_id: Option<ModuleInstanceId>,
    pub peer_id: PeerId,
}

impl From<(ConsensusVersionVote, PeerId)> for ConsensusVersionVoteKey {
    fn from((vote, peer_id): (ConsensusVersionVote, PeerId)) -> Self {
        Self {
            module_id: vote.module_id,
            peer_id,
        }
    }
}

#[derive(Copy, Clone, Debug, Encodable, Decodable, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusVersionVoteValue {
    pub desired: ConsensusVersion,
    pub accelerate: bool,
}

impl From<ConsensusVersionVote> for ConsensusVersionVoteValue {
    fn from(
        ConsensusVersionVote {
            module_id: _,
            desired,
            accelerate,
        }: ConsensusVersionVote,
    ) -> Self {
        Self {
            desired,
            accelerate,
        }
    }
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ConsensusVersionVotePrefixAll;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ConsensusVersionVotePrefixByModuleId(Option<ModuleInstanceId>);

impl_db_record!(
    key = ConsensusVersionVoteKey,
    value = ConsensusVersionVoteValue,
    db_prefix = DbKeyPrefix::ConsensusVersionVote,
    notify_on_modify = false,
);

impl_db_lookup!(
    key = ConsensusVersionVoteKey,
    query_prefix = ConsensusVersionVotePrefixAll
);
impl_db_lookup!(
    key = ConsensusVersionVoteKey,
    query_prefix = ConsensusVersionVotePrefixByModuleId
);

#[async_trait]
pub trait DatabaseTransactionExt {
    async fn get_consensus_version_opt(
        &mut self,
        module_id: Option<ModuleInstanceId>,
        num_peers: NumPeers,
    ) -> Option<ConsensusVersion>;
    async fn get_consensus_version(
        &mut self,
        module_id: Option<ModuleInstanceId>,
        cfg: &ServerConfigConsensus,
    ) -> ConsensusVersion;

    async fn get_all_consensus_versions(
        &mut self,
        cfg: &ServerConfigConsensus,
    ) -> (
        CoreConsensusVersion,
        BTreeMap<ModuleInstanceId, ModuleConsensusVersion>,
    );
}

#[async_trait]
impl<Cap: Send> DatabaseTransactionExt for DatabaseTransaction<'_, Cap> {
    async fn get_all_consensus_versions(
        &mut self,
        cfg: &ServerConfigConsensus,
    ) -> (
        CoreConsensusVersion,
        BTreeMap<ModuleInstanceId, ModuleConsensusVersion>,
    ) {
        let core_consensus_version = self.get_consensus_version(None, cfg).await;
        let mut module_consensus_versions = BTreeMap::new();

        for module_id in cfg.modules.keys().copied() {
            module_consensus_versions.insert(
                module_id,
                self.get_consensus_version(Some(module_id), cfg)
                    .await
                    .into(),
            );
        }

        (core_consensus_version.into(), module_consensus_versions)
    }

    async fn get_consensus_version(
        &mut self,
        module_id: Option<ModuleInstanceId>,
        cfg: &ServerConfigConsensus,
    ) -> ConsensusVersion {
        self.get_consensus_version_opt(module_id, cfg.api_endpoints.to_num_peers())
            .await
            .unwrap_or_else(|| {
                if let Some(module_id) = module_id {
                    cfg.modules
                        .get(&module_id)
                        .expect("Must have a matching module")
                        .version
                        .into()
                } else {
                    cfg.version.into()
                }
            })
    }

    async fn get_consensus_version_opt(
        &mut self,
        module_id: Option<ModuleInstanceId>,
        num_peers: NumPeers,
    ) -> Option<ConsensusVersion> {
        let mut votes: Vec<_> = self
            .find_by_prefix(&ConsensusVersionVotePrefixByModuleId(module_id))
            .await
            .map(|(_k, v)| Some(v))
            .chain(stream::repeat(None))
            .take(num_peers.total())
            .collect::<Vec<_>>()
            .await;

        get_consensus_from_votes(&mut votes, num_peers)
    }
}

/// Calculate the effective consensus version based on the votes of `num_peers`
///
/// The `votes.len()` must equal `num_peers`.
fn get_consensus_from_votes(
    votes: &mut [Option<ConsensusVersionVoteValue>],
    num_peers: NumPeers,
) -> Option<ConsensusVersion> {
    assert_eq!(votes.len(), num_peers.total());

    votes.sort();

    // The desire version is one that threshold amount of peers are ready for.
    let threshold_desired_version = votes[num_peers.max_evil()].map(|vote| vote.desired)?;

    // If all peers are ready for the desired version, we accept it
    if votes[0].map(|v| v.desired) == Some(threshold_desired_version) {
        return Some(threshold_desired_version);
    }

    // If any peer voted to accelerate switching, we accept it
    if votes.iter().any(|v| v.is_some_and(|v| v.accelerate)) {
        return Some(threshold_desired_version);
    }

    // Otherwise, we proceed with the lowest vote
    votes[0].map(|v| v.desired)
}

#[test]
fn get_consensus_from_votes_sanity() {
    for (raw_votes, res) in [
        ([Some((0, 0, false))].as_slice(), Some((0, 0))),
        (&[Some((1, 2, false)), None, None, None], None),
        (
            &[Some((1, 2, false)), Some((1, 2, false)), None, None],
            None,
        ),
        (
            &[
                Some((1, 2, false)),
                Some((1, 2, false)),
                Some((1, 2, false)),
                None,
            ],
            None,
        ),
        (
            &[
                Some((1, 2, false)),
                Some((1, 2, false)),
                Some((1, 2, false)),
                Some((1, 2, false)),
            ],
            Some((1, 2)),
        ),
        (
            &[
                Some((1, 2, false)),
                Some((1, 2, false)),
                Some((1, 2, true)),
                None,
            ],
            Some((1, 2)),
        ),
        (
            &[
                Some((1, 3, false)),
                Some((1, 3, false)),
                Some((1, 2, false)),
                Some((1, 3, false)),
            ],
            Some((1, 2)),
        ),
        (
            &[
                Some((1, 1, false)),
                Some((1, 2, false)),
                Some((1, 3, false)),
                Some((1, 4, false)),
            ],
            Some((1, 1)),
        ),
        (
            &[
                Some((1, 3, false)),
                Some((1, 2, false)),
                Some((1, 2, true)),
                Some((1, 3, false)),
            ],
            Some((1, 2)),
        ),
        (
            &[
                Some((1, 3, false)),
                Some((1, 2, false)),
                Some((1, 2, false)),
                Some((1, 3, true)),
            ],
            Some((1, 2)),
        ),
        (
            &[
                Some((1, 3, false)),
                Some((1, 3, false)),
                Some((1, 2, true)),
                Some((1, 3, false)),
            ],
            Some((1, 3)),
        ),
        (
            &[
                Some((1, 3, true)),
                Some((1, 3, false)),
                Some((1, 2, false)),
                Some((1, 3, false)),
            ],
            Some((1, 3)),
        ),
        (
            &[
                Some((1, 1, false)),
                Some((1, 2, false)),
                Some((1, 3, false)),
                Some((1, 4, false)),
                Some((1, 5, false)),
                Some((1, 6, false)),
                Some((1, 7, false)),
            ],
            Some((1, 1)),
        ),
        (
            &[
                Some((1, 1, false)),
                Some((1, 2, false)),
                Some((1, 3, false)),
                Some((1, 4, false)),
                Some((1, 5, false)),
                Some((1, 6, true)),
                Some((1, 7, false)),
            ],
            Some((1, 3)),
        ),
        (
            &[
                None,
                None,
                Some((1, 3, false)),
                Some((1, 4, false)),
                Some((1, 5, false)),
                Some((1, 6, true)),
                Some((1, 7, false)),
            ],
            Some((1, 3)),
        ),
    ] {
        use fedimint_core::NumPeersExt;
        let num_peers = raw_votes.to_num_peers();
        let mut votes: Vec<_> = raw_votes
            .iter()
            .map(|raw| {
                raw.map(|(major, minor, accelerate)| ConsensusVersionVoteValue {
                    desired: ConsensusVersion { major, minor },
                    accelerate,
                })
            })
            .collect();
        assert_eq!(
            get_consensus_from_votes(&mut votes, num_peers),
            res.map(|(major, minor)| ConsensusVersion { major, minor }),
            "For votes {raw_votes:?}"
        );
    }
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use anyhow::ensure;
    use bitcoin::key::KeyPair;
    use bitcoin::secp256k1;
    use bitcoin_hashes::Hash;
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
    use fedimint_core::{Amount, PeerId, ServerModule, TransactionId};
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
        DbKeyPrefix, SignedSessionOutcomeKey, SignedSessionOutcomePrefix, GLOBAL_DATABASE_VERSION,
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
        let key_pair = KeyPair::from_secret_key(&secp, &sk);
        let schnorr = secp.sign_schnorr_with_rng(
            &Message::from_slice(&BYTE_32).unwrap(),
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
                signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[42; 64]).unwrap(),
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
                        DbKeyPrefix::ApiAnnouncements => {
                            let announcements = dbtx
                                .find_by_prefix(&ApiAnnouncementPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;

                            assert_eq!(announcements.len(), 1);
                        }
                        // Module prefix is reserved for modules, no migration testing is needed
                        DbKeyPrefix::Module | DbKeyPrefix::ConsensusVersionVote => {}
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
