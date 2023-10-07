use std::fmt::Debug;

use fedimint_core::api::ClientConfigDownloadToken;
use fedimint_core::block::{AcceptedItem, SignedBlock};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseVersion, MigrationMap, MODULE_GLOBAL_PREFIX};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::{SerdeSignature, SerdeSignatureShare};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId, TransactionId};
use serde::Serialize;
use strum_macros::EnumIter;

pub const GLOBAL_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    AcceptedItem = 0x01,
    AcceptedTransaction = 0x02,
    SignedBlock = 0x04,
    AlephUnits = 0x05,
    ClientConfigSignature = 0x07,
    ClientConfigSignatureShare = 0x3,
    ClientConfigDownload = 0x09,
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
pub struct SignedBlockKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedBlockPrefix;

impl_db_record!(
    key = SignedBlockKey,
    value = SignedBlock,
    db_prefix = DbKeyPrefix::SignedBlock,
    notify_on_modify = true,
);
impl_db_lookup!(key = SignedBlockKey, query_prefix = SignedBlockPrefix);

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

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureKey;

impl_db_record!(
    key = ClientConfigSignatureKey,
    value = SerdeSignature,
    db_prefix = DbKeyPrefix::ClientConfigSignature,
    notify_on_modify = true
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureShareKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct ClientConfigSignatureSharePrefix;

impl_db_record!(
    key = ClientConfigSignatureShareKey,
    value = SerdeSignatureShare,
    db_prefix = DbKeyPrefix::ClientConfigSignatureShare,
);

impl_db_lookup!(
    key = ClientConfigSignatureShareKey,
    query_prefix = ClientConfigSignatureSharePrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigDownloadKeyPrefix;

#[derive(Debug, Encodable, Decodable, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClientConfigDownloadKey(pub ClientConfigDownloadToken);

impl_db_record!(
    key = ClientConfigDownloadKey,
    value = u64,
    db_prefix = DbKeyPrefix::ClientConfigDownload
);
impl_db_lookup!(
    key = ClientConfigDownloadKey,
    query_prefix = ClientConfigDownloadKeyPrefix
);

pub fn get_global_database_migrations<'a>() -> MigrationMap<'a> {
    MigrationMap::new()
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use anyhow::{ensure, Context};
    use bitcoin::{secp256k1, KeyPair};
    use bitcoin_hashes::Hash;
    use fedimint_core::api::ClientConfigDownloadToken;
    use fedimint_core::block::{Block, SignedBlock};
    use fedimint_core::core::DynInput;
    use fedimint_core::db::{apply_migrations, DatabaseTransaction};
    use fedimint_core::epoch::{ConsensusItem, SerdeSignature, SerdeSignatureShare};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::transaction::Transaction;
    use fedimint_core::{Amount, PeerId, ServerModule, TransactionId};
    use fedimint_dummy_common::{DummyCommonGen, DummyInput, DummyOutput};
    use fedimint_dummy_server::Dummy;
    use fedimint_testing::db::{prepare_db_migration_snapshot, validate_migrations, BYTE_32};
    use futures::StreamExt;
    use rand::distributions::{Distribution, Standard};
    use rand::rngs::OsRng;
    use rand::Rng;
    use secp256k1_zkp::Message;
    use strum::IntoEnumIterator;
    use threshold_crypto::SignatureShare;

    use super::{
        AcceptedTransactionKey, ClientConfigSignatureKey, ClientConfigSignatureSharePrefix,
    };
    use crate::core::DynOutput;
    use crate::db::{
        get_global_database_migrations, AcceptedItem, AcceptedItemKey,
        AcceptedTransactionKeyPrefix, AlephUnitsKey, AlephUnitsPrefix, ClientConfigDownloadKey,
        ClientConfigDownloadKeyPrefix, ClientConfigSignatureShareKey, DbKeyPrefix, SignedBlockKey,
        SignedBlockPrefix, GLOBAL_DATABASE_VERSION,
    };

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let accepted_tx_id = AcceptedTransactionKey(TransactionId::from_slice(&BYTE_32).unwrap());

        let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let key_pair = KeyPair::from_secret_key(&secp, &sk);
        let schnorr = secp.sign_schnorr(&Message::from_slice(&BYTE_32).unwrap(), &key_pair);
        let transaction = Transaction {
            inputs: vec![DynInput::from_typed(
                0,
                DummyInput {
                    amount: Amount::ZERO,
                    account: key_pair.x_only_public_key().0,
                },
            )],
            outputs: vec![DynOutput::from_typed(
                0,
                DummyOutput {
                    amount: Amount::ZERO,
                    account: key_pair.x_only_public_key().0,
                },
            )],
            signature: Some(schnorr),
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
            &SignedBlockKey(0),
            &SignedBlock {
                block: Block { items: Vec::new() },
                signatures: BTreeMap::new(),
            },
        )
        .await;

        dbtx.insert_new_entry(&AlephUnitsKey(0), &vec![42, 42, 42])
            .await;

        let sig_share = SignatureShare(Standard.sample(&mut OsRng));

        let _consensus_items = vec![
            ConsensusItem::ClientConfigSignatureShare(SerdeSignatureShare(sig_share.clone())),
            ConsensusItem::Transaction(transaction),
        ];

        let serde_sig = SerdeSignature(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(&ClientConfigSignatureKey, &serde_sig)
            .await;

        let serde_sig_share = SerdeSignatureShare(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(
            &ClientConfigSignatureShareKey(PeerId::from(0)),
            &serde_sig_share,
        )
        .await;

        dbtx.insert_new_entry(
            &ClientConfigDownloadKey(ClientConfigDownloadToken(OsRng.gen())),
            &0,
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "global-v0",
            |dbtx| {
                Box::pin(async move {
                    create_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                0,
                DummyCommonGen::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() -> anyhow::Result<()> {
        validate_migrations(
            "global",
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
                        DbKeyPrefix::AcceptedItem => {},
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
                        DbKeyPrefix::SignedBlock => {
                                let signed_blocks = dbtx
                                    .find_by_prefix(&SignedBlockPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_signed_blocks = signed_blocks.len();
                                ensure!(
                                    num_signed_blocks > 0,
                                    "validate_migrations was not able to read any SignedBlocks"
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
                        DbKeyPrefix::ClientConfigSignature => {
                            dbtx
                                .get_value(&ClientConfigSignatureKey)
                                .await
                                .expect("validate_migrations was not able to read the ClientConfigSignature");
                        }
                        DbKeyPrefix::ClientConfigSignatureShare => {
                            let signature_shares = dbtx
                                .find_by_prefix(&ClientConfigSignatureSharePrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_signature_shares = signature_shares.len();
                            ensure!(
                                num_signature_shares > 0,
                                "validate_migrations was not able to read any ClientConfigSignatureShares"
                            );
                        }
                        DbKeyPrefix::ClientConfigDownload => {
                            let downloads = dbtx
                                .find_by_prefix(&ClientConfigDownloadKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let downloads_len = downloads.len();
                            ensure!(
                                downloads_len > 0,
                                "validate_migrations was not able to read any ClientConfigDownloadKey"
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
                DummyCommonGen::KIND,
                <Dummy as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}
