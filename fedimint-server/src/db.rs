use std::fmt::Debug;

use fedimint_core::api::ClientConfigDownloadToken;
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
    AcceptedTransaction = 0x02,
    // SignedBlock = 0x04, this prefix is used in the atomic broadcast crate
    // AlephBackup = 0x05, this prefix is used in the atomic broadcast crate
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
    use std::collections::BTreeSet;

    use anyhow::{ensure, Context};
    use bitcoin::{secp256k1, KeyPair};
    use bitcoin_hashes::Hash;
    use fedimint_core::api::ClientConfigDownloadToken;
    use fedimint_core::core::DynInput;
    use fedimint_core::db::{apply_migrations, DatabaseTransaction};
    use fedimint_core::epoch::{
        ConsensusItem, EpochOutcome, SerdeSignature, SerdeSignatureShare, SignedEpochOutcome,
    };
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::CommonModuleInit;
    use fedimint_core::transaction::Transaction;
    use fedimint_core::{Amount, PeerId, ServerModule, TransactionId};
    use fedimint_dummy_common::{DummyCommonGen, DummyInput, DummyOutput};
    use fedimint_dummy_server::Dummy;
    use fedimint_testing::db::{
        prepare_db_migration_snapshot, validate_migrations, BYTE_32, BYTE_8,
    };
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
        get_global_database_migrations, AcceptedTransactionKeyPrefix, ClientConfigDownloadKey,
        ClientConfigDownloadKeyPrefix, ClientConfigSignatureShareKey, DbKeyPrefix,
        GLOBAL_DATABASE_VERSION,
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

        let sig_share = SignatureShare(Standard.sample(&mut OsRng));

        let consensus_items = vec![
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
