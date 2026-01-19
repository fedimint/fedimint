use fedimint_core::db::{
    IReadDatabaseTransactionOps as _, IReadDatabaseTransactionOpsTyped,
    IWriteDatabaseTransactionOps as _, IWriteDatabaseTransactionOpsTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{Amount, OutPoint, impl_db_lookup, impl_db_record};
use fedimint_dummy_common::DummyOutputOutcomeV0;
use fedimint_server_core::migration::ServerModuleDbMigrationFnContext;
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{Dummy, DummyOutputOutcome};

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Funds = 0x01,
    Outcome = 0x02,
}

// TODO: Boilerplate-code
impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Example old version 0 of DB entries
// TODO: can we simplify this by just using macros?
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyFundsKeyV0(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct DummyFundsKeyPrefixV0;

impl_db_record!(
    key = DummyFundsKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::Funds,
);
impl_db_lookup!(key = DummyFundsKeyV0, query_prefix = DummyFundsKeyPrefixV0);

/// Lookup funds for a user by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyFundsKeyV1(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct DummyFundsPrefixV1;

impl_db_record!(
    key = DummyFundsKeyV1,
    value = Amount,
    db_prefix = DbKeyPrefix::Funds,
);
impl_db_lookup!(key = DummyFundsKeyV1, query_prefix = DummyFundsPrefixV1);

/// Example DB migration from version 0 to version 1
pub async fn migrate_to_v1(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Dummy>,
) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();
    // Select old entries
    let v0_entries = dbtx
        .find_by_prefix(&DummyFundsKeyPrefixV0)
        .await
        .collect::<Vec<(DummyFundsKeyV0, ())>>()
        .await;

    // Remove old entries
    dbtx.remove_by_prefix(&DummyFundsKeyPrefixV0).await;

    // Migrate to new entries
    for (v0_key, _v0_val) in v0_entries {
        let v1_key = DummyFundsKeyV1(v0_key.0);
        dbtx.insert_new_entry(&v1_key, &Amount::ZERO).await;
    }
    Ok(())
}

pub async fn migrate_to_v2(
    mut ctx: ServerModuleDbMigrationFnContext<'_, Dummy>,
) -> Result<(), anyhow::Error> {
    const OUTCOME_RAW_KEY_PREFIX: [u8; 1] = [DbKeyPrefix::Outcome as u8];

    let mut dbtx = ctx.dbtx();

    // Select old entries
    let raw_entries = dbtx
        .raw_find_by_prefix(&OUTCOME_RAW_KEY_PREFIX)
        .await?
        .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
        .await;

    // Remove old entries
    dbtx.raw_remove_by_prefix(&OUTCOME_RAW_KEY_PREFIX).await?;

    // Migrate to new entries
    for (key, val) in raw_entries {
        let old = DummyOutputOutcomeV0::consensus_decode_whole(&val, &ModuleRegistry::default())?;
        dbtx.raw_insert_bytes(
            &key,
            &DummyOutputOutcome(old.0, AmountUnit::BITCOIN, old.1).consensus_encode_to_vec(),
        )
        .await?;
    }
    Ok(())
}

/// Lookup tx outputs by key or prefix
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyOutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct DummyOutcomePrefix;

impl_db_record!(
    key = DummyOutcomeKey,
    value = DummyOutputOutcome,
    db_prefix = DbKeyPrefix::Outcome,
);
impl_db_lookup!(key = DummyOutcomeKey, query_prefix = DummyOutcomePrefix);
