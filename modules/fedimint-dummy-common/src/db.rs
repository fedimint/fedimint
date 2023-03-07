use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;

/// Example function that will migrate the Dummy Module's database from
/// version 0 to version 1. This function selects all of the ExampleKeyV0
/// and inserts a new String to construct ExampleKeys, deletes the old
/// ExampleKeyV0, then inserts the new ExampleKeys.
pub async fn migrate_dummy_db_version_0<'a, 'b>(
    dbtx: &'b mut DatabaseTransaction<'a>,
) -> Result<(), anyhow::Error> {
    let example_keys_v0 = dbtx
        .find_by_prefix(&ExampleKeyPrefixV0)
        .await
        .collect::<Vec<_>>()
        .await;
    dbtx.remove_by_prefix(&ExampleKeyPrefixV0).await;
    for (key, val) in example_keys_v0 {
        let key_v2 = ExampleKey(key.0, "Example String".to_string());
        dbtx.insert_new_entry(&key_v2, &val).await;
    }
    Ok(())
}

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Example = 0x80,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKeyV0(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefixV0;

impl_db_record!(
    key = ExampleKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::Example,
);

impl_db_lookup!(key = ExampleKeyV0, query_prefix = ExampleKeyPrefixV0);
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKey(pub u64, pub String);

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefix;

impl_db_record!(
    key = ExampleKey,
    value = (),
    db_prefix = DbKeyPrefix::Example,
);
impl_db_lookup!(key = ExampleKey, query_prefix = ExampleKeyPrefix);
