use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_record, Amount};
use strum_macros::EnumIter;
use tracing::warn;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    ClientFunds = 0x04,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV0;

impl_db_record!(
    key = DummyClientFundsKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV1;

impl_db_record!(
    key = DummyClientFundsKeyV1,
    value = Amount,
    db_prefix = DbKeyPrefix::ClientFunds,
);

pub async fn migrate_to_v1(dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
    if dbtx.remove_entry(&DummyClientFundsKeyV0).await.is_some() {
        // Since this is a dummy migration, we can insert any value for the client
        // funds. Real modules should handle the funds properly.

        dbtx.insert_new_entry(&DummyClientFundsKeyV1, &Amount::from_sats(1000))
            .await;
    } else {
        warn!("Dummy client did not have client funds, skipping database migration");
    }

    Ok(())
}
