use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, impl_db_lookup, impl_db_record};

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DbKeyPrefix {
    /// Value locked in the incoming HTLC behind a circuit completion
    /// operation, keyed by that operation's id. Written before the operation
    /// is created; a completion without a record is scored as unknown.
    IncomingAmount = 0x01,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingAmountKey(pub OperationId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingAmountKeyPrefix;

impl_db_record!(
    key = IncomingAmountKey,
    value = Amount,
    db_prefix = DbKeyPrefix::IncomingAmount,
);
impl_db_lookup!(
    key = IncomingAmountKey,
    query_prefix = IncomingAmountKeyPrefix
);

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[tokio::test]
    async fn incoming_amount_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op = OperationId([1; 32]);

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&IncomingAmountKey(op), &Amount::from_msats(42))
            .await;
        dbtx.commit_tx().await;

        let stored = db
            .begin_transaction_nc()
            .await
            .get_value(&IncomingAmountKey(op))
            .await;
        assert_eq!(stored, Some(Amount::from_msats(42)));
    }
}
