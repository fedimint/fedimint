use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, impl_db_lookup, impl_db_record};
use serde::Serialize;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DbKeyPrefix {
    /// Amounts of an LNv1 incoming forward keyed by its receive operation.
    /// 0x50 sits clear of the `fedimint-ln-client` prefixes (0x28..=0x46)
    /// in case any shared code writes into this module's namespace.
    IncomingAmounts = 0x50,
}

/// Both amounts of an LNv1 incoming forward, recorded when the HTLC is
/// intercepted. Neither is held by the receive or complete state machines.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct Lnv1IncomingAmounts {
    /// Amount the gateway funds the incoming contract with (the offer amount).
    pub contract_amount: Amount,
    /// Value actually locked in the incoming HTLC — never the onion amount.
    pub incoming_amount: Amount,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingAmountsKey(pub OperationId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingAmountsKeyPrefix;

impl_db_record!(
    key = IncomingAmountsKey,
    value = Lnv1IncomingAmounts,
    db_prefix = DbKeyPrefix::IncomingAmounts,
);
impl_db_lookup!(
    key = IncomingAmountsKey,
    query_prefix = IncomingAmountsKeyPrefix
);

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[tokio::test]
    async fn incoming_amounts_round_trip() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op = OperationId([2; 32]);
        let amounts = Lnv1IncomingAmounts {
            contract_amount: Amount::from_msats(990),
            incoming_amount: Amount::from_msats(1_000),
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&IncomingAmountsKey(op), &amounts).await;
        dbtx.commit_tx().await;

        assert_eq!(
            db.begin_transaction_nc()
                .await
                .get_value(&IncomingAmountsKey(op))
                .await,
            Some(amounts)
        );
    }
}
