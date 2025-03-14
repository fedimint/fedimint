use std::collections::HashMap;

use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{AutocommitError, Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_client::recurring::{PaymentCodeId, PaymentCodeRootKey, RecurringPaymentProtocol};
use futures::stream::StreamExt;
use lightning_invoice::Bolt11Invoice;
use rand::Rng;

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    fedimint_core::encoding::Encodable,
    fedimint_core::encoding::Decodable,
)]
pub struct FederationDbPrefix([u8; 16]);

impl FederationDbPrefix {
    pub fn random() -> FederationDbPrefix {
        FederationDbPrefix(thread_rng().gen())
    }

    fn prepend(&self, byte: u8) -> Vec<u8> {
        let mut full_prefix = Vec::with_capacity(17);
        full_prefix.push(byte);
        full_prefix.extend(&self.0);
        full_prefix
    }
}

async fn load_federation_clients(db: &Database) -> Vec<(FederationId, FederationDbPrefix)> {
    let mut dbtx = db.begin_transaction_nc().await;
    dbtx.find_by_prefix(&FederationClientPrefix)
        .await
        .map(|(k, v)| (k.federation_id, v.db_prefix))
        .collect::<Vec<_>>()
        .await
}

pub fn open_client_db(db: &Database, db_prefix: FederationDbPrefix) -> Database {
    db.with_prefix(db_prefix.prepend(DbKeyPrefix::ClientDB as u8))
}

pub async fn try_add_federation_database(
    db: &Database,
    federation_id: FederationId,
    db_prefix: FederationDbPrefix,
) -> Result<(), FederationDbPrefix> {
    db.autocommit(
        |dbtx, _| {
            Box::pin(async move {
                if let Some(federation_db_entry) =
                    dbtx.get_value(&FederationClientKey { federation_id }).await
                {
                    return Err(federation_db_entry.db_prefix);
                }

                dbtx.insert_new_entry(
                    &FederationClientKey { federation_id },
                    &FederationClientEntry { db_prefix },
                )
                .await;

                Ok(())
            })
        },
        None,
    )
    .await
    .map_err(|e| match e {
        AutocommitError::CommitFailed { .. } => unreachable!("will keep retrying"),
        AutocommitError::ClosureError { error, .. } => {
            // TODO: clean up DB once parallel joins are enabled
            error
        }
    })
}

pub async fn load_federation_client_databases(db: &Database) -> HashMap<FederationId, Database> {
    load_federation_clients(db)
        .await
        .into_iter()
        .map(|(federation_id, db_prefix)| (federation_id, open_client_db(db, db_prefix)))
        .collect()
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum DbKeyPrefix {
    ClientList = 0x00,
    ClientDB = 0x01,
    PaymentCodes = 0x02,
    PaymentCodeNextInvoiceIndex = 0x03,
    PaymentCodeInvoices = 0x04,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationClientKey {
    pub federation_id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationClientPrefix;

impl_db_record!(
    key = FederationClientKey,
    value = FederationClientEntry,
    db_prefix = DbKeyPrefix::ClientList,
);
impl_db_lookup!(
    key = FederationClientKey,
    query_prefix = FederationClientPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct FederationClientEntry {
    pub db_prefix: FederationDbPrefix,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeKey {
    pub payment_code_id: PaymentCodeId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodePrefix;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum PaymentCodeVariant {
    Lnurl { meta: String },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeEntry {
    pub root_key: PaymentCodeRootKey,
    pub federation_id: FederationId,
    pub protocol: RecurringPaymentProtocol,
    pub payment_code: String,
    pub variant: PaymentCodeVariant,
}

impl_db_record!(
    key = PaymentCodeKey,
    value = PaymentCodeEntry,
    db_prefix = DbKeyPrefix::PaymentCodes,
);
impl_db_lookup!(key = PaymentCodeKey, query_prefix = PaymentCodePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeNextInvoiceIndexKey {
    pub payment_code_id: PaymentCodeId,
}

impl_db_record!(
    key = PaymentCodeNextInvoiceIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::PaymentCodeNextInvoiceIndex,
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceKey {
    pub payment_code_id: PaymentCodeId,
    pub index: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoicePrefix {
    payment_code_id: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceEntry {
    pub operation_id: OperationId,
    // TODO: use a more versatile type in the future to support BOLT12
    pub invoice: Bolt11Invoice,
}

impl_db_record!(
    key = PaymentCodeInvoiceKey,
    value = PaymentCodeInvoiceEntry,
    db_prefix = DbKeyPrefix::PaymentCodeInvoices,
);
impl_db_lookup!(
    key = PaymentCodeInvoiceKey,
    query_prefix = PaymentCodeInvoicePrefix
);
