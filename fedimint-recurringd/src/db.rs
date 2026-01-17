use std::collections::{BTreeMap, HashMap, HashSet};

use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    Database, IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped,
    WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::util::BoxFuture;
use fedimint_core::{Amount, impl_db_lookup, impl_db_record};
use fedimint_ln_client::recurring::{PaymentCodeId, PaymentCodeRootKey, RecurringPaymentProtocol};
use fedimint_ln_client::tweak_user_key;
use futures::stream::StreamExt;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use rand::Rng;

use crate::{
    LnClientContextExt, PaymentCodeInvoice, RecurringInvoiceServer, operation_id_from_user_key,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Encodable, Decodable)]
pub struct FederationDbPrefix([u8; 16]);

impl FederationDbPrefix {
    pub fn random() -> FederationDbPrefix {
        FederationDbPrefix(thread_rng().r#gen())
    }

    fn prepend(&self, byte: u8) -> Vec<u8> {
        let mut full_prefix = Vec::with_capacity(17);
        full_prefix.push(byte);
        full_prefix.extend(&self.0);
        full_prefix
    }
}

async fn load_federation_clients(db: &Database) -> Vec<(FederationId, FederationDbPrefix)> {
    let mut dbtx = db.begin_read_transaction().await;
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
    let mut dbtx = db.begin_write_transaction().await;

    if let Some(federation_db_entry) = dbtx.get_value(&FederationClientKey { federation_id }).await
    {
        return Err(federation_db_entry.db_prefix);
    }

    dbtx.insert_new_entry(
        &FederationClientKey { federation_id },
        &FederationClientEntry { db_prefix },
    )
    .await;

    dbtx.commit_tx().await;
    Ok(())
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

    SchemaVersion = 0xff,
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeNextInvoiceIndexKeyPrefix;

impl_db_record!(
    key = PaymentCodeNextInvoiceIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::PaymentCodeNextInvoiceIndex,
);
impl_db_lookup!(
    key = PaymentCodeNextInvoiceIndexKey,
    query_prefix = PaymentCodeNextInvoiceIndexKeyPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceKey {
    pub payment_code_id: PaymentCodeId,
    pub index: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoicePrefix {
    payment_code_id: PaymentCodeId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeInvoiceEntry {
    pub operation_id: OperationId,
    pub invoice: PaymentCodeInvoice,
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SchemaVersionKey;

impl_db_record!(
    key = SchemaVersionKey,
    value = u64,
    db_prefix = DbKeyPrefix::SchemaVersion,
);

type DbMigration =
    for<'a> fn(&'a RecurringInvoiceServer, WriteDatabaseTransaction<'a>) -> BoxFuture<'a, ()>;

impl RecurringInvoiceServer {
    pub(crate) fn migrations() -> BTreeMap<u64, DbMigration> {
        vec![(
            1,
            (|server: &RecurringInvoiceServer, dbtx| Box::pin(server.db_migration_v1(dbtx)))
                as DbMigration,
        )]
        .into_iter()
        .collect()
    }

    /// Backfill DB fix for bug that caused "holes" in invoice indices keeping
    /// the client from syncing. See <https://github.com/fedimint/fedimint/pull/7653>.
    async fn db_migration_v1(&self, mut dbtx: WriteDatabaseTransaction<'_>) {
        const BACKFILL_AMOUNT: Amount = Amount::from_msats(111111);

        let mut payment_codes = dbtx
            .find_by_prefix(&PaymentCodePrefix)
            .await
            .map(|(k, v)| (k.payment_code_id, v))
            .collect::<HashMap<PaymentCodeId, PaymentCodeEntry>>()
            .await;

        let payment_code_indices = dbtx
            .find_by_prefix(&PaymentCodeNextInvoiceIndexKeyPrefix)
            .await
            .map(|(payment_code_key, invoice_idx)| (payment_code_key.payment_code_id, invoice_idx))
            .collect::<HashMap<PaymentCodeId, u64>>()
            .await;

        for (payment_code_id, current_invoice_index) in payment_code_indices {
            let payment_code_entry = payment_codes
                .remove(&payment_code_id)
                .expect("If there's an index, there's a payment code entry");

            let payment_code_invoice_indices = dbtx
                .find_by_prefix(&PaymentCodeInvoicePrefix { payment_code_id })
                .await
                .map(|(invoice_key, _)| invoice_key.index)
                .collect::<HashSet<_>>()
                .await;

            let client = self
                .get_federation_client(payment_code_entry.federation_id)
                .await
                .expect("Federation client exists if we have the code in our DB");
            let ln_client_module = client.get_ln_module().expect("LN module is present");

            let missing_indices = (1..=current_invoice_index)
                .filter(|idx| !payment_code_invoice_indices.contains(idx));
            for missing_index in missing_indices {
                let initial_operation_id =
                    operation_id_from_user_key(payment_code_entry.root_key, missing_index);
                let invoice = if let Some(invoice) =
                    Self::check_if_invoice_exists(&client, initial_operation_id).await
                {
                    invoice
                } else {
                    // Generate fake invoice to backfill "holes" in invoice indices
                    let (_, invoice, _) = ln_client_module
                        .create_bolt11_invoice_for_user(
                            BACKFILL_AMOUNT,
                            Bolt11InvoiceDescription::Direct(
                                Description::new("Backfill".to_string()).unwrap(),
                            ),
                            Some(3600),
                            tweak_user_key(SECP256K1, payment_code_entry.root_key.0, missing_index),
                            (),
                            None,
                        )
                        .await
                        .expect("We checked that there is no invoice for that index already");
                    invoice
                };

                self.save_bolt11_invoice(
                    &mut dbtx.to_ref(),
                    initial_operation_id,
                    payment_code_id,
                    missing_index,
                    invoice,
                )
                .await;
            }
        }
    }
}
