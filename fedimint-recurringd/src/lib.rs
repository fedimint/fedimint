use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use fedimint_client::{Client, ClientHandleArc, ClientModule, ClientModuleInstance};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    AutocommitResultExt, Database, IRawDatabase, IReadDatabaseTransactionOpsTyped,
    IWriteDatabaseTransactionOpsTyped, WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::secp256k1::hashes::sha256;
use fedimint_core::task::timeout;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use fedimint_derive_secret::DerivableSecret;
use fedimint_ln_client::recurring::{
    PaymentCodeId, PaymentCodeRootKey, RecurringPaymentError, RecurringPaymentProtocol,
};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnReceiveState, tweak_user_key,
};
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Sha256};
use lnurl::Tag;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

use crate::db::{
    FederationDbPrefix, PaymentCodeEntry, PaymentCodeInvoiceEntry, PaymentCodeInvoiceKey,
    PaymentCodeKey, PaymentCodeNextInvoiceIndexKey, PaymentCodeVariant, SchemaVersionKey,
    load_federation_client_databases, open_client_db, try_add_federation_database,
};

mod db;

#[derive(Clone)]
pub struct RecurringInvoiceServer {
    db: Database,
    connectors: ConnectorRegistry,
    clients: Arc<RwLock<HashMap<FederationId, ClientHandleArc>>>,
    invoice_generated: Arc<Notify>,
    base_url: SafeUrl,
}

impl RecurringInvoiceServer {
    pub async fn new(
        connectors: ConnectorRegistry,
        db: impl IRawDatabase + 'static,
        base_url: SafeUrl,
    ) -> anyhow::Result<Self> {
        let db = Database::new(db, Default::default());

        let mut clients = HashMap::<_, ClientHandleArc>::new();

        for (federation_id, db) in load_federation_client_databases(&db).await {
            let mut client_builder = Client::builder().await?;
            client_builder.with_module(LightningClientInit::default());
            client_builder.with_module(MintClientInit);
            let client = client_builder
                .open(
                    connectors.clone(),
                    db,
                    fedimint_client::RootSecret::StandardDoubleDerive(Self::default_secret()),
                )
                .await?;
            clients.insert(federation_id, Arc::new(client));
        }

        let slf = Self {
            db: db.clone(),
            clients: Arc::new(RwLock::new(clients)),
            invoice_generated: Arc::new(Default::default()),
            base_url,
            connectors,
        };

        slf.run_db_migrations().await;

        Ok(slf)
    }

    /// We don't want to hold any money or sign anything ourselves, we only use
    /// the client with externally supplied key material and to track
    /// ongoing progress of other users' receives.
    fn default_secret() -> DerivableSecret {
        DerivableSecret::new_root(&[], &[])
    }

    pub async fn register_federation(
        &self,
        invite_code: &InviteCode,
    ) -> Result<FederationId, RecurringPaymentError> {
        let federation_id = invite_code.federation_id();
        info!("Registering federation {}", federation_id);

        // We lock to prevent parallel join attempts
        // TODO: lock per federation
        let mut clients = self.clients.write().await;
        if clients.contains_key(&federation_id) {
            return Err(RecurringPaymentError::FederationAlreadyRegistered(
                federation_id,
            ));
        }

        // We don't know if joining will succeed or be interrupted. We use a random DB
        // prefix to initialize the client and only write the prefix to the DB if that
        // succeeds. If it fails we end up with some orphaned data in the DB, if it ever
        // becomes a problem we can clean it up later.
        let client_db_prefix = FederationDbPrefix::random();
        let client_db = open_client_db(&self.db, client_db_prefix);

        match Self::join_federation_static(self.connectors.clone(), client_db, invite_code).await {
            Ok(client) => {
                try_add_federation_database(&self.db, federation_id, client_db_prefix)
                    .await
                    .expect("We hold a global lock, no parallel joining can happen");
                clients.insert(federation_id, client);
                Ok(federation_id)
            }
            Err(e) => {
                // TODO: clean up DB?
                Err(e)
            }
        }
    }

    async fn join_federation_static(
        connectors: ConnectorRegistry,
        client_db: Database,
        invite_code: &InviteCode,
    ) -> Result<ClientHandleArc, RecurringPaymentError> {
        let mut client_builder = Client::builder()
            .await
            .map_err(RecurringPaymentError::JoiningFederationFailed)?;

        client_builder.with_module(LightningClientInit::default());
        client_builder.with_module(MintClientInit);

        let client = client_builder
            .preview(connectors, invite_code)
            .await?
            .join(
                client_db,
                fedimint_client::RootSecret::StandardDoubleDerive(Self::default_secret()),
            )
            .await
            .map_err(RecurringPaymentError::JoiningFederationFailed)?;
        Ok(Arc::new(client))
    }

    pub async fn register_recurring_payment_code(
        &self,
        federation_id: FederationId,
        payment_code_root_key: PaymentCodeRootKey,
        protocol: RecurringPaymentProtocol,
        meta: &str,
    ) -> Result<String, RecurringPaymentError> {
        // TODO: support BOLT12
        if protocol != RecurringPaymentProtocol::LNURL {
            return Err(RecurringPaymentError::UnsupportedProtocol(protocol));
        }

        // Ensure the federation is supported
        self.get_federation_client(federation_id).await?;

        let payment_code = self.create_lnurl(payment_code_root_key.to_payment_code_id());
        let payment_code_entry = PaymentCodeEntry {
            root_key: payment_code_root_key,
            federation_id,
            protocol,
            payment_code: payment_code.clone(),
            variant: PaymentCodeVariant::Lnurl {
                meta: meta.to_owned(),
            },
        };

        let mut dbtx = self.db.begin_write_transaction().await;
        if let Some(existing_code) = dbtx
            .insert_entry(
                &PaymentCodeKey {
                    payment_code_id: payment_code_root_key.to_payment_code_id(),
                },
                &payment_code_entry,
            )
            .await
        {
            if existing_code != payment_code_entry {
                return Err(RecurringPaymentError::PaymentCodeAlreadyExists(
                    payment_code_root_key,
                ));
            }

            dbtx.ignore_uncommitted();
            return Ok(payment_code);
        }

        dbtx.insert_new_entry(
            &PaymentCodeNextInvoiceIndexKey {
                payment_code_id: payment_code_root_key.to_payment_code_id(),
            },
            &0,
        )
        .await;
        dbtx.commit_tx_result().await.map_err(anyhow::Error::from)?;

        Ok(payment_code)
    }

    fn create_lnurl(&self, payment_code_id: PaymentCodeId) -> String {
        let lnurl = LnUrl::from_url(format!(
            "{}lnv1/paycodes/{}",
            self.base_url, payment_code_id
        ));
        lnurl.encode()
    }

    pub async fn lnurl_pay(
        &self,
        payment_code_id: PaymentCodeId,
    ) -> Result<PayResponse, RecurringPaymentError> {
        let payment_code = self.get_payment_code(payment_code_id).await?;
        let PaymentCodeVariant::Lnurl { meta } = payment_code.variant;

        Ok(PayResponse {
            callback: format!("{}lnv1/paycodes/{}/invoice", self.base_url, payment_code_id),
            max_sendable: 100000000000,
            min_sendable: 1,
            tag: Tag::PayRequest,
            metadata: meta,
            comment_allowed: None,
            allows_nostr: None,
            nostr_pubkey: None,
        })
    }

    pub async fn lnurl_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<LNURLPayInvoice, RecurringPaymentError> {
        let (operation_id, federation_id, invoice) =
            self.create_bolt11_invoice(payment_code_id, amount).await?;
        Ok(LNURLPayInvoice {
            pr: invoice.to_string(),
            verify: format!(
                "{}lnv1/verify/{}/{}",
                self.base_url,
                federation_id,
                operation_id.fmt_full()
            ),
        })
    }

    async fn create_bolt11_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<(OperationId, FederationId, Bolt11Invoice), RecurringPaymentError> {
        // Invoices are valid for one day by default, might become dynamic with BOLT12
        // support
        const DEFAULT_EXPIRY_TIME: u64 = 60 * 60 * 24;

        let payment_code = self.get_payment_code(payment_code_id).await?;

        let federation_client = self
            .get_federation_client(payment_code.federation_id)
            .await?;

        let (operation_id, invoice) = self
            .db
            .autocommit(
                |dbtx, _| {
                    let federation_client = federation_client.clone();
                    let payment_code = payment_code.clone();
                    Box::pin(async move {
                        let invoice_index = self
                            .get_next_invoice_index(&mut dbtx.to_ref_nc(), payment_code_id)
                            .await;

                        // Check if the invoice index was already used in an aborted call to this
                        // fn. If so:
                        //   1. Save the previously generated invoice. We don't want to reuse it
                        //      since it may be expired and in the future may contain call-specific
                        //      data, but also want to allow the client to sync past it.
                        //   2. Increment the invoice index to generate a new invoice since re-using
                        //      the same index wouldn't work (operation id reuse is forbidden).
                        let initial_operation_id =
                            operation_id_from_user_key(payment_code.root_key, invoice_index);
                        let invoice_index = if let Some(invoice) =
                            Self::check_if_invoice_exists(&federation_client, initial_operation_id)
                                .await
                        {
                            self.save_bolt11_invoice(
                                dbtx,
                                initial_operation_id,
                                payment_code_id,
                                invoice_index,
                                invoice,
                            )
                            .await;
                            self.get_next_invoice_index(&mut dbtx.to_ref_nc(), payment_code_id)
                                .await
                        } else {
                            invoice_index
                        };

                        // This is where the main part starts: generate the invoice and save it to
                        // the DB
                        let federation_client_ln_module = federation_client.get_ln_module()?;
                        let gateway = federation_client_ln_module
                            .get_gateway(None, false)
                            .await?
                            .ok_or(RecurringPaymentError::NoGatewayFound)?;

                        let lnurl_meta = match payment_code.variant {
                            PaymentCodeVariant::Lnurl { meta } => meta,
                        };
                        let meta_hash = Sha256(sha256::Hash::hash(lnurl_meta.as_bytes()));
                        let description = Bolt11InvoiceDescription::Hash(meta_hash);

                        // TODO: ideally creating the invoice would take a dbtx as argument so we
                        // don't have to do the "check if invoice already exists" dance
                        let (operation_id, invoice, _preimage) = federation_client_ln_module
                            .create_bolt11_invoice_for_user_tweaked(
                                amount,
                                description,
                                Some(DEFAULT_EXPIRY_TIME),
                                payment_code.root_key.0,
                                invoice_index,
                                serde_json::Value::Null,
                                Some(gateway),
                            )
                            .await?;

                        self.save_bolt11_invoice(
                            dbtx,
                            operation_id,
                            payment_code_id,
                            invoice_index,
                            invoice.clone(),
                        )
                        .await;

                        Result::<_, anyhow::Error>::Ok((operation_id, invoice))
                    })
                },
                None,
            )
            .await
            .unwrap_autocommit()?;

        await_invoice_confirmed(&federation_client.get_ln_module()?, operation_id).await?;

        Ok((operation_id, federation_client.federation_id(), invoice))
    }

    async fn save_bolt11_invoice(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        operation_id: OperationId,
        payment_code_id: PaymentCodeId,
        invoice_index: u64,
        invoice: Bolt11Invoice,
    ) {
        dbtx.insert_new_entry(
            &PaymentCodeInvoiceKey {
                payment_code_id,
                index: invoice_index,
            },
            &PaymentCodeInvoiceEntry {
                operation_id,
                invoice: PaymentCodeInvoice::Bolt11(invoice.clone()),
            },
        )
        .await;

        let invoice_generated_notifier = self.invoice_generated.clone();
        dbtx.on_commit(move || {
            invoice_generated_notifier.notify_waiters();
        });
    }

    async fn check_if_invoice_exists(
        federation_client: &ClientHandleArc,
        operation_id: OperationId,
    ) -> Option<Bolt11Invoice> {
        let operation = federation_client
            .operation_log()
            .get_operation(operation_id)
            .await?;

        assert_eq!(
            operation.operation_module_kind(),
            LightningClientModule::kind().as_str()
        );

        let LightningOperationMetaVariant::Receive { invoice, .. } =
            operation.meta::<LightningOperationMeta>().variant
        else {
            panic!(
                "Unexpected operation meta variant: {:?}",
                operation.meta::<LightningOperationMeta>().variant
            );
        };

        Some(invoice)
    }

    async fn get_federation_client(
        &self,
        federation_id: FederationId,
    ) -> Result<ClientHandleArc, RecurringPaymentError> {
        self.clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(RecurringPaymentError::UnknownFederationId(federation_id))
    }

    pub async fn await_invoice_index_generated(
        &self,
        payment_code_id: PaymentCodeId,
        invoice_index: u64,
    ) -> Result<PaymentCodeInvoiceEntry, RecurringPaymentError> {
        self.get_payment_code(payment_code_id).await?;

        let mut notified = self.invoice_generated.notified();
        loop {
            let mut dbtx = self.db.begin_read_transaction().await;
            if let Some(invoice_entry) = dbtx
                .get_value(&PaymentCodeInvoiceKey {
                    payment_code_id,
                    index: invoice_index,
                })
                .await
            {
                break Ok(invoice_entry);
            };

            notified.await;
            notified = self.invoice_generated.notified();
        }
    }

    async fn get_next_invoice_index(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        payment_code_id: PaymentCodeId,
    ) -> u64 {
        let next_index = dbtx
            .get_value(&PaymentCodeNextInvoiceIndexKey { payment_code_id })
            .await
            .map(|index| index + 1)
            .unwrap_or(0);
        dbtx.insert_entry(
            &PaymentCodeNextInvoiceIndexKey { payment_code_id },
            &next_index,
        )
        .await;

        next_index
    }

    pub async fn list_federations(&self) -> Vec<FederationId> {
        self.clients.read().await.keys().cloned().collect()
    }

    async fn get_payment_code(
        &self,
        payment_code_id: PaymentCodeId,
    ) -> Result<PaymentCodeEntry, RecurringPaymentError> {
        self.db
            .begin_read_transaction()
            .await
            .get_value(&PaymentCodeKey { payment_code_id })
            .await
            .ok_or(RecurringPaymentError::UnknownPaymentCode(payment_code_id))
    }

    /// Returns if an invoice has been paid yet. To avoid DB indirection and
    /// since the URLs would be similarly long either way we identify
    /// invoices by federation id and operation id instead of the payment
    /// code. This function is the basis of `recurringd`'s [LUD-21]
    /// implementation that allows clients to verify if a given invoice they
    /// generated using the LNURL has been paid yet.
    ///
    /// [LUD-21]: https://github.com/lnurl/luds/blob/luds/21.md
    pub async fn verify_invoice_paid(
        &self,
        federation_id: FederationId,
        operation_id: OperationId,
    ) -> Result<InvoiceStatus, RecurringPaymentError> {
        let federation_client = self.get_federation_client(federation_id).await?;

        // Unfortunately LUD-21 wants us to return the invoice again, so we have to
        // fetch it from the operation meta.
        let invoice = {
            let operation = federation_client
                .operation_log()
                .get_operation(operation_id)
                .await
                .ok_or(RecurringPaymentError::UnknownInvoice(operation_id))?;

            if operation.operation_module_kind() != LightningClientModule::kind().as_str() {
                return Err(RecurringPaymentError::UnknownInvoice(operation_id));
            }

            let LightningOperationMetaVariant::Receive { invoice, .. } =
                operation.meta::<LightningOperationMeta>().variant
            else {
                return Err(RecurringPaymentError::UnknownInvoice(operation_id));
            };

            invoice
        };

        let ln_module = federation_client
            .get_first_module::<LightningClientModule>()
            .map_err(|e| {
                warn!("No compatible lightning module found {e}");
                RecurringPaymentError::NoLightningModuleFound
            })?;

        let mut stream = ln_module
            .subscribe_ln_receive(operation_id)
            .await
            .map_err(|_| RecurringPaymentError::UnknownInvoice(operation_id))?
            .into_stream();
        let status = loop {
            // Unfortunately the fedimint client doesn't track payment status internally
            // yet, but relies on integrators to consume the update streams belonging to
            // operations to figure out their state. Since the verify endpoint is meant to
            // be non-blocking, we need to find a way to consume the stream until we think
            // no immediate progress will be made anymore. That's why we limit each update
            // step to 100ms, far more than a DB read should ever take, and abort if we'd
            // block to wait for further progress to be made.
            let update = timeout(Duration::from_millis(100), stream.next()).await;
            match update {
                // For some reason recurringd jumps right to claimed without going over funded … but
                // either is fine to conclude the user will receive their money once they come
                // online.
                Ok(Some(LnReceiveState::Funded | LnReceiveState::Claimed)) => {
                    break PaymentStatus::Paid;
                }
                // Keep looking for a state update indicating the invoice having been paid
                Ok(Some(_)) => {
                    continue;
                }
                // If we reach the end of the update stream without observing a state indicating the
                // invoice having been paid there was likely some error or the invoice timed out.
                // Either way we just show the invoice as unpaid.
                Ok(None) | Err(_) => {
                    break PaymentStatus::Pending;
                }
            }
        };

        Ok(InvoiceStatus { invoice, status })
    }

    async fn run_db_migrations(&self) {
        let migrations = Self::migrations();
        let schema_version: u64 = self
            .db
            .begin_read_transaction()
            .await
            .get_value(&SchemaVersionKey)
            .await
            .unwrap_or_default();

        for (target_schema, migration_fn) in migrations
            .into_iter()
            .skip_while(|(target_schema, _)| *target_schema <= schema_version)
        {
            let mut dbtx = self.db.begin_write_transaction().await;
            dbtx.insert_entry(&SchemaVersionKey, &target_schema).await;

            migration_fn(self, dbtx.to_ref_nc()).await;

            dbtx.commit_tx().await;
        }
    }
}

async fn await_invoice_confirmed(
    ln_module: &ClientModuleInstance<'_, LightningClientModule>,
    operation_id: OperationId,
) -> Result<(), RecurringPaymentError> {
    let mut operation_updated = ln_module
        .subscribe_ln_receive(operation_id)
        .await?
        .into_stream();

    while let Some(update) = operation_updated.next().await {
        if matches!(update, LnReceiveState::WaitingForPayment { .. }) {
            return Ok(());
        }
    }

    Err(RecurringPaymentError::Other(anyhow!(
        "BOLT11 invoice not confirmed"
    )))
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum PaymentCodeInvoice {
    Bolt11(Bolt11Invoice),
}

/// Helper struct indicating if an invoice was paid. In the future it may also
/// contain the preimage to be fully LUD-21 compliant.
pub struct InvoiceStatus {
    pub invoice: Bolt11Invoice,
    pub status: PaymentStatus,
}

pub enum PaymentStatus {
    Paid,
    Pending,
}

impl PaymentStatus {
    pub fn is_paid(&self) -> bool {
        matches!(self, PaymentStatus::Paid)
    }
}

/// The lnurl-rs crate doesn't have the `verify` field in this type and we don't
/// use any of the other fields right now. Once we upstream the verify field
/// this struct can be removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LNURLPayInvoice {
    pub pr: String,
    pub verify: String,
}

fn operation_id_from_user_key(user_key: PaymentCodeRootKey, index: u64) -> OperationId {
    let invoice_key = tweak_user_key(SECP256K1, user_key.0, index);
    let preimage = sha256::Hash::hash(&invoice_key.serialize()[..]);
    let payment_hash = sha256::Hash::hash(&preimage[..]);

    OperationId(payment_hash.to_byte_array())
}

trait LnClientContextExt {
    fn get_ln_module(
        &'_ self,
    ) -> Result<ClientModuleInstance<'_, LightningClientModule>, RecurringPaymentError>;
}

impl LnClientContextExt for ClientHandleArc {
    fn get_ln_module(
        &'_ self,
    ) -> Result<ClientModuleInstance<'_, LightningClientModule>, RecurringPaymentError> {
        self.get_first_module::<LightningClientModule>()
            .map_err(|e| {
                warn!("No compatible lightning module found {e}");
                RecurringPaymentError::NoLightningModuleFound
            })
    }
}
