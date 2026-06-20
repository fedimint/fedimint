use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use fedimint_client::meta::MetaService;
use fedimint_client::{Client, ClientHandleArc, ClientModule, ClientModuleInstance};
use fedimint_client_module::meta::LegacyMetaSource;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    AutocommitResultExt, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
    IRawDatabase,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::secp256k1::hashes::sha256;
use fedimint_core::secp256k1::{PublicKey, SECP256K1};
use fedimint_core::task::timeout;
use fedimint_core::util::{FmtCompact, FmtCompactAnyhow, SafeUrl};
use fedimint_core::{Amount, BitcoinHash, runtime};
use fedimint_derive_secret::DerivableSecret;
use fedimint_ln_client::common::{LightningGateway, LightningGatewayAnnouncement};
use fedimint_ln_client::recurring::{
    PaymentCodeId, PaymentCodeRootKey, RecurringPaymentError, RecurringPaymentProtocol,
};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnReceiveState, tweak_user_key,
};
use fedimint_lnurl::{PayResponse, encode_lnurl, pay_request_tag};
use fedimint_meta_client::MetaModuleMetaSourceWithFallback;
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Sha256};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock, watch};
use tracing::{debug, info, warn};

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
    gateway_cache: Arc<RwLock<HashMap<FederationId, watch::Receiver<Vec<CachedGateway>>>>>,
    invoice_generated: Arc<Notify>,
    base_url: SafeUrl,
}

#[derive(Clone)]
struct CachedGateway {
    gateway: LightningGateway,
    vetted: bool,
}

impl RecurringInvoiceServer {
    pub async fn new(
        connectors: ConnectorRegistry,
        db: impl IRawDatabase + 'static,
        base_url: SafeUrl,
    ) -> anyhow::Result<Self> {
        let db = Database::new(db, Default::default());

        let mut clients = HashMap::<_, ClientHandleArc>::new();
        let mut gateway_cache = HashMap::<FederationId, watch::Receiver<Vec<CachedGateway>>>::new();

        for (federation_id, db) in load_federation_client_databases(&db).await {
            let mut client_builder = Client::builder().await?;
            client_builder.with_meta_service(recurringd_meta_service());
            client_builder.with_module(LightningClientInit::default());
            client_builder.with_module(MintClientInit);
            let client = client_builder
                .open(
                    connectors.clone(),
                    db,
                    fedimint_client::RootSecret::StandardDoubleDerive(Self::default_secret()),
                )
                .await?;
            let client = Arc::new(client);
            gateway_cache.insert(
                federation_id,
                spawn_gateway_cache_refresh(federation_id, &client),
            );
            clients.insert(federation_id, client);
        }

        let slf = Self {
            db: db.clone(),
            clients: Arc::new(RwLock::new(clients)),
            gateway_cache: Arc::new(RwLock::new(gateway_cache)),
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
                self.gateway_cache.write().await.insert(
                    federation_id,
                    spawn_gateway_cache_refresh(federation_id, &client),
                );
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

        client_builder.with_meta_service(recurringd_meta_service());
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

        let mut dbtx = self.db.begin_transaction().await;
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
        encode_lnurl(&format!(
            "{}lnv1/paycodes/{}",
            self.base_url, payment_code_id
        ))
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
            tag: pay_request_tag(),
            metadata: meta,
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

        let gateway = self
            .get_cached_gateway(payment_code.federation_id, amount)
            .await?;

        let (operation_id, invoice) = self
            .db
            .autocommit(
                |dbtx, _| {
                    let federation_client = federation_client.clone();
                    let payment_code = payment_code.clone();
                    let gateway = gateway.clone();
                    Box::pin(async move {
                        let mut invoice_index = self
                            .get_next_invoice_index(&mut dbtx.to_ref_nc(), payment_code_id)
                            .await;

                        // Check if any invoice indices were already used in aborted calls to this
                        // fn. If so:
                        //   1. Save each previously generated invoice. We don't want to reuse it
                        //      since it may be expired and in the future may contain call-specific
                        //      data, but also want to allow the client to sync past it.
                        //   2. Increment the invoice index until we find an unused one, since
                        //      re-using an index would re-use an operation id, which is forbidden.
                        //
                        // A single request can only create one orphaned operation, but multiple
                        // cancelled/restarted requests in a row can leave multiple consecutive
                        // orphaned operations before recurringd commits its own DB state.
                        let invoice_index = loop {
                            let operation_id =
                                operation_id_from_user_key(payment_code.root_key, invoice_index);

                            let Some(invoice) =
                                Self::check_if_invoice_exists(&federation_client, operation_id)
                                    .await
                            else {
                                break invoice_index;
                            };

                            self.save_bolt11_invoice(
                                dbtx,
                                operation_id,
                                payment_code_id,
                                invoice_index,
                                invoice,
                            )
                            .await;

                            invoice_index = self
                                .get_next_invoice_index(&mut dbtx.to_ref_nc(), payment_code_id)
                                .await;
                        };

                        // This is where the main part starts: generate the invoice and save it to
                        // the DB
                        let federation_client_ln_module = federation_client.get_ln_module()?;

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
        dbtx: &mut DatabaseTransaction<'_>,
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

    async fn get_cached_gateway(
        &self,
        federation_id: FederationId,
        amount: Amount,
    ) -> Result<LightningGateway, RecurringPaymentError> {
        const EMPTY_GATEWAY_CACHE_WAIT: Duration = Duration::from_secs(60);

        let mut gateway_cache = self
            .gateway_cache
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(RecurringPaymentError::NoGatewayFound)?;

        if let Some(gateway) = select_preferred_gateway(&gateway_cache.borrow(), amount) {
            return Ok(gateway);
        }

        timeout(EMPTY_GATEWAY_CACHE_WAIT, async {
            loop {
                gateway_cache
                    .changed()
                    .await
                    .map_err(|_| RecurringPaymentError::NoGatewayFound)?;

                if let Some(gateway) =
                    select_preferred_gateway(&gateway_cache.borrow_and_update(), amount)
                {
                    break Ok(gateway);
                }
            }
        })
        .await
        .map_err(|_| RecurringPaymentError::NoGatewayFound)?
    }

    pub async fn await_invoice_index_generated(
        &self,
        payment_code_id: PaymentCodeId,
        invoice_index: u64,
    ) -> Result<PaymentCodeInvoiceEntry, RecurringPaymentError> {
        self.get_payment_code(payment_code_id).await?;

        let mut notified = self.invoice_generated.notified();
        loop {
            let mut dbtx = self.db.begin_transaction_nc().await;
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
        dbtx: &mut DatabaseTransaction<'_>,
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
            .begin_transaction_nc()
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
            .begin_transaction_nc()
            .await
            .get_value(&SchemaVersionKey)
            .await
            .unwrap_or_default();

        for (target_schema, migration_fn) in migrations
            .into_iter()
            .skip_while(|(target_schema, _)| *target_schema <= schema_version)
        {
            let mut dbtx = self.db.begin_transaction().await;
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

fn recurringd_meta_service() -> Arc<MetaService> {
    MetaService::new(MetaModuleMetaSourceWithFallback::<LegacyMetaSource>::default())
}

fn spawn_gateway_cache_refresh(
    federation_id: FederationId,
    client: &ClientHandleArc,
) -> watch::Receiver<Vec<CachedGateway>> {
    const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

    let (gateway_cache_sender, gateway_cache_receiver) = watch::channel(Vec::new());
    let task_group = client.task_group().clone();
    let client = client.clone();
    task_group.spawn_cancellable("recurringd-gateway-cache-refresh", async move {
        loop {
            match select_available_gateways(&client).await {
                Ok(gateways) => {
                    gateway_cache_sender.send_replace(gateways);
                }
                Err(err) => {
                    warn!(
                        federation_id = %federation_id,
                        err = %err.fmt_compact(),
                        "Failed to refresh recurringd gateway cache"
                    );
                }
            }

            runtime::sleep(REFRESH_INTERVAL).await;
        }
    });

    gateway_cache_receiver
}

async fn select_available_gateways(
    client: &ClientHandleArc,
) -> Result<Vec<CachedGateway>, RecurringPaymentError> {
    let ln_module = client.get_ln_module()?;
    ln_module.update_gateway_cache().await.map_err(|err| {
        warn!(
            err = %err.fmt_compact_anyhow(),
            "Failed to refresh gateway announcements"
        );
        RecurringPaymentError::NoGatewayFound
    })?;

    let mut gateways = ln_module.list_gateways().await;
    if gateways.is_empty() {
        return Err(RecurringPaymentError::NoGatewayFound);
    }

    let vetted_gateway_ids = fetch_vetted_gateway_ids(client).await;
    sort_gateways_by_preference(&mut gateways, &vetted_gateway_ids);

    let mut available_gateways = Vec::new();
    for gateway in gateways {
        let gateway_id = gateway.info.gateway_id;
        let vetted = gateway.vetted || vetted_gateway_ids.contains(&gateway_id);
        match ln_module
            .select_available_gateway(Some(gateway.info), None)
            .await
        {
            Ok(gateway) => available_gateways.push(CachedGateway { gateway, vetted }),
            Err(err) => {
                debug!(
                    gateway_id = %gateway_id,
                    err = %err.fmt_compact_anyhow(),
                    "Gateway failed availability check"
                );
            }
        }
    }

    if available_gateways.is_empty() {
        return Err(RecurringPaymentError::NoGatewayFound);
    }

    Ok(available_gateways)
}

fn select_preferred_gateway(
    gateways: &[CachedGateway],
    amount: Amount,
) -> Option<LightningGateway> {
    gateways
        .iter()
        .min_by_key(|gateway| {
            (
                !gateway.vetted,
                gateway_fee_msat(&gateway.gateway, amount),
                gateway.gateway.gateway_id.serialize(),
            )
        })
        .map(|gateway| gateway.gateway.clone())
}

fn gateway_fee_msat(gateway: &LightningGateway, amount: Amount) -> u64 {
    let proportional_fee =
        (u128::from(amount.msats) * u128::from(gateway.fees.proportional_millionths)) / 1_000_000;

    u64::from(gateway.fees.base_msat)
        .saturating_add(u64::try_from(proportional_fee).unwrap_or(u64::MAX))
}

fn sort_gateways_by_preference(
    gateways: &mut [LightningGatewayAnnouncement],
    vetted_gateway_ids: &HashSet<PublicKey>,
) {
    gateways.sort_by_cached_key(|gateway| {
        let vetted = gateway.vetted || vetted_gateway_ids.contains(&gateway.info.gateway_id);
        (
            !vetted,
            u64::from(gateway.info.fees.base_msat),
            gateway.info.gateway_id.serialize(),
        )
    });
}

async fn fetch_vetted_gateway_ids(client: &ClientHandleArc) -> HashSet<PublicKey> {
    let Some(vetted_gateways) = client
        .meta_service()
        .entries(client.db())
        .await
        .and_then(|entries| entries.get("vetted_gateways").cloned())
        .and_then(|value| parse_vetted_gateway_ids(&value))
    else {
        debug!("No vetted gateways configured in federation metadata");
        return HashSet::new();
    };

    vetted_gateways
        .into_iter()
        .filter_map(|gateway_id| match gateway_id.parse::<PublicKey>() {
            Ok(gateway_id) => Some(gateway_id),
            Err(err) => {
                warn!(
                    %gateway_id,
                    err = %err.fmt_compact(),
                    "Failed to parse vetted gateway ID"
                );
                None
            }
        })
        .collect()
}

fn parse_vetted_gateway_ids(value: &serde_json::Value) -> Option<Vec<String>> {
    if let Ok(gateway_ids) = serde_json::from_value::<Vec<String>>(value.clone()) {
        return Some(gateway_ids);
    }

    let value = value.as_str()?;

    // The canonical metadata format is a JSON array of gateway ID strings. Older
    // configs may have stored that JSON array as a string.
    match serde_json::from_str::<Vec<String>>(value) {
        Ok(gateway_ids) => {
            warn!("vetted_gateways metadata should be configured as a JSON array, not a string");
            Some(gateway_ids)
        }
        Err(_) => None,
    }
}
