//TODO:remove
#![allow(dead_code, unused_variables)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_api_client::api::net::Connector;
use fedimint_client::{Client, ClientHandleArc, ClientModuleInstance};
use fedimint_core::config::FederationId;
use fedimint_core::core::{ModuleKind, OperationId};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, IRawDatabase};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::secp256k1::hashes::sha256;
use fedimint_core::secp256k1::{All, Secp256k1};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use fedimint_derive_secret::DerivableSecret;
use fedimint_ln_client::recurring::{
    PaymentCodeId, PaymentCodeRootKey, RecurringPaymentError, RecurringPaymentProtocol,
};
use fedimint_ln_client::{LightningClientInit, LightningClientModule, LnReceiveState};
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Sha256};
use lnurl::lnurl::LnUrl;
use lnurl::pay::{LnURLPayInvoice, PayResponse};
use lnurl::Tag;
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

use crate::db::{
    load_federation_client_databases, open_client_db, try_add_federation_database,
    FederationDbPrefix, PaymentCodeEntry, PaymentCodeInvoiceEntry, PaymentCodeInvoiceKey,
    PaymentCodeKey, PaymentCodeNextInvoiceIndexKey, PaymentCodeVariant,
};

mod db;

#[derive(Clone)]
pub struct RecurringInvoiceServer {
    db: Database,
    clients: Arc<RwLock<HashMap<FederationId, ClientHandleArc>>>,
    invoice_generated: Arc<Notify>,
    base_url: SafeUrl,
    secp_ctx: Secp256k1<All>,
}

impl RecurringInvoiceServer {
    pub async fn new(db: impl IRawDatabase + 'static, base_url: SafeUrl) -> anyhow::Result<Self> {
        let db = Database::new(db, Default::default());

        let mut clients = HashMap::<_, ClientHandleArc>::new();

        for (federation_id, db) in load_federation_client_databases(&db).await {
            let mut client_builder = Client::builder(db).await?;
            client_builder.with_module(LightningClientInit::default());
            client_builder.with_module(MintClientInit);
            client_builder.with_primary_module_kind(ModuleKind::from_static_str("mint"));
            let client = client_builder.open(Self::default_secret()).await?;
            clients.insert(federation_id, Arc::new(client));
        }

        Ok(Self {
            db,
            clients: Arc::new(RwLock::new(clients)),
            invoice_generated: Arc::new(Default::default()),
            base_url,
            secp_ctx: Default::default(),
        })
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

        match Self::join_federation_static(client_db, invite_code).await {
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
        client_db: Database,
        invite_code: &InviteCode,
    ) -> Result<ClientHandleArc, RecurringPaymentError> {
        let config = Connector::default()
            .download_from_invite_code(invite_code)
            .await
            .map_err(RecurringPaymentError::JoiningFederationFailed)?;

        let mut client_builder = Client::builder(client_db)
            .await
            .map_err(RecurringPaymentError::JoiningFederationFailed)?;

        client_builder.with_connector(Connector::default());
        client_builder.with_module(LightningClientInit::default());
        client_builder.with_module(MintClientInit);
        client_builder.with_primary_module_kind(ModuleKind::from_static_str("mint"));

        let client = client_builder
            .join(Self::default_secret(), config, None)
            .await
            .map_err(RecurringPaymentError::JoiningFederationFailed)?;
        Ok(Arc::new(client))
    }

    pub async fn register_recurring_payment_code(
        &self,
        federation_id: FederationId,
        payment_code_root_key: PaymentCodeRootKey,
        protocol: RecurringPaymentProtocol,
    ) -> Result<String, RecurringPaymentError> {
        // TODO: support BOLT12
        if protocol != RecurringPaymentProtocol::LNURL {
            return Err(RecurringPaymentError::UnsupportedProtocol(protocol));
        }

        let payment_code = self.create_lnurl(payment_code_root_key.to_payment_code_id());
        let payment_code_entry = PaymentCodeEntry {
            root_key: payment_code_root_key,
            federation_id,
            protocol,
            payment_code: payment_code.clone(),
            variant: PaymentCodeVariant::Lnurl {
                // TODO: put useful info here
                meta: "[]".to_string(),
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
        dbtx.commit_tx().await;

        Ok(payment_code)
    }

    fn create_lnurl(&self, payment_code_id: PaymentCodeId) -> String {
        let lnurl = LnUrl::from_url(format!("{}paycodes/{}", self.base_url, payment_code_id));
        lnurl.encode()
    }

    pub fn lnurl_pay(&self, payment_code_id: PaymentCodeId) -> PayResponse {
        PayResponse {
            callback: format!("{}paycodes/{}/invoice", self.base_url, payment_code_id),
            max_sendable: 100000000000,
            min_sendable: 1,
            tag: Tag::PayRequest,
            metadata: "".to_string(),
            comment_allowed: None,
            allows_nostr: None,
            nostr_pubkey: None,
        }
    }

    pub async fn lnurl_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<LnURLPayInvoice, RecurringPaymentError> {
        Ok(LnURLPayInvoice::new(
            self.create_bolt11_invoice(payment_code_id, amount)
                .await?
                .to_string(),
        ))
    }

    pub async fn create_bolt11_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<Bolt11Invoice, RecurringPaymentError> {
        // Invoices are valid for one day by default, might become dynamic with BOLT12
        // support
        const DEFAULT_EXPIRY_TIME: u64 = 60 * 60 * 24;

        let payment_code = self.get_payment_code(payment_code_id).await?;
        let invoice_index = self.get_next_invoice_index(payment_code_id).await;

        let federation_client = self
            .get_federation_client(payment_code.federation_id)
            .await?;
        let federation_client_ln_module = federation_client
            .get_first_module::<LightningClientModule>()
            .map_err(|e| {
                warn!("No compatible lightning module found {e}");
                RecurringPaymentError::NoLightningModuleFound
            })?;

        let gateway = federation_client_ln_module
            .get_gateway(None, false)
            .await?
            .ok_or(RecurringPaymentError::NoGatewayFound)?;

        let lnurl_meta = match payment_code.variant {
            PaymentCodeVariant::Lnurl { meta } => meta,
        };
        let meta_hash = Sha256(sha256::Hash::hash(lnurl_meta.as_bytes()));
        let description = Bolt11InvoiceDescription::Hash(&meta_hash);

        // TODO: ideally creating the invoice would take a dbtx as argument so we don't
        // get holes in our used indexes in case this function fails/is cancelled
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

        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_new_entry(
            &PaymentCodeInvoiceKey {
                payment_code_id,
                index: invoice_index,
            },
            &PaymentCodeInvoiceEntry {
                operation_id,
                invoice: invoice.clone(),
            },
        )
        .await;

        let invoice_generated_notifier = self.invoice_generated.clone();
        dbtx.on_commit(move || {
            invoice_generated_notifier.notify_waiters();
        });
        dbtx.commit_tx().await;

        await_invoice_confirmed(&federation_client_ln_module, operation_id).await?;

        Ok(invoice)
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

    async fn get_next_invoice_index(&self, payment_code_id: PaymentCodeId) -> u64 {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async move {
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
                        Result::<_, ()>::Ok(next_index)
                    })
                },
                None,
            )
            .await
            .expect("Loops forever and never returns errors internally")
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
