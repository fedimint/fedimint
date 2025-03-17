pub mod api;

use std::fmt::{Display, Formatter};
use std::future::pending;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use api::{RecurringdApiError, RecurringdClient};
use async_stream::stream;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::SECP256K1;
use fedimint_client_module::OperationId;
use fedimint_client_module::module::ClientContext;
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_core::BitcoinHash;
use fedimint_core::config::FederationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::task::sleep;
use fedimint_core::util::{BoxFuture, FmtCompact, SafeUrl};
use fedimint_derive_secret::ChildId;
use futures::StreamExt;
use futures::future::select_all;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::select;
use tokio::sync::Notify;
use tracing::{debug, trace};

use crate::db::RecurringPaymentCodeKeyPrefix;
use crate::receive::LightningReceiveError;
use crate::{
    LightningClientModule, LightningClientStateMachines, LightningOperationMeta,
    LightningOperationMetaVariant, LnReceiveState, tweak_user_secret_key,
};

impl LightningClientModule {
    pub async fn register_recurring_payment_code(
        &self,
        protocol: RecurringPaymentProtocol,
        recurringd_api: SafeUrl,
        meta: &str,
    ) -> Result<RecurringPaymentCodeEntry, RecurringdApiError> {
        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let recurringd_api_inner = recurringd_api.clone();
                    let new_recurring_payment_code = self.new_recurring_payment_code.clone();
                    Box::pin(async move {
                        let next_idx = dbtx
                            .find_by_prefix_sorted_descending(&RecurringPaymentCodeKeyPrefix)
                            .await
                            .map(|(k, _)| k.derivation_idx)
                            .next()
                            .await
                            .map_or(0, |last_idx| last_idx + 1);

                        let payment_code_root_key = self.get_payment_code_root_key(next_idx);

                        let recurringd_client = RecurringdClient::new(recurringd_api_inner.clone());
                        let register_response = recurringd_client
                            .register_recurring_payment_code(
                                self.client_ctx
                                    .get_config()
                                    .await
                                    .global
                                    .calculate_federation_id(),
                                protocol,
                                crate::recurring::PaymentCodeRootKey(
                                    payment_code_root_key.public_key(),
                                ),
                                meta,
                            )
                            .await?;

                        let payment_code_entry = RecurringPaymentCodeEntry {
                            protocol,
                            root_keypair: payment_code_root_key,
                            code: register_response.recurring_payment_code,
                            recurringd_api: recurringd_api_inner,
                            last_derivation_index: 0,
                            creation_time: fedimint_core::time::now(),
                            meta: meta.to_owned(),
                        };
                        dbtx.insert_new_entry(
                            &crate::db::RecurringPaymentCodeKey {
                                derivation_idx: next_idx,
                            },
                            &payment_code_entry,
                        )
                        .await;
                        dbtx.on_commit(move || new_recurring_payment_code.notify_waiters());

                        Ok(payment_code_entry)
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                fedimint_core::db::AutocommitError::ClosureError { error, .. } => error,
                fedimint_core::db::AutocommitError::CommitFailed { last_error, .. } => {
                    panic!("Commit failed: {last_error}")
                }
            })
    }

    pub async fn get_recurring_payment_codes(&self) -> Vec<(u64, RecurringPaymentCodeEntry)> {
        Self::get_recurring_payment_codes_static(self.client_ctx.module_db()).await
    }

    pub async fn get_recurring_payment_codes_static(
        db: &fedimint_core::db::Database,
    ) -> Vec<(u64, RecurringPaymentCodeEntry)> {
        assert!(!db.is_global(), "Needs to run in module context");
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&RecurringPaymentCodeKeyPrefix)
            .await
            .map(|(idx, entry)| (idx.derivation_idx, entry))
            .collect()
            .await
    }

    fn get_payment_code_root_key(&self, payment_code_registration_idx: u64) -> Keypair {
        self.recurring_payment_code_secret
            .child_key(ChildId(payment_code_registration_idx))
            .to_secp_key(&self.secp)
    }

    pub async fn scan_recurring_payment_code_invoices(
        client: ClientContext<Self>,
        new_code_registered: Arc<Notify>,
    ) {
        const QUERY_RETRY_DELAY: Duration = Duration::from_secs(60);

        loop {
            // We have to register the waiter before querying the DB for recurring payment
            // code registrations so we don't miss any notification between querying the DB
            // and registering the notifier.
            let new_code_registered_future = new_code_registered.notified();

            // We wait for all recurring payment codes to have an invoice in parallel
            let all_recurring_invoice_futures = Self::get_recurring_payment_codes_static(client.module_db())
                .await
                .into_iter()
                .map(|(payment_code_idx, payment_code)| Box::pin(async move {
                    let client = RecurringdClient::new(payment_code.recurringd_api.clone());
                    let invoice_index = payment_code.last_derivation_index + 1;

                    trace!(
                        root_key=?payment_code.root_keypair.public_key(),
                        %invoice_index,
                        server=%payment_code.recurringd_api,
                        "Waiting for new invoice from recurringd"
                    );

                    match client.await_new_invoice(crate::recurring::PaymentCodeRootKey(payment_code.root_keypair.public_key()), invoice_index).await {
                        Ok(invoice) => {Ok((payment_code_idx, payment_code, invoice_index, invoice))}
                        Err(err) => {
                            debug!(
                                err=%err.fmt_compact(),
                                root_key=?payment_code.root_keypair.public_key(),
                                invoice_index=%invoice_index,
                                server=%payment_code.recurringd_api,
                                "Failed querying recurring payment code invoice, will retry in {:?}",
                                QUERY_RETRY_DELAY,
                            );
                            sleep(QUERY_RETRY_DELAY).await;
                            Err(err)
                        }
                    }
                }))
                .collect::<Vec<_>>();

            // TODO: isn't there some shorthand for this
            let await_any_invoice: BoxFuture<_> = if all_recurring_invoice_futures.is_empty() {
                Box::pin(pending())
            } else {
                Box::pin(select_all(all_recurring_invoice_futures))
            };

            let (payment_code_idx, _payment_code, invoice_idx, invoice) = select! {
                (ret, _, _) = await_any_invoice => match ret {
                    Ok(ret) => ret,
                    Err(_) => {
                        continue;
                    }
                },
                () = new_code_registered_future => {
                    continue;
                }
            };

            Self::process_recurring_payment_code_invoice(
                &client,
                payment_code_idx,
                invoice_idx,
                invoice,
            )
            .await;

            // Just in case something goes wrong, we don't want to burn too much CPU
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn process_recurring_payment_code_invoice(
        client: &ClientContext<Self>,
        payment_code_idx: u64,
        invoice_idx: u64,
        invoice: lightning_invoice::Bolt11Invoice,
    ) {
        let mut dbtx = client.module_db().begin_transaction().await;
        let old_payment_code_entry = dbtx
            .get_value(&crate::db::RecurringPaymentCodeKey {
                derivation_idx: payment_code_idx,
            })
            .await
            .expect("We queried it, so it exists in our DB");

        let new_payment_code_entry = RecurringPaymentCodeEntry {
            last_derivation_index: invoice_idx,
            ..old_payment_code_entry.clone()
        };
        dbtx.insert_entry(
            &crate::db::RecurringPaymentCodeKey {
                derivation_idx: payment_code_idx,
            },
            &new_payment_code_entry,
        )
        .await;

        Self::create_recurring_receive_operation(
            client,
            &mut dbtx.to_ref_nc(),
            &old_payment_code_entry,
            invoice_idx,
            invoice,
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[allow(clippy::pedantic)]
    async fn create_recurring_receive_operation(
        client: &ClientContext<Self>,
        dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
        payment_code: &RecurringPaymentCodeEntry,
        invoice_index: u64,
        invoice: lightning_invoice::Bolt11Invoice,
    ) {
        // TODO: pipe secure secp context to here
        let invoice_key =
            tweak_user_secret_key(SECP256K1, payment_code.root_keypair, invoice_index);

        // TODO: use proper operation id, what do we use for LN normally? Preimage I
        // guess?
        let operation_id = OperationId::new_random();
        debug!(
            ?operation_id,
            payment_code_key=?payment_code.root_keypair.public_key(),
            invoice_index=%invoice_index,
            "Creating recurring receive operation"
        );
        let ln_state =
            LightningClientStateMachines::Receive(crate::receive::LightningReceiveStateMachine {
                operation_id,
                // TODO: technically we want a state that doesn't assume the offer was accepted
                // since we haven't checked, but for an MVP this is good enough
                state: crate::receive::LightningReceiveStates::ConfirmedInvoice(
                    crate::receive::LightningReceiveConfirmedInvoice {
                        invoice: invoice.clone(),
                        receiving_key: crate::ReceivingKey::Personal(invoice_key),
                    },
                ),
            });

        client
            .manual_operation_start_dbtx(
                dbtx,
                operation_id,
                "ln",
                LightningOperationMeta {
                    variant: LightningOperationMetaVariant::RecurringPaymentReceive(
                        ReurringPaymentReceiveMeta {
                            payment_code_id: PaymentCodeRootKey(
                                payment_code.root_keypair.public_key(),
                            )
                            .to_payment_code_id(),
                            invoice,
                        },
                    ),
                    extra_meta: serde_json::Value::Null,
                },
                vec![client.make_dyn_state(ln_state)],
            )
            .await
            .expect("OperationId is random");
    }

    pub async fn subscribe_ln_recurring_receive(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<LnReceiveState>> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let LightningOperationMetaVariant::RecurringPaymentReceive(ReurringPaymentReceiveMeta {
            invoice,
            ..
        }) = operation.meta::<LightningOperationMeta>().variant
        else {
            bail!("Operation is not a recurring lightning receive")
        };

        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(operation, operation_id, move || {
            stream! {
                let self_ref = client_ctx.self_ref();

                yield LnReceiveState::Created;
                yield LnReceiveState::WaitingForPayment { invoice: invoice.to_string(), timeout: invoice.expiry_time() };

                match self_ref.await_receive_success(operation_id).await {
                    Ok(_) => {
                        yield LnReceiveState::Funded;

                        if let Ok(out_points) = self_ref.await_claim_acceptance(operation_id).await {
                            yield LnReceiveState::AwaitingFunds;

                            if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                yield LnReceiveState::Claimed;
                                return;
                            }
                        }

                        yield LnReceiveState::Canceled { reason: LightningReceiveError::Rejected };
                    }
                    Err(e) => {
                        yield LnReceiveState::Canceled { reason: e };
                    }
                }
            }
        }))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub struct PaymentCodeRootKey(pub PublicKey);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub struct PaymentCodeId(sha256::Hash);

impl PaymentCodeRootKey {
    pub fn to_payment_code_id(&self) -> PaymentCodeId {
        PaymentCodeId(sha256::Hash::hash(&self.0.serialize()))
    }
}

impl Display for PaymentCodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(sha256::Hash::from_str(s)?))
    }
}

impl Display for PaymentCodeRootKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeRootKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(PublicKey::from_str(s)?))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub enum RecurringPaymentProtocol {
    LNURL,
    BOLT12,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReurringPaymentReceiveMeta {
    pub payment_code_id: PaymentCodeId,
    pub invoice: Bolt11Invoice,
}

#[derive(Debug, Error)]
pub enum RecurringPaymentError {
    #[error("Unsupported protocol: {0:?}")]
    UnsupportedProtocol(RecurringPaymentProtocol),
    #[error("Unknown federation ID: {0}")]
    UnknownFederationId(FederationId),
    #[error("Unknown payment code: {0:?}")]
    UnknownPaymentCode(PaymentCodeId),
    #[error("No compatible lightning module found")]
    NoLightningModuleFound,
    #[error("No gateway found")]
    NoGatewayFound,
    #[error("Payment code already exists with different settings: {0:?}")]
    PaymentCodeAlreadyExists(PaymentCodeRootKey),
    #[error("Federation already registered: {0}")]
    FederationAlreadyRegistered(FederationId),
    #[error("Error joining federation: {0}")]
    JoiningFederationFailed(anyhow::Error),
    #[error("Error registering with recurring payment service: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecurringPaymentCodeEntry {
    pub protocol: RecurringPaymentProtocol,
    pub root_keypair: Keypair,
    pub code: String,
    pub recurringd_api: SafeUrl,
    pub last_derivation_index: u64,
    pub creation_time: SystemTime,
    pub meta: String,
}
