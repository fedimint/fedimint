// TODO: move to separate crate for sharing with LNv2
pub mod api;

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::SystemTime;

use bitcoin::hashes::sha256;
use fedimint_client::derivable_secret::ChildId;
use fedimint_core::config::FederationId;
use fedimint_core::db::{AutocommitError, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::util::SafeUrl;
use fedimint_core::BitcoinHash;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::{RecurringPaymentCodeKey, RecurringPaymentCodeKeyPrefix};
use crate::recurring::api::{RecurringdApiError, RecurringdClient};
use crate::LightningClientModule;

impl LightningClientModule {
    pub async fn register_recurring_payment(
        &self,
        protocol: RecurringPaymentProtocol,
        recurringd_api: SafeUrl,
    ) -> Result<RecurringPaymentCodeEntry, RecurringdApiError> {
        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let recurringd_api_inner = recurringd_api.clone();
                    Box::pin(async move {
                        let next_idx = dbtx
                            .find_by_prefix_sorted_descending(&RecurringPaymentCodeKeyPrefix)
                            .await
                            .map(|(k, _)| k.derivation_idx)
                            .next()
                            .await
                            .unwrap_or(0);

                        let payment_code_root_key = self.get_payment_code_root_key(next_idx);

                        let recurringd_client = RecurringdClient::new(recurringd_api_inner.clone());
                        let register_response = recurringd_client
                            .register_recurring_payment(
                                self.client_ctx
                                    .get_config()
                                    .await
                                    .global
                                    .calculate_federation_id(),
                                protocol,
                                PaymentCodeRootKey(payment_code_root_key.public_key()),
                            )
                            .await?;

                        let payment_code_entry = RecurringPaymentCodeEntry {
                            protocol,
                            code: register_response.recurring_payment_code,
                            recurringd_api: recurringd_api_inner,
                            last_derivation_index: 0,
                            creation_time: fedimint_core::time::now(),
                        };
                        dbtx.insert_new_entry(
                            &RecurringPaymentCodeKey {
                                derivation_idx: next_idx,
                            },
                            &payment_code_entry,
                        )
                        .await;

                        Ok(payment_code_entry)
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    panic!("Commit failed: {}", last_error)
                }
            })
    }

    pub async fn get_recurring_payment_codes(&self) -> Vec<RecurringPaymentCodeEntry> {
        self.client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .find_by_prefix(&RecurringPaymentCodeKeyPrefix)
            .await
            .map(|(_idx, entry)| entry)
            .collect()
            .await
    }

    fn get_payment_code_root_key(&self, payment_code_registration_idx: u64) -> Keypair {
        self.recurring_payment_code_secret
            .child_key(ChildId(payment_code_registration_idx))
            .to_secp_key(&self.secp)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecurringPaymentCodeEntry {
    protocol: RecurringPaymentProtocol,
    code: String,
    recurringd_api: SafeUrl,
    last_derivation_index: u64,
    creation_time: SystemTime,
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
