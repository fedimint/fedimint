use fedimint_core::config::FederationId;
use fedimint_core::util::{FmtCompactErrorAnyhow, SafeUrl};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::recurring::{PaymentCodeRootKey, RecurringPaymentProtocol};

pub struct RecurringdClient {
    client: reqwest::Client,
    base_url: SafeUrl,
}

impl RecurringdClient {
    pub fn new(base_url: SafeUrl) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
        }
    }

    pub async fn register_recurring_payment_code(
        &self,
        federation_id: FederationId,
        protocol: RecurringPaymentProtocol,
        payment_code_root_key: PaymentCodeRootKey,
    ) -> Result<RecurringPaymentRegistrationResponse, RecurringdApiError> {
        // TODO: validate decoding works like this and maybe figure out a cleaner way to
        // communicate errors
        let request = RecurringPaymentRegistrationRequest {
            federation_id,
            protocol,
            payment_code_root_key,
        };

        let response = self
            .client
            .put(format!("{}paycodes", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(RecurringdApiError::NetworkError)?;

        response
            .json::<ApiResult<RecurringPaymentRegistrationResponse>>()
            .await
            .map_err(|e| RecurringdApiError::DecodingError(e.into()))?
            .into_result()
    }

    pub async fn await_new_invoice(
        &self,
        payment_code_root_key: PaymentCodeRootKey,
        invoice_index: u64,
    ) -> Result<Bolt11Invoice, RecurringdApiError> {
        let response = self
            .client
            .get(format!(
                "{}paycodes/recipient/{}/generated/{}",
                self.base_url, payment_code_root_key, invoice_index
            ))
            .send()
            .await
            .map_err(RecurringdApiError::NetworkError)?;
        response
            .json::<ApiResult<Bolt11Invoice>>()
            .await
            .map_err(|e| RecurringdApiError::DecodingError(e.into()))?
            .into_result()
    }
}

#[derive(Debug, Error)]
pub enum RecurringdApiError {
    #[error("Recurring payment server error: {0}")]
    ApiError(String),
    #[error("Invalid response: {}", FmtCompactErrorAnyhow(.0))]
    DecodingError(anyhow::Error),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationRequest {
    /// Federation ID in which the invoices should be generated
    pub federation_id: FederationId,
    /// Recurring payment protocol to use
    pub protocol: RecurringPaymentProtocol,
    /// Public key from which other keys will be derived for each generated
    /// invoice
    pub payment_code_root_key: PaymentCodeRootKey,
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationResponse {
    /// Either a BOLT12 offer or LNURL
    pub recurring_payment_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ApiResult<T> {
    Ok(T),
    Err { error: String },
}

impl<T> ApiResult<T> {
    pub fn into_result(self) -> Result<T, RecurringdApiError> {
        match self {
            ApiResult::Ok(result) => Ok(result),
            ApiResult::Err { error } => Err(RecurringdApiError::ApiError(error)),
        }
    }
}
