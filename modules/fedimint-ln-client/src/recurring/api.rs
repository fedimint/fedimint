use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
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

    pub async fn register_recurring_payment(
        &self,
        federation_id: FederationId,
        protocol: RecurringPaymentProtocol,
        payment_code_root_key: PaymentCodeRootKey,
    ) -> Result<RecurringPaymentRegistrationResponse, RecurringdApiError> {
        let request = RecurringPaymentRegistrationRequest {
            federation_id,
            protocol,
            payment_code_root_key,
        };
        let response = self
            .client
            .put(&format!("{}/paycode", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| RecurringdApiError::NetworkError(e))?;

        // TODO: validate decoding works like this and maybe figure out a cleaner way to
        // communicate errors
        #[derive(Debug, Deserialize)]
        struct ApiError {
            error: String,
        }
        response
            .json::<Result<RecurringPaymentRegistrationResponse, ApiError>>()
            .await
            .map_err(|e| RecurringdApiError::DecodingError(e.into()))?
            .map_err(|e| RecurringdApiError::ApiError(e.error))
    }
}

#[derive(Debug, Error)]
pub enum RecurringdApiError {
    #[error("Recurring payment server error: {0}")]
    ApiError(String),
    #[error("Invalid response: {0}")]
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
