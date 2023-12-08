use std::result::Result;

use bitcoin::Address;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, TransactionId};
pub use reqwest::{Error, Response};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use super::{
    BackupPayload, BalancePayload, ConfigPayload, ConnectFedPayload, DepositAddressPayload,
    FederationConnectionInfo, GatewayFedConfig, GatewayInfo, LeaveFedPayload, RestorePayload,
    SetConfigurationPayload, WithdrawPayload,
};

pub struct GatewayRpcClient {
    // Base URL to gateway web server
    base_url: SafeUrl,
    // A request client
    client: reqwest::Client,
    // Password
    password: Option<String>,
}

impl GatewayRpcClient {
    pub fn new(base_url: SafeUrl, password: Option<String>) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
            password,
        }
    }

    pub fn with_password(&self, password: Option<String>) -> Self {
        GatewayRpcClient::new(self.base_url.clone(), password)
    }

    pub async fn get_info(&self) -> GatewayRpcResult<GatewayInfo> {
        let url = self.base_url.join("/info").expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn get_config(&self, payload: ConfigPayload) -> GatewayRpcResult<GatewayFedConfig> {
        let url = self.base_url.join("/config").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_balance(&self, payload: BalancePayload) -> GatewayRpcResult<Amount> {
        let url = self.base_url.join("/balance").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_deposit_address(
        &self,
        payload: DepositAddressPayload,
    ) -> GatewayRpcResult<Address> {
        let url = self.base_url.join("/address").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn withdraw(&self, payload: WithdrawPayload) -> GatewayRpcResult<TransactionId> {
        let url = self.base_url.join("/withdraw").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> GatewayRpcResult<FederationConnectionInfo> {
        let url = self
            .base_url
            .join("/connect-fed")
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn leave_federation(&self, payload: LeaveFedPayload) -> GatewayRpcResult<()> {
        let url = self.base_url.join("/leave-fed").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn backup(&self, payload: BackupPayload) -> GatewayRpcResult<()> {
        let url = self.base_url.join("/backup").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn restore(&self, payload: RestorePayload) -> GatewayRpcResult<()> {
        let url = self.base_url.join("/restore").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn set_configuration(
        &self,
        payload: SetConfigurationPayload,
    ) -> GatewayRpcResult<()> {
        let url = self
            .base_url
            .join("/set_configuration")
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        url: SafeUrl,
        payload: Option<P>,
    ) -> Result<T, GatewayRpcError> {
        let mut builder = self.client.request(method, url.to_unsafe());
        if let Some(password) = self.password.clone() {
            builder = builder.bearer_auth(password);
        }
        if let Some(payload) = payload {
            builder = builder
                .json(&payload)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
        }
        let response = builder.send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json().await?),
            status => Err(GatewayRpcError::BadStatus(status)),
        }
    }

    async fn call_get<T: DeserializeOwned>(&self, url: SafeUrl) -> Result<T, GatewayRpcError> {
        self.call(Method::GET, url, None::<()>).await
    }

    async fn call_post<P: Serialize, T: DeserializeOwned>(
        &self,
        url: SafeUrl,
        payload: P,
    ) -> Result<T, GatewayRpcError> {
        self.call(Method::POST, url, Some(payload)).await
    }
}

pub type GatewayRpcResult<T> = Result<T, GatewayRpcError>;

#[derive(Error, Debug)]
pub enum GatewayRpcError {
    #[error("Bad status returned {0}")]
    BadStatus(StatusCode),
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
}
