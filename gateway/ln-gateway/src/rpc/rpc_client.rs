use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, TransactionId};
use fedimint_ln_common::gateway_endpoint_constants::{
    BACKUP_ENDPOINT, BALANCE_ENDPOINT, CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT,
    CONNECT_FED_ENDPOINT, GATEWAY_INFO_ENDPOINT, GATEWAY_INFO_POST_ENDPOINT, GET_BALANCES_ENDPOINT,
    GET_FUNDING_ADDRESS_ENDPOINT, LEAVE_FED_ENDPOINT, LIST_ACTIVE_CHANNELS_ENDPOINT,
    OPEN_CHANNEL_ENDPOINT, RECEIVE_ECASH_ENDPOINT, RESTORE_ENDPOINT, SET_CONFIGURATION_ENDPOINT,
    SPEND_ECASH_ENDPOINT, WITHDRAW_ENDPOINT,
};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use super::{
    BackupPayload, BalancePayload, CloseChannelsWithPeerPayload, ConfigPayload, ConnectFedPayload,
    DepositAddressPayload, FederationInfo, GatewayFedConfig, GatewayInfo, GetFundingAddressPayload,
    LeaveFedPayload, OpenChannelPayload, ReceiveEcashPayload, ReceiveEcashResponse, RestorePayload,
    SetConfigurationPayload, SpendEcashPayload, SpendEcashResponse, WithdrawPayload,
};
use crate::lightning::ChannelInfo;
use crate::{CloseChannelsWithPeerResponse, GatewayBalances};

pub struct GatewayRpcClient {
    /// Base URL to gateway web server
    /// This should include an applicable API version, e.g. http://localhost:8080/v1
    base_url: SafeUrl,
    /// A request client
    client: reqwest::Client,
    /// Optional gateway password
    password: Option<String>,
}

impl GatewayRpcClient {
    pub fn new(versioned_api: SafeUrl, password: Option<String>) -> Self {
        Self {
            base_url: versioned_api,
            client: reqwest::Client::new(),
            password,
        }
    }

    pub fn with_password(&self, password: Option<String>) -> Self {
        GatewayRpcClient::new(self.base_url.clone(), password)
    }

    pub async fn get_info(&self) -> GatewayRpcResult<GatewayInfo> {
        let url = self
            .base_url
            .join(GATEWAY_INFO_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    // FIXME: deprecated >= 0.3.0
    pub async fn get_info_legacy(&self) -> GatewayRpcResult<GatewayInfo> {
        let url = self
            .base_url
            .join(GATEWAY_INFO_POST_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, ()).await
    }

    pub async fn get_config(&self, payload: ConfigPayload) -> GatewayRpcResult<GatewayFedConfig> {
        let url = self
            .base_url
            .join(CONFIGURATION_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_balance(&self, payload: BalancePayload) -> GatewayRpcResult<Amount> {
        let url = self
            .base_url
            .join(BALANCE_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_deposit_address(
        &self,
        payload: DepositAddressPayload,
    ) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        let url = self.base_url.join("/address").expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn withdraw(&self, payload: WithdrawPayload) -> GatewayRpcResult<TransactionId> {
        let url = self
            .base_url
            .join(WITHDRAW_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> GatewayRpcResult<FederationInfo> {
        let url = self
            .base_url
            .join(CONNECT_FED_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> GatewayRpcResult<FederationInfo> {
        let url = self
            .base_url
            .join(LEAVE_FED_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn backup(&self, payload: BackupPayload) -> GatewayRpcResult<()> {
        let url = self
            .base_url
            .join(BACKUP_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn restore(&self, payload: RestorePayload) -> GatewayRpcResult<()> {
        let url = self
            .base_url
            .join(RESTORE_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn set_configuration(
        &self,
        payload: SetConfigurationPayload,
    ) -> GatewayRpcResult<()> {
        let url = self
            .base_url
            .join(SET_CONFIGURATION_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_funding_address(
        &self,
        payload: GetFundingAddressPayload,
    ) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        let url = self
            .base_url
            .join(GET_FUNDING_ADDRESS_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn open_channel(&self, payload: OpenChannelPayload) -> GatewayRpcResult<()> {
        let url = self
            .base_url
            .join(OPEN_CHANNEL_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn close_channels_with_peer(
        &self,
        payload: CloseChannelsWithPeerPayload,
    ) -> GatewayRpcResult<CloseChannelsWithPeerResponse> {
        let url = self
            .base_url
            .join(CLOSE_CHANNELS_WITH_PEER_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn list_active_channels(&self) -> GatewayRpcResult<Vec<ChannelInfo>> {
        let url = self
            .base_url
            .join(LIST_ACTIVE_CHANNELS_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn spend_ecash(
        &self,
        payload: SpendEcashPayload,
    ) -> GatewayRpcResult<SpendEcashResponse> {
        let url = self
            .base_url
            .join(SPEND_ECASH_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn receive_ecash(
        &self,
        payload: ReceiveEcashPayload,
    ) -> GatewayRpcResult<ReceiveEcashResponse> {
        let url = self
            .base_url
            .join(RECEIVE_ECASH_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_balances(&self) -> GatewayRpcResult<GatewayBalances> {
        let url = self
            .base_url
            .join(GET_BALANCES_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        url: SafeUrl,
        payload: Option<P>,
    ) -> Result<T, GatewayRpcError> {
        let mut builder = self.client.request(method, url.clone().to_unsafe());
        if let Some(password) = self.password.clone() {
            builder = builder.bearer_auth(password);
        }
        if let Some(payload) = payload {
            builder = builder
                .json(&payload)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
        }

        let response = builder.send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json::<T>().await?),
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
