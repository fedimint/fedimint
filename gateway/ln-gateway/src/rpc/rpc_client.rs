use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_core::util::SafeUrl;
use lightning_invoice::Bolt11Invoice;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use super::{
    AuthChallengePayload, AuthChallengeResponse, BackupPayload, CloseChannelsWithPeerPayload,
    ConfigPayload, ConnectFedPayload, CreateInvoiceForOperatorPayload, DepositAddressPayload,
    FederationInfo, GatewayBalances, GatewayFedConfig, GatewayInfo, LeaveFedPayload,
    MnemonicResponse, OpenChannelPayload, PayInvoiceForOperatorPayload, PaymentLogPayload,
    PaymentLogResponse, ReceiveEcashPayload, ReceiveEcashResponse, SendOnchainPayload,
    SetConfigurationPayload, SpendEcashPayload, SpendEcashResponse, WithdrawPayload,
    WithdrawResponse, ADDRESS_ENDPOINT, AUTH_CHALLENGE_ENDPOINT, AUTH_SESSION_ENDPOINT,
    AUTH_SIGN_CHALLENGE_ENDPOINT, BACKUP_ENDPOINT, CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
    CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT, CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
    GATEWAY_INFO_ENDPOINT, GATEWAY_INFO_POST_ENDPOINT, GET_BALANCES_ENDPOINT,
    GET_LN_ONCHAIN_ADDRESS_ENDPOINT, LEAVE_FED_ENDPOINT, LIST_ACTIVE_CHANNELS_ENDPOINT,
    MNEMONIC_ENDPOINT, OPEN_CHANNEL_ENDPOINT, PAYMENT_LOG_ENDPOINT,
    PAY_INVOICE_FOR_OPERATOR_ENDPOINT, RECEIVE_ECASH_ENDPOINT, SEND_ONCHAIN_ENDPOINT,
    SET_CONFIGURATION_ENDPOINT, SPEND_ECASH_ENDPOINT, STOP_ENDPOINT, WITHDRAW_ENDPOINT,
};
use crate::lightning::{ChannelInfo, CloseChannelsWithPeerResponse};

pub struct GatewayRpcClient {
    /// Base URL to gateway web server
    /// This should include an applicable API version, e.g. http://localhost:8080/v1
    base_url: SafeUrl,
    /// A request client
    client: reqwest::Client,
    /// Optional gateway password
    password: Option<String>,
    /// Optional gateway JWT
    pub jwt_code: Option<String>,
}

impl GatewayRpcClient {
    pub fn new(versioned_api: SafeUrl, password: Option<String>, jwt_code: Option<String>) -> Self {
        Self {
            base_url: versioned_api,
            client: reqwest::Client::new(),
            password,
            jwt_code,
        }
    }

    pub fn with_password(&self, password: Option<String>) -> Self {
        GatewayRpcClient::new(self.base_url.clone(), password, self.jwt_code.clone())
    }

    pub fn with_jwt_code(&self, jwt_code: Option<String>) -> Self {
        GatewayRpcClient::new(self.base_url.clone(), self.password.clone(), jwt_code)
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

    pub async fn get_deposit_address(
        &self,
        payload: DepositAddressPayload,
    ) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        let url = self
            .base_url
            .join(ADDRESS_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn withdraw(&self, payload: WithdrawPayload) -> GatewayRpcResult<WithdrawResponse> {
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

    pub async fn create_invoice_for_self(
        &self,
        payload: CreateInvoiceForOperatorPayload,
    ) -> GatewayRpcResult<Bolt11Invoice> {
        let url = self
            .base_url
            .join(CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn pay_invoice(
        &self,
        payload: PayInvoiceForOperatorPayload,
    ) -> GatewayRpcResult<String> {
        let url = self
            .base_url
            .join(PAY_INVOICE_FOR_OPERATOR_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    pub async fn get_ln_onchain_address(&self) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        let url = self
            .base_url
            .join(GET_LN_ONCHAIN_ADDRESS_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn open_channel(&self, payload: OpenChannelPayload) -> GatewayRpcResult<Txid> {
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

    pub async fn send_onchain(&self, payload: SendOnchainPayload) -> GatewayRpcResult<Txid> {
        let url = self
            .base_url
            .join(SEND_ONCHAIN_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
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

    pub async fn get_mnemonic(&self) -> GatewayRpcResult<MnemonicResponse> {
        let url = self
            .base_url
            .join(MNEMONIC_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn stop(&self) -> GatewayRpcResult<()> {
        let url = self.base_url.join(STOP_ENDPOINT).expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn payment_log(
        &self,
        payload: PaymentLogPayload,
    ) -> GatewayRpcResult<PaymentLogResponse> {
        let url = self
            .base_url
            .join(PAYMENT_LOG_ENDPOINT)
            .expect("Invalid base url");

        self.call_post(url, payload).await
    }
    pub async fn challenge_auth(&self) -> GatewayRpcResult<String> {
        let url = self
            .base_url
            .join(AUTH_CHALLENGE_ENDPOINT)
            .expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn sign_challenge_auth(
        &self,
        auth_challenge_payload: AuthChallengeResponse,
    ) -> GatewayRpcResult<bitcoin::secp256k1::schnorr::Signature> {
        let url = self
            .base_url
            .join(AUTH_SIGN_CHALLENGE_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, auth_challenge_payload).await
    }

    pub async fn session_auth(&self, payload: AuthChallengePayload) -> GatewayRpcResult<String> {
        let url = self
            .base_url
            .join(AUTH_SESSION_ENDPOINT)
            .expect("invalid base url");
        self.call_post(url, payload).await
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        url: SafeUrl,
        payload: Option<P>,
    ) -> Result<T, GatewayRpcError> {
        let mut builder = self.client.request(method, url.clone().to_unsafe());

        if let Some(jwt_code) = self.jwt_code.clone() {
            builder = builder.bearer_auth(jwt_code);
        } else if let Some(password) = self.password.clone() {
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
