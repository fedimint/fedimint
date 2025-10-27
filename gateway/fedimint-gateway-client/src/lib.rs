use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use anyhow::Context;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_core::envs::{FM_IROH_ENABLE_DHT_ENV, is_env_var_set};
use fedimint_core::iroh_prod::FM_IROH_DNS_FEDIMINT_PROD;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    ADDRESS_ENDPOINT, ADDRESS_RECHECK_ENDPOINT, BACKUP_ENDPOINT, BackupPayload,
    CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT,
    CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
    ChannelInfo, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, ConfigPayload,
    ConnectFedPayload, CreateInvoiceForOperatorPayload, CreateOfferPayload, CreateOfferResponse,
    DepositAddressPayload, DepositAddressRecheckPayload, FEDIMINT_GATEWAY_ALPN, FederationInfo,
    GATEWAY_INFO_ENDPOINT, GET_BALANCES_ENDPOINT, GET_INVOICE_ENDPOINT,
    GET_LN_ONCHAIN_ADDRESS_ENDPOINT, GatewayBalances, GatewayFedConfig, GatewayInfo,
    GetInvoiceRequest, GetInvoiceResponse, IrohGatewayRequest, IrohGatewayResponse,
    LEAVE_FED_ENDPOINT, LIST_CHANNELS_ENDPOINT, LIST_TRANSACTIONS_ENDPOINT, LeaveFedPayload,
    ListTransactionsPayload, ListTransactionsResponse, MNEMONIC_ENDPOINT, MnemonicResponse,
    OPEN_CHANNEL_ENDPOINT, OpenChannelRequest, PAY_INVOICE_FOR_OPERATOR_ENDPOINT,
    PAY_OFFER_FOR_OPERATOR_ENDPOINT, PAYMENT_LOG_ENDPOINT, PAYMENT_SUMMARY_ENDPOINT,
    PayInvoiceForOperatorPayload, PayOfferPayload, PayOfferResponse, PaymentLogPayload,
    PaymentLogResponse, PaymentSummaryPayload, PaymentSummaryResponse, RECEIVE_ECASH_ENDPOINT,
    ReceiveEcashPayload, ReceiveEcashResponse, SEND_ONCHAIN_ENDPOINT, SET_FEES_ENDPOINT,
    SPEND_ECASH_ENDPOINT, STOP_ENDPOINT, SendOnchainRequest, SetFeesPayload, SpendEcashPayload,
    SpendEcashResponse, V1_API_ENDPOINT, WITHDRAW_ENDPOINT, WithdrawPayload, WithdrawResponse,
};
use fedimint_logging::LOG_NET_IROH;
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId};
use lightning_invoice::Bolt11Invoice;
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{info, trace};

pub struct GatewayRpcClient {
    base_url: SafeUrl,
    iroh_connector: Option<GatewayIrohConnector>,
    client: reqwest::Client,
    password: Option<String>,
}

#[derive(Debug, Clone)]
struct GatewayIrohConnector {
    node_id: iroh::NodeId,
    endpoint: Endpoint,
    password: Option<String>,
    connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

impl GatewayIrohConnector {
    pub async fn new(
        iroh_pk: iroh::PublicKey,
        password: Option<String>,
        iroh_dns: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        let mut builder = Endpoint::builder();

        let iroh_dns_servers: Vec<_> = iroh_dns.map_or_else(
            || {
                FM_IROH_DNS_FEDIMINT_PROD
                    .into_iter()
                    .map(|url| Url::parse(url).expect("Hardcoded, can't fail"))
                    .collect()
            },
            |url| vec![url.to_unsafe()],
        );

        for iroh_dns in iroh_dns_servers {
            builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
        }

        // As a client, we don't need to register on any relays
        let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

        // See <https://github.com/fedimint/fedimint/issues/7811>
        if is_env_var_set(FM_IROH_ENABLE_DHT_ENV) {
            #[cfg(not(target_family = "wasm"))]
            {
                builder = builder.discovery_dht();
            }
        } else {
            info!(
                target: LOG_NET_IROH,
                "Iroh DHT is disabled"
            );
        }

        // instead of `.discovery_n0`, which brings publisher we don't want
        {
            #[cfg(target_family = "wasm")]
            {
                builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
            }

            #[cfg(not(target_family = "wasm"))]
            {
                builder = builder
                    .add_discovery(move |_| Some(iroh::discovery::dns::DnsDiscovery::n0_dns()));
            }
        }

        let endpoint = builder.bind().await?;

        Ok(Self {
            node_id: iroh_pk,
            endpoint,
            password,
            connection_overrides: BTreeMap::new(),
        })
    }

    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    async fn connect(&self) -> anyhow::Result<Connection> {
        let connection = match self.connection_overrides.get(&self.node_id) {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, node_id = %self.node_id, "Using a connectivity override for connection");
                self.endpoint
                    .connect(node_addr.clone(), FEDIMINT_GATEWAY_ALPN)
                    .await?
            }
            None => {
                self.endpoint
                    .connect(self.node_id, FEDIMINT_GATEWAY_ALPN)
                    .await?
            }
        };

        // TODO: Spawn connection monitoring?
        Ok(connection)
    }

    pub async fn request(
        &self,
        route: &str,
        payload: Option<serde_json::Value>,
    ) -> anyhow::Result<IrohGatewayResponse> {
        let iroh_request = IrohGatewayRequest {
            route: route.to_string(),
            params: payload,
            password: self.password.clone(),
        };
        let json = serde_json::to_vec(&iroh_request).expect("serialization cant fail");
        let connection = self.connect().await?;
        let (mut sink, mut stream) = connection.open_bi().await?;
        sink.write_all(&json).await?;
        sink.finish()?;
        let response = stream.read_to_end(1_000_000).await?;
        let iroh_response = serde_json::from_slice::<IrohGatewayResponse>(&response)?;
        Ok(iroh_response)
    }
}

impl GatewayRpcClient {
    pub async fn new(
        api: SafeUrl,
        password: Option<String>,
        iroh_dns: Option<SafeUrl>,
        connection_override: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        let mut base_url = api.clone();
        let iroh_connector = if api.scheme() == "iroh" {
            let host = api.host_str().context("Url is missing host")?;
            let iroh_pk = iroh::PublicKey::from_str(host).context(format!(
                "Could not parse Iroh Public key: Invalid public key: {host}"
            ))?;
            let mut iroh_connector =
                GatewayIrohConnector::new(iroh_pk, password.clone(), iroh_dns).await?;

            if let Some(connection_override) = connection_override {
                let node_addr = NodeAddr {
                    node_id: iroh_pk,
                    relay_url: None,
                    direct_addresses: BTreeSet::from([SocketAddr::V4(SocketAddrV4::new(
                        connection_override
                            .host_str()
                            .ok_or(anyhow::anyhow!("No connection override host"))?
                            .parse::<Ipv4Addr>()?,
                        connection_override.port().ok_or(anyhow::anyhow!(
                            "No iroh port supplied for connection override"
                        ))?,
                    ))]),
                };

                iroh_connector = iroh_connector.with_connection_override(iroh_pk, node_addr);
            }
            Some(iroh_connector)
        } else {
            base_url = base_url.join(V1_API_ENDPOINT)?;
            None
        };

        Ok(Self {
            base_url,
            iroh_connector,
            client: reqwest::Client::new(),
            password,
        })
    }

    pub async fn get_info(&self) -> GatewayRpcResult<GatewayInfo> {
        self.call_get(GATEWAY_INFO_ENDPOINT).await
    }

    pub async fn get_config(&self, payload: ConfigPayload) -> GatewayRpcResult<GatewayFedConfig> {
        self.call_post(CONFIGURATION_ENDPOINT, payload).await
    }

    pub async fn get_deposit_address(
        &self,
        payload: DepositAddressPayload,
    ) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        self.call_post(ADDRESS_ENDPOINT, payload).await
    }

    pub async fn withdraw(&self, payload: WithdrawPayload) -> GatewayRpcResult<WithdrawResponse> {
        self.call_post(WITHDRAW_ENDPOINT, payload).await
    }

    pub async fn connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> GatewayRpcResult<FederationInfo> {
        self.call_post(CONNECT_FED_ENDPOINT, payload).await
    }

    pub async fn leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> GatewayRpcResult<FederationInfo> {
        self.call_post(LEAVE_FED_ENDPOINT, payload).await
    }

    pub async fn backup(&self, payload: BackupPayload) -> GatewayRpcResult<()> {
        self.call_post(BACKUP_ENDPOINT, payload).await
    }

    pub async fn set_fees(&self, payload: SetFeesPayload) -> GatewayRpcResult<()> {
        self.call_post(SET_FEES_ENDPOINT, payload).await
    }

    pub async fn create_invoice_for_self(
        &self,
        payload: CreateInvoiceForOperatorPayload,
    ) -> GatewayRpcResult<Bolt11Invoice> {
        self.call_post(CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, payload)
            .await
    }

    pub async fn pay_invoice(
        &self,
        payload: PayInvoiceForOperatorPayload,
    ) -> GatewayRpcResult<String> {
        self.call_post(PAY_INVOICE_FOR_OPERATOR_ENDPOINT, payload)
            .await
    }

    pub async fn get_ln_onchain_address(&self) -> GatewayRpcResult<Address<NetworkUnchecked>> {
        self.call_get(GET_LN_ONCHAIN_ADDRESS_ENDPOINT).await
    }

    pub async fn open_channel(&self, payload: OpenChannelRequest) -> GatewayRpcResult<Txid> {
        self.call_post(OPEN_CHANNEL_ENDPOINT, payload).await
    }

    pub async fn close_channels_with_peer(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> GatewayRpcResult<CloseChannelsWithPeerResponse> {
        self.call_post(CLOSE_CHANNELS_WITH_PEER_ENDPOINT, payload)
            .await
    }

    pub async fn list_channels(&self) -> GatewayRpcResult<Vec<ChannelInfo>> {
        self.call_get(LIST_CHANNELS_ENDPOINT).await
    }

    pub async fn send_onchain(&self, payload: SendOnchainRequest) -> GatewayRpcResult<Txid> {
        self.call_post(SEND_ONCHAIN_ENDPOINT, payload).await
    }

    pub async fn recheck_address(
        &self,
        payload: DepositAddressRecheckPayload,
    ) -> GatewayRpcResult<serde_json::Value> {
        self.call_post(ADDRESS_RECHECK_ENDPOINT, payload).await
    }

    pub async fn spend_ecash(
        &self,
        payload: SpendEcashPayload,
    ) -> GatewayRpcResult<SpendEcashResponse> {
        self.call_post(SPEND_ECASH_ENDPOINT, payload).await
    }

    pub async fn receive_ecash(
        &self,
        payload: ReceiveEcashPayload,
    ) -> GatewayRpcResult<ReceiveEcashResponse> {
        self.call_post(RECEIVE_ECASH_ENDPOINT, payload).await
    }

    pub async fn get_balances(&self) -> GatewayRpcResult<GatewayBalances> {
        self.call_get(GET_BALANCES_ENDPOINT).await
    }

    pub async fn get_mnemonic(&self) -> GatewayRpcResult<MnemonicResponse> {
        self.call_get(MNEMONIC_ENDPOINT).await
    }

    pub async fn stop(&self) -> GatewayRpcResult<()> {
        self.call_get(STOP_ENDPOINT).await
    }

    pub async fn payment_log(
        &self,
        payload: PaymentLogPayload,
    ) -> GatewayRpcResult<PaymentLogResponse> {
        self.call_post(PAYMENT_LOG_ENDPOINT, payload).await
    }

    pub async fn payment_summary(
        &self,
        payload: PaymentSummaryPayload,
    ) -> GatewayRpcResult<PaymentSummaryResponse> {
        self.call_post(PAYMENT_SUMMARY_ENDPOINT, payload).await
    }

    pub async fn get_invoice(
        &self,
        payload: GetInvoiceRequest,
    ) -> GatewayRpcResult<Option<GetInvoiceResponse>> {
        self.call_post(GET_INVOICE_ENDPOINT, payload).await
    }

    pub async fn list_transactions(
        &self,
        payload: ListTransactionsPayload,
    ) -> GatewayRpcResult<ListTransactionsResponse> {
        self.call_post(LIST_TRANSACTIONS_ENDPOINT, payload).await
    }

    pub async fn create_offer(
        &self,
        payload: CreateOfferPayload,
    ) -> GatewayRpcResult<CreateOfferResponse> {
        self.call_post(CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT, payload)
            .await
    }

    pub async fn pay_offer(&self, payload: PayOfferPayload) -> GatewayRpcResult<PayOfferResponse> {
        self.call_post(PAY_OFFER_FOR_OPERATOR_ENDPOINT, payload)
            .await
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        route: &str,
        payload: Option<P>,
    ) -> Result<T, GatewayRpcError> {
        match &self.iroh_connector {
            Some(iroh_connector) => {
                let payload =
                    payload.map(|p| serde_json::to_value(p).expect("Could not serialize"));
                let response = iroh_connector
                    .request(route, payload)
                    .await
                    .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
                let status_code = StatusCode::from_u16(response.status)
                    .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
                match status_code {
                    StatusCode::OK => {
                        let response = serde_json::from_value::<T>(response.body)
                            .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
                        Ok(response)
                    }
                    status => Err(GatewayRpcError::BadStatus(status)),
                }
            }
            None => {
                let url = self.base_url.join(route).expect("Invalid base url");
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
        }
    }

    async fn call_get<T: DeserializeOwned>(&self, route: &str) -> Result<T, GatewayRpcError> {
        self.call(Method::GET, route, None::<()>).await
    }

    async fn call_post<P: Serialize, T: DeserializeOwned>(
        &self,
        route: &str,
        payload: P,
    ) -> Result<T, GatewayRpcError> {
        self.call(Method::POST, route, Some(payload)).await
    }
}

pub type GatewayRpcResult<T> = Result<T, GatewayRpcError>;

#[derive(Error, Debug)]
pub enum GatewayRpcError {
    #[error("Bad status returned {0}")]
    BadStatus(StatusCode),
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),
    #[error("Iroh error: {0}")]
    IrohError(String),
}
