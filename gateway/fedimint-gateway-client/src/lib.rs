use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_connectors::ServerResult;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    ADDRESS_ENDPOINT, ADDRESS_RECHECK_ENDPOINT, BACKUP_ENDPOINT, BackupPayload,
    CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT,
    CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
    ChannelInfo, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, ConfigPayload,
    ConnectFedPayload, CreateInvoiceForOperatorPayload, CreateOfferPayload, CreateOfferResponse,
    DepositAddressPayload, DepositAddressRecheckPayload, FederationInfo, GATEWAY_INFO_ENDPOINT,
    GET_BALANCES_ENDPOINT, GET_INVOICE_ENDPOINT, GET_LN_ONCHAIN_ADDRESS_ENDPOINT, GatewayBalances,
    GatewayFedConfig, GatewayInfo, GetInvoiceRequest, GetInvoiceResponse, LEAVE_FED_ENDPOINT,
    LIST_CHANNELS_ENDPOINT, LIST_TRANSACTIONS_ENDPOINT, LeaveFedPayload, ListTransactionsPayload,
    ListTransactionsResponse, MNEMONIC_ENDPOINT, MnemonicResponse, OPEN_CHANNEL_ENDPOINT,
    OpenChannelRequest, PAY_INVOICE_FOR_OPERATOR_ENDPOINT, PAY_OFFER_FOR_OPERATOR_ENDPOINT,
    PAYMENT_LOG_ENDPOINT, PAYMENT_SUMMARY_ENDPOINT, PayInvoiceForOperatorPayload, PayOfferPayload,
    PayOfferResponse, PaymentLogPayload, PaymentLogResponse, PaymentSummaryPayload,
    PaymentSummaryResponse, RECEIVE_ECASH_ENDPOINT, ReceiveEcashPayload, ReceiveEcashResponse,
    SEND_ONCHAIN_ENDPOINT, SET_FEES_ENDPOINT, SPEND_ECASH_ENDPOINT, STOP_ENDPOINT,
    SendOnchainRequest, SetFeesPayload, SpendEcashPayload, SpendEcashResponse, WITHDRAW_ENDPOINT,
    WithdrawPayload, WithdrawResponse,
};
use fedimint_ln_common::Method;
use fedimint_ln_common::client::GatewayApi;
use lightning_invoice::Bolt11Invoice;

pub async fn get_info(client: &GatewayApi, base_url: &SafeUrl) -> ServerResult<GatewayInfo> {
    client
        .request::<(), GatewayInfo>(base_url, Method::GET, GATEWAY_INFO_ENDPOINT, None)
        .await
}

pub async fn get_config(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: ConfigPayload,
) -> ServerResult<GatewayFedConfig> {
    client
        .request(
            base_url,
            Method::POST,
            CONFIGURATION_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn get_deposit_address(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: DepositAddressPayload,
) -> ServerResult<Address<NetworkUnchecked>> {
    client
        .request(base_url, Method::POST, ADDRESS_ENDPOINT, Some(payload))
        .await
}

pub async fn withdraw(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: WithdrawPayload,
) -> ServerResult<WithdrawResponse> {
    client
        .request(base_url, Method::POST, WITHDRAW_ENDPOINT, Some(payload))
        .await
}

pub async fn connect_federation(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: ConnectFedPayload,
) -> ServerResult<FederationInfo> {
    client
        .request(base_url, Method::POST, CONNECT_FED_ENDPOINT, Some(payload))
        .await
}

pub async fn leave_federation(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: LeaveFedPayload,
) -> ServerResult<FederationInfo> {
    client
        .request(base_url, Method::POST, LEAVE_FED_ENDPOINT, Some(payload))
        .await
}

pub async fn backup(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: BackupPayload,
) -> ServerResult<()> {
    client
        .request(base_url, Method::POST, BACKUP_ENDPOINT, Some(payload))
        .await
}

pub async fn set_fees(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: SetFeesPayload,
) -> ServerResult<()> {
    client
        .request(base_url, Method::POST, SET_FEES_ENDPOINT, Some(payload))
        .await
}

pub async fn create_invoice_for_self(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: CreateInvoiceForOperatorPayload,
) -> ServerResult<Bolt11Invoice> {
    client
        .request(
            base_url,
            Method::POST,
            CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn pay_invoice(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: PayInvoiceForOperatorPayload,
) -> ServerResult<String> {
    client
        .request(
            base_url,
            Method::POST,
            PAY_INVOICE_FOR_OPERATOR_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn get_ln_onchain_address(
    client: &GatewayApi,
    base_url: &SafeUrl,
) -> ServerResult<Address<NetworkUnchecked>> {
    client
        .request::<(), Address<NetworkUnchecked>>(
            base_url,
            Method::GET,
            GET_LN_ONCHAIN_ADDRESS_ENDPOINT,
            None,
        )
        .await
}

pub async fn open_channel(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: OpenChannelRequest,
) -> ServerResult<Txid> {
    client
        .request(base_url, Method::POST, OPEN_CHANNEL_ENDPOINT, Some(payload))
        .await
}

pub async fn close_channels_with_peer(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: CloseChannelsWithPeerRequest,
) -> ServerResult<CloseChannelsWithPeerResponse> {
    client
        .request(
            base_url,
            Method::POST,
            CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn list_channels(
    client: &GatewayApi,
    base_url: &SafeUrl,
) -> ServerResult<Vec<ChannelInfo>> {
    client
        .request::<(), Vec<ChannelInfo>>(base_url, Method::GET, LIST_CHANNELS_ENDPOINT, None)
        .await
}

pub async fn send_onchain(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: SendOnchainRequest,
) -> ServerResult<Txid> {
    client
        .request(base_url, Method::POST, SEND_ONCHAIN_ENDPOINT, Some(payload))
        .await
}

pub async fn recheck_address(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: DepositAddressRecheckPayload,
) -> ServerResult<serde_json::Value> {
    client
        .request(
            base_url,
            Method::POST,
            ADDRESS_RECHECK_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn spend_ecash(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: SpendEcashPayload,
) -> ServerResult<SpendEcashResponse> {
    client
        .request(base_url, Method::POST, SPEND_ECASH_ENDPOINT, Some(payload))
        .await
}

pub async fn receive_ecash(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: ReceiveEcashPayload,
) -> ServerResult<ReceiveEcashResponse> {
    client
        .request(
            base_url,
            Method::POST,
            RECEIVE_ECASH_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn get_balances(
    client: &GatewayApi,
    base_url: &SafeUrl,
) -> ServerResult<GatewayBalances> {
    client
        .request::<(), GatewayBalances>(base_url, Method::GET, GET_BALANCES_ENDPOINT, None)
        .await
}

pub async fn get_mnemonic(
    client: &GatewayApi,
    base_url: &SafeUrl,
) -> ServerResult<MnemonicResponse> {
    client
        .request::<(), MnemonicResponse>(base_url, Method::GET, MNEMONIC_ENDPOINT, None)
        .await
}

pub async fn stop(client: &GatewayApi, base_url: &SafeUrl) -> ServerResult<()> {
    client
        .request::<(), ()>(base_url, Method::GET, STOP_ENDPOINT, None)
        .await
}

pub async fn payment_log(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: PaymentLogPayload,
) -> ServerResult<PaymentLogResponse> {
    client
        .request(base_url, Method::POST, PAYMENT_LOG_ENDPOINT, Some(payload))
        .await
}

pub async fn payment_summary(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: PaymentSummaryPayload,
) -> ServerResult<PaymentSummaryResponse> {
    client
        .request(
            base_url,
            Method::POST,
            PAYMENT_SUMMARY_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn get_invoice(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: GetInvoiceRequest,
) -> ServerResult<Option<GetInvoiceResponse>> {
    client
        .request(base_url, Method::POST, GET_INVOICE_ENDPOINT, Some(payload))
        .await
}

pub async fn list_transactions(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: ListTransactionsPayload,
) -> ServerResult<ListTransactionsResponse> {
    client
        .request(
            base_url,
            Method::POST,
            LIST_TRANSACTIONS_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn create_offer(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: CreateOfferPayload,
) -> ServerResult<CreateOfferResponse> {
    client
        .request(
            base_url,
            Method::POST,
            CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
            Some(payload),
        )
        .await
}

pub async fn pay_offer(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: PayOfferPayload,
) -> ServerResult<PayOfferResponse> {
    client
        .request(
            base_url,
            Method::POST,
            PAY_OFFER_FOR_OPERATOR_ENDPOINT,
            Some(payload),
        )
        .await
}
