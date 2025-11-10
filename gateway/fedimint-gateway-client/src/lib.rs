use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
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
use fedimint_ln_common::client::{GatewayRpcClient, GatewayRpcResult};
use lightning_invoice::Bolt11Invoice;

pub async fn get_info(client: &GatewayRpcClient) -> GatewayRpcResult<GatewayInfo> {
    client.call_get(GATEWAY_INFO_ENDPOINT).await
}

pub async fn get_config(
    client: &GatewayRpcClient,
    payload: ConfigPayload,
) -> GatewayRpcResult<GatewayFedConfig> {
    client.call_post(CONFIGURATION_ENDPOINT, payload).await
}

pub async fn get_deposit_address(
    client: &GatewayRpcClient,
    payload: DepositAddressPayload,
) -> GatewayRpcResult<Address<NetworkUnchecked>> {
    client.call_post(ADDRESS_ENDPOINT, payload).await
}

pub async fn withdraw(
    client: &GatewayRpcClient,
    payload: WithdrawPayload,
) -> GatewayRpcResult<WithdrawResponse> {
    client.call_post(WITHDRAW_ENDPOINT, payload).await
}

pub async fn connect_federation(
    client: &GatewayRpcClient,
    payload: ConnectFedPayload,
) -> GatewayRpcResult<FederationInfo> {
    client.call_post(CONNECT_FED_ENDPOINT, payload).await
}

pub async fn leave_federation(
    client: &GatewayRpcClient,
    payload: LeaveFedPayload,
) -> GatewayRpcResult<FederationInfo> {
    client.call_post(LEAVE_FED_ENDPOINT, payload).await
}

pub async fn backup(client: &GatewayRpcClient, payload: BackupPayload) -> GatewayRpcResult<()> {
    client.call_post(BACKUP_ENDPOINT, payload).await
}

pub async fn set_fees(client: &GatewayRpcClient, payload: SetFeesPayload) -> GatewayRpcResult<()> {
    client.call_post(SET_FEES_ENDPOINT, payload).await
}

pub async fn create_invoice_for_self(
    client: &GatewayRpcClient,
    payload: CreateInvoiceForOperatorPayload,
) -> GatewayRpcResult<Bolt11Invoice> {
    client
        .call_post(CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, payload)
        .await
}

pub async fn pay_invoice(
    client: &GatewayRpcClient,
    payload: PayInvoiceForOperatorPayload,
) -> GatewayRpcResult<String> {
    client
        .call_post(PAY_INVOICE_FOR_OPERATOR_ENDPOINT, payload)
        .await
}

pub async fn get_ln_onchain_address(
    client: &GatewayRpcClient,
) -> GatewayRpcResult<Address<NetworkUnchecked>> {
    client.call_get(GET_LN_ONCHAIN_ADDRESS_ENDPOINT).await
}

pub async fn open_channel(
    client: &GatewayRpcClient,
    payload: OpenChannelRequest,
) -> GatewayRpcResult<Txid> {
    client.call_post(OPEN_CHANNEL_ENDPOINT, payload).await
}

pub async fn close_channels_with_peer(
    client: &GatewayRpcClient,
    payload: CloseChannelsWithPeerRequest,
) -> GatewayRpcResult<CloseChannelsWithPeerResponse> {
    client
        .call_post(CLOSE_CHANNELS_WITH_PEER_ENDPOINT, payload)
        .await
}

pub async fn list_channels(client: &GatewayRpcClient) -> GatewayRpcResult<Vec<ChannelInfo>> {
    client.call_get(LIST_CHANNELS_ENDPOINT).await
}

pub async fn send_onchain(
    client: &GatewayRpcClient,
    payload: SendOnchainRequest,
) -> GatewayRpcResult<Txid> {
    client.call_post(SEND_ONCHAIN_ENDPOINT, payload).await
}

pub async fn recheck_address(
    client: &GatewayRpcClient,
    payload: DepositAddressRecheckPayload,
) -> GatewayRpcResult<serde_json::Value> {
    client.call_post(ADDRESS_RECHECK_ENDPOINT, payload).await
}

pub async fn spend_ecash(
    client: &GatewayRpcClient,
    payload: SpendEcashPayload,
) -> GatewayRpcResult<SpendEcashResponse> {
    client.call_post(SPEND_ECASH_ENDPOINT, payload).await
}

pub async fn receive_ecash(
    client: &GatewayRpcClient,
    payload: ReceiveEcashPayload,
) -> GatewayRpcResult<ReceiveEcashResponse> {
    client.call_post(RECEIVE_ECASH_ENDPOINT, payload).await
}

pub async fn get_balances(client: &GatewayRpcClient) -> GatewayRpcResult<GatewayBalances> {
    client.call_get(GET_BALANCES_ENDPOINT).await
}

pub async fn get_mnemonic(client: &GatewayRpcClient) -> GatewayRpcResult<MnemonicResponse> {
    client.call_get(MNEMONIC_ENDPOINT).await
}

pub async fn stop(client: &GatewayRpcClient) -> GatewayRpcResult<()> {
    client.call_get(STOP_ENDPOINT).await
}

pub async fn payment_log(
    client: &GatewayRpcClient,
    payload: PaymentLogPayload,
) -> GatewayRpcResult<PaymentLogResponse> {
    client.call_post(PAYMENT_LOG_ENDPOINT, payload).await
}

pub async fn payment_summary(
    client: &GatewayRpcClient,
    payload: PaymentSummaryPayload,
) -> GatewayRpcResult<PaymentSummaryResponse> {
    client.call_post(PAYMENT_SUMMARY_ENDPOINT, payload).await
}

pub async fn get_invoice(
    client: &GatewayRpcClient,
    payload: GetInvoiceRequest,
) -> GatewayRpcResult<Option<GetInvoiceResponse>> {
    client.call_post(GET_INVOICE_ENDPOINT, payload).await
}

pub async fn list_transactions(
    client: &GatewayRpcClient,
    payload: ListTransactionsPayload,
) -> GatewayRpcResult<ListTransactionsResponse> {
    client.call_post(LIST_TRANSACTIONS_ENDPOINT, payload).await
}

pub async fn create_offer(
    client: &GatewayRpcClient,
    payload: CreateOfferPayload,
) -> GatewayRpcResult<CreateOfferResponse> {
    client
        .call_post(CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT, payload)
        .await
}

pub async fn pay_offer(
    client: &GatewayRpcClient,
    payload: PayOfferPayload,
) -> GatewayRpcResult<PayOfferResponse> {
    client
        .call_post(PAY_OFFER_FOR_OPERATOR_ENDPOINT, payload)
        .await
}
