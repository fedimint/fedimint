use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use fedimint_connectors::ServerResult;
use fedimint_connectors::error::{GatewayStatusCode, ServerError};
use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    ADDRESS_ENDPOINT, ADDRESS_RECHECK_ENDPOINT, BACKUP_ENDPOINT, BackupPayload,
    CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT,
    CONNECT_PEER_ENDPOINT, CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
    CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT, ChannelInfo, CloseChannelsWithPeerRequest,
    CloseChannelsWithPeerResponse, ConfigPayload, ConnectFedPayload, ConnectPeerRequest,
    CreateInvoiceForOperatorPayload, CreateOfferPayload, CreateOfferResponse,
    DepositAddressPayload, DepositAddressRecheckPayload, FEDERATION_STATUS_ENDPOINT,
    FederationInfo, FederationStatusRequest, FederationStatusResponse, GATEWAY_INFO_ENDPOINT,
    GET_BALANCES_ENDPOINT, GET_INVOICE_ENDPOINT, GET_LN_ONCHAIN_ADDRESS_ENDPOINT, GatewayBalances,
    GatewayCheckResult, GatewayFedConfig, GatewayHealth, GatewayInfo, GetInvoiceRequest,
    GetInvoiceResponse, INVITE_CODES_ENDPOINT, LEAVE_FED_ENDPOINT, LIST_CHANNELS_ENDPOINT,
    LIST_TRANSACTIONS_ENDPOINT, LeaveFedPayload, ListTransactionsPayload, ListTransactionsResponse,
    MNEMONIC_ENDPOINT, MnemonicResponse, OPEN_CHANNEL_ENDPOINT, OPEN_CHANNEL_WITH_PUSH_ENDPOINT,
    OpenChannelRequest, PAY_INVOICE_FOR_OPERATOR_ENDPOINT, PAY_OFFER_FOR_OPERATOR_ENDPOINT,
    PAYMENT_LOG_ENDPOINT, PAYMENT_SUMMARY_ENDPOINT, PEGIN_FROM_ONCHAIN_ENDPOINT,
    PayInvoiceForOperatorPayload, PayOfferPayload, PayOfferResponse, PaymentLogPayload,
    PaymentLogResponse, PaymentSummaryPayload, PaymentSummaryResponse, PeginFromOnchainPayload,
    RECEIVE_ECASH_ENDPOINT, ReceiveEcashPayload, ReceiveEcashResponse, SEND_ONCHAIN_ENDPOINT,
    SET_CHANNEL_FEES_ENDPOINT, SET_FEES_ENDPOINT, SPEND_ECASH_ENDPOINT, STOP_ENDPOINT,
    SendOnchainRequest, SetChannelFeesRequest, SetFeesPayload, SetMnemonicPayload,
    SpendEcashPayload, SpendEcashResponse, WITHDRAW_ENDPOINT, WITHDRAW_TO_ONCHAIN_ENDPOINT,
    WithdrawPayload, WithdrawResponse, WithdrawToOnchainPayload,
};
use fedimint_ln_common::Method;
use fedimint_ln_common::client::GatewayApi;
use fedimint_ln_common::gateway_registry::{Lnv1RegistrySnapshotResult, Lnv1RegistryState};
use fedimint_lnv2_common::gateway_registry::{Lnv2RegistrySnapshotResult, Lnv2RegistryState};
use futures::stream::{FuturesUnordered, StreamExt as _};
use lightning_invoice::Bolt11Invoice;

/// Whether a Lightning module is configured and ready to query.
pub enum ConfiguredModule<'a, T> {
    /// The federation does not configure this module.
    Absent,
    /// The configured module initialized and can be queried.
    Present(&'a T),
    /// The module is configured but no usable typed client exists.
    PresentUnusable,
}

pub async fn get_info(client: &GatewayApi, base_url: &SafeUrl) -> ServerResult<GatewayInfo> {
    client
        .request::<(), GatewayInfo>(base_url, Method::GET, GATEWAY_INFO_ENDPOINT, None)
        .await
}

/// Queries one gateway's public status for a specific federation.
///
/// Gateway UI, CLI, and server use one release, so the request does not
/// negotiate endpoint versions. Transport failures, malformed responses, and
/// non-success statuses remain errors.
pub async fn get_federation_status(
    client: &GatewayApi,
    base_url: &SafeUrl,
    federation_id: FederationId,
) -> ServerResult<FederationStatusResponse> {
    let status = client
        .request::<_, FederationStatusResponse>(
            base_url,
            Method::POST,
            FEDERATION_STATUS_ENDPOINT,
            Some(FederationStatusRequest { federation_id }),
        )
        .await?;
    validate_federation_status(status, federation_id)
}

fn validate_federation_status(
    status: FederationStatusResponse,
    federation_id: FederationId,
) -> ServerResult<FederationStatusResponse> {
    if status.federation_id() != federation_id {
        return Err(ServerError::InvalidResponse(anyhow::anyhow!(
            "Gateway federation status response names a different federation"
        )));
    }
    Ok(status)
}

/// Checks one gateway's `LNv1` status without returning raw transport errors.
pub async fn check_lnv1_gateway(
    client: &GatewayApi,
    base_url: &SafeUrl,
    federation_id: FederationId,
) -> GatewayCheckResult {
    classify_gateway_check(
        get_federation_status(client, base_url, federation_id).await,
        fedimint_gateway_common::lnv1_gateway_check_result,
    )
}

/// Checks one gateway's `LNv2` status without returning raw transport errors.
pub async fn check_lnv2_gateway(
    client: &GatewayApi,
    base_url: &SafeUrl,
    federation_id: FederationId,
) -> GatewayCheckResult {
    classify_gateway_check(
        get_federation_status(client, base_url, federation_id).await,
        fedimint_gateway_common::lnv2_gateway_check_result,
    )
}

/// Reads the `LNv1` registry and checks every distinct current registration.
///
/// Returns `Unknown` when a guardian is missing or malformed, guardians run
/// different endpoint versions, the snapshot version is unsupported, or the
/// registry contains duplicate gateway identities.
pub async fn check_lnv1_gateways(
    client: &GatewayApi,
    module: ConfiguredModule<'_, fedimint_ln_client::LightningClientModule>,
) -> GatewayHealth {
    let module = match module {
        ConfiguredModule::Absent => return GatewayHealth::ModuleAbsent,
        ConfiguredModule::Present(module) => module,
        ConfiguredModule::PresentUnusable => return GatewayHealth::Unknown,
    };
    let federation_id = module.federation_id();
    let snapshot_result = module.gateway_registry_snapshot().await;
    gateway_health_from_lnv1_snapshot(client, federation_id, snapshot_result).await
}

async fn gateway_health_from_lnv1_snapshot<E>(
    client: &GatewayApi,
    federation_id: FederationId,
    snapshot_result: Result<Lnv1RegistrySnapshotResult, E>,
) -> GatewayHealth {
    let Ok(Lnv1RegistrySnapshotResult::Snapshot(snapshot)) = snapshot_result else {
        return GatewayHealth::Unknown;
    };
    match snapshot.state() {
        Lnv1RegistryState::NoRegistrations => GatewayHealth::NoRegistrations,
        Lnv1RegistryState::RegistrationsExpired => GatewayHealth::RegistrationsExpired,
        Lnv1RegistryState::RegistrationsCurrent => {
            let mut identities = std::collections::BTreeSet::new();
            let mut registrations = Vec::with_capacity(snapshot.registrations().len());
            for registration in snapshot.registrations() {
                if !identities.insert(registration.info.gateway_id) {
                    return GatewayHealth::Unknown;
                }
                registrations.push(registration.info.api.clone());
            }
            check_registered_gateways(
                client,
                federation_id,
                registrations,
                |client, url, id| async move { check_lnv1_gateway(client, &url, id).await },
            )
            .await
        }
    }
}

/// Reads the `LNv2` registry and checks every distinct current registration.
///
/// Returns `Unknown` when a guardian is missing or malformed, guardians run
/// different endpoint versions, the snapshot version is unsupported, or the
/// registry contains duplicate URLs. `LNv2` registrations do not expire.
pub async fn check_lnv2_gateways(
    client: &GatewayApi,
    module: ConfiguredModule<'_, fedimint_lnv2_client::LightningClientModule>,
) -> GatewayHealth {
    let module = match module {
        ConfiguredModule::Absent => return GatewayHealth::ModuleAbsent,
        ConfiguredModule::Present(module) => module,
        ConfiguredModule::PresentUnusable => return GatewayHealth::Unknown,
    };
    let federation_id = module.federation_id();
    let snapshot_result = module.gateway_registry_snapshot().await;
    gateway_health_from_lnv2_snapshot(client, federation_id, snapshot_result).await
}

async fn gateway_health_from_lnv2_snapshot<E>(
    client: &GatewayApi,
    federation_id: FederationId,
    snapshot_result: Result<Lnv2RegistrySnapshotResult, E>,
) -> GatewayHealth {
    let Ok(Lnv2RegistrySnapshotResult::Snapshot(snapshot)) = snapshot_result else {
        return GatewayHealth::Unknown;
    };
    match snapshot.state() {
        Lnv2RegistryState::NoRegistrations => GatewayHealth::NoRegistrations,
        Lnv2RegistryState::RegistrationsCurrent => {
            let mut registrations = std::collections::BTreeSet::new();
            for registration in snapshot.registrations() {
                if !registrations.insert(registration.clone()) {
                    return GatewayHealth::Unknown;
                }
            }
            check_registered_gateways(
                client,
                federation_id,
                registrations,
                |client, url, id| async move { check_lnv2_gateway(client, &url, id).await },
            )
            .await
        }
    }
}

async fn check_registered_gateways<'a, I, F, Fut>(
    client: &'a GatewayApi,
    federation_id: FederationId,
    registrations: I,
    check: F,
) -> GatewayHealth
where
    I: IntoIterator<Item = SafeUrl>,
    F: Fn(&'a GatewayApi, SafeUrl, FederationId) -> Fut + Copy + 'a,
    Fut: Future<Output = GatewayCheckResult> + 'a,
{
    const GATEWAY_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
    let mut pending = FuturesUnordered::new();
    for registration in registrations {
        pending.push(async move {
            fedimint_core::task::timeout(
                GATEWAY_CHECK_TIMEOUT,
                check(client, registration, federation_id),
            )
            .await
            .unwrap_or(GatewayCheckResult::Unknown)
        });
    }
    let mut outcomes = Vec::new();
    while let Some(outcome) = pending.next().await {
        if outcome == GatewayCheckResult::Healthy {
            return GatewayHealth::Healthy;
        }
        outcomes.push(outcome);
    }
    summarize_gateway_checks(&outcomes)
}

fn summarize_gateway_checks(checks: &[GatewayCheckResult]) -> GatewayHealth {
    if checks.is_empty() {
        GatewayHealth::Unknown
    } else if checks.contains(&GatewayCheckResult::Healthy) {
        GatewayHealth::Healthy
    } else if checks
        .iter()
        .all(|result| *result == GatewayCheckResult::Unreachable)
    {
        GatewayHealth::GatewayUnreachable
    } else if checks
        .iter()
        .all(|result| *result == GatewayCheckResult::EndpointUnavailable)
    {
        GatewayHealth::GatewayStatusUnavailable
    } else {
        GatewayHealth::Unknown
    }
}

fn classify_gateway_check(
    result: ServerResult<FederationStatusResponse>,
    reduce: impl FnOnce(&FederationStatusResponse) -> GatewayCheckResult,
) -> GatewayCheckResult {
    match result {
        Ok(status) => reduce(&status),
        Err(ServerError::GatewayStatus {
            status: GatewayStatusCode::NOT_FOUND,
        }) => GatewayCheckResult::EndpointUnavailable,
        Err(ServerError::Connection(_) | ServerError::Transport(_)) => {
            GatewayCheckResult::Unreachable
        }
        Err(_) => GatewayCheckResult::Unknown,
    }
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

pub async fn pegin_from_onchain(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: PeginFromOnchainPayload,
) -> ServerResult<Txid> {
    client
        .request(
            base_url,
            Method::POST,
            PEGIN_FROM_ONCHAIN_ENDPOINT,
            Some(payload),
        )
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

pub async fn withdraw_to_onchain(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: WithdrawToOnchainPayload,
) -> ServerResult<WithdrawResponse> {
    client
        .request(
            base_url,
            Method::POST,
            WITHDRAW_TO_ONCHAIN_ENDPOINT,
            Some(payload),
        )
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

pub async fn connect_peer(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: ConnectPeerRequest,
) -> ServerResult<()> {
    client
        .request(base_url, Method::POST, CONNECT_PEER_ENDPOINT, Some(payload))
        .await
}

pub async fn open_channel_with_push(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: OpenChannelRequest,
) -> ServerResult<Txid> {
    client
        .request(
            base_url,
            Method::POST,
            OPEN_CHANNEL_WITH_PUSH_ENDPOINT,
            Some(payload),
        )
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

pub async fn set_channel_fees(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: SetChannelFeesRequest,
) -> ServerResult<()> {
    client
        .request(
            base_url,
            Method::POST,
            SET_CHANNEL_FEES_ENDPOINT,
            Some(payload),
        )
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

pub async fn set_mnemonic(
    client: &GatewayApi,
    base_url: &SafeUrl,
    payload: SetMnemonicPayload,
) -> ServerResult<()> {
    client
        .request(base_url, Method::POST, MNEMONIC_ENDPOINT, Some(payload))
        .await
}

pub async fn get_invite_codes(
    client: &GatewayApi,
    base_url: &SafeUrl,
) -> ServerResult<BTreeMap<FederationId, BTreeMap<PeerId, (String, InviteCode)>>> {
    client
        .request::<(), BTreeMap<FederationId, BTreeMap<PeerId, (String, InviteCode)>>>(
            base_url,
            Method::GET,
            INVITE_CODES_ENDPOINT,
            None,
        )
        .await
}

#[cfg(test)]
mod tests;
