mod bitcoin;
mod connect_fed;
mod federation;
mod general;
mod lightning;
mod mnemonic;
mod payment_summary;
mod setup;

use std::fmt::Display;
use std::sync::Arc;

use ::bitcoin::{Address, Txid};
use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_core::bitcoin::Network;
use fedimint_core::secp256k1::serde::Deserialize;
use fedimint_core::task::TaskGroup;
use fedimint_gateway_common::{
    ChainSource, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, ConnectFedPayload,
    CreateInvoiceForOperatorPayload, DepositAddressPayload, FederationInfo, GatewayBalances,
    GatewayInfo, LeaveFedPayload, LightningMode, ListTransactionsPayload, ListTransactionsResponse,
    MnemonicResponse, OpenChannelRequest, PayInvoiceForOperatorPayload, PaymentLogPayload,
    PaymentLogResponse, PaymentSummaryPayload, PaymentSummaryResponse, ReceiveEcashPayload,
    ReceiveEcashResponse, SendOnchainRequest, SetFeesPayload, SetMnemonicPayload,
    SpendEcashPayload, SpendEcashResponse, WithdrawPayload, WithdrawPreviewPayload,
    WithdrawPreviewResponse, WithdrawResponse,
};
use fedimint_ln_common::contracts::Preimage;
use fedimint_logging::LOG_GATEWAY_UI;
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState, dashboard_layout, login_form_response,
    login_layout,
};
use lightning_invoice::Bolt11Invoice;
use maud::html;
use tracing::debug;

use crate::connect_fed::connect_federation_handler;
use crate::federation::{
    deposit_address_handler, leave_federation_handler, receive_ecash_handler, set_fees_handler,
    spend_ecash_handler, withdraw_confirm_handler, withdraw_preview_handler,
};
use crate::lightning::{
    channels_fragment_handler, close_channel_handler, create_bolt11_invoice_handler,
    generate_receive_address_handler, open_channel_handler, pay_bolt11_invoice_handler,
    payments_fragment_handler, send_onchain_handler, transactions_fragment_handler,
    wallet_fragment_handler,
};
use crate::mnemonic::{mnemonic_iframe_handler, mnemonic_reveal_handler};
use crate::payment_summary::payment_log_fragment_handler;
use crate::setup::{create_wallet_handler, recover_wallet_form, recover_wallet_handler};
pub type DynGatewayApi<E> = Arc<dyn IAdminGateway<Error = E> + Send + Sync + 'static>;

pub(crate) const OPEN_CHANNEL_ROUTE: &str = "/ui/channels/open";
pub(crate) const CLOSE_CHANNEL_ROUTE: &str = "/ui/channels/close";
pub(crate) const CHANNEL_FRAGMENT_ROUTE: &str = "/ui/channels/fragment";
pub(crate) const LEAVE_FEDERATION_ROUTE: &str = "/ui/federations/{id}/leave";
pub(crate) const CONNECT_FEDERATION_ROUTE: &str = "/ui/federations/join";
pub(crate) const SET_FEES_ROUTE: &str = "/ui/federation/set-fees";
pub(crate) const SEND_ONCHAIN_ROUTE: &str = "/ui/wallet/send";
pub(crate) const WALLET_FRAGMENT_ROUTE: &str = "/ui/wallet/fragment";
pub(crate) const LN_ONCHAIN_ADDRESS_ROUTE: &str = "/ui/wallet/receive";
pub(crate) const DEPOSIT_ADDRESS_ROUTE: &str = "/ui/federations/deposit-address";
pub(crate) const PAYMENTS_FRAGMENT_ROUTE: &str = "/ui/payments/fragment";
pub(crate) const CREATE_BOLT11_INVOICE_ROUTE: &str = "/ui/payments/receive/bolt11";
pub(crate) const PAY_BOLT11_INVOICE_ROUTE: &str = "/ui/payments/send/bolt11";
pub(crate) const TRANSACTIONS_FRAGMENT_ROUTE: &str = "/ui/transactions/fragment";
pub(crate) const RECEIVE_ECASH_ROUTE: &str = "/ui/federations/receive";
pub(crate) const STOP_GATEWAY_ROUTE: &str = "/ui/stop";
pub(crate) const WITHDRAW_PREVIEW_ROUTE: &str = "/ui/federations/withdraw-preview";
pub(crate) const WITHDRAW_CONFIRM_ROUTE: &str = "/ui/federations/withdraw-confirm";
pub(crate) const SPEND_ECASH_ROUTE: &str = "/ui/federations/spend";
pub(crate) const PAYMENT_LOG_ROUTE: &str = "/ui/payment-log";
pub(crate) const CREATE_WALLET_ROUTE: &str = "/ui/wallet/create";
pub(crate) const RECOVER_WALLET_ROUTE: &str = "/ui/wallet/recover";
pub(crate) const MNEMONIC_IFRAME_ROUTE: &str = "/ui/mnemonic/iframe";

#[derive(Default, Deserialize)]
pub struct DashboardQuery {
    pub success: Option<String>,
    pub ui_error: Option<String>,
}

fn redirect_success(msg: String) -> impl IntoResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
    Redirect::to(&format!("/?success={}", encoded))
}

fn redirect_error(msg: String) -> impl IntoResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
    Redirect::to(&format!("/?ui_error={}", encoded))
}

pub fn is_allowed_setup_route(path: &str) -> bool {
    path == ROOT_ROUTE
        || path == LOGIN_ROUTE
        || path.starts_with("/assets/")
        || path == CREATE_WALLET_ROUTE
        || path == RECOVER_WALLET_ROUTE
}

#[async_trait]
pub trait IAdminGateway {
    type Error;

    async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;

    async fn handle_list_channels_msg(
        &self,
    ) -> Result<Vec<fedimint_gateway_common::ChannelInfo>, Self::Error>;

    async fn handle_payment_summary_msg(
        &self,
        PaymentSummaryPayload {
            start_millis,
            end_millis,
        }: PaymentSummaryPayload,
    ) -> Result<PaymentSummaryResponse, Self::Error>;

    async fn handle_leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> Result<FederationInfo, Self::Error>;

    async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo, Self::Error>;

    async fn handle_set_fees_msg(&self, payload: SetFeesPayload) -> Result<(), Self::Error>;

    async fn handle_mnemonic_msg(&self) -> Result<MnemonicResponse, Self::Error>;

    async fn handle_open_channel_msg(
        &self,
        payload: OpenChannelRequest,
    ) -> Result<Txid, Self::Error>;

    async fn handle_close_channels_with_peer_msg(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, Self::Error>;

    async fn handle_get_balances_msg(&self) -> Result<GatewayBalances, Self::Error>;

    async fn handle_send_onchain_msg(
        &self,
        payload: SendOnchainRequest,
    ) -> Result<Txid, Self::Error>;

    async fn handle_get_ln_onchain_address_msg(&self) -> Result<Address, Self::Error>;

    async fn handle_deposit_address_msg(
        &self,
        payload: DepositAddressPayload,
    ) -> Result<Address, Self::Error>;

    async fn handle_receive_ecash_msg(
        &self,
        payload: ReceiveEcashPayload,
    ) -> Result<ReceiveEcashResponse, Self::Error>;

    async fn handle_create_invoice_for_operator_msg(
        &self,
        payload: CreateInvoiceForOperatorPayload,
    ) -> Result<Bolt11Invoice, Self::Error>;

    async fn handle_pay_invoice_for_operator_msg(
        &self,
        payload: PayInvoiceForOperatorPayload,
    ) -> Result<Preimage, Self::Error>;

    async fn handle_list_transactions_msg(
        &self,
        payload: ListTransactionsPayload,
    ) -> Result<ListTransactionsResponse, Self::Error>;

    async fn handle_spend_ecash_msg(
        &self,
        payload: SpendEcashPayload,
    ) -> Result<SpendEcashResponse, Self::Error>;

    async fn handle_shutdown_msg(&self, task_group: TaskGroup) -> Result<(), Self::Error>;

    fn get_task_group(&self) -> TaskGroup;

    async fn handle_withdraw_msg(
        &self,
        payload: WithdrawPayload,
    ) -> Result<WithdrawResponse, Self::Error>;

    async fn handle_withdraw_preview_msg(
        &self,
        payload: WithdrawPreviewPayload,
    ) -> Result<WithdrawPreviewResponse, Self::Error>;

    async fn handle_payment_log_msg(
        &self,
        payload: PaymentLogPayload,
    ) -> Result<PaymentLogResponse, Self::Error>;

    fn get_password_hash(&self) -> String;

    fn gatewayd_version(&self) -> String;

    async fn get_chain_source(&self) -> (ChainSource, Network);

    fn lightning_mode(&self) -> LightningMode;

    async fn is_configured(&self) -> bool;

    async fn handle_set_mnemonic_msg(&self, payload: SetMnemonicPayload)
    -> Result<(), Self::Error>;
}

async fn login_form<E>(State(_state): State<UiState<DynGatewayApi<E>>>) -> impl IntoResponse {
    login_form_response("Fedimint Gateway Login")
}

// Dashboard login submit handler
async fn login_submit<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    if let Ok(verify) = bcrypt::verify(input.password, &state.api.get_password_hash())
        && verify
    {
        let mut cookie = Cookie::new(state.auth_cookie_name.clone(), state.auth_cookie_value);
        cookie.set_path(ROOT_ROUTE);

        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        let jar = jar.add(cookie);
        return (jar, Redirect::to(ROOT_ROUTE)).into_response();
    }

    let content = html! {
        div class="alert alert-danger" { "The password is invalid" }
        div class="button-container" {
            a href=(LOGIN_ROUTE) class="btn btn-primary setup-btn" { "Return to Login" }
        }
    };

    Html(login_layout("Login Failed", content).into_string()).into_response()
}

async fn dashboard_view<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Query(msg): Query<DashboardQuery>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    // If gateway is not configured, show setup view instead of dashboard
    if !state.api.is_configured().await {
        return setup::setup_view(State(state), Query(msg))
            .await
            .into_response();
    }

    let gatewayd_version = state.api.gatewayd_version();
    debug!(target: LOG_GATEWAY_UI, "Getting gateway info...");
    let gateway_info = match state.api.handle_get_info().await {
        Ok(info) => info,
        Err(err) => {
            let content = html! {
                div class="alert alert-danger mt-4" {
                    strong { "Failed to fetch gateway info: " }
                    (err.to_string())
                }
            };
            return Html(
                dashboard_layout(content, "Fedimint Gateway UI", Some(&gatewayd_version))
                    .into_string(),
            )
            .into_response();
        }
    };

    let content = html! {

       (federation::scripts())

        @if let Some(success) = msg.success {
            div class="alert alert-success mt-2 d-flex justify-content-between align-items-center" {
                span { (success) }
                a href=(ROOT_ROUTE)
                class="ms-3 text-decoration-none text-dark fw-bold"
                style="font-size: 1.5rem; line-height: 1; cursor: pointer;"
                { "×" }
            }
        }
        @if let Some(error) = msg.ui_error {
            div class="alert alert-danger mt-2 d-flex justify-content-between align-items-center" {
                span { (error) }
                a href=(ROOT_ROUTE)
                class="ms-3 text-decoration-none text-dark fw-bold"
                style="font-size: 1.5rem; line-height: 1; cursor: pointer;"
                { "×" }
            }
        }

        div class="row mt-4" {
            div class="col-md-12 text-end" {
                form action=(STOP_GATEWAY_ROUTE) method="post" {
                    button class="btn btn-outline-danger" type="submit"
                        onclick="return confirm('Are you sure you want to safely stop the gateway? The gateway will wait for outstanding payments and then shutdown.');"
                    {
                        "Safely Stop Gateway"
                    }
                }
            }
        }

        div class="row gy-4" {
            div class="col-md-6" {
                (general::render(&gateway_info))
            }
            div class="col-md-6" {
                (payment_summary::render(&state.api, &gateway_info.federations).await)
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-6" {
                (bitcoin::render(&state.api).await)
            }
            div class="col-md-6" {
                (mnemonic::render())
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-12" {
                (lightning::render(&gateway_info, &state.api).await)
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-12" {
                (connect_fed::render())
            }
        }

        @for fed in gateway_info.federations {
            (federation::render(&fed))
        }
    };

    Html(dashboard_layout(content, "Fedimint Gateway UI", Some(&gatewayd_version)).into_string())
        .into_response()
}

async fn stop_gateway_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    match state
        .api
        .handle_shutdown_msg(state.api.get_task_group())
        .await
    {
        Ok(_) => redirect_success("Gateway is safely shutting down...".to_string()).into_response(),
        Err(err) => redirect_error(format!("Failed to stop gateway: {err}")).into_response(),
    }
}

pub fn router<E: Display + Send + Sync + std::fmt::Debug + 'static>(
    api: DynGatewayApi<E>,
) -> Router {
    let app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
        .route(OPEN_CHANNEL_ROUTE, post(open_channel_handler))
        .route(CLOSE_CHANNEL_ROUTE, post(close_channel_handler))
        .route(CHANNEL_FRAGMENT_ROUTE, get(channels_fragment_handler))
        .route(WALLET_FRAGMENT_ROUTE, get(wallet_fragment_handler))
        .route(LEAVE_FEDERATION_ROUTE, post(leave_federation_handler))
        .route(CONNECT_FEDERATION_ROUTE, post(connect_federation_handler))
        .route(SET_FEES_ROUTE, post(set_fees_handler))
        .route(SEND_ONCHAIN_ROUTE, post(send_onchain_handler))
        .route(
            LN_ONCHAIN_ADDRESS_ROUTE,
            get(generate_receive_address_handler),
        )
        .route(DEPOSIT_ADDRESS_ROUTE, post(deposit_address_handler))
        .route(SPEND_ECASH_ROUTE, post(spend_ecash_handler))
        .route(RECEIVE_ECASH_ROUTE, post(receive_ecash_handler))
        .route(PAYMENTS_FRAGMENT_ROUTE, get(payments_fragment_handler))
        .route(
            CREATE_BOLT11_INVOICE_ROUTE,
            post(create_bolt11_invoice_handler),
        )
        .route(PAY_BOLT11_INVOICE_ROUTE, post(pay_bolt11_invoice_handler))
        .route(
            TRANSACTIONS_FRAGMENT_ROUTE,
            get(transactions_fragment_handler),
        )
        .route(STOP_GATEWAY_ROUTE, post(stop_gateway_handler))
        .route(WITHDRAW_PREVIEW_ROUTE, post(withdraw_preview_handler))
        .route(WITHDRAW_CONFIRM_ROUTE, post(withdraw_confirm_handler))
        .route(PAYMENT_LOG_ROUTE, get(payment_log_fragment_handler))
        .route(CREATE_WALLET_ROUTE, post(create_wallet_handler))
        .route(
            RECOVER_WALLET_ROUTE,
            get(recover_wallet_form).post(recover_wallet_handler),
        )
        .route(
            MNEMONIC_IFRAME_ROUTE,
            get(mnemonic_iframe_handler).post(mnemonic_reveal_handler),
        )
        .with_static_routes();

    app.with_state(UiState::new(api))
}
