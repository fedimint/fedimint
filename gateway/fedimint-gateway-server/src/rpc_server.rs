use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::{Path, Query, Request};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::Engine;
use bitcoin::hashes::sha256;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompact;
use fedimint_gateway_common::{
    ADDRESS_ENDPOINT, ADDRESS_RECHECK_ENDPOINT, AuthenticatedUser, BACKUP_ENDPOINT, BackupPayload,
    CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT,
    CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
    CloseChannelsWithPeerRequest, ConfigPayload, ConnectFedPayload,
    CreateInvoiceForOperatorPayload, CreateOfferPayload, CreateUserPayload, DepositAddressPayload,
    DepositAddressRecheckPayload, GATEWAY_INFO_ENDPOINT, GET_BALANCES_ENDPOINT,
    GET_INVOICE_ENDPOINT, GET_LN_ONCHAIN_ADDRESS_ENDPOINT, GetInvoiceRequest,
    INVITE_CODES_ENDPOINT, LEAVE_FED_ENDPOINT, LIST_CHANNELS_ENDPOINT, LIST_TRANSACTIONS_ENDPOINT,
    LeaveFedPayload, ListTransactionsPayload, MNEMONIC_ENDPOINT, OPEN_CHANNEL_ENDPOINT,
    OpenChannelRequest, PAY_INVOICE_FOR_OPERATOR_ENDPOINT, PAY_OFFER_FOR_OPERATOR_ENDPOINT,
    PAYMENT_LOG_ENDPOINT, PAYMENT_SUMMARY_ENDPOINT, PayInvoiceForOperatorPayload, PayOfferPayload,
    PaymentLogPayload, PaymentSummaryPayload, RECEIVE_ECASH_ENDPOINT, ReceiveEcashPayload,
    SEND_ONCHAIN_ENDPOINT, SET_FEES_ENDPOINT, SPEND_ECASH_ENDPOINT, STOP_ENDPOINT,
    SendOnchainRequest, SetFeesPayload, SetMnemonicPayload, SpendEcashPayload, USERS_ENDPOINT,
    UserAuthorization, V1_API_ENDPOINT, WITHDRAW_ENDPOINT, WithdrawPayload,
};
use fedimint_gateway_server_db::GatewayDbtxNcExt;
use fedimint_gateway_ui::IAdminGateway;
use fedimint_ln_common::gateway_endpoint_constants::{
    GET_GATEWAY_ID_ENDPOINT, PAY_INVOICE_ENDPOINT,
};
use fedimint_lnurl::LnurlResponse;
use fedimint_lnv2_common::endpoint_constants::{
    CREATE_BOLT11_INVOICE_ENDPOINT, ROUTING_INFO_ENDPOINT, SEND_PAYMENT_ENDPOINT,
};
use fedimint_lnv2_common::gateway_api::{CreateBolt11InvoicePayload, SendPaymentPayload};
use fedimint_logging::LOG_GATEWAY;
use hex::ToHex;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, instrument, warn};

use crate::error::{AdminGatewayError, GatewayError, LnurlError};
use crate::iroh_server::{Handlers, start_iroh_endpoint};
use crate::{Gateway, GatewayState};

/// Creates the webserver's routes and spawns the webserver in a separate task.
pub async fn run_webserver(
    gateway: Arc<Gateway>,
    mut mnemonic_receiver: tokio::sync::broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let task_group = gateway.task_group.clone();
    let mut handlers = Handlers::new();

    let routes = routes(gateway.clone(), task_group.clone(), &mut handlers);
    let ui_routes = fedimint_gateway_ui::router(gateway.clone());
    let api_v1 = Router::new()
        .nest(&format!("/{V1_API_ENDPOINT}"), routes.clone())
        // Backwards compatibility: Continue supporting gateway APIs without versioning
        .merge(routes)
        .merge(ui_routes);

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx();
    let listener = TcpListener::bind(&gateway.listen).await?;
    let serve = axum::serve(listener, api_v1.into_make_service());
    task_group.spawn("Gateway Webserver", |_| async {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        match graceful.await {
            Err(err) => {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error shutting down gatewayd webserver");
            }
            _ => {
                info!(target: LOG_GATEWAY, "Successfully shutdown webserver");
            }
        }
    });
    info!(target: LOG_GATEWAY, listen = %gateway.listen, "Successfully started webserver");

    // Don't start the Iroh endpoint until the mnemonic has been set via HTTP or the
    // UI
    if let GatewayState::NotConfigured { .. } = gateway.get_state().await {
        info!(target: LOG_GATEWAY, "Waiting for the mnemonic to be set before starting iroh loop.");
        let _ = mnemonic_receiver.recv().await;
    }

    start_iroh_endpoint(&gateway, task_group, Arc::new(handlers)).await?;

    Ok(())
}

/// Extracts the Bearer token from the Authorization header of the request.
fn extract_bearer_token(request: &Request) -> Option<String> {
    let headers = request.headers();
    let auth_header = headers.get(header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;

    if auth_str.starts_with("Bearer ") {
        Some(auth_str.trim_start_matches("Bearer ").to_string())
    } else {
        None
    }
}

/// Extracts Basic Auth credentials (username, password) from the Authorization
/// header.
fn extract_basic_auth(request: &Request) -> Option<(String, String)> {
    let headers = request.headers();
    let auth_header = headers.get(header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;

    if !auth_str.starts_with("Basic ") {
        return None;
    }

    let encoded = auth_str.trim_start_matches("Basic ");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;

    let mut parts = credentials.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();

    Some((username, password))
}

// ==================== Authorization Helper Functions ====================

/// Checks if the authenticated user has permission to spend money.
/// Returns `Ok(Some(max_amount))` for users with a SendLimit authorization.
/// Returns `Ok(None)` for Admin (no limit).
/// Returns `Err(Forbidden)` if the user doesn't have spend permission.
pub fn check_spend_permission(
    auth_user: &AuthenticatedUser,
) -> Result<Option<Amount>, AdminGatewayError> {
    match auth_user {
        AuthenticatedUser::Admin => Ok(None), // No limit for admin
        AuthenticatedUser::User { authorizations, .. } => {
            // Find SendLimit authorization
            for auth in authorizations {
                if let UserAuthorization::SendLimit { max_send_amount } = auth {
                    return Ok(Some(*max_send_amount));
                }
            }
            // User doesn't have SendLimit permission
            Err(AdminGatewayError::Forbidden)
        }
    }
}

/// Checks if the requested amount is within the user's spend limit.
/// Returns `Ok(())` if the amount is allowed.
/// Returns `Err(Forbidden)` if the amount exceeds the limit.
fn check_amount_within_limit(
    limit: Option<Amount>,
    amount: Amount,
) -> Result<(), AdminGatewayError> {
    match limit {
        None => Ok(()),                               // Admin, no limit
        Some(max) if amount <= max => Ok(()),         // Within limit
        Some(_) => Err(AdminGatewayError::Forbidden), // Exceeds limit
    }
}

/// Checks if the authenticated user has permission to manage users.
/// Returns `Ok(())` for Admin or users with UserManagement authorization.
/// Returns `Err(Forbidden)` otherwise.
pub fn check_user_management_permission(
    auth_user: &AuthenticatedUser,
) -> Result<(), AdminGatewayError> {
    match auth_user {
        AuthenticatedUser::Admin => Ok(()),
        AuthenticatedUser::User { authorizations, .. } => {
            if authorizations
                .iter()
                .any(|a| matches!(a, UserAuthorization::UserManagement))
            {
                Ok(())
            } else {
                Err(AdminGatewayError::Forbidden)
            }
        }
    }
}

/// Checks if the authenticated user has permission to manage federations
/// (join/leave). Returns `Ok(())` for Admin or users with FederationManagement
/// authorization. Returns `Err(Forbidden)` otherwise.
pub fn check_federation_management_permission(
    auth_user: &AuthenticatedUser,
) -> Result<(), AdminGatewayError> {
    match auth_user {
        AuthenticatedUser::Admin => Ok(()),
        AuthenticatedUser::User { authorizations, .. } => {
            if authorizations
                .iter()
                .any(|a| matches!(a, UserAuthorization::FederationManagement))
            {
                Ok(())
            } else {
                Err(AdminGatewayError::Forbidden)
            }
        }
    }
}

/// Checks if the authenticated user has permission to modify fees.
/// Returns `Ok(())` for Admin or users with FeeManagement authorization.
/// Returns `Err(Forbidden)` otherwise.
pub fn check_fee_management_permission(
    auth_user: &AuthenticatedUser,
) -> Result<(), AdminGatewayError> {
    match auth_user {
        AuthenticatedUser::Admin => Ok(()),
        AuthenticatedUser::User { authorizations, .. } => {
            if authorizations
                .iter()
                .any(|a| matches!(a, UserAuthorization::FeeManagement))
            {
                Ok(())
            } else {
                Err(AdminGatewayError::Forbidden)
            }
        }
    }
}

/// Checks if the authenticated user is the admin (authenticated via bearer
/// token). This is used for sensitive operations like accessing the mnemonic.
/// Returns `Ok(())` for Admin only.
/// Returns `Err(Forbidden)` for any user (even with all permissions).
pub fn check_admin_only(auth_user: &AuthenticatedUser) -> Result<(), AdminGatewayError> {
    match auth_user {
        AuthenticatedUser::Admin => Ok(()),
        AuthenticatedUser::User { .. } => Err(AdminGatewayError::Forbidden),
    }
}

async fn not_configured_middleware(
    Extension(gateway): Extension<Arc<Gateway>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    if matches!(
        gateway.get_state().await,
        GatewayState::NotConfigured { .. }
    ) {
        let method = request.method().clone();
        let path = request.uri().path();

        // Allow the API mnemonic endpoint (for CLI usage)
        let is_mnemonic_api = method == axum::http::Method::POST
            && (path == MNEMONIC_ENDPOINT
                || path == format!("/{V1_API_ENDPOINT}/{MNEMONIC_ENDPOINT}"));

        let is_setup_route = fedimint_gateway_ui::is_allowed_setup_route(path);

        if !is_mnemonic_api && !is_setup_route {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    Ok(next.run(request).await)
}

/// Middleware to authenticate an incoming request. Supports two authentication
/// methods:
/// 1. Basic Auth (username:password) - Looks up user in database, verifies
///    bcrypt hash
/// 2. Bearer Auth (password only) - Verifies against admin password hash
///
/// On successful authentication, inserts `AuthenticatedUser` into request
/// extensions.
async fn auth_middleware(
    Extension(gateway): Extension<Arc<Gateway>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // Try Basic Auth first (for user authentication)
    if let Some((username, password)) = extract_basic_auth(&request) {
        let mut dbtx = gateway.gateway_db.begin_transaction_nc().await;
        if let Some(user) = dbtx.get_user(&username).await {
            if bcrypt::verify(&password, &user.password_hash).unwrap_or(false) {
                // Authentication successful - insert user identity into extensions
                let auth_user = AuthenticatedUser::User {
                    username,
                    authorizations: user.authorization,
                };
                request.extensions_mut().insert(auth_user);
                return Ok(next.run(request).await);
            }
        }

        // Invalid user/password - return unauthorized
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Try Bearer Auth (for admin authentication)
    if let Some(token) = extract_bearer_token(&request) {
        if bcrypt::verify(token, &gateway.bcrypt_password_hash.to_string())
            .expect("Bcrypt hash is valid since we just stringified it")
        {
            // Admin authentication successful
            request.extensions_mut().insert(AuthenticatedUser::Admin);
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Registers a public GET API handler (no authentication required).
/// For Iroh, the handler will receive `AuthenticatedUser::Admin` since these
/// are public endpoints.
fn register_public_get_handler<F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    router: Router,
) -> Router
where
    F: Fn(Extension<Arc<Gateway>>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    // For Iroh, wrap the handler to accept AuthenticatedUser (ignored)
    let func_for_iroh = func.clone();
    let iroh_wrapper = move |gateway: Extension<Arc<Gateway>>,
                             _auth_user: Extension<AuthenticatedUser>| {
        func_for_iroh(gateway)
    };
    handlers.add_handler(route, iroh_wrapper, false);
    router.route(route, get(func))
}

/// Registers a public POST API handler (no authentication required).
/// For Iroh, the handler will receive `AuthenticatedUser::Admin` since these
/// are public endpoints.
fn register_public_post_handler<P, F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    router: Router,
) -> Router
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Json<P>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    // For Iroh, wrap the handler to accept AuthenticatedUser (ignored)
    let func_for_iroh = func.clone();
    let iroh_wrapper = move |gateway: Extension<Arc<Gateway>>,
                             _auth_user: Extension<AuthenticatedUser>,
                             json: Json<P>| { func_for_iroh(gateway, json) };
    handlers.add_handler_with_payload(route, iroh_wrapper, false);
    router.route(route, post(func))
}

/// Registers an authenticated GET API handler.
/// Handler receives `AuthenticatedUser` for authorization checks.
fn register_authed_get_handler<F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    router: Router,
) -> Router
where
    F: Fn(Extension<Arc<Gateway>>, Extension<AuthenticatedUser>) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler(route, func.clone(), true);
    router.route(route, get(func))
}

/// Registers an authenticated POST API handler.
/// Handler receives `AuthenticatedUser` for authorization checks.
fn register_authed_post_handler<P, F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    router: Router,
) -> Router
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Extension<AuthenticatedUser>, Json<P>) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler_with_payload(route, func.clone(), true);
    router.route(route, post(func))
}

/// Public routes that are used in the LNv1 protocol
fn lnv1_routes(handlers: &mut Handlers) -> Router {
    let router = Router::new();
    let router = register_public_post_handler(handlers, PAY_INVOICE_ENDPOINT, pay_invoice, router);
    register_public_get_handler(handlers, GET_GATEWAY_ID_ENDPOINT, get_gateway_id, router)
}

/// Public routes that are used in the LNv2 protocol
fn lnv2_routes(handlers: &mut Handlers) -> Router {
    let router = Router::new();
    let router =
        register_public_post_handler(handlers, ROUTING_INFO_ENDPOINT, routing_info_v2, router);
    let router = register_public_post_handler(
        handlers,
        SEND_PAYMENT_ENDPOINT,
        pay_bolt11_invoice_v2,
        router,
    );
    let router = register_public_post_handler(
        handlers,
        CREATE_BOLT11_INVOICE_ENDPOINT,
        create_bolt11_invoice_v2,
        router,
    );
    // Verify endpoint does not have the same signature, it is handled separately
    router.route("/verify/{payment_hash}", get(verify_bolt11_preimage_v2_get))
}

/// Gateway Webserver Routes. The gateway supports two types of routes
/// - Always Authenticated: these routes always require a Bearer token. Used by
///   gateway administrators.
/// - Un-authenticated: anyone can request these routes. Used by fedimint
///   clients.
fn routes(gateway: Arc<Gateway>, task_group: TaskGroup, handlers: &mut Handlers) -> Router {
    // Public routes on gateway webserver
    let mut public_routes = register_public_post_handler(
        handlers,
        RECEIVE_ECASH_ENDPOINT,
        receive_ecash,
        Router::new(),
    );
    public_routes = public_routes.merge(lnv1_routes(handlers));
    public_routes = public_routes.merge(lnv2_routes(handlers));

    // Authenticated routes used for gateway administration
    // Authentication is handled by register_authed_* functions
    let authenticated_routes = Router::new();
    let authenticated_routes =
        register_authed_post_handler(handlers, ADDRESS_ENDPOINT, address, authenticated_routes);
    let authenticated_routes =
        register_authed_post_handler(handlers, WITHDRAW_ENDPOINT, withdraw, authenticated_routes);
    let authenticated_routes = register_authed_post_handler(
        handlers,
        CONNECT_FED_ENDPOINT,
        connect_fed,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        LEAVE_FED_ENDPOINT,
        leave_fed,
        authenticated_routes,
    );
    let authenticated_routes =
        register_authed_post_handler(handlers, BACKUP_ENDPOINT, backup, authenticated_routes);
    let authenticated_routes = register_authed_post_handler(
        handlers,
        CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
        create_invoice_for_operator,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
        create_offer_for_operator,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        PAY_INVOICE_FOR_OPERATOR_ENDPOINT,
        pay_invoice_operator,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        PAY_OFFER_FOR_OPERATOR_ENDPOINT,
        pay_offer_operator,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        GET_INVOICE_ENDPOINT,
        get_invoice,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_get_handler(
        handlers,
        GET_LN_ONCHAIN_ADDRESS_ENDPOINT,
        get_ln_onchain_address,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        OPEN_CHANNEL_ENDPOINT,
        open_channel,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
        close_channels_with_peer,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_get_handler(
        handlers,
        LIST_CHANNELS_ENDPOINT,
        list_channels,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        LIST_TRANSACTIONS_ENDPOINT,
        list_transactions,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        SEND_ONCHAIN_ENDPOINT,
        send_onchain,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        ADDRESS_RECHECK_ENDPOINT,
        recheck_address,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_get_handler(
        handlers,
        GET_BALANCES_ENDPOINT,
        get_balances,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        SPEND_ECASH_ENDPOINT,
        spend_ecash,
        authenticated_routes,
    );
    let authenticated_routes =
        register_authed_get_handler(handlers, MNEMONIC_ENDPOINT, mnemonic, authenticated_routes);
    // Stop does not have the same function signature, it is handled separately
    let authenticated_routes = authenticated_routes.route(STOP_ENDPOINT, get(stop));
    let authenticated_routes = register_authed_post_handler(
        handlers,
        PAYMENT_LOG_ENDPOINT,
        payment_log,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_post_handler(
        handlers,
        PAYMENT_SUMMARY_ENDPOINT,
        payment_summary,
        authenticated_routes,
    );
    let authenticated_routes =
        register_authed_post_handler(handlers, SET_FEES_ENDPOINT, set_fees, authenticated_routes);
    let authenticated_routes = register_authed_post_handler(
        handlers,
        CONFIGURATION_ENDPOINT,
        configuration,
        authenticated_routes,
    );
    let authenticated_routes =
        register_authed_get_handler(handlers, GATEWAY_INFO_ENDPOINT, info, authenticated_routes);
    let authenticated_routes = register_authed_post_handler(
        handlers,
        MNEMONIC_ENDPOINT,
        set_mnemonic,
        authenticated_routes,
    );
    let authenticated_routes = register_authed_get_handler(
        handlers,
        INVITE_CODES_ENDPOINT,
        invite_codes,
        authenticated_routes,
    );
    // User management routes
    let authenticated_routes =
        register_authed_get_handler(handlers, USERS_ENDPOINT, list_users, authenticated_routes);
    let authenticated_routes =
        register_authed_post_handler(handlers, USERS_ENDPOINT, create_user, authenticated_routes);
    // User routes with path parameter are handled separately (not through
    // register_* helpers)
    let authenticated_routes = authenticated_routes
        .route(&format!("{USERS_ENDPOINT}/{{username}}"), get(get_user))
        .route(
            &format!("{USERS_ENDPOINT}/{{username}}"),
            axum::routing::delete(delete_user),
        );
    let authenticated_routes = authenticated_routes.layer(middleware::from_fn(auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .layer(middleware::from_fn(not_configured_middleware))
        .layer(Extension(gateway))
        .layer(Extension(task_group))
        .layer(CorsLayer::permissive())
}

/// Display high-level information about the Gateway
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn info(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway config
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn configuration(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<ConfigPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let gateway_fed_config = gateway
        .handle_get_federation_config(payload.federation_id)
        .await?;
    Ok(Json(json!(gateway_fed_config)))
}

/// Generate deposit address
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn address(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

/// Withdraw from a gateway federation.
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn withdraw(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // Resolve amount for limit check
    let amount_to_check = match &payload.amount {
        fedimint_core::BitcoinAmountOrAll::Amount(btc_amount) => {
            Amount::from_sats(btc_amount.to_sat())
        }
        fedimint_core::BitcoinAmountOrAll::All => {
            // Get balance from the federation
            let balances = gateway.handle_get_balances_msg().await?;
            balances
                .ecash_balances
                .iter()
                .find(|b| b.federation_id == payload.federation_id)
                .map_or(Amount::ZERO, |b| b.ecash_balance_msats)
        }
    };

    // Check if amount is within limit
    check_amount_within_limit(limit, amount_to_check)?;

    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn create_invoice_for_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<CreateInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invoice = gateway
        .handle_create_invoice_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(invoice)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_invoice_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<PayInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // Get amount from invoice
    let amount_msat = payload
        .invoice
        .amount_milli_satoshis()
        .ok_or(AdminGatewayError::Forbidden)?; // Reject amountless invoices for limited users

    // Check if amount is within limit
    check_amount_within_limit(limit, Amount::from_msats(amount_msat))?;

    let preimage = gateway.handle_pay_invoice_for_operator_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_invoice(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<fedimint_ln_client::pay::PayInvoicePayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let preimage = gateway.handle_pay_invoice_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

/// Connect a new federation
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn connect_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    check_federation_management_permission(&auth_user)?;
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Leave a federation
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn leave_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<LeaveFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    check_federation_management_permission(&auth_user)?;
    let fed = gateway.handle_leave_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn backup(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<BackupPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_backup_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn set_fees(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<SetFeesPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    check_fee_management_permission(&auth_user)?;
    gateway.handle_set_fees_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_ln_onchain_address(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let address = gateway.handle_get_ln_onchain_address_msg().await?;
    Ok(Json(json!(address.to_string())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn open_channel(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<OpenChannelRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // Only check push_amount_sats against limit (not channel_size_sats)
    if payload.push_amount_sats > 0 {
        let push_amount = Amount::from_sats(payload.push_amount_sats);
        check_amount_within_limit(limit, push_amount)?;
    }

    let funding_txid = gateway.handle_open_channel_msg(payload).await?;
    Ok(Json(json!(funding_txid)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn close_channels_with_peer(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<CloseChannelsWithPeerRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let response = gateway.handle_close_channels_with_peer_msg(payload).await?;
    Ok(Json(json!(response)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn list_channels(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let channels = gateway.handle_list_channels_msg().await?;
    Ok(Json(json!(channels)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn send_onchain(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<SendOnchainRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // Resolve amount for limit check
    let amount_to_check = match &payload.amount {
        fedimint_core::BitcoinAmountOrAll::Amount(btc_amount) => {
            Amount::from_sats(btc_amount.to_sat())
        }
        fedimint_core::BitcoinAmountOrAll::All => {
            // Get LN node on-chain balance
            let balances = gateway.handle_get_balances_msg().await?;
            Amount::from_sats(balances.onchain_balance_sats)
        }
    };

    // Check if amount is within limit
    check_amount_within_limit(limit, amount_to_check)?;

    let txid = gateway.handle_send_onchain_msg(payload).await?;
    Ok(Json(json!(txid)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn recheck_address(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<DepositAddressRecheckPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_recheck_address_msg(payload).await?;
    Ok(Json(json!({})))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_balances(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let balances = gateway.handle_get_balances_msg().await?;
    Ok(Json(json!(balances)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_gateway_id(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!(gateway.http_gateway_id().await)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn routing_info_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(federation_id): Json<FederationId>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let routing_info = gateway.routing_info_v2(&federation_id).await?;
    Ok(Json(json!(routing_info)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SendPaymentPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let payment_result = gateway.send_payment_v2(payload).await?;
    Ok(Json(json!(payment_result)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn create_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CreateBolt11InvoicePayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invoice = gateway.create_bolt11_invoice_v2(payload).await?;
    Ok(Json(json!(invoice)))
}

pub(crate) async fn verify_bolt11_preimage_v2_get(
    Extension(gateway): Extension<Arc<Gateway>>,
    Path(payment_hash): Path<sha256::Hash>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let response = gateway
        .verify_bolt11_preimage_v2(payment_hash, query.contains_key("wait"))
        .await
        .map_err(|e| LnurlError::internal(anyhow!(e)))?;

    Ok(Json(json!(LnurlResponse::Ok(response))))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn spend_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<SpendEcashPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // Check if amount is within limit
    check_amount_within_limit(limit, payload.amount)?;

    Ok(Json(json!(gateway.handle_spend_ecash_msg(payload).await?)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn receive_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ReceiveEcashPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!(
        gateway.handle_receive_ecash_msg(payload).await?
    )))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn mnemonic(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Mnemonic access is restricted to admin only (bearer token auth)
    check_admin_only(&auth_user)?;
    let words = gateway.handle_mnemonic_msg().await?;
    Ok(Json(json!(words)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn set_mnemonic(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<SetMnemonicPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Mnemonic access is restricted to admin only (bearer token auth)
    check_admin_only(&auth_user)?;
    gateway.handle_set_mnemonic_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
pub(crate) async fn stop(
    Extension(task_group): Extension<TaskGroup>,
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Stopping the gateway is restricted to admin only (bearer token auth)
    check_admin_only(&auth_user)?;
    gateway.handle_shutdown_msg(task_group).await?;
    Ok(Json(json!(())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn payment_log(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<PaymentLogPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let payment_log = gateway.handle_payment_log_msg(payload).await?;
    Ok(Json(json!(payment_log)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn payment_summary(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<PaymentSummaryPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let payment_summary = gateway.handle_payment_summary_msg(payload).await?;
    Ok(Json(json!(payment_summary)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_invoice(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<GetInvoiceRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invoice = gateway.handle_get_invoice_msg(payload).await?;
    Ok(Json(json!(invoice)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn list_transactions(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<ListTransactionsPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let transactions = gateway.handle_list_transactions_msg(payload).await?;
    Ok(Json(json!(transactions)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn create_offer_for_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Json(payload): Json<CreateOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let offer = gateway
        .handle_create_offer_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(offer)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_offer_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<PayOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check spend permission
    let limit = check_spend_permission(&auth_user)?;

    // For users with SendLimit, require explicit amount
    // (BOLT12 offers may have amount determined by the offer itself,
    // but for security we require the user to specify it explicitly)
    if let Some(max_amount) = limit {
        let amount = payload.amount.ok_or(AdminGatewayError::Forbidden)?;
        check_amount_within_limit(Some(max_amount), amount)?;
    }

    let response = gateway.handle_pay_offer_for_operator_msg(payload).await?;
    Ok(Json(json!(response)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn invite_codes(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invite_codes = gateway.handle_export_invite_codes().await;
    Ok(Json(json!(invite_codes)))
}

// ==================== User Management Endpoints ====================

/// List all users
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn list_users(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let users = gateway.handle_list_users().await?;
    Ok(Json(json!(users)))
}

/// Create a new user
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn create_user(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<CreateUserPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check user management permission
    check_user_management_permission(&auth_user)?;

    let user = gateway.handle_create_user(payload).await?;
    Ok(Json(json!(user)))
}

/// Get a specific user by username
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(%username))]
async fn get_user(
    Extension(gateway): Extension<Arc<Gateway>>,
    _auth_user: Extension<AuthenticatedUser>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let user = gateway.handle_get_user(&username).await?;
    Ok(Json(json!(user)))
}

/// Delete a user by username
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(%username))]
async fn delete_user(
    Extension(gateway): Extension<Arc<Gateway>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Check user management permission
    check_user_management_permission(&auth_user)?;

    let deleted = gateway.handle_delete_user(&username).await?;
    Ok(Json(json!({ "deleted": deleted })))
}
