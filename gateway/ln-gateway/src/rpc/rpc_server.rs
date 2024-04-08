use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use bitcoin::consensus::Encodable;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::config::FederationId;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_lnv2_client::{CreateInvoicePayload, SendPaymentPayload};
use hex::ToHex;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info, instrument};

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, InfoPayload,
    LeaveFedPayload, RestorePayload, SetConfigurationPayload, WithdrawPayload, V1_API_ENDPOINT,
};
use crate::rpc::ConfigPayload;
use crate::{Gateway, GatewayError};

/// Creates the webserver's routes and spawns the webserver in a separate task.
pub async fn run_webserver(gateway: Gateway, task_group: &mut TaskGroup) -> anyhow::Result<()> {
    let v1_routes = v1_routes(gateway.clone());
    let api_v1 = Router::new()
        .nest(&format!("/{V1_API_ENDPOINT}"), v1_routes.clone())
        // Backwards compatibility: Continue supporting gateway APIs without versioning
        .merge(v1_routes);

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let listener = TcpListener::bind(&gateway.listen).await?;
    let serve = axum::serve(listener, api_v1.into_make_service());
    task_group.spawn("Gateway Webserver", move |_| async move {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down gatewayd webserver: {:?}", e);
        } else {
            info!("Successfully shutdown webserver");
        }
    });

    info!("Successfully started webserver");
    Ok(())
}

/// Extracts the Bearer token from the Authorization header of the request.
fn extract_bearer_token(request: &Request) -> Result<String, StatusCode> {
    let headers = request.headers();
    let auth_header = headers.get(header::AUTHORIZATION);
    if let Some(header_value) = auth_header {
        let auth_str = header_value
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let token = auth_str.trim_start_matches("Bearer ").to_string();
        return Ok(token);
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Middleware to authenticate an incoming request. Routes that are
/// authenticated with this middleware always require a Bearer token to be
/// supplied in the Authorization header.
async fn auth_middleware(
    Extension(gateway): Extension<Gateway>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // These routes are not available unless the gateway's configuration is set.
    let gateway_config = gateway
        .gateway_config
        .read()
        .await
        .clone()
        .ok_or(StatusCode::NOT_FOUND)?;
    let gateway_hashed_password = gateway_config.hashed_password;
    let password_salt = gateway_config.password_salt;
    authenticate(gateway_hashed_password, password_salt, request, next).await
}

/// Middleware to authenticate an incoming request. Routes that are
/// authenticated with this middleware are un-authenticated if the gateway has
/// not yet been configured. After the gateway is configured, this middleware
/// enforces that a Bearer token must be supplied in the Authorization header.
async fn auth_after_config_middleware(
    Extension(gateway): Extension<Gateway>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // If the gateway's config has not been set, allow the request to continue, so
    // that the gateway can be configured
    let gateway_config = gateway.gateway_config.read().await.clone();
    if gateway_config.is_none() {
        return Ok(next.run(request).await);
    }

    // Otherwise, validate that the Bearer token matches the gateway's hashed
    // password
    let gateway_config = gateway_config.expect("Already validated the gateway config is not none");
    let gateway_hashed_password = gateway_config.hashed_password;
    let password_salt = gateway_config.password_salt;
    authenticate(gateway_hashed_password, password_salt, request, next).await
}

/// Validate that the Bearer token matches the gateway's hashed password
async fn authenticate(
    gateway_hashed_password: sha256::Hash,
    password_salt: [u8; 16],
    request: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let token = extract_bearer_token(&request)?;
    let hashed_password = hash_password(token, password_salt);
    if gateway_hashed_password == hashed_password {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Gateway Webserver Routes. The gateway supports three types of routes
/// - Always Authenticated: these routes always require a Bearer token. Used by
///   gateway administrators.
/// - Authenticated after config: these routes are unauthenticated before
///   configuring the gateway to allow the user
/// to set a password. After setting the password, they become authenticated.
/// - Un-authenticated: anyone can request these routes. Used by fedimint
///   clients.
fn v1_routes(gateway: Gateway) -> Router {
    // Public routes on gateway webserver
    let public_routes = Router::new()
        .route("/pay_invoice", post(pay_invoice))
        .route("/id", get(get_gateway_id))
        // These routes are for next generation lightning
        .route("/payment_info", post(payment_info_v2))
        .route("/send_payment", post(send_payment_v2))
        .route("/create_invoice", post(create_invoice_v2));

    // Authenticated, public routes used for gateway administration
    let always_authenticated_routes = Router::new()
        .route("/balance", post(balance))
        .route("/address", post(address))
        .route("/withdraw", post(withdraw))
        .route("/connect-fed", post(connect_fed))
        .route("/leave-fed", post(leave_fed))
        .route("/backup", post(backup))
        .route("/restore", post(restore))
        .layer(middleware::from_fn(auth_middleware));

    // Routes that are un-authenticated before gateway configuration, then become
    // authenticated after a password has been set.
    let authenticated_after_config_routes = Router::new()
        .route("/set_configuration", post(set_configuration))
        .route("/config", get(configuration))
        // FIXME: deprecated >= 0.3.0
        .route("/info", post(handle_post_info))
        .route("/info", get(info))
        .layer(middleware::from_fn(auth_after_config_middleware));

    Router::new()
        .merge(public_routes)
        .merge(always_authenticated_routes)
        .merge(authenticated_after_config_routes)
        .layer(Extension(gateway))
        .layer(CorsLayer::permissive())
}

/// Creates a password hash by appending a 4 byte salt to the plaintext
/// password.
pub fn hash_password(plaintext_password: String, salt: [u8; 16]) -> sha256::Hash {
    let mut bytes = Vec::<u8>::new();
    plaintext_password
        .consensus_encode(&mut bytes)
        .expect("Password is encodable");
    salt.consensus_encode(&mut bytes)
        .expect("Salt is encodable");
    sha256::Hash::hash(&bytes)
}

/// Display high-level information about the Gateway
// FIXME: deprecated >= 0.3.0
// This endpoint exists only to remain backwards-compatible with the original POST endpoint
#[debug_handler]
#[instrument(skip_all, err)]
async fn handle_post_info(
    Extension(gateway): Extension<Gateway>,
    Json(_payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(Extension(gateway): Extension<Gateway>) -> Result<impl IntoResponse, GatewayError> {
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway config
#[debug_handler]
#[instrument(skip_all, err, fields(?payload))]
async fn configuration(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<ConfigPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let gateway_fed_config = gateway
        .handle_get_federation_config(payload.federation_id)
        .await?;
    Ok(Json(json!(gateway_fed_config)))
}

/// Display gateway ecash note balance
#[debug_handler]
#[instrument(skip_all, err, fields(?payload))]
async fn balance(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let amount = gateway.handle_balance_msg(payload).await?;
    Ok(Json(json!(amount)))
}

/// Generate deposit address
#[debug_handler]
#[instrument(skip_all, err, fields(?payload))]
async fn address(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

/// Withdraw from a gateway federation.
#[debug_handler]
#[instrument(skip_all, err, fields(?payload))]
async fn withdraw(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

#[instrument(skip_all, err, fields(?payload))]
async fn pay_invoice(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let preimage = gateway.handle_pay_invoice_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

/// Connect a new federation
#[instrument(skip_all, err, fields(?payload))]
async fn connect_fed(
    Extension(mut gateway): Extension<Gateway>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Leave a federation
#[instrument(skip_all, err, fields(?payload))]
async fn leave_fed(
    Extension(mut gateway): Extension<Gateway>,
    Json(payload): Json<LeaveFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = gateway.handle_leave_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state
#[instrument(skip_all, err, fields(?payload))]
async fn backup(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_backup_msg(payload).await?;
    Ok(())
}

// Restore a gateway actor state
#[instrument(skip_all, err, fields(?payload))]
async fn restore(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_restore_msg(payload).await?;
    Ok(())
}

#[instrument(skip_all, err, fields(?payload))]
async fn set_configuration(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<SetConfigurationPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_set_configuration_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(skip_all, err)]
async fn get_gateway_id(
    Extension(gateway): Extension<Gateway>,
) -> Result<impl IntoResponse, GatewayError> {
    Ok(Json(json!(gateway.gateway_id)))
}

async fn payment_info_v2(
    Extension(gateway): Extension<Gateway>,
    Json(federation_id): Json<FederationId>,
) -> Json<Value> {
    Json(json!(gateway.payment_info_v2(&federation_id).await))
}

async fn send_payment_v2(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<SendPaymentPayload>,
) -> Json<Value> {
    Json(json!(gateway
        .send_payment_v2(payload)
        .await
        .map_err(|e| e.to_string())))
}

async fn create_invoice_v2(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<CreateInvoicePayload>,
) -> Json<Value> {
    Json(json!(gateway
        .create_invoice_v2(payload)
        .await
        .map_err(|e| e.to_string())))
}
