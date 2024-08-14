use std::sync::Arc;

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::gateway_endpoint_constants::{
    ADDRESS_ENDPOINT, BACKUP_ENDPOINT, BALANCE_ENDPOINT, CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
    CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT, CREATE_BOLT11_INVOICE_V2_ENDPOINT,
    GATEWAY_INFO_ENDPOINT, GATEWAY_INFO_POST_ENDPOINT, GET_BALANCES_ENDPOINT,
    GET_FUNDING_ADDRESS_ENDPOINT, GET_GATEWAY_ID_ENDPOINT, LEAVE_FED_ENDPOINT,
    LIST_ACTIVE_CHANNELS_ENDPOINT, OPEN_CHANNEL_ENDPOINT, PAY_INVOICE_ENDPOINT,
    RECEIVE_ECASH_ENDPOINT, RESTORE_ENDPOINT, ROUTING_INFO_V2_ENDPOINT, SEND_PAYMENT_V2_ENDPOINT,
    SET_CONFIGURATION_ENDPOINT, SPEND_ECASH_ENDPOINT, WITHDRAW_ENDPOINT,
};
use fedimint_lnv2_client::{CreateBolt11InvoicePayload, SendPaymentPayload};
use hex::ToHex;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info, instrument};

use super::{
    BackupPayload, BalancePayload, CloseChannelsWithPeerPayload, ConnectFedPayload,
    DepositAddressPayload, GetFundingAddressPayload, InfoPayload, LeaveFedPayload,
    OpenChannelPayload, ReceiveEcashPayload, RestorePayload, SetConfigurationPayload,
    SpendEcashPayload, WithdrawPayload, V1_API_ENDPOINT,
};
use crate::rpc::ConfigPayload;
use crate::{Gateway, GatewayError};

/// Creates the webserver's routes and spawns the webserver in a separate task.
pub async fn run_webserver(gateway: Arc<Gateway>, task_group: &TaskGroup) -> anyhow::Result<()> {
    let v1_routes = v1_routes(gateway.clone());
    let api_v1 = Router::new()
        .nest(&format!("/{V1_API_ENDPOINT}"), v1_routes.clone())
        // Backwards compatibility: Continue supporting gateway APIs without versioning
        .merge(v1_routes);

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx();
    let listener = TcpListener::bind(&gateway.listen).await?;
    let serve = axum::serve(listener, api_v1.into_make_service());
    task_group.spawn("Gateway Webserver", |_| async {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down gatewayd webserver: {:?}", e);
        } else {
            info!("Successfully shutdown webserver");
        }
    });

    info!("Successfully started webserver on {}", gateway.listen);
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
    Extension(gateway): Extension<Arc<Gateway>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // These routes are not available unless the gateway's configuration is set.
    let gateway_config = gateway
        .clone_gateway_config()
        .await
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
    Extension(gateway): Extension<Arc<Gateway>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    // If the gateway's config has not been set, allow the request to continue, so
    // that the gateway can be configured
    let gateway_config = gateway.clone_gateway_config().await;
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
    let hashed_password = hash_password(&token, password_salt);
    if gateway_hashed_password == hashed_password {
        return Ok(next.run(request).await);
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Gateway Webserver Routes. The gateway supports three types of routes
/// - Always Authenticated: these routes always require a Bearer token. Used by
///   gateway administrators.
/// - Authenticated after config: these routes are unauthenticated before
///   configuring the gateway to allow the user to set a password. After setting
///   the password, they become authenticated.
/// - Un-authenticated: anyone can request these routes. Used by fedimint
///   clients.
fn v1_routes(gateway: Arc<Gateway>) -> Router {
    // Public routes on gateway webserver
    let public_routes = Router::new()
        .route(PAY_INVOICE_ENDPOINT, post(pay_invoice))
        .route(GET_GATEWAY_ID_ENDPOINT, get(get_gateway_id))
        // These routes are for next generation lightning
        .route(ROUTING_INFO_V2_ENDPOINT, post(routing_info_v2))
        .route(SEND_PAYMENT_V2_ENDPOINT, post(pay_bolt11_invoice_v2))
        .route(
            CREATE_BOLT11_INVOICE_V2_ENDPOINT,
            post(create_bolt11_invoice_v2),
        )
        .route(SPEND_ECASH_ENDPOINT, post(spend_ecash))
        .route(RECEIVE_ECASH_ENDPOINT, post(receive_ecash));

    // Authenticated, public routes used for gateway administration
    let always_authenticated_routes = Router::new()
        .route(BALANCE_ENDPOINT, post(balance))
        .route(ADDRESS_ENDPOINT, post(address))
        .route(WITHDRAW_ENDPOINT, post(withdraw))
        .route(CONNECT_FED_ENDPOINT, post(connect_fed))
        .route(LEAVE_FED_ENDPOINT, post(leave_fed))
        .route(BACKUP_ENDPOINT, post(backup))
        .route(RESTORE_ENDPOINT, post(restore))
        .route(GET_FUNDING_ADDRESS_ENDPOINT, post(get_funding_address))
        .route(OPEN_CHANNEL_ENDPOINT, post(open_channel))
        .route(
            CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
            post(close_channels_with_peer),
        )
        .route(LIST_ACTIVE_CHANNELS_ENDPOINT, get(list_active_channels))
        .route(GET_BALANCES_ENDPOINT, get(get_balances))
        .layer(middleware::from_fn(auth_middleware));

    // Routes that are un-authenticated before gateway configuration, then become
    // authenticated after a password has been set.
    let authenticated_after_config_routes = Router::new()
        .route(SET_CONFIGURATION_ENDPOINT, post(set_configuration))
        .route(CONFIGURATION_ENDPOINT, post(configuration))
        // FIXME: deprecated >= 0.3.0
        .route(GATEWAY_INFO_POST_ENDPOINT, post(handle_post_info))
        .route(GATEWAY_INFO_ENDPOINT, get(info))
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
pub fn hash_password(plaintext_password: &str, salt: [u8; 16]) -> sha256::Hash {
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
#[instrument(skip_all, err)]
async fn handle_post_info(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(_payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway
#[instrument(skip_all, err)]
async fn info(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<impl IntoResponse, GatewayError> {
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway config
#[instrument(skip_all, err, fields(?payload))]
async fn configuration(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ConfigPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let gateway_fed_config = gateway
        .handle_get_federation_config(payload.federation_id)
        .await?;
    Ok(Json(json!(gateway_fed_config)))
}

/// Display gateway ecash note balance
#[instrument(skip_all, err, fields(?payload))]
async fn balance(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let amount = gateway.handle_balance_msg(payload).await?;
    Ok(Json(json!(amount)))
}

/// Generate deposit address
#[instrument(skip_all, err, fields(?payload))]
async fn address(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

/// Withdraw from a gateway federation.
#[instrument(skip_all, err, fields(?payload))]
async fn withdraw(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

#[instrument(skip_all, err, fields(?payload))]
async fn pay_invoice(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let preimage = gateway.handle_pay_invoice_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

/// Connect a new federation
#[instrument(skip_all, err, fields(?payload))]
async fn connect_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Leave a federation
#[instrument(skip_all, err, fields(?payload))]
async fn leave_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<LeaveFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = gateway.handle_leave_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state
#[instrument(skip_all, err, fields(?payload))]
async fn backup(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_backup_msg(payload)?;
    Ok(())
}

// Restore a gateway actor state
#[instrument(skip_all, err, fields(?payload))]
async fn restore(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_restore_msg(payload)?;
    Ok(())
}

#[instrument(skip_all, err, fields(?payload))]
async fn set_configuration(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SetConfigurationPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_set_configuration_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(skip_all, err)]
async fn get_funding_address(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(_payload): Json<GetFundingAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let address = gateway.handle_get_funding_address_msg().await?;
    Ok(Json(json!(address.to_string())))
}

#[instrument(skip_all, err, fields(?payload))]
async fn open_channel(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<OpenChannelPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_open_channel_msg(payload).await?;
    Ok(Json(json!(())))
}

#[instrument(skip_all, err, fields(?payload))]
async fn close_channels_with_peer(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CloseChannelsWithPeerPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let response = gateway.handle_close_channels_with_peer_msg(payload).await?;
    Ok(Json(json!(response)))
}

#[instrument(skip_all, err)]
async fn list_active_channels(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<impl IntoResponse, GatewayError> {
    let channels = gateway.handle_list_active_channels_msg().await?;
    Ok(Json(json!(channels)))
}

#[instrument(skip_all, err)]
async fn get_balances(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<impl IntoResponse, GatewayError> {
    let balances = gateway.handle_get_balances_msg().await?;
    Ok(Json(json!(balances)))
}

#[instrument(skip_all, err)]
async fn get_gateway_id(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<impl IntoResponse, GatewayError> {
    Ok(Json(json!(gateway.gateway_id)))
}

async fn routing_info_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(federation_id): Json<FederationId>,
) -> Json<Value> {
    Json(json!(gateway.routing_info_v2(&federation_id).await))
}

async fn pay_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SendPaymentPayload>,
) -> Json<Value> {
    Json(json!(gateway
        .send_payment_v2(payload)
        .await
        .map_err(|e| e.to_string())))
}

async fn create_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CreateBolt11InvoicePayload>,
) -> Json<Value> {
    Json(json!(gateway
        .create_bolt11_invoice_v2(payload)
        .await
        .map_err(|e| e.to_string())))
}

async fn spend_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SpendEcashPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    Ok(Json(json!(gateway.spend_ecash(payload).await?)))
}

async fn receive_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ReceiveEcashPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    Ok(Json(json!(gateway.receive_ecash(payload).await?)))
}
