use std::net::SocketAddr;

use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use bitcoin_hashes::hex::ToHex;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::pay::PayInvoicePayload;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing::{error, info, instrument};

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, InfoPayload,
    LeaveFedPayload, RestorePayload, SetConfigurationPayload, WithdrawPayload, V1_API_ENDPOINT,
};
use crate::db::GatewayConfiguration;
use crate::rpc::ConfigPayload;
use crate::{Gateway, GatewayError};

pub async fn run_webserver(
    config: Option<GatewayConfiguration>,
    bind_addr: SocketAddr,
    gateway: Gateway,
    task_group: &mut TaskGroup,
) -> anyhow::Result<()> {
    let v1_routes = v1_routes(config, gateway.clone());
    let api_v1 = Router::new()
        .nest(&format!("/{V1_API_ENDPOINT}"), v1_routes.clone())
        // Backwards compatibility: Continue supporting gateway APIs without versioning
        .merge(v1_routes);

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let listener = TcpListener::bind(&bind_addr).await?;
    let serve = axum::serve(listener, api_v1.into_make_service());
    task_group.spawn("Gateway Webserver", move |_| async move {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down gateway webserver: {:?}", e);
        } else {
            info!("Successfully shutdown gateway webserver");
        }
    });

    Ok(())
}

fn v1_routes(config: Option<GatewayConfiguration>, gateway: Gateway) -> Router {
    let (public_routes, admin_routes) = if let Some(gateway_config) = config {
        // Public routes on gateway webserver
        let public_routes = Router::new()
            .route("/pay_invoice", post(pay_invoice))
            .route("/id", get(get_gateway_id));

        // Authenticated, public routes used for gateway administration
        let admin_routes = Router::new()
            // FIXME: deprecated >= 0.3.0
            .route("/info", post(handle_post_info))
            .route("/info", get(info))
            .route("/config", post(configuration))
            .route("/balance", post(balance))
            .route("/address", post(address))
            .route("/withdraw", post(withdraw))
            .route("/connect-fed", post(connect_fed))
            .route("/leave-fed", post(leave_fed))
            .route("/backup", post(backup))
            .route("/restore", post(restore))
            .route("/set_configuration", post(set_configuration))
            .layer(ValidateRequestHeaderLayer::bearer(&gateway_config.password));
        (public_routes, admin_routes)
    } else {
        let public_routes = Router::new()
            .route("/set_configuration", post(set_configuration))
            .route("/config", get(configuration))
            // FIXME: deprecated >= 0.3.0
            .route("/info", post(handle_post_info))
            .route("/info", get(info));
        let admin_routes = Router::new();
        (public_routes, admin_routes)
    };

    Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .layer(Extension(gateway))
        .layer(CorsLayer::permissive())
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
    Ok(Json(json!(preimage.0.to_hex())))
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
