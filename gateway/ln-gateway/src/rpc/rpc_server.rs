use std::net::SocketAddr;

use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use bitcoin_hashes::hex::ToHex;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::pay::PayInvoicePayload;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tower_http::cors::CorsLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing::{error, instrument};

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, InfoPayload,
    RestorePayload, SetConfigurationPayload, WithdrawPayload,
};
use crate::db::GatewayConfiguration;
use crate::{Gateway, GatewayError};

pub async fn run_webserver(
    authkey: String,
    bind_addr: SocketAddr,
    gateway: Gateway,
    task_group: &mut TaskGroup,
) -> axum::response::Result<()> {
    // Public routes on gateway webserver
    let routes = Router::new().route("/pay_invoice", post(pay_invoice));

    // Authenticated, public routes used for gateway administration
    let admin_routes = Router::new()
        .route("/info", post(info))
        .route("/balance", post(balance))
        .route("/address", post(address))
        .route("/withdraw", post(withdraw))
        .route("/connect-fed", post(connect_fed))
        .route("/backup", post(backup))
        .route("/restore", post(restore))
        .route("/set_configuration", post(set_configuration))
        .layer(ValidateRequestHeaderLayer::bearer(&authkey));

    let app = Router::new()
        .merge(routes)
        .merge(admin_routes)
        .layer(Extension(gateway.clone()))
        .layer(CorsLayer::permissive());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let server = axum::Server::bind(&bind_addr).serve(app.into_make_service());
    task_group
        .spawn("Gateway Webserver", move |_| async move {
            let graceful = server.with_graceful_shutdown(async {
                shutdown_rx.await;
            });

            if let Err(e) = graceful.await {
                error!("Error shutting down gatewayd webserver: {:?}", e);
            }
        })
        .await;

    Ok(())
}

pub async fn run_config_webserver(
    bind_addr: SocketAddr,
    task_group: &mut TaskGroup,
) -> Receiver<GatewayConfiguration> {
    // Public routes on gateway webserver
    let public_routes = Router::new().route("/set_configuration", post(set_configuration_public));

    let (sender, receiver) = mpsc::channel::<GatewayConfiguration>(10);

    let app = Router::new()
        .merge(public_routes)
        .layer(Extension(sender))
        .layer(CorsLayer::permissive());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let server = axum::Server::bind(&bind_addr).serve(app.into_make_service());
    task_group
        .spawn("Gateway Config Webserver", move |_| async move {
            let graceful = server.with_graceful_shutdown(async {
                shutdown_rx.await;
            });

            if let Err(e) = graceful.await {
                error!("Error shutting down gatewayd config webserver: {:?}", e);
            }
        })
        .await;

    receiver
}

/// Display high-level information about the Gateway
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let info = gateway.handle_get_info(payload).await?;
    Ok(Json(json!(info)))
}

/// Display gateway ecash note balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn balance(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let amount = gateway.handle_balance_msg(payload).await?;
    Ok(Json(json!(amount)))
}

/// Generate deposit address
#[debug_handler]
#[instrument(skip_all, err)]
async fn address(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

/// Withdraw from a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn withdraw(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

#[instrument(skip_all, err)]
async fn pay_invoice(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let preimage = gateway.handle_pay_invoice_msg(payload).await?;
    Ok(Json(json!(preimage.0.to_hex())))
}

/// Connect a new federation
#[instrument(skip_all, err)]
async fn connect_fed(
    Extension(mut gateway): Extension<Gateway>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state
#[instrument(skip_all, err)]
async fn backup(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_backup_msg(payload).await?;
    Ok(())
}

// Restore a gateway actor state
#[instrument(skip_all, err)]
async fn restore(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_restore_msg(payload).await?;
    Ok(())
}

#[instrument(skip_all, err)]
async fn set_configuration_public(
    Extension(sender): Extension<mpsc::Sender<GatewayConfiguration>>,
    Json(payload): Json<SetConfigurationPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let gateway_configuration = GatewayConfiguration {
        password: payload.password.clone(),
    };

    sender.send(gateway_configuration).await.map_err(|e| {
        GatewayError::UnexpectedState(format!("Gateway is not in Configuring state: {e:?}"))
    })?;
    Ok(())
}

#[instrument(skip_all, err)]
async fn set_configuration(
    Extension(gateway): Extension<Gateway>,
    Json(payload): Json<SetConfigurationPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    gateway.handle_set_configuration_msg(payload).await?;
    Ok(Json(json!(())))
}
