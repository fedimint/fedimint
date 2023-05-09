use std::net::SocketAddr;

use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use bitcoin_hashes::hex::ToHex;
use fedimint_client_legacy::ln::PayInvoicePayload;
use fedimint_core::task::TaskGroup;
use serde_json::json;
use tokio::sync::oneshot;
use tower_http::auth::RequireAuthorizationLayer;
use tower_http::cors::CorsLayer;
use tracing::{error, instrument};

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload,
    GatewayRpcSender, InfoPayload, LightningReconnectPayload, RestorePayload, WithdrawPayload,
};
use crate::GatewayError;

pub async fn run_webserver(
    authkey: String,
    bind_addr: SocketAddr,
    sender: GatewayRpcSender,
    mut tg: TaskGroup,
) -> axum::response::Result<oneshot::Sender<()>> {
    // Public routes on gateway webserver
    let routes = Router::new().route("/pay_invoice", post(pay_invoice));

    // Authenticated, public routes used for gateway administration
    let admin_routes = Router::new()
        .route("/info", post(info))
        .route("/balance", post(balance))
        .route("/address", post(address))
        .route("/deposit", post(deposit))
        .route("/withdraw", post(withdraw))
        .route("/connect-fed", post(connect_fed))
        .route("/backup", post(backup))
        .route("/restore", post(restore))
        .route("/connect-ln", post(connect_ln))
        .layer(RequireAuthorizationLayer::bearer(&authkey));

    let app = Router::new()
        .merge(routes)
        .merge(admin_routes)
        .layer(Extension(sender))
        .layer(CorsLayer::permissive());

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::Server::bind(&bind_addr).serve(app.into_make_service());
    tg.spawn("Gateway Webserver", move |_| async move {
        let graceful = server.with_graceful_shutdown(async {
            rx.await.ok();
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down gatewayd webserver: {:?}", e);
        }
    })
    .await;

    Ok(tx)
}

/// Display gateway ecash note balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let info = rpc.send(payload).await?;
    Ok(Json(json!(info)))
}

/// Display gateway ecash note balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn balance(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let amount = rpc.send(payload).await?;
    Ok(Json(json!({ "balance_msat": amount.msats })))
}

/// Generate deposit address
#[debug_handler]
#[instrument(skip_all, err)]
async fn address(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let address = rpc.send(payload).await?;
    Ok(Json(json!({ "address": address })))
}

/// Deposit into a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn deposit(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<DepositPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let txid = rpc.send(payload).await?;
    Ok(Json(json!({ "fedimint_txid": txid.to_string() })))
}

/// Withdraw from a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn withdraw(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let txid = rpc.send(payload).await?;
    Ok(Json(json!({ "fedimint_txid": txid.to_string() })))
}

#[instrument(skip_all, err)]
async fn pay_invoice(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let preimage = rpc.send(payload).await?;
    Ok(Json(json!(preimage.0.to_hex())))
}

/// Connect a new federation
#[instrument(skip_all, err)]
async fn connect_fed(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    let fed = rpc.send(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state
#[instrument(skip_all, err)]
async fn backup(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    rpc.send(payload).await?;
    Ok(())
}

// Restore a gateway actor state
#[instrument(skip_all, err)]
async fn restore(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    rpc.send(payload).await?;
    Ok(())
}

// Reconnect to the lightning node
#[instrument(skip_all, err)]
async fn connect_ln(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<LightningReconnectPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    rpc.send(payload).await?;
    Ok(())
}
