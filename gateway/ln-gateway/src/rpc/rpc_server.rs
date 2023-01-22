use std::net::SocketAddr;

use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use axum_macros::debug_handler;
use mint_client::ln::PayInvoicePayload;
use serde_json::json;
use tower_http::{auth::RequireAuthorizationLayer, cors::CorsLayer};
use tracing::instrument;

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload,
    GatewayRpcSender, InfoPayload, RestorePayload, WithdrawPayload,
};
use crate::LnGatewayError;

pub async fn run_webserver(
    authkey: String,
    bind_addr: SocketAddr,
    sender: GatewayRpcSender,
) -> axum::response::Result<()> {
    // Public routes on gateway webserver
    let routes = Router::new().route("/pay_invoice", post(pay_invoice));

    // Authenticated, public routes used for gateway administration
    let admin_routes = Router::new()
        .route("/info", post(info))
        .route("/balance", post(balance))
        .route("/address", post(address))
        .route("/deposit", post(deposit))
        .route("/withdraw", post(withdraw))
        .route("/connect", post(connect))
        .route("/backup", post(backup))
        .route("/restore", post(restore))
        .layer(RequireAuthorizationLayer::bearer(&authkey));

    let app = Router::new()
        .merge(routes)
        .merge(admin_routes)
        .layer(Extension(sender))
        .layer(CorsLayer::permissive());

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start webserver");

    Ok(())
}

/// Display gateway ecash token balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    let info = rpc.send(payload).await?;
    Ok(Json(json!(info)))
}

/// Display gateway ecash token balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn balance(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    let amount = rpc.send(payload).await?;
    Ok(Json(json!({ "balance_msat": amount.msats })))
}

/// Generate deposit address
#[debug_handler]
#[instrument(skip_all, err)]
async fn address(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    let address = rpc.send(payload).await?;
    Ok(Json(json!({ "address": address })))
}

/// Deposit into a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn deposit(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<DepositPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    let txid = rpc.send(payload).await?;
    Ok(Json(json!({ "fedimint_txid": txid.to_string() })))
}

/// Withdraw from a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn withdraw(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    let txid = rpc.send(payload).await?;
    Ok(Json(json!({ "fedimint_txid": txid.to_string() })))
}

#[instrument(skip_all, err)]
async fn pay_invoice(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    rpc.send(payload).await?;
    Ok(())
}

/// Connect a new federation
#[instrument(skip_all, err)]
async fn connect(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    rpc.send(payload).await?;
    Ok(())
}

/// Backup a gateway actor state
#[instrument(skip_all, err)]
async fn backup(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    rpc.send(payload).await?;
    Ok(())
}

// Restore a gateway actor state
#[instrument(skip_all, err)]
async fn restore(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, LnGatewayError> {
    rpc.send(payload).await?;
    Ok(())
}
