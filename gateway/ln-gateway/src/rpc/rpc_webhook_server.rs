use std::net::SocketAddr;

use axum::routing::post;
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use fedimint_core::task::TaskGroup;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{error, instrument};

use crate::gateway_lnrpc::intercept_htlc_response::Action;
use crate::gateway_lnrpc::{InterceptHtlcRequest, InterceptHtlcResponse};
use crate::lightning::alby::GatewayAlbyClient;
use crate::lightning::LightningRpcError;
use crate::GatewayError;

pub async fn run_webhook_server(
    bind_addr: SocketAddr,
    task_group: &mut TaskGroup,
    htlc_stream_sender: tokio::sync::mpsc::Sender<Result<InterceptHtlcRequest, tonic::Status>>,
    client: GatewayAlbyClient,
) -> axum::response::Result<()> {
    let app = Router::new()
        .route("/handle_htlc", post(handle_htlc))
        .layer(Extension(htlc_stream_sender.clone()))
        .layer(Extension(client));

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let server = axum::Server::bind(&bind_addr).serve(app.into_make_service());
    task_group
        .spawn("Gateway Webhook Server", move |_| async move {
            let graceful = server.with_graceful_shutdown(async {
                shutdown_rx.await;
            });

            if let Err(e) = graceful.await {
                error!("Error shutting down gatewayd webhook server: {:?}", e);
            }
        })
        .await;

    Ok(())
}

/// `WebhookHandleHtlcParams` is a structure that holds an intercepted HTLC
/// request.
///
/// Example JSON representation:
/// ```json
/// {
///     "htlc": {
///         "payment_hash": "a3f1e3b56a...",
///         "incoming_amount_msat": 1000,
///         "outgoing_amount_msat": 900,
///         "incoming_expiry": 300,
///         "short_channel_id": 2, // This is the short channel id of the federation mapping
///         "incoming_chan_id": 987654321,
///         "htlc_id": 12345
///     }
/// }
/// ```
struct WebhookHandleHtlcParams {
    htlc: InterceptHtlcRequest,
}

use std::fmt;

use serde::de::{MapAccess, Visitor};

impl<'de> Deserialize<'de> for WebhookHandleHtlcParams {
    fn deserialize<D>(deserializer: D) -> Result<WebhookHandleHtlcParams, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WebhookHandleHtlcParamsVisitor;

        impl<'de> Visitor<'de> for WebhookHandleHtlcParamsVisitor {
            type Value = WebhookHandleHtlcParams;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct WebhookHandleHtlcParams")
            }

            fn visit_map<A>(self, mut map: A) -> Result<WebhookHandleHtlcParams, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut htlc = InterceptHtlcRequest::default();

                while let Some(key) = map.next_key()? {
                    match key {
                        "payment_hash" => htlc.payment_hash = map.next_value()?,
                        "incoming_amount_msat" => htlc.incoming_amount_msat = map.next_value()?,
                        "outgoing_amount_msat" => htlc.outgoing_amount_msat = map.next_value()?,
                        "incoming_expiry" => htlc.incoming_expiry = map.next_value()?,
                        "short_channel_id" => htlc.short_channel_id = map.next_value()?,
                        "incoming_chan_id" => htlc.incoming_chan_id = map.next_value()?,
                        "htlc_id" => htlc.htlc_id = map.next_value()?,
                        _ => (),
                    }
                }

                Ok(WebhookHandleHtlcParams { htlc })
            }
        }

        deserializer.deserialize_struct(
            "WebhookHandleHtlcParams",
            &[
                "payment_hash",
                "incoming_amount_msat",
                "outgoing_amount_msat",
                "incoming_expiry",
                "short_channel_id",
                "incoming_chan_id",
                "htlc_id",
            ],
            WebhookHandleHtlcParamsVisitor,
        )
    }
}

#[derive(Serialize)]
struct WebhookHandleHtlcResponse {
    preimage: Vec<u8>,
}

#[debug_handler]
#[instrument(skip_all, err)]
async fn handle_htlc(
    Extension(htlc_stream_sender): Extension<
        tokio::sync::mpsc::Sender<Result<InterceptHtlcRequest, tonic::Status>>,
    >,
    Extension(client): Extension<GatewayAlbyClient>,
    params: Json<WebhookHandleHtlcParams>,
) -> Result<Json<WebhookHandleHtlcResponse>, GatewayError> {
    let htlc = params.htlc.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel::<InterceptHtlcResponse>();

    client.outcomes.lock().await.insert(htlc.htlc_id, sender);

    htlc_stream_sender.send(Ok(htlc)).await.map_err(|e| {
        error!("Error sending htlc to stream: {:?}", e);
        anyhow::anyhow!("Error sending htlc to stream: {:?}", e)
    })?;

    let response = receiver.await.map_err(|_| GatewayError::Disconnected)?;

    match response.action {
        Some(Action::Settle(preimage)) => Ok(Json(WebhookHandleHtlcResponse {
            preimage: preimage.preimage,
        })),
        Some(Action::Cancel(cancel)) => Err(GatewayError::LightningRpcError(
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: cancel.reason,
            },
        )),
        _ => Err(GatewayError::LightningRpcError(
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "Invalid action specified for htlc {htlc_id}".to_string(),
            },
        )),
    }
}
