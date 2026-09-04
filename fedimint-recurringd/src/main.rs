use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Json;
use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum_auth::AuthBearer;
use clap::Parser;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiAuth;
use fedimint_core::util::SafeUrl;
use fedimint_ln_client::recurring::api::{
    RecurringPaymentRegistrationRequest, RecurringPaymentRegistrationResponse,
};
use fedimint_ln_client::recurring::{PaymentCodeId, PaymentCodeRootKey};
use fedimint_lnurl::{LnurlResponse, PayResponse};
use fedimint_logging::TracingSetup;
use fedimint_recurringd::{LNURLPayInvoice, PaymentCodeInvoice, RecurringInvoiceServer};
use fedimint_rocksdb::RocksDb;
use lightning_invoice::Bolt11Invoice;
use serde_json::json;
#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;
use tokio::net::TcpListener;
use tower_http::cors;
use tower_http::cors::CorsLayer;
use tracing::{debug, info};

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug, Parser)]
struct CliOpts {
    #[clap(
        long,
        default_value = "127.0.0.1:8176",
        env = "FM_RECURRING_BIND_ADDRESS"
    )]
    bind_address: SocketAddr,
    #[clap(long, env = "FM_RECURRING_API_ADDRESS")]
    api_address: SafeUrl,
    #[clap(
        long,
        env = "FM_RECURRING_API_BEARER_TOKEN",
        value_parser = parse_non_empty_bearer_token
    )]
    bearer_token: String,
    #[clap(long, env = "FM_RECURRING_DATA_DIR")]
    data_dir: PathBuf,
}

fn parse_non_empty_bearer_token(token: &str) -> Result<String, &'static str> {
    if token.is_empty() {
        Err("bearer token must not be empty")
    } else {
        Ok(token.to_owned())
    }
}

#[cfg(test)]
mod main_tests;

#[derive(Clone)]
struct AppState {
    auth_token: ApiAuth,
    recurring_invoice_server: RecurringInvoiceServer,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli_opts = CliOpts::parse();

    let db = RocksDb::build(cli_opts.data_dir).open().await?;
    let recurring_invoice_server = RecurringInvoiceServer::new(
        ConnectorRegistry::build_from_server_env()?
            .http(true)
            .bind()
            .await?,
        db,
        cli_opts.api_address.clone(),
    )
    .await?;

    let cors = CorsLayer::new()
        .allow_origin(cors::Any)
        .allow_methods(cors::Any)
        .allow_headers(cors::Any);

    let api_v1 = axum::Router::new()
        .route("/federations", put(add_federation))
        .route("/federations", get(list_federations))
        .route("/paycodes", put(add_payment_code))
        .route("/paycodes/{payment_code_id}", get(lnurl_pay))
        .route(
            "/verify/{federation_id}/{operation_id}",
            get(verify_invoice_paid),
        )
        .route(
            "/paycodes/{payment_code_id}/invoice",
            get(lnurl_pay_invoice),
        )
        .route(
            "/paycodes/recipient/{payment_code_root_key}/generated/{invoice_index}",
            get(await_invoice),
        )
        .layer(cors);

    let app = axum::Router::new()
        .nest("/lnv1", api_v1)
        .with_state(AppState {
            auth_token: ApiAuth::new(cli_opts.bearer_token),
            recurring_invoice_server,
        });

    info!(api_address = %cli_opts.bind_address, "recurringd started");
    let listener = TcpListener::bind(&cli_opts.bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct AddFederationRequest {
    invite: InviteCode,
}

/// Extractor that verifies the bearer token required to register federations.
struct FederationAuth;

impl FromRequestParts<AppState> for FederationAuth {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        app_state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthBearer(token) = AuthBearer::from_request_parts(parts, app_state)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        if app_state.auth_token.verify(&token) {
            Ok(Self)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn add_federation(
    State(app_state): State<AppState>,
    _auth: FederationAuth,
    request: Json<AddFederationRequest>,
) -> Result<Json<FederationId>, ApiError> {
    let federation_id = app_state
        .recurring_invoice_server
        .register_federation(&request.invite)
        .await?;
    Ok(Json(federation_id))
}

async fn add_payment_code(
    State(app_state): State<AppState>,
    request: Json<RecurringPaymentRegistrationRequest>,
) -> Result<Json<RecurringPaymentRegistrationResponse>, ApiError> {
    let payment_code = app_state
        .recurring_invoice_server
        .register_recurring_payment_code(
            request.federation_id,
            request.payment_code_root_key,
            request.protocol,
            &request.meta,
        )
        .await?;

    Ok(Json(RecurringPaymentRegistrationResponse {
        recurring_payment_code: payment_code,
    }))
}

#[derive(Debug, serde::Deserialize)]
struct GetInvoiceParams {
    amount: Amount,
}

async fn lnurl_pay(
    State(app_state): State<AppState>,
    Path(payment_code_id): Path<PaymentCodeId>,
) -> Json<LnurlResponse<PayResponse>> {
    Json(
        match app_state
            .recurring_invoice_server
            .lnurl_pay(payment_code_id)
            .await
        {
            Ok(response) => LnurlResponse::Ok(response),
            Err(e) => LnurlResponse::error(e.to_string()),
        },
    )
}

async fn lnurl_pay_invoice(
    State(app_state): State<AppState>,
    Path(payment_code_id): Path<PaymentCodeId>,
    Query(params): Query<GetInvoiceParams>,
) -> Json<LnurlResponse<LNURLPayInvoice>> {
    Json(
        match app_state
            .recurring_invoice_server
            .lnurl_invoice(payment_code_id, params.amount)
            .await
        {
            Ok(invoice) => LnurlResponse::Ok(invoice),
            Err(e) => LnurlResponse::error(e.to_string()),
        },
    )
}

async fn await_invoice(
    State(app_state): State<AppState>,
    Path((payment_code_root_key, invoice_index)): Path<(PaymentCodeRootKey, u64)>,
) -> Result<Json<Bolt11Invoice>, ApiError> {
    let PaymentCodeInvoice::Bolt11(invoice) = app_state
        .recurring_invoice_server
        .await_invoice_index_generated(payment_code_root_key.to_payment_code_id(), invoice_index)
        .await?
        .invoice;

    Ok(Json(invoice))
}

async fn list_federations(State(app_state): State<AppState>) -> Json<Vec<FederationId>> {
    Json(app_state.recurring_invoice_server.list_federations().await)
}

/// See [LUD-21](https://github.com/lnurl/luds/blob/luds/21.md).
async fn verify_invoice_paid(
    State(app_state): State<AppState>,
    Path((federation_id, operation_id)): Path<(FederationId, OperationId)>,
) -> Json<serde_json::Value> {
    let result = app_state
        .recurring_invoice_server
        .verify_invoice_paid(federation_id, operation_id)
        .await
        .map(|status| {
            // Technically we aren't fully LUD-21 compliant here because we are leaving out
            // the preimage. There's no good way to only get the preimage once the payment
            // happened in the current architecture, so we skip it entirely to not
            // accidentally leak it prematurely.
            json!({
                "status": "OK",
                "settled": status.status.is_paid(),
                "pr": status.invoice,

            })
        })
        .unwrap_or_else(|e| {
            json!({
                "status": "ERROR",
                "reason": e.to_string(),
            })
        });

    Json(result)
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        debug!("ApiError: {}", self.0);

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": self.0.to_string(),
            })),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to
// turn them into `Result<_, AppError>`. That way you don't need to do that
// manually.
impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
