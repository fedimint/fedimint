use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::Json;
use clap::Parser;
use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_core::Amount;
use fedimint_ln_client::recurring::api::{
    RecurringPaymentRegistrationRequest, RecurringPaymentRegistrationResponse,
};
use fedimint_ln_client::recurring::{PaymentCodeId, PaymentCodeRootKey};
use fedimint_logging::TracingSetup;
use fedimint_recurringd::RecurringInvoiceServer;
use fedimint_rocksdb::RocksDb;
use lightning_invoice::Bolt11Invoice;
use lnurl::pay::{LnURLPayInvoice, PayResponse};
use tokio::net::TcpListener;

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
    #[clap(long, env = "FM_RECURRING_API_BEARER_TOKEN")]
    bearer_token: String,
    #[clap(long, env = "FM_RECURRING_DATA_DIR")]
    data_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    recurring_invoice_server: RecurringInvoiceServer,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli_opts = CliOpts::parse();

    let db = RocksDb::open(cli_opts.data_dir)?;
    let recurring_invoice_server = RecurringInvoiceServer::new(db, cli_opts.api_address).await?;

    let app = axum::Router::new()
        .route("/federations", put(add_federation))
        .route("/federations", get(list_federations))
        .route("/paycodes", put(add_payment_code))
        .route("/paycodes/:payment_code_id", get(lnurl_pay))
        .route("/paycodes/:payment_code_id/invoice", get(lnurl_pay_invoice))
        .route(
            "/paycodes/recipient/:payment_code_root_key/generated/:invoice_index",
            get(await_invoice),
        )
        .with_state(AppState {
            recurring_invoice_server,
        });

    let listener = TcpListener::bind(&cli_opts.bind_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct AddFederationRequest {
    invite: InviteCode,
}

async fn add_federation(
    State(app_state): State<AppState>,
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
) -> Json<PayResponse> {
    Json(
        app_state
            .recurring_invoice_server
            .lnurl_pay(payment_code_id),
    )
}

async fn lnurl_pay_invoice(
    State(app_state): State<AppState>,
    Path(payment_code_id): Path<PaymentCodeId>,
    Query(params): Query<GetInvoiceParams>,
) -> Result<Json<LnURLPayInvoice>, ApiError> {
    let invoice = app_state
        .recurring_invoice_server
        .lnurl_invoice(payment_code_id, params.amount)
        .await?;
    Ok(Json(invoice))
}

async fn await_invoice(
    State(app_state): State<AppState>,
    Path((payment_code_root_key, invoice_index)): Path<(PaymentCodeRootKey, u64)>,
) -> Result<Json<Bolt11Invoice>, ApiError> {
    let invoice_entry = app_state
        .recurring_invoice_server
        .await_invoice_index_generated(payment_code_root_key.to_payment_code_id(), invoice_index)
        .await?;

    Ok(Json(invoice_entry.invoice))
}

async fn list_federations(State(app_state): State<AppState>) -> Json<Vec<FederationId>> {
    Json(app_state.recurring_invoice_server.list_federations().await)
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
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
