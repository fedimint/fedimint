use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use devimint::util::ProcessManager;
use devimint::vars::{Global, mkdir};
use devimint::{DevFed, cmd, dev_fed};
// nosemgrep: ban-wildcard-imports
use devimintd_client::*;
use fedimint_core::BitcoinHash;
use fedimint_core::envs::is_env_var_set;
use listenfd::ListenFd;
use tokio::sync::{Notify, OnceCell, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

async fn custom_setup() -> anyhow::Result<ProcessManager> {
    let test_dir = tempfile::Builder::new()
        .prefix("devimintd-")
        .tempdir()
        .expect("Failed to create temp dir")
        .keep();

    mkdir(test_dir.clone()).await?;
    let logs_dir = test_dir.join("logs");
    mkdir(logs_dir.clone()).await?;

    let globals = Global::new(&test_dir, 1, 4, 0, None).await?;
    // Note: setting these as global env vars limits us to one devfed per server
    // instance as they will conflict if multiple devfeds are started.
    for (var, value) in globals.vars() {
        unsafe {
            std::env::set_var(var, value);
        }
    }

    Ok(ProcessManager::new(globals))
}

#[derive(Clone)]
enum DevFedInternalState {
    Initializing,
    Ready(Arc<DevFed>),
    Killed,
}

struct TaskAbortOnDrop<R>(JoinHandle<R>);

impl<R> Drop for TaskAbortOnDrop<R> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct DevFedState {
    state: watch::Sender<DevFedInternalState>,
    kind: DevFedKind,
    keep_alive_notify: Notify,
}

#[derive(Clone, PartialEq, Eq)]
enum DevFedKind {
    Shared,
    Dedicated,
}

impl DevFedState {
    fn new(kind: DevFedKind) -> (Arc<Self>, TaskAbortOnDrop<()>) {
        let state = watch::Sender::new(DevFedInternalState::Initializing);
        let this = Arc::new(Self {
            state,
            kind,
            keep_alive_notify: Notify::new(),
        });
        (
            this.clone(),
            TaskAbortOnDrop(fedimint_core::runtime::spawn(
                "devfed manager",
                this.manage_task(),
            )),
        )
    }

    async fn manage_task(self: Arc<Self>) {
        let process_mgr = custom_setup().await.expect("failed to setup a devfed");

        let dev_fed = dev_fed(&process_mgr)
            .await
            // this should never happen, panicked for easy debugging
            .expect("failed to setup a devfed");
        self.state
            .send_replace(DevFedInternalState::Ready(Arc::new(dev_fed)));
        if self.kind == DevFedKind::Shared {
            // never kill a shared federation
            return;
        }
        let mut die_instant = Instant::now() + Duration::from_secs(30);
        loop {
            tokio::select! {
                biased;
                () = self.keep_alive_notify.notified() => {
                    die_instant = die_instant.max(Instant::now() + Duration::from_secs(15));
                }
                () = sleep_until(die_instant) => {
                    // completed the sleep, time to die
                    break;
                }
            }
        }

        // will die once all Arc are dropped by methods
        self.state.send_replace(DevFedInternalState::Killed);
    }

    // extend life of this dev fed by 15 seconds, please keep calling it every 10
    // seconds to make sure it never dies
    fn keep_alive(&self) {
        self.keep_alive_notify.notify_one();
    }

    async fn wait(&self) -> anyhow::Result<Arc<DevFed>> {
        let mut sub = self.state.subscribe();
        let state = sub
            .wait_for(|x| {
                matches!(
                    x,
                    DevFedInternalState::Ready(_) | DevFedInternalState::Killed
                )
            })
            .await
            .expect("self contains sender");
        match &*state {
            DevFedInternalState::Initializing => unreachable!(),
            DevFedInternalState::Ready(dev_fed) => Ok(dev_fed.clone()),
            DevFedInternalState::Killed => bail!("The devfed is dead, long live the devfed!"),
        }
    }
}

type DevFedStateWithTask = (Arc<DevFedState>, TaskAbortOnDrop<()>);

#[derive(Clone, Default)]
struct AppState {
    dev_feds: Arc<Mutex<HashMap<String, DevFedStateWithTask>>>,
}

impl AppState {
    async fn get_devfed(&self, id: &str) -> anyhow::Result<Arc<DevFed>> {
        self.get_devfed_no_wait(id).await.wait().await
    }

    async fn get_devfed_no_wait(&self, id: &str) -> Arc<DevFedState> {
        self.dev_feds
            .lock()
            .expect("poison")
            .entry(id.to_string())
            .or_insert_with(|| {
                DevFedState::new(if id == "shared" {
                    DevFedKind::Shared
                } else {
                    DevFedKind::Dedicated
                })
            })
            .0
            .clone()
    }
}

#[derive(Parser)]
struct Cli {
    /// Port to listen on (default: 0 for random)
    #[arg(short, long, default_value = "0")]
    port: u16,

    /// Run a command after the server is ready
    #[arg(trailing_var_arg = true)]
    run_after_ready: Vec<std::ffi::OsString>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // already running devimintd, just run the command
    if is_env_var_set("DEVIMINTD_URL") {
        return devimint::cli::exec_user_command(cli.run_after_ready).await;
    }

    fedimint_logging::TracingSetup::default()
        .with_base_level("warn") // reduce logging
        .init()?;

    let state = AppState::default();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/{devfed_id}/invite_code", get(handle_invite_code))
        .route("/{devfed_id}/ecash/generate", post(handle_generate_ecash))
        .route("/{devfed_id}/ecash/receive", post(handle_receive_ecash))
        .route("/{devfed_id}/bitcoin/send", post(handle_send_bitcoin))
        .route("/{devfed_id}/bitcoin/mine", post(handle_mine_blocks))
        .route("/{devfed_id}/bitcoin/address", get(handle_bitcoin_address))
        .route(
            "/{devfed_id}/bitcoin/transaction",
            post(handle_poll_bitcoin_transaction),
        )
        .route("/{devfed_id}/deposit_fees", get(handle_deposit_fees))
        .route("/{devfed_id}/lightning/invoice", post(handle_lnd_invoice))
        .route("/{devfed_id}/lightning/pay", post(handle_lnd_pay))
        .route("/{devfed_id}/lightning/wait", post(handle_lnd_wait))
        .route("/{devfed_id}/lightning/pubkey", get(handle_lnd_pubkey))
        .route("/{devfed_id}/gateway/invoice", post(handle_gateway_invoice))
        .route("/{devfed_id}/gateway/wait", post(handle_gateway_wait))
        .route("/{devfed_id}/recurringd/url", get(handle_recurringd_url))
        .route("/{devfed_id}/keep-alive", post(handle_keep_alive))
        .route(
            "/{devfed_id}/terminate_all_fed_servers",
            post(handle_terminate_all_fed_servers),
        )
        .layer(cors)
        .with_state(state);

    let mut listenfd = ListenFd::from_env();
    let listener = if let Some(listener) = listenfd.take_tcp_listener(0)? {
        info!("Using listenfd socket");
        listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(listener)?
    } else {
        tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, cli.port)).await?
    };

    let port = listener.local_addr()?.port();
    info!("devimintd listening on http://127.0.0.1:{port}");

    // Set env var for tests to discover the server
    unsafe {
        std::env::set_var("DEVIMINTD_URL", format!("http://127.0.0.1:{port}"));
    }

    let user_cmd_failed = Arc::new(OnceCell::new());
    let user_cmd_failed2 = user_cmd_failed.clone();
    let shutdown_signal = async move {
        if devimint::cli::exec_user_command(cli.run_after_ready)
            .await
            .is_err()
        {
            user_cmd_failed2.set(true).unwrap();
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    if user_cmd_failed.get().is_some_and(|x| *x) {
        anyhow::bail!("User command failed");
    }

    Ok(())
}

struct DevimintdError(anyhow::Error);

impl<T: Into<anyhow::Error>> From<T> for DevimintdError {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl IntoResponse for DevimintdError {
    fn into_response(self) -> axum::response::Response {
        let error_msg = self.0.to_string();
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: error_msg }),
        )
            .into_response()
    }
}

async fn handle_invite_code(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<InviteCodeResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let invite_code = dev_fed.fed.invite_code()?;
    Ok(Json(InviteCodeResponse { invite_code }))
}

async fn handle_generate_ecash(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<GenerateEcashRequest>,
) -> Result<Json<GenerateEcashResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let client = dev_fed.fed.internal_client().await?;
    let ecash = cmd!(client, "spend", "--allow-overpay", req.amount_msats)
        .out_json()
        .await?["notes"]
        .as_str()
        .unwrap()
        .to_owned();
    Ok(Json(GenerateEcashResponse { ecash }))
}

async fn handle_receive_ecash(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<ReceiveEcashRequest>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let client = dev_fed.fed.internal_client().await?;
    cmd!(client, "reissue", req.ecash).run().await?;
    Ok(Json(()))
}

async fn handle_send_bitcoin(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<SendBitcoinRequest>,
) -> Result<Json<SendBitcoinResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let txid = dev_fed
        .bitcoind
        .send_to(req.address, req.amount_sats)
        .await?;
    // Mine blocks to confirm the transaction
    dev_fed.bitcoind.mine_blocks(11).await?;
    Ok(Json(SendBitcoinResponse {
        txid: txid.to_string(),
    }))
}

async fn handle_mine_blocks(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<MineBlocksRequest>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    dev_fed.bitcoind.mine_blocks(req.count).await?;
    Ok(Json(()))
}

async fn handle_bitcoin_address(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<BitcoinAddressResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let address = dev_fed.bitcoind.get_new_address().await?;
    Ok(Json(BitcoinAddressResponse {
        address: address.to_string(),
    }))
}

async fn handle_poll_bitcoin_transaction(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PollTransactionRequest>,
) -> Result<Json<PollTransactionResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let txid = req.txid.parse()?;
    let hex = dev_fed.bitcoind.poll_get_transaction(txid).await?;
    Ok(Json(PollTransactionResponse { hex }))
}

async fn handle_deposit_fees(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<GetDepositFeesResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let msats = dev_fed.fed.deposit_fees()?.msats;
    Ok(Json(GetDepositFeesResponse { msats }))
}

async fn handle_lnd_invoice(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<CreateInvoiceRequest>,
) -> Result<Json<LndInvoiceResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let (invoice, payment_hash) = dev_fed.lnd.invoice(req.amount_msats).await?;
    Ok(Json(LndInvoiceResponse {
        invoice,
        payment_hash,
    }))
}

async fn handle_lnd_pay(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PayInvoiceRequest>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    dev_fed.lnd.pay_bolt11_invoice(req.invoice).await?;
    Ok(Json(()))
}

async fn handle_lnd_wait(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<WaitInvoiceRequest>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    dev_fed.lnd.wait_bolt11_invoice(req.payment_hash).await?;
    Ok(Json(()))
}

async fn handle_lnd_pubkey(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<LndPubkeyResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let pubkey = dev_fed.lnd.pub_key().await?;
    Ok(Json(LndPubkeyResponse { pubkey }))
}

async fn handle_gateway_invoice(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<CreateInvoiceRequest>,
) -> Result<Json<GatewayInvoiceResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    let invoice = dev_fed.gw_ldk.create_invoice(req.amount_msats).await?;
    let payment_hash = invoice.payment_hash().to_byte_array().to_vec();
    Ok(Json(GatewayInvoiceResponse {
        invoice: invoice.to_string(),
        payment_hash,
    }))
}

async fn handle_gateway_wait(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<WaitInvoiceRequest>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    dev_fed.gw_ldk.wait_bolt11_invoice(req.payment_hash).await?;
    Ok(Json(()))
}

async fn handle_recurringd_url(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<RecurringdUrlResponse>, DevimintdError> {
    let dev_fed = state.get_devfed(&devfed_id).await?;
    Ok(Json(RecurringdUrlResponse {
        url: dev_fed.recurringd.api_url.to_string(),
    }))
}

async fn handle_keep_alive(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<()>, DevimintdError> {
    state.get_devfed_no_wait(&devfed_id).await.keep_alive();
    Ok(Json(()))
}

async fn handle_terminate_all_fed_servers(
    Path(devfed_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<()>, DevimintdError> {
    let dev_fed_state = state.get_devfed_no_wait(&devfed_id).await;
    info!("terminating {devfed_id}");
    if dev_fed_state.kind != DevFedKind::Dedicated {
        return Err(anyhow::format_err!("Only dedicated devfeds can be terminated").into());
    }
    let dev_fed = dev_fed_state.wait().await?;
    dev_fed.fed.clone().terminate_all_servers().await?;
    Ok(Json(()))
}
